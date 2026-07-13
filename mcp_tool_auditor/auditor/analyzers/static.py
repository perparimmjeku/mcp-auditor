import re
from collections.abc import Iterable
from importlib import resources
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised in minimal local installs
    yaml = None  # type: ignore[assignment]

from ..models import Finding, Severity
from . import context as context_classifier
from .surface import label_for_kind, rule_for_kind

_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".zip", ".whl", ".jar", ".7z", ".tar", ".gz")
_ARCHIVE_MIME_TYPES = {
    "application/gzip",
    "application/x-gzip",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-tar",
    "application/java-archive",
    "application/x-7z-compressed",
}

# Two categories of JSON-Schema/MCP-protocol structural keys, both scoped as
# narrowly as possible so a real attack can never hide behind them:
#
# _FULLY_EXCLUDED_KEYS: the key AND its entire value subtree are skipped.
# Reserved for fields that are fixed, protocol-mandated boilerplate no tool
# author can change -- "$schema" is the JSON-Schema meta-schema URI (e.g.
# "http://json-schema.org/draft-07/schema#", present on virtually every real
# tool's inputSchema/outputSchema and coincidentally matching ST_DATA_EXFIL's
# "http" component); "execution" is the MCP 2025-06-18+ task-support block
# ({"taskSupport": "forbidden"|"optional"|"required"}), a closed protocol
# enum with no free-text field anywhere inside it, whose key name alone
# matches ST_EXECUTE's "execute" pattern. Neither can ever carry attacker
# content without breaking JSON-Schema validation or MCP protocol compliance.
#
# _KEYWORD_ONLY_EXCLUDED_KEYS: only the KEY NAME token is skipped; the VALUE
# is still fully recursed into and scanned. These are JSON-Schema vocabulary
# words that happen to be ordinary English words a future signature could
# collide with -- but their values are exactly where real attacker-controlled
# content lives (parameter names/descriptions under "properties", poisoned
# enum entries under "enum", nested array-item schemas under "items"), so the
# value must never be skipped. This set must never include "description",
# "title", "name", or any other genuinely free-text field.
_FULLY_EXCLUDED_KEYS = {"$schema", "execution"}
_KEYWORD_ONLY_EXCLUDED_KEYS = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "enum",
    "items",
}


class StaticAnalyzer:
    """Signature-based static analysis of MCP tool definitions."""

    _SEVERITY_GROUPS = {
        "critical_severity": Severity.CRITICAL,
        "high_severity": Severity.HIGH,
        "medium_severity": Severity.MEDIUM,
        "low_severity": Severity.LOW,
        "info_severity": Severity.INFO,
    }

    def __init__(self, custom_signatures: list[dict[str, Any]] | None = None):
        self._builtin = self._load_builtin_signatures()
        self._custom = custom_signatures or []

    def analyze(self, tool: dict[str, Any], kind: str = "tool") -> list[Finding]:
        """Run static analysis on a single tool/resource/prompt/instructions definition.

        `kind` selects which MCP surface `tool` represents ("tool", "resource",
        "prompt", or "instructions"); it only affects finding labeling, not
        detection — the same signatures apply everywhere text can hide an
        injection payload.
        """
        findings: list[Finding] = []
        tool_name = tool.get("name", "unknown")
        text = self._get_text(tool)

        for signature in self._builtin:
            if not self._matches(signature["pattern"], text):
                continue
            rule = signature.get("rule", "STATIC_SIGNATURE")
            if rule in context_classifier.CLASSIFIED_RULES:
                outcome = context_classifier.classify(
                    rule,
                    signature["pattern"],
                    text,
                    self._get_core_text(tool),
                    self._get_output_text(tool),
                )
                if outcome is None:
                    continue  # context indicates no real security signal
                severity, confidence = outcome
                findings.append(
                    self._finding_from_signature(
                        signature,
                        tool_name,
                        kind,
                        severity_override=severity,
                        confidence_override=confidence,
                    )
                )
            else:
                findings.append(self._finding_from_signature(signature, tool_name, kind))

        if self._is_archive(tool):
            findings.append(self._archive_finding(tool_name, kind))

        # Custom signatures
        for cs in self._custom:
            pattern = cs.get("pattern", "")
            rule = cs.get("rule", "CUSTOM")
            msg = cs.get("message", "Custom signature match")
            atype = cs.get("attack_type", "custom")
            severity = Severity(cs.get("severity", "MEDIUM"))
            owasp = cs.get("owasp_id", "MCP03")
            if pattern and self._matches(pattern, text):
                findings.append(
                    Finding(
                        severity=severity,
                        rule=rule_for_kind(f"CUSTOM_{rule}", kind),
                        message=f"{label_for_kind(kind)} '{tool_name}': {msg}",
                        owasp_id=owasp,
                        attack_type=atype,
                        tool_name=tool_name,
                    )
                )

        return findings

    def _finding_from_signature(
        self,
        signature: dict[str, Any],
        tool_name: str,
        kind: str,
        severity_override: Severity | None = None,
        confidence_override: str | None = None,
    ) -> Finding:
        return Finding(
            severity=severity_override or signature["severity"],
            rule=rule_for_kind(signature.get("rule", "STATIC_SIGNATURE"), kind),
            message=f"{label_for_kind(kind)} '{tool_name}': "
            f"{signature.get('message', 'Signature match')}",
            owasp_id=signature.get("owasp_id", "MCP03"),
            attack_type=signature.get("attack_type", "tool_poisoning"),
            tool_name=tool_name,
            confidence=confidence_override,
        )

    def _get_output_text(self, tool: dict[str, Any]) -> str:
        """Text from the tool's output schema only -- describes what the
        tool *returns*, a weaker signal than a request or capability
        description found elsewhere."""
        output_schema = tool.get("outputSchema")
        if not output_schema:
            return ""
        return " ".join(self._iter_strings(output_schema))

    def _get_core_text(self, tool: dict[str, Any]) -> str:
        """Every text field except the output schema."""
        reduced = {k: v for k, v in tool.items() if k != "outputSchema"}
        return " ".join(self._iter_strings(reduced))

    @staticmethod
    def _is_archive(tool: dict[str, Any]) -> bool:
        name = str(tool.get("name", "")).lower()
        uri = str(tool.get("uri", "")).lower()
        mime = str(tool.get("mimeType", "")).lower()
        if mime in _ARCHIVE_MIME_TYPES:
            return True
        return any(name.endswith(suf) or uri.endswith(suf) for suf in _ARCHIVE_SUFFIXES)

    @staticmethod
    def _archive_finding(tool_name: str, kind: str) -> Finding:
        return Finding(
            severity=Severity.INFO,
            rule=rule_for_kind("ST_ARCHIVE_UNINSPECTED", kind),
            message=f"{label_for_kind(kind)} '{tool_name}': Archive format detected — "
            f"contents not inspected; treat as untrusted until verified.",
            owasp_id="MCP04",
            attack_type="unverified_archive",
            tool_name=tool_name,
            confidence="INFO",
        )

    def _load_builtin_signatures(self) -> list[dict[str, Any]]:
        with (
            resources.files("mcp_tool_auditor.auditor.signatures")
            .joinpath("descriptions.yaml")
            .open("r", encoding="utf-8") as fh
        ):
            text = fh.read()
        if yaml:
            data = yaml.safe_load(text) or {}
        else:
            data = self._parse_simple_signature_yaml(text)

        signatures: list[dict[str, Any]] = []
        for group, severity in self._SEVERITY_GROUPS.items():
            for signature in data.get(group, []):
                signatures.append({**signature, "severity": severity})
        return signatures

    @staticmethod
    def _parse_simple_signature_yaml(text: str) -> dict[str, list[dict[str, str]]]:
        """Parse this repo's simple signature YAML when PyYAML is unavailable."""
        data: dict[str, list[dict[str, str]]] = {}
        current_group = ""
        current_item: dict[str, str] | None = None

        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            if not line.startswith(" ") and line.endswith(":"):
                current_group = line[:-1].strip()
                data[current_group] = []
                current_item = None
                continue

            stripped = line.strip()
            if stripped.startswith("- "):
                if current_group:
                    current_item = {}
                    data.setdefault(current_group, []).append(current_item)
                    stripped = stripped[2:].strip()
                else:
                    continue

            if current_item is not None and ":" in stripped:
                key, value = stripped.split(":", 1)
                current_item[key.strip()] = value.strip().strip('"').strip("'")

        return data

    def _get_text(self, tool: dict[str, Any]) -> str:
        """Concatenate all text fields from a tool definition."""
        return " ".join(self._iter_strings(tool))

    @classmethod
    def _iter_strings(cls, value: Any) -> Iterable[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for key, inner in value.items():
                if key in _FULLY_EXCLUDED_KEYS:
                    continue
                if key not in _KEYWORD_ONLY_EXCLUDED_KEYS:
                    yield str(key)
                yield from cls._iter_strings(inner)
        elif isinstance(value, list):
            for inner in value:
                yield from cls._iter_strings(inner)

    @staticmethod
    def _matches(pattern: str, text: str) -> bool:
        try:
            return re.search(pattern, text, re.IGNORECASE) is not None
        except re.error:
            return re.search(re.escape(pattern), text, re.IGNORECASE) is not None
