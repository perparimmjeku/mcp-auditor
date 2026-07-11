import re
from collections.abc import Iterable
from importlib import resources
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised in minimal local installs
    yaml = None  # type: ignore[assignment]

from ..models import Finding, Severity
from .surface import label_for_kind, rule_for_kind


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
            if self._matches(signature["pattern"], text):
                findings.append(self._finding_from_signature(signature, tool_name, kind))

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
        self, signature: dict[str, Any], tool_name: str, kind: str
    ) -> Finding:
        return Finding(
            severity=signature["severity"],
            rule=rule_for_kind(signature.get("rule", "STATIC_SIGNATURE"), kind),
            message=f"{label_for_kind(kind)} '{tool_name}': "
            f"{signature.get('message', 'Signature match')}",
            owasp_id=signature.get("owasp_id", "MCP03"),
            attack_type=signature.get("attack_type", "tool_poisoning"),
            tool_name=tool_name,
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
