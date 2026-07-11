"""Cross-tool composition risk analysis.

Individual tools can look benign in isolation while, combined, forming a
confused-deputy chain: one tool reads credentials/secrets, another can send
data to an arbitrary destination. An MCP client grants an agent every tool
in a session at once, so the combination is exactly as reachable as either
tool alone — but analyzers that score one tool at a time can't see it. This
looks across the whole tool set from a single scan for that pairing.
"""

from __future__ import annotations

import re
from typing import Any

from ..models import Finding, Severity

_SENSITIVE_ACCESS_PATTERN = re.compile(
    r"\b(credential|secret|password|passwd|api[_-]?key|access[_-]?token|private[_-]?key|"
    r"ssh[_-]?key|environment\s+variable|\.env\b|browser\s+cookie|session\s+cookie|"
    r"auth(?:orization)?\s+token|keychain|wallet\s+seed|mnemonic)\b",
    re.IGNORECASE,
)

_EGRESS_PATTERN = re.compile(
    r"\b(send\s+(?:an?\s+)?(?:http|request|email|message)|http\s+post|webhook|upload|"
    r"publish\s+to|post\s+(?:data\s+)?to\s+a?\s*url|exfiltrat\w*|outbound\s+request|"
    r"fetch\s+(?:a\s+)?url|make\s+a\s+network\s+request)\b",
    re.IGNORECASE,
)

_EGRESS_PARAM_NAMES = {
    "url",
    "endpoint",
    "webhook_url",
    "callback_url",
    "destination",
    "target_url",
}


class CompositionAnalyzer:
    """Flags dangerous capability pairs spread across a server's tool set."""

    def analyze(self, tools: list[dict[str, Any]]) -> list[Finding]:
        if len(tools) < 2:
            return []

        access_tools: set[str] = set()
        egress_tools: set[str] = set()

        for tool in tools:
            name = tool.get("name", "unknown")
            text = self._text(tool)
            if _SENSITIVE_ACCESS_PATTERN.search(text):
                access_tools.add(name)
            if _EGRESS_PATTERN.search(text) or self._has_egress_param(tool):
                egress_tools.add(name)

        # A single tool doing both isn't a *composition* risk — heuristic
        # agency scoring already flags one overreaching tool on its own.
        if not any(a != e for a in access_tools for e in egress_tools):
            return []

        access_list = ", ".join(f"'{n}'" for n in sorted(access_tools))
        egress_list = ", ".join(f"'{n}'" for n in sorted(egress_tools))
        return [
            Finding(
                severity=Severity.HIGH,
                rule="COMPOSITION_CONFUSED_DEPUTY",
                message=(
                    f"Server exposes tool(s) that access sensitive data ({access_list}) "
                    f"alongside tool(s) with outbound network/send capability ({egress_list}). "
                    "Each tool may look benign alone, but an agent with both available in one "
                    "session can chain them to exfiltrate data."
                ),
                owasp_id="MCP02",
                attack_type="composition_risk",
            )
        ]

    @staticmethod
    def _text(tool: dict[str, Any]) -> str:
        parts = [
            str(tool.get("name", "")),
            str(tool.get("title", "")),
            str(tool.get("description", "")),
        ]
        schema = tool.get("inputSchema", {}) or {}
        for param_name, param in (schema.get("properties", {}) or {}).items():
            parts.append(str(param_name))
            if isinstance(param, dict):
                parts.append(str(param.get("description", "")))
        return " ".join(parts)

    @staticmethod
    def _has_egress_param(tool: dict[str, Any]) -> bool:
        schema = tool.get("inputSchema", {}) or {}
        properties = schema.get("properties", {}) or {}
        return any(str(name).lower() in _EGRESS_PARAM_NAMES for name in properties)
