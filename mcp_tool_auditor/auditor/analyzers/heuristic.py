import re
from typing import Any

from ..models import Finding, Severity
from . import patterns
from .surface import label_for_kind, rule_for_kind


class HeuristicAnalyzer:
    """Applies heuristic scoring to detect tool poisoning patterns."""

    DESC_LENGTH_THRESHOLD = 500
    PARAM_DESC_LENGTH_THRESHOLD = 300
    IMPERATIVE_COUNT_THRESHOLD = 2
    AGENCY_COUNT_THRESHOLD = 3
    AUTHORITY_COUNT_THRESHOLD = 2

    IMPERATIVE_PATTERNS = patterns.IMPERATIVE_PATTERNS
    AGENCY_PATTERNS = patterns.AGENCY_PATTERNS
    AUTHORITY_PATTERNS = patterns.AUTHORITY_PATTERNS

    UNICODE_SUSPECT = patterns.UNICODE_SUSPECT

    def __init__(self, config=None):
        self.desc_length_threshold = getattr(
            config, "desc_length_threshold", self.DESC_LENGTH_THRESHOLD
        )
        self.param_desc_length_threshold = getattr(
            config, "param_desc_length_threshold", self.PARAM_DESC_LENGTH_THRESHOLD
        )
        self.imperative_count_threshold = getattr(
            config, "imperative_count_threshold", self.IMPERATIVE_COUNT_THRESHOLD
        )
        self.agency_count_threshold = getattr(
            config, "agency_count_threshold", self.AGENCY_COUNT_THRESHOLD
        )
        self.authority_count_threshold = getattr(
            config, "authority_count_threshold", self.AUTHORITY_COUNT_THRESHOLD
        )

    def score_tool(self, tool: dict[str, Any], kind: str = "tool") -> list[Finding]:
        """Score a tool/resource/prompt/instructions definition for poisoning heuristics.

        `kind` selects which MCP surface `tool` represents; it only changes
        finding labeling, not the scoring itself.
        """
        findings: list[Finding] = []
        tool_name = tool.get("name", "unknown")
        label = label_for_kind(kind)
        text = f"{tool.get('name', '')} {tool.get('title', '')} " f"{tool.get('description', '')}"

        # --- Description length heuristic ---
        desc = tool.get("description", "")
        if len(desc) > self.desc_length_threshold:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    rule=rule_for_kind("HEUR_DESC_LENGTH", kind),
                    message=f"{label} '{tool_name}': Description is very long ({len(desc)} chars) — may contain embedded instructions.",
                    owasp_id="MCP03",
                    attack_type="tool_poisoning",
                    tool_name=tool_name,
                )
            )

        # --- Unicode invisible characters ---
        for field_name in ("name", "description", "title"):
            val = str(tool.get(field_name, ""))
            matches = HeuristicAnalyzer.UNICODE_SUSPECT.findall(val)
            if matches:
                codepoints = [hex(ord(c)) for c in set(matches)]
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        rule=rule_for_kind("HEUR_UNICODE_HIDDEN", kind),
                        message=f"{label} '{tool_name}': Unicode invisible characters in '{field_name}': {codepoints} — possible hidden instructions.",
                        owasp_id="MCP03",
                        attack_type="stealth",
                        tool_name=tool_name,
                        field=f"{field_name}",
                    )
                )

        # --- Imperative language scoring ---
        imperative_count = sum(
            len(re.findall(p, text, re.IGNORECASE)) for p in HeuristicAnalyzer.IMPERATIVE_PATTERNS
        )
        if imperative_count >= self.imperative_count_threshold:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    rule=rule_for_kind("HEUR_IMPERATIVE", kind),
                    message=f"{label} '{tool_name}': {imperative_count} imperative/directive patterns — description issues commands to the agent.",
                    owasp_id="MCP03",
                    attack_type="tool_poisoning",
                    tool_name=tool_name,
                )
            )

        # --- Agency/action scoring ---
        agency_count = sum(
            len(re.findall(p, text, re.IGNORECASE)) for p in HeuristicAnalyzer.AGENCY_PATTERNS
        )
        if agency_count >= self.agency_count_threshold:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    rule=rule_for_kind("HEUR_AGENCY", kind),
                    message=f"{label} '{tool_name}': {agency_count} agency/action patterns — may request broad capabilities.",
                    owasp_id="MCP02",
                    attack_type="excessive_agency",
                    tool_name=tool_name,
                )
            )

        # --- Authority spoofing ---
        auth_count = sum(
            len(re.findall(p, text, re.IGNORECASE)) for p in HeuristicAnalyzer.AUTHORITY_PATTERNS
        )
        if auth_count >= self.authority_count_threshold:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    rule=rule_for_kind("HEUR_AUTHORITY_SPOOF", kind),
                    message=f"{label} '{tool_name}': {auth_count} authority-claim patterns — may be spoofing system-level authority.",
                    owasp_id="MCP03",
                    attack_type="authority_spoofing",
                    tool_name=tool_name,
                )
            )

        # --- Parameter heuristic analysis (tools only; resources/prompts have no inputSchema) ---
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})

        # Check for parameters with suspiciously long descriptions
        for param_name, param in properties.items():
            param_desc = param.get("description", "")
            if len(param_desc) > self.param_desc_length_threshold:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        rule=rule_for_kind("HEUR_PARAM_DESC_LONG", kind),
                        message=f"{label} '{tool_name}': Parameter '{param_name}' description is very long ({len(param_desc)} chars) — possible embedded instructions.",
                        owasp_id="MCP03",
                        attack_type="full_schema_poisoning",
                        tool_name=tool_name,
                        field=f"inputSchema.properties.{param_name}.description",
                    )
                )

        return findings
