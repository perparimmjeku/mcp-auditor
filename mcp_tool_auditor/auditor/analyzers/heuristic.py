import re
from typing import List, Dict, Any
from ..models import Finding, Severity


class HeuristicAnalyzer:
    """Applies heuristic scoring to detect tool poisoning patterns."""

    IMPERATIVE_PATTERNS = [
        r"\b(must|always|never|required|mandatory)\b",
        r"\b(you (shall|will|need to|have to))\b",
        r"\b(do not|don't|should not)\b",
    ]

    AGENCY_PATTERNS = [
        r"\b(send|post|upload|exfiltrate)\b",
        r"\b(read|write|delete|modify)\b",
        r"\b(access|retrieve|fetch|download)\b",
    ]

    AUTHORITY_PATTERNS = [
        r"\b(system|admin|root|supervisor|compliance|audit)\b",
        r"\b(official|authoritative|certified|approved)\b",
    ]

    UNICODE_SUSPECT = re.compile(
        r"[\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff]"
    )

    @staticmethod
    def score_tool(tool: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        tool_name = tool.get("name", "unknown")
        text = (
            f"{tool.get('name', '')} {tool.get('title', '')} "
            f"{tool.get('description', '')}"
        )

        # --- Description length heuristic ---
        desc = tool.get("description", "")
        if len(desc) > 500:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                rule="HEUR_DESC_LENGTH",
                message=f"Tool '{tool_name}': Description is very long ({len(desc)} chars) — may contain embedded instructions.",
                owasp_id="MCP03",
                attack_type="tool_poisoning",
                tool_name=tool_name,
            ))

        # --- Unicode invisible characters ---
        for field_name in ("name", "description", "title"):
            val = str(tool.get(field_name, ""))
            matches = HeuristicAnalyzer.UNICODE_SUSPECT.findall(val)
            if matches:
                codepoints = [hex(ord(c)) for c in set(matches)]
                findings.append(Finding(
                    severity=Severity.HIGH,
                    rule="HEUR_UNICODE_HIDDEN",
                    message=f"Tool '{tool_name}': Unicode invisible characters in '{field_name}': {codepoints} — possible hidden instructions.",
                    owasp_id="MCP03",
                    attack_type="stealth",
                    tool_name=tool_name,
                    field=f"{field_name}",
                ))

        # --- Imperative language scoring ---
        imperative_count = sum(
            len(re.findall(p, text, re.IGNORECASE))
            for p in HeuristicAnalyzer.IMPERATIVE_PATTERNS
        )
        if imperative_count >= 2:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                rule="HEUR_IMPERATIVE",
                message=f"Tool '{tool_name}': {imperative_count} imperative/directive patterns — tool description issues commands to the agent.",
                owasp_id="MCP03",
                attack_type="tool_poisoning",
                tool_name=tool_name,
            ))

        # --- Agency/action scoring ---
        agency_count = sum(
            len(re.findall(p, text, re.IGNORECASE))
            for p in HeuristicAnalyzer.AGENCY_PATTERNS
        )
        if agency_count >= 3:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                rule="HEUR_AGENCY",
                message=f"Tool '{tool_name}': {agency_count} agency/action patterns — may request broad capabilities.",
                owasp_id="MCP02",
                attack_type="excessive_agency",
                tool_name=tool_name,
            ))

        # --- Authority spoofing ---
        auth_count = sum(
            len(re.findall(p, text, re.IGNORECASE))
            for p in HeuristicAnalyzer.AUTHORITY_PATTERNS
        )
        if auth_count >= 2:
            findings.append(Finding(
                severity=Severity.HIGH,
                rule="HEUR_AUTHORITY_SPOOF",
                message=f"Tool '{tool_name}': {auth_count} authority-claim patterns — tool may be spoofing system-level authority.",
                owasp_id="MCP03",
                attack_type="authority_spoofing",
                tool_name=tool_name,
            ))

        # --- Parameter heuristic analysis ---
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})

        # Check for parameters with suspiciously long descriptions
        for param_name, param in properties.items():
            param_desc = param.get("description", "")
            if len(param_desc) > 300:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    rule="HEUR_PARAM_DESC_LONG",
                    message=f"Tool '{tool_name}': Parameter '{param_name}' description is very long ({len(param_desc)} chars) — possible embedded instructions.",
                    owasp_id="MCP03",
                    attack_type="full_schema_poisoning",
                    tool_name=tool_name,
                    field=f"inputSchema.properties.{param_name}.description",
                ))

        return findings