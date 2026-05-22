from typing import List, Dict, Any
from ..models import Finding, Severity


class SchemaAnalyzer:
    """Analyzes tool schemas for poisoning indicators — especially Full-Schema Poisoning (FSP)."""

    # CyberArk-identified FSP parameter names
    FSP_SUSPICIOUS_PARAM_NAMES = [
        "sidenote", "note", "comment", "remark", "metadata",
        "context", "extra", "additional", "auxiliary",
    ]

    # Known prompt injection vector parameter names
    PROMPT_INJECTION_PARAMS = [
        "system_prompt", "instructions", "directive", "command",
        "override", "priority", "mode",
    ]

    # Overly permissive schema types
    SUSPICIOUS_TYPES = ["any", "null"]

    @staticmethod
    def analyze(tool: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        tool_name = tool.get("name", "unknown")
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        # --- FSP: Check parameter names ---
        for param_name, param in properties.items():
            param_lower = param_name.lower()

            for fsp_name in SchemaAnalyzer.FSP_SUSPICIOUS_PARAM_NAMES:
                if SchemaAnalyzer._param_name_matches(param_lower, fsp_name):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        rule="FSP_PARAM_NAME",
                        message=f"Tool '{tool_name}': Parameter '{param_name}' matches FSP-suspicious name '{fsp_name}' — possible hidden instruction injection.",
                        owasp_id="MCP03",
                        attack_type="full_schema_poisoning",
                        tool_name=tool_name,
                        field=f"inputSchema.properties.{param_name}",
                    ))

            for inj_name in SchemaAnalyzer.PROMPT_INJECTION_PARAMS:
                if inj_name in param_lower:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        rule="FSP_INJECTION_PARAM",
                        message=f"Tool '{tool_name}': Parameter '{param_name}' is a known prompt injection vector name.",
                        owasp_id="MCP03",
                        attack_type="full_schema_poisoning",
                        tool_name=tool_name,
                        field=f"inputSchema.properties.{param_name}",
                    ))

            # Check parameter description for injection patterns
            param_desc = param.get("description", "")
            if "ignore" in param_desc.lower() and "security" in param_desc.lower():
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    rule="FSP_DESC_INJECTION",
                    message=f"Tool '{tool_name}': Parameter '{param_name}' description contains 'ignore' and 'security' — likely injection payload.",
                    owasp_id="MCP03",
                    attack_type="full_schema_poisoning",
                    tool_name=tool_name,
                    field=f"inputSchema.properties.{param_name}.description",
                ))

            # Check for overly permissive types
            param_type = param.get("type", "string")
            if param_type in SchemaAnalyzer.SUSPICIOUS_TYPES:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    rule="SCHEMA_GENERIC_TYPE",
                    message=f"Tool '{tool_name}': Parameter '{param_name}' uses type '{param_type}' which is overly permissive.",
                    owasp_id="MCP03",
                    attack_type="schema_poisoning",
                    tool_name=tool_name,
                    field=f"inputSchema.properties.{param_name}.type",
                ))

            # Untyped parameters (no type, no enum, no $ref)
            if "type" not in param and "enum" not in param and "$ref" not in param:
                findings.append(Finding(
                    severity=Severity.LOW,
                    rule="SCHEMA_UNTYPED",
                    message=f"Tool '{tool_name}': Parameter '{param_name}' has no type constraint — accepts any value.",
                    owasp_id="MCP03",
                    attack_type="schema_poisoning",
                    tool_name=tool_name,
                    field=f"inputSchema.properties.{param_name}",
                ))

        # --- FSP: Check required array for embedded instructions ---
        for req_field in required:
            if req_field not in properties:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    rule="FSP_MISSING_REQUIRED",
                    message=f"Tool '{tool_name}': Required field '{req_field}' is not defined in properties — may be poisoned.",
                    owasp_id="MCP03",
                    attack_type="schema_poisoning",
                    tool_name=tool_name,
                    field="inputSchema.required",
                ))
            if len(req_field) > 50:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    rule="FSP_REQUIRED_LENGTH",
                    message=f"Tool '{tool_name}': Required field name is excessively long ({len(req_field)} chars) — possible embedded instruction.",
                    owasp_id="MCP03",
                    attack_type="schema_poisoning",
                    tool_name=tool_name,
                    field="inputSchema.required",
                ))

        # --- FSP: Check enum values for injection ---
        for param_name, param in properties.items():
            enum_vals = param.get("enum", [])
            for val in enum_vals:
                if isinstance(val, str) and len(val) > 100:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        rule="FSP_ENUM_INJECTION",
                        message=f"Tool '{tool_name}': Enum value in '{param_name}' is excessively long ({len(val)} chars) — possible embedded instruction.",
                        owasp_id="MCP03",
                        attack_type="full_schema_poisoning",
                        tool_name=tool_name,
                        field=f"inputSchema.properties.{param_name}.enum",
                    ))
                if isinstance(val, str) and any(
                    kw in val.lower() for kw in ["read_file", "ignore", "must", "send"]
                ):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        rule="FSP_ENUM_POISON",
                        message=f"Tool '{tool_name}': Enum value in '{param_name}' contains instructional keywords — possible poisoning.",
                        owasp_id="MCP03",
                        attack_type="full_schema_poisoning",
                        tool_name=tool_name,
                        field=f"inputSchema.properties.{param_name}.enum",
                    ))

        # --- FSP: Check default values for injection ---
        for param_name, param in properties.items():
            default_val = param.get("default", "")
            if isinstance(default_val, str) and (
                len(default_val) > 150
                or any(
                    kw in default_val.lower()
                    for kw in [
                        "ignore",
                        "read_file",
                        "execute",
                        "send",
                        "credential",
                        "secret",
                        "token",
                        "api_key",
                    ]
                )
            ):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    rule="FSP_DEFAULT_INJECTION",
                    message=f"Tool '{tool_name}': Default value in '{param_name}' is excessively long ({len(default_val)} chars) — possible embedded instruction.",
                    owasp_id="MCP03",
                    attack_type="full_schema_poisoning",
                    tool_name=tool_name,
                    field=f"inputSchema.properties.{param_name}.default",
                ))

        return findings

    @staticmethod
    def _param_name_matches(param_name: str, suspicious_name: str) -> bool:
        return (
            param_name == suspicious_name
            or param_name.startswith(f"{suspicious_name}_")
            or param_name.endswith(f"_{suspicious_name}")
            or f"_{suspicious_name}_" in param_name
        )
