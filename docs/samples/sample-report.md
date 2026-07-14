# MCP Tool Auditor Report

**Generated:** 2026-07-14T18:12:49.310184+00:00
**Tool:** mcp-tool-auditor v1.10.2
**OWASP Reference:** OWASP MCP Top 10 (2025)

## Summary

| Metric | Value |
|--------|-------|
| Servers Scanned | 1 |
| Tools Scanned | 5 |
| Total Findings | 9 |

### Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 3 |
| 🟡 MEDIUM | 6 |
| 🔵 LOW | 0 |
| ⚪ INFO | 0 |
| ❌ ERROR | 0 |

### OWASP MCP Top 10 Mapping

| OWASP ID | Issue | Findings |
|----------|-------|----------|
| MCP02 | Privilege Escalation via Scope Creep | 1 |
| MCP03 | Tool Poisoning | 8 |

---
## Server: `tests/fixtures/poisoned_tools.json`

- **Tools Scanned:** 5
- **Findings:** 9

### 🟠 HIGH Severity Findings (3)

**1. Tool 'get_compliance_status': Attempting to supersede agent configuration.**
    - **Rule:** `ST_OVERRIDE`
    - **Confidence:** HIGH
    - **OWASP ID:** MCP03
    - **Attack Type:** `tool_poisoning`
    - **Remediation:** A known tool-poisoning signature matched the tool text (e.g. 'ignore previous', 'bypass'). Reject the tool and report it to the server author.

**2. Tool 'get_compliance_status': 9 authority-claim patterns — may be spoofing system-level authority.**
    - **Rule:** `HEUR_AUTHORITY_SPOOF`
    - **Confidence:** MEDIUM
    - **OWASP ID:** MCP03
    - **Attack Type:** `authority_spoofing`
    - **Remediation:** The description claims system/admin authority to coerce the agent. Tool descriptions must not assert authority; treat this as an attempted authority-spoofing attack.

**3. Tool 'read_file': Tool description contains 'always use this tool' — overriding agent tool selection.**
    - **Rule:** `ST_ALWAYS_USE`
    - **Confidence:** HIGH
    - **OWASP ID:** MCP03
    - **Attack Type:** `tool_poisoning`
    - **Remediation:** A known tool-poisoning signature matched the tool text (e.g. 'ignore previous', 'bypass'). Reject the tool and report it to the server author.

### 🟡 MEDIUM Severity Findings (6)

**1. Tool 'get_compliance_status': File read capability mentioned — potential sensitive data access.**
    - **Rule:** `ST_READ_FILE`
    - **Confidence:** LOW
    - **OWASP ID:** MCP03
    - **Attack Type:** `sensitive_access`
    - **Remediation:** File-read capability terminology matched. Confirm the tool restricts reads to an expected directory and doesn't expose arbitrary filesystem contents to the agent.

**2. Tool 'get_compliance_status': 2 imperative/directive patterns — description issues commands to the agent.**
    - **Rule:** `HEUR_IMPERATIVE`
    - **Confidence:** LOW
    - **OWASP ID:** MCP03
    - **Attack Type:** `tool_poisoning`
    - **Remediation:** The description uses imperative/agency language that issues commands to the agent. Tool descriptions should describe function, not instruct the agent; review and reject if poisoned.

**3. Tool 'data_processor': Parameter 'sidenote' matches FSP-suspicious name 'sidenote' — possible hidden instruction injection.**
    - **Rule:** `FSP_PARAM_NAME`
    - **Confidence:** MEDIUM
    - **OWASP ID:** MCP03
    - **Attack Type:** `full_schema_poisoning`
    - **Field:** `inputSchema.properties.sidenote`
    - **Remediation:** A schema field (parameter name, description, enum, default, or required entry) carries hidden instructions (Full-Schema Poisoning). Reject the tool and report it to the server author; do not expose the parameter to the agent.

**4. Tool 'weather_service': AWS credential exposure risk.**
    - **Rule:** `ST_CREDENTIAL`
    - **Confidence:** MEDIUM
    - **OWASP ID:** MCP02
    - **Attack Type:** `credential_exposure`
    - **Remediation:** Credential/secret-related terminology matched in the tool text. Confirm the tool doesn't request secrets unnecessarily, doesn't instruct revealing environment variables, and doesn't transmit or embed credentials; scope secret access narrowly and redact credential values from any output.

**5. Tool 'read_file': File read capability mentioned — potential sensitive data access.**
    - **Rule:** `ST_READ_FILE`
    - **Confidence:** LOW
    - **OWASP ID:** MCP03
    - **Attack Type:** `sensitive_access`
    - **Remediation:** File-read capability terminology matched. Confirm the tool restricts reads to an expected directory and doesn't expose arbitrary filesystem contents to the agent.

**6. Tool 'read_file': Potential data exfiltration via HTTP.**
    - **Rule:** `ST_DATA_EXFIL`
    - **Confidence:** MEDIUM
    - **OWASP ID:** MCP03
    - **Attack Type:** `data_exfiltration`
    - **Remediation:** Terminology describing outbound data transmission (HTTP send/post) matched. Confirm the destination is restricted to expected, allowlisted endpoints and that no sensitive data is sent without explicit user awareness; add a domain allowlist if the tool makes arbitrary outbound requests.

---
## Remediation Recommendations

1. **Pin tool versions** — Never use `latest`. Pin to specific, verified versions.
2. **Register tool fingerprints** — Run `mcp-tool-auditor register` to establish baselines.
3. **Use pre-deployment scanning** — Scan all tool definitions before approval (CI/CD gate).
4. **Isolate privileged tools** — Run high-privilege tools in a separate agent context.
5. **Enforce server-side controls** — Don't rely on system prompts for tool restrictions.
6. **Require user confirmation** — For destructive or data-exfiltrating actions.
7. **Monitor for rug pulls** — Run `mcp-tool-auditor check` periodically.
8. **Control egress traffic** — Only allow connections to known, approved destinations.

---
Findings mapped to the OWASP MCP Top 10
mcp-tool-auditor by Përparim Mjeku — https://www.linkedin.com/in/p%C3%ABrparimmjeku/
