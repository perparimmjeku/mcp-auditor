from datetime import datetime, timezone

from ... import __version__
from ..models import CROSS_SERVER_KEY, ScanResult, Severity


class MarkdownReporter:
    SEVERITY_EMOJI = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "⚪",
        Severity.ERROR: "❌",
    }

    OWASP_LABELS = {
        "MCP01": "Token Mismanagement & Secret Exposure",
        "MCP02": "Privilege Escalation via Scope Creep",
        "MCP03": "Tool Poisoning",
        "MCP04": "Software Supply Chain Attacks",
        "MCP05": "Command Injection & Execution",
        "MCP06": "Improper Output Handling",
        "MCP07": "Insecure Session Management",
        "MCP08": "Denial of Service",
        "MCP09": "Data Leakage via Side Channels",
        "MCP10": "Insufficient Logging & Monitoring",
    }

    @staticmethod
    def generate(results: dict[str, ScanResult]) -> str:
        lines = []
        lines.append("# MCP Tool Auditor Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
        lines.append(f"**Tool:** mcp-tool-auditor v{__version__}")
        lines.append("**OWASP Reference:** OWASP MCP Top 10 (2025)")
        lines.append("")

        total_findings = sum(len(r.findings) for r in results.values())
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        server_count = sum(1 for name in results if name != CROSS_SERVER_KEY)
        lines.append(f"| Servers Scanned | {server_count} |")
        lines.append(f"| Tools Scanned | {sum(r.tools_scanned for r in results.values())} |")
        lines.append(f"| Total Findings | {total_findings} |")
        lines.append("")

        # Severity breakdown
        severity_counts: dict[str, int] = {}
        for r in results.values():
            for f in r.findings:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append("### Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in Severity:
            emoji = MarkdownReporter.SEVERITY_EMOJI.get(sev, "")
            count = severity_counts.get(sev.value, 0)
            lines.append(f"| {emoji} {sev.value} | {count} |")
        lines.append("")

        # OWASP mapping
        owasp_counts: dict[str, int] = {}
        for r in results.values():
            for f in r.findings:
                owasp_counts[f.owasp_id] = owasp_counts.get(f.owasp_id, 0) + 1

        lines.append("### OWASP MCP Top 10 Mapping")
        lines.append("")
        lines.append("| OWASP ID | Issue | Findings |")
        lines.append("|----------|-------|----------|")
        for oid in sorted(owasp_counts):
            label = MarkdownReporter.OWASP_LABELS.get(oid, "Unknown")
            count = owasp_counts[oid]
            lines.append(f"| {oid} | {label} | {count} |")
        lines.append("")

        # Per-server results
        for server_name, scan_result in results.items():
            lines.append("---")
            if server_name == CROSS_SERVER_KEY:
                lines.append("## Cross-Server Toxic-Flow Findings")
                lines.append("")
                lines.append(
                    "_Findings below implicate a tool pair on two different servers — see "
                    "each finding's message for both endpoints._"
                )
            else:
                lines.append(f"## Server: `{server_name}`")
                lines.append("")
                lines.append(f"- **Tools Scanned:** {scan_result.tools_scanned}")
            lines.append(f"- **Findings:** {len(scan_result.findings)}")
            lines.append("")

            if not scan_result.findings:
                lines.append("✅ **No findings.** This server appears clean.")
                continue

            for sev in Severity:
                sev_findings = [f for f in scan_result.findings if f.severity == sev]
                if not sev_findings:
                    continue
                emoji = MarkdownReporter.SEVERITY_EMOJI.get(sev, "")
                lines.append(f"### {emoji} {sev.value} Severity Findings ({len(sev_findings)})")
                lines.append("")

                for i, finding in enumerate(sev_findings, 1):
                    lines.append(f"**{i}. {finding.message}**")
                    lines.append(f"    - **Rule:** `{finding.rule}`")
                    lines.append(f"    - **OWASP ID:** {finding.owasp_id}")
                    lines.append(f"    - **Attack Type:** `{finding.attack_type}`")
                    if finding.field:
                        lines.append(f"    - **Field:** `{finding.field}`")
                    lines.append("")

        # Recommendations
        lines.append("---")
        lines.append("## Remediation Recommendations")
        lines.append("")
        lines.append(
            "1. **Pin tool versions** — Never use `latest`. Pin to specific, verified versions."
        )
        lines.append(
            "2. **Register tool fingerprints** — Run `mcp-tool-auditor register` to establish baselines."
        )
        lines.append(
            "3. **Use pre-deployment scanning** — Scan all tool definitions before approval (CI/CD gate)."
        )
        lines.append(
            "4. **Isolate privileged tools** — Run high-privilege tools in a separate agent context."
        )
        lines.append(
            "5. **Enforce server-side controls** — Don't rely on system prompts for tool restrictions."
        )
        lines.append(
            "6. **Require user confirmation** — For destructive or data-exfiltrating actions."
        )
        lines.append("7. **Monitor for rug pulls** — Run `mcp-tool-auditor check` periodically.")
        lines.append(
            "8. **Control egress traffic** — Only allow connections to known, approved destinations."
        )
        lines.append("")
        lines.append("---")
        lines.append("*Report generated by mcp-tool-auditor | OWASP MCP Top 10 Compliant*")

        return "\n".join(lines)
