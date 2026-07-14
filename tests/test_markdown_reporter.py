from mcp_tool_auditor.auditor.models import CROSS_SERVER_KEY, Finding, ScanResult, Severity
from mcp_tool_auditor.auditor.reporters.markdown_reporter import MarkdownReporter


def _results():
    tools = [{"name": "read_secrets", "description": "Reads an API key."}]
    return {"fs-server": ScanResult(tools_scanned=1, findings=[], tools=tools)}


def _results_with_cross_server_flow():
    results = _results()
    flow_finding = Finding(
        severity=Severity.CRITICAL,
        rule="FLOW_CROSS_SERVER_EXFIL",
        message="Cross-server toxic flow: tool 'read_secrets' ... tool 'send_webhook' ...",
        owasp_id="MCP02",
        attack_type="cross_server_exfil_chain",
        tool_name="read_secrets",
        field="source_server:fs-server",
        related_tool="send_webhook",
        related_server="http-server",
    )
    results[CROSS_SERVER_KEY] = ScanResult(tools_scanned=0, findings=[flow_finding])
    return results


def test_markdown_report_cross_server_section_heading():
    report = MarkdownReporter.generate(_results_with_cross_server_flow())
    assert "## Cross-Server Toxic-Flow Findings" in report
    assert "## Server: `__cross_server__`" not in report


def test_markdown_report_servers_scanned_excludes_synthetic_entry():
    report = MarkdownReporter.generate(_results_with_cross_server_flow())
    assert "| Servers Scanned | 1 |" in report


def test_markdown_report_without_cross_server_findings_unaffected():
    report = MarkdownReporter.generate(_results())
    assert "Cross-Server" not in report
    assert "| Servers Scanned | 1 |" in report


def _results_with_one_finding():
    tools = [{"name": "read_secrets", "description": "Reads an API key."}]
    finding = Finding(
        severity=Severity.HIGH,
        rule="FSP_DEFAULT_INJECTION",
        message="Tool 'read_secrets': suspicious default value.",
        owasp_id="MCP03",
        attack_type="full_schema_poisoning",
        tool_name="read_secrets",
        confidence="MEDIUM",
    )
    return {"fs-server": ScanResult(tools_scanned=1, findings=[finding], tools=tools)}


def test_markdown_report_shows_per_finding_confidence_distinct_from_severity():
    """A HIGH-severity/MEDIUM-confidence finding must not read as high-certainty

    -- confidence is displayed alongside severity for every finding.
    """
    report = MarkdownReporter.generate(_results_with_one_finding())
    assert "**Confidence:** MEDIUM" in report
    assert "🟠 HIGH Severity Findings" in report


def test_markdown_report_shows_rule_specific_remediation_per_finding():
    report = MarkdownReporter.generate(_results_with_one_finding())
    assert "**Remediation:** " in report
    assert "Full-Schema Poisoning" in report


def test_markdown_report_footer_has_attribution_not_compliance_overclaim():
    report = MarkdownReporter.generate(_results())
    assert "OWASP MCP Top 10 Compliant" not in report
    assert "Findings mapped to the OWASP MCP Top 10" in report
    assert "Përparim Mjeku" in report
    assert "https://www.linkedin.com/in/p%C3%ABrparimmjeku/" in report
