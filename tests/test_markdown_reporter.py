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
