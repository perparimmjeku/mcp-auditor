"""1.10.2: the report footer/metadata dropped the "OWASP MCP Top 10 Compliant"
overclaim (the tool maps findings to MCP01/02/03/05 -- it isn't a compliance
certification) in favor of accurate wording plus author attribution. This
covers the JSON and SARIF metadata fields; markdown/pentest footer text is
covered in their own reporter test files."""

import json

from mcp_tool_auditor.auditor.models import Finding, ScanResult, Severity
from mcp_tool_auditor.auditor.reporters.json_reporter import JSONReporter
from mcp_tool_auditor.auditor.reporters.sarif_reporter import SarifReporter


def _results():
    tools = [{"name": "read_secrets", "description": "Reads an API key."}]
    finding = Finding(
        severity=Severity.HIGH,
        rule="ST_CREDENTIAL",
        message="Tool 'read_secrets': credential terminology matched.",
        owasp_id="MCP01",
        attack_type="credential_exposure",
        tool_name="read_secrets",
    )
    return {"fs-server": ScanResult(tools_scanned=1, findings=[finding], tools=tools)}


def test_json_reporter_scan_metadata_has_author_attribution():
    doc = json.loads(JSONReporter.generate(_results()))
    meta = doc["scan_metadata"]
    assert meta["author"] == "Përparim Mjeku"
    assert meta["author_url"] == "https://www.linkedin.com/in/p%C3%ABrparimmjeku/"


def test_sarif_reporter_tool_driver_has_organization_attribution():
    doc = json.loads(SarifReporter.generate(_results()))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["organization"] == "Përparim Mjeku"
