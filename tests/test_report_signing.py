import copy

from mcp_tool_auditor.auditor import report_signing
from mcp_tool_auditor.auditor.models import Finding, ScanResult, Severity
from mcp_tool_auditor.auditor.reporters.pentest_reporter import PentestReporter
from mcp_tool_auditor.engagement import Engagement


def _results():
    findings = [
        Finding(
            severity=Severity.CRITICAL,
            rule="FSP_DESC_INJECTION",
            message="Tool 'read_creds': injection payload.",
            owasp_id="MCP03",
            tool_name="read_creds",
        )
    ]
    return {
        "https://target.example.com/mcp": ScanResult(
            tools_scanned=1, findings=findings, tools=[{"name": "read_creds"}]
        )
    }


def _engagement():
    return Engagement(client="Acme Corp", tester="J. Doe", start_date="2026-07-01")


def test_sign_then_verify_is_valid(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_TOOL_AUDITOR_REPORT_KEY", "test-key-for-signing")
    sidecar = report_signing.sign_report(_results(), "9.9.9", engagement=_engagement())
    result = report_signing.verify_report(sidecar)
    assert result["status"] == "VALID"
    assert result["tool_version"] == "9.9.9"
    assert result["key_id"] == result["verifying_key_id"]


def test_altered_finding_in_payload_is_tampered(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_AUDITOR_REPORT_KEY", "test-key-for-signing")
    sidecar = report_signing.sign_report(_results(), "9.9.9", engagement=_engagement())
    tampered = copy.deepcopy(sidecar)
    tampered["payload"]["findings"][0]["severity"] = "LOW"
    result = report_signing.verify_report(tampered)
    assert result["status"] == "TAMPERED"


def test_altered_rule_in_payload_is_tampered(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_AUDITOR_REPORT_KEY", "test-key-for-signing")
    sidecar = report_signing.sign_report(_results(), "9.9.9", engagement=_engagement())
    tampered = copy.deepcopy(sidecar)
    tampered["payload"]["findings"][0]["rule"] = "ST_IGNORE_PREVIOUS"
    result = report_signing.verify_report(tampered)
    assert result["status"] == "TAMPERED"


def test_altered_target_scope_is_tampered(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_AUDITOR_REPORT_KEY", "test-key-for-signing")
    sidecar = report_signing.sign_report(_results(), "9.9.9", engagement=_engagement())
    tampered = copy.deepcopy(sidecar)
    # Re-attributing a finding to a different server is scope tampering,
    # not just content tampering -- must be caught too.
    tampered["payload"]["findings"][0]["server"] = "https://out-of-scope.example.com/mcp"
    result = report_signing.verify_report(tampered)
    assert result["status"] == "TAMPERED"


def test_reformatting_the_human_report_does_not_affect_the_signature(monkeypatch):
    """The whole point of signing a canonical payload instead of raw bytes:
    the rendered markdown can be freely reformatted/annotated without
    invalidating the signature, because the signature never depended on the
    prose bytes in the first place."""
    monkeypatch.setenv("MCP_TOOL_AUDITOR_REPORT_KEY", "test-key-for-signing")
    results = _results()
    engagement = _engagement()
    sidecar = report_signing.sign_report(results, "9.9.9", engagement=engagement)

    original_report = PentestReporter.generate(results, engagement=engagement)
    reformatted_report = (
        "<!-- Annotated by legal review 2026-07-13 -->\n\n"
        + original_report.replace("Executive Summary", "EXECUTIVE SUMMARY (reviewed)")
        + "\n\n<!-- end annotation -->\n"
    )
    assert reformatted_report != original_report

    # Verification only ever looks at the sidecar's payload, never the
    # report text, so reformatting it changes nothing about the result.
    result = report_signing.verify_report(sidecar)
    assert result["status"] == "VALID"


def test_wrong_key_is_invalid_not_tampered(tmp_path, monkeypatch):
    monkeypatch.delenv("MCP_TOOL_AUDITOR_REPORT_KEY", raising=False)
    key_dir_a = str(tmp_path / "a")
    key_dir_b = str(tmp_path / "b")
    sidecar = report_signing.sign_report(
        _results(), "9.9.9", engagement=_engagement(), key_dir=key_dir_a
    )
    result = report_signing.verify_report(sidecar, key_dir=key_dir_b)
    assert result["status"] == "INVALID"
    assert result["key_id"] != result["verifying_key_id"]


def test_missing_signature_or_payload_is_invalid():
    assert report_signing.verify_report({})["status"] == "INVALID"
    assert report_signing.verify_report({"signature": "abc"})["status"] == "INVALID"
    assert report_signing.verify_report({"payload": {}})["status"] == "INVALID"


def test_payload_binds_tool_version_and_engagement_metadata(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_AUDITOR_REPORT_KEY", "test-key-for-signing")
    engagement = _engagement()
    sidecar = report_signing.sign_report(_results(), "9.9.9", engagement=engagement)
    payload = sidecar["payload"]
    assert payload["tool_version"] == "9.9.9"
    assert payload["engagement"]["client"] == "Acme Corp"
    assert payload["engagement"]["tester"] == "J. Doe"
    assert payload["engagement"]["start_date"] == "2026-07-01"
    assert payload["targets"] == ["https://target.example.com/mcp"]
    assert sidecar["tool_version"] == "9.9.9"


def test_payload_without_engagement_has_empty_but_present_fields(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_AUDITOR_REPORT_KEY", "test-key-for-signing")
    sidecar = report_signing.sign_report(_results(), "9.9.9", engagement=None)
    assert sidecar["payload"]["engagement"] == {
        "client": "",
        "tester": "",
        "start_date": "",
        "end_date": "",
        "notes": "",
        "allowed_targets": [],
    }
