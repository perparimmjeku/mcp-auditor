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


def test_canonical_payload_is_deterministic_across_dict_insertion_order(monkeypatch):
    """Required for (A) to work at all: two ScanResult dicts with the same
    findings/metadata but built in a DIFFERENT insertion order (e.g. two
    separate scan runs that happen to enumerate servers differently) must
    produce a byte-identical canonical payload, or the same real findings
    could sign to two different signatures depending on incidental ordering."""
    findings_a = [
        Finding(
            severity=Severity.HIGH,
            rule="ST_IGNORE_PREVIOUS",
            message="m-a",
            owasp_id="MCP01",
            tool_name="tool_a",
        )
    ]
    findings_b = [
        Finding(
            severity=Severity.MEDIUM,
            rule="HEUR_IMPERATIVE",
            message="m-b",
            owasp_id="MCP03",
            tool_name="tool_b",
        )
    ]
    results_order_1 = {
        "server-a": ScanResult(tools_scanned=1, findings=findings_a),
        "server-b": ScanResult(tools_scanned=1, findings=findings_b),
    }
    results_order_2 = {
        "server-b": ScanResult(tools_scanned=1, findings=findings_b),
        "server-a": ScanResult(tools_scanned=1, findings=findings_a),
    }
    engagement = _engagement()
    payload_1 = report_signing.build_canonical_payload(
        results_order_1, "9.9.9", engagement=engagement
    )
    payload_2 = report_signing.build_canonical_payload(
        results_order_2, "9.9.9", engagement=engagement
    )
    assert payload_1 == payload_2

    from mcp_tool_auditor.auditor import signing

    assert signing.canonical_bytes(payload_1) == signing.canonical_bytes(payload_2)


def test_sign_report_is_reproducible_modulo_timestamp(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_AUDITOR_REPORT_KEY", "test-key-for-signing")
    results = _results()
    engagement = _engagement()
    sidecar_1 = report_signing.sign_report(results, "9.9.9", engagement=engagement)
    sidecar_2 = report_signing.sign_report(results, "9.9.9", engagement=engagement)
    assert sidecar_1["signature"] == sidecar_2["signature"]
    assert sidecar_1["payload_sha256"] == sidecar_2["payload_sha256"]
    assert sidecar_1["payload"] == sidecar_2["payload"]
    # The only field allowed to differ between two signings of the same data.
    assert "signed_at" in sidecar_1 and "signed_at" in sidecar_2


def test_retest_payload_includes_fixed_findings_sorted(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_AUDITOR_REPORT_KEY", "test-key-for-signing")
    fixed_b = (
        "server-b",
        Finding(
            severity=Severity.HIGH,
            rule="ST_BYPASS",
            message="fixed-b",
            owasp_id="MCP01",
            tool_name="tool_b",
        ),
    )
    fixed_a = (
        "server-a",
        Finding(
            severity=Severity.MEDIUM,
            rule="HEUR_AGENCY",
            message="fixed-a",
            owasp_id="MCP02",
            tool_name="tool_a",
        ),
    )
    sidecar = report_signing.sign_report(
        _results(), "9.9.9", engagement=_engagement(), fixed=[fixed_b, fixed_a]
    )
    payload = sidecar["payload"]
    assert payload["is_retest"] is True
    assert [f["server"] for f in payload["fixed_findings"]] == ["server-a", "server-b"]
    assert payload["fixed_findings"][0]["rule"] == "HEUR_AGENCY"

    # Verifies cleanly too -- the fixed_findings block is part of what's signed.
    result = report_signing.verify_report(sidecar)
    assert result["status"] == "VALID"


def test_retest_payload_tampering_fixed_findings_is_tampered(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_AUDITOR_REPORT_KEY", "test-key-for-signing")
    fixed = [
        (
            "server-a",
            Finding(
                severity=Severity.HIGH,
                rule="ST_BYPASS",
                message="fixed-a",
                owasp_id="MCP01",
                tool_name="tool_a",
            ),
        )
    ]
    sidecar = report_signing.sign_report(_results(), "9.9.9", engagement=_engagement(), fixed=fixed)
    tampered = copy.deepcopy(sidecar)
    tampered["payload"]["fixed_findings"][0]["rule"] = "ST_IGNORE_PREVIOUS"
    result = report_signing.verify_report(tampered)
    assert result["status"] == "TAMPERED"


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
