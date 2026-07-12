import json

from mcp_tool_auditor.auditor.models import Finding, ScanResult, Severity
from mcp_tool_auditor.auditor.reporters.sarif_reporter import SarifReporter


def _results():
    findings = [
        Finding(
            severity=Severity.CRITICAL,
            rule="FSP_DESC_INJECTION",
            message="Tool 'x': injection payload.",
            owasp_id="MCP03",
            attack_type="full_schema_poisoning",
            tool_name="x",
            field="inputSchema.properties.note.description",
        ),
        Finding(
            severity=Severity.MEDIUM,
            rule="HEUR_IMPERATIVE",
            message="Tool 'x': imperative language.",
            owasp_id="MCP03",
            tool_name="x",
        ),
    ]
    return {"server-a": ScanResult(tools_scanned=1, findings=findings)}


def test_sarif_has_valid_top_level_structure():
    doc = json.loads(SarifReporter.generate(_results()))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].startswith("https://")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-tool-auditor"


def test_sarif_dedupes_rules_and_maps_levels():
    run = json.loads(SarifReporter.generate(_results()))["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert sorted(rule_ids) == ["FSP_DESC_INJECTION", "HEUR_IMPERATIVE"]

    by_rule = {res["ruleId"]: res for res in run["results"]}
    assert by_rule["FSP_DESC_INJECTION"]["level"] == "error"  # CRITICAL
    assert by_rule["HEUR_IMPERATIVE"]["level"] == "warning"  # MEDIUM


def test_sarif_includes_owasp_and_location():
    run = json.loads(SarifReporter.generate(_results()))["runs"][0]
    res = next(r for r in run["results"] if r["ruleId"] == "FSP_DESC_INJECTION")
    assert res["properties"]["owasp_id"] == "MCP03"
    loc = res["locations"][0]["logicalLocations"][0]
    assert loc["name"] == "x"


def test_sarif_empty_results_is_valid():
    doc = json.loads(SarifReporter.generate({}))
    assert doc["runs"][0]["results"] == []


def test_sarif_rule_includes_remediation_help():
    run = json.loads(SarifReporter.generate(_results()))["runs"][0]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "FSP_DESC_INJECTION")
    assert "help" in rule and rule["help"]["text"]


def _unsorted_results():
    """Findings deliberately out of alphabetical rule/tool order, so a

    determinism/sort-order test actually exercises the sort instead of
    passing by coincidence.
    """
    findings = [
        Finding(
            severity=Severity.HIGH,
            rule="ST_YOU_MUST",
            message="m1",
            owasp_id="MCP03",
            tool_name="zzz_tool",
        ),
        Finding(
            severity=Severity.HIGH,
            rule="ST_ALWAYS_USE",
            message="m2",
            owasp_id="MCP03",
            tool_name="aaa_tool",
        ),
        Finding(
            severity=Severity.MEDIUM,
            rule="HEUR_IMPERATIVE",
            message="m3",
            owasp_id="MCP03",
            tool_name="mmm_tool",
        ),
    ]
    return {"server-a": ScanResult(tools_scanned=1, findings=findings)}


def test_sarif_output_is_byte_identical_across_runs():
    results = _unsorted_results()
    first = SarifReporter.generate(results)
    second = SarifReporter.generate(results)
    assert first == second


def test_sarif_rules_and_results_are_sorted():
    doc = json.loads(SarifReporter.generate(_unsorted_results()))
    run = doc["runs"][0]

    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids == sorted(rule_ids)
    assert rule_ids == ["HEUR_IMPERATIVE", "ST_ALWAYS_USE", "ST_YOU_MUST"]

    result_rule_ids = [r["ruleId"] for r in run["results"]]
    assert result_rule_ids == sorted(result_rule_ids)


def test_sarif_rule_includes_help_uri():
    run = json.loads(SarifReporter.generate(_results()))["runs"][0]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "FSP_DESC_INJECTION")
    assert rule["helpUri"].endswith("docs/RULES.md")


def test_sarif_rule_includes_empty_atlas_ids_placeholder():
    run = json.loads(SarifReporter.generate(_results()))["runs"][0]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "FSP_DESC_INJECTION")
    assert rule["properties"]["atlas_ids"] == []


def test_sarif_result_properties_include_retest_status():
    findings = [
        Finding(
            severity=Severity.HIGH,
            rule="ST_YOU_MUST",
            message="m",
            owasp_id="MCP03",
            tool_name="t",
        )
    ]
    findings[0].retest_status = "STILL_PRESENT"
    results = {"server-a": ScanResult(tools_scanned=1, findings=findings)}

    run = json.loads(SarifReporter.generate(results))["runs"][0]
    assert run["results"][0]["properties"]["retest_status"] == "STILL_PRESENT"


def test_sarif_result_properties_retest_status_null_for_plain_scan():
    """A plain (non-retest) scan must not silently drop the key -- it's

    present and null, not absent, so consumers can rely on the field
    existing.
    """
    run = json.loads(SarifReporter.generate(_results()))["runs"][0]
    assert "retest_status" in run["results"][0]["properties"]
    assert run["results"][0]["properties"]["retest_status"] is None


def test_sarif_result_properties_include_confidence_and_attack_type():
    run = json.loads(SarifReporter.generate(_results()))["runs"][0]
    res = next(r for r in run["results"] if r["ruleId"] == "FSP_DESC_INJECTION")
    assert res["properties"]["confidence"] == "HIGH"
    assert res["properties"]["attack_type"] == "full_schema_poisoning"
