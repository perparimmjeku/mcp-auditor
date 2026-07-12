from mcp_tool_auditor.auditor import suppressions
from mcp_tool_auditor.auditor.confidence import confidence_for
from mcp_tool_auditor.auditor.models import Finding, ScanResult, Severity


def _finding(rule, tool="t", owasp="MCP03"):
    return Finding(severity=Severity.HIGH, rule=rule, message="m", owasp_id=owasp, tool_name=tool)


# --- confidence ---


def test_confidence_high_for_definitive_rules():
    assert confidence_for("ST_IGNORE_PREVIOUS") == "HIGH"
    assert confidence_for("SRC_SHELL_INJECTION") == "HIGH"
    assert confidence_for("BEHAV_ATPA_TRANSITION") == "HIGH"


def test_confidence_low_for_fuzzy_heuristics():
    assert confidence_for("HEUR_IMPERATIVE") == "LOW"
    assert confidence_for("SCHEMA_UNTYPED") == "LOW"


def test_confidence_defaults_medium():
    assert confidence_for("SOMETHING_ELSE") == "MEDIUM"


def test_confidence_flow_tiers():
    # Coupled cross-server pair (name cross-reference) is definitive evidence
    # of wiring -> HIGH. Generic co-presence (no evidence of wiring) stays at
    # the MEDIUM default, deliberately not promoted -- see confidence.py.
    assert confidence_for("FLOW_CROSS_SERVER_EXFIL") == "HIGH"
    assert confidence_for("FLOW_SENSITIVE_SINK") == "MEDIUM"
    assert confidence_for("COMPOSITION_CONFUSED_DEPUTY") == "MEDIUM"


def test_finding_resolves_confidence_on_creation():
    assert _finding("ST_BYPASS").confidence == "HIGH"
    assert _finding("HEUR_IMPERATIVE").confidence == "LOW"
    # explicit override wins
    f = Finding(
        severity=Severity.LOW,
        rule="HEUR_IMPERATIVE",
        message="m",
        owasp_id="MCP03",
        confidence="HIGH",
    )
    assert f.confidence == "HIGH"


# --- suppressions ---


def test_suppress_by_rule():
    results = {
        "s": ScanResult(
            tools_scanned=1, findings=[_finding("HEUR_IMPERATIVE"), _finding("ST_BYPASS")]
        )
    }
    out = suppressions.apply(results, rules=["HEUR_IMPERATIVE"], entries=[])
    remaining = {f.rule for r in out.values() for f in r.findings}
    assert remaining == {"ST_BYPASS"}


def test_suppress_by_rule_and_tool():
    results = {
        "s": ScanResult(
            tools_scanned=2,
            findings=[_finding("HEUR_IMPERATIVE", tool="a"), _finding("HEUR_IMPERATIVE", tool="b")],
        )
    }
    out = suppressions.apply(results, rules=[], entries=[{"rule": "HEUR_IMPERATIVE", "tool": "a"}])
    remaining = [(f.rule, f.tool_name) for r in out.values() for f in r.findings]
    assert remaining == [("HEUR_IMPERATIVE", "b")]


def test_load_suppressions_file(tmp_path):
    f = tmp_path / "ignore.yaml"
    f.write_text("- rule: HEUR_IMPERATIVE\n- rule: SCHEMA_UNTYPED\n  tool: x\n", encoding="utf-8")
    entries = suppressions.load(str(f))
    assert {"rule": "HEUR_IMPERATIVE"} in entries
    assert {"rule": "SCHEMA_UNTYPED", "tool": "x"} in entries
