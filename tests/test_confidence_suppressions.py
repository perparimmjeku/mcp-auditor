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


def test_bare_keyword_st_rules_are_never_high():
    """The blanket "ST_" prefix used to promote every ST_* rule to HIGH
    confidence, including bare keyword matches with zero corroborating
    context. Only the explicit instruction-override rules stay HIGH; the
    keyword families drop to LOW."""
    for rule in (
        "ST_CREDENTIAL",
        "ST_DATA_EXFIL",
        "ST_CODE_EXEC",
        "ST_SENSITIVE",
        "ST_FILESYSTEM",
        "ST_READ_FILE",
        "ST_EXECUTE",
        "ST_CONTEXT_HARVEST",
    ):
        assert confidence_for(rule) == "LOW", rule
        # Surface-prefixed forms (resources/prompts/instructions) too.
        assert confidence_for(f"RES_{rule}") == "LOW", rule


def test_instruction_override_rules_stay_high():
    for rule in (
        "ST_ALWAYS_USE",
        "ST_SEND_FULL",
        "ST_IGNORE_PREVIOUS",
        "ST_IGNORE_ALL",
        "ST_IGNORE_SECURITY",
        "ST_AUTHORITATIVE",
        "ST_DO_NOT_QUESTION",
        "ST_YOU_MUST",
        "ST_ALWAYS_CALL",
        "ST_BYPASS",
        "ST_DO_NOT_TELL",
        "ST_SYSTEM_CLAIM",
        "ST_OVERRIDE",
        "ST_MANDATORY",
    ):
        assert confidence_for(rule) == "HIGH", rule


def test_archive_uninspected_is_info():
    assert confidence_for("ST_ARCHIVE_UNINSPECTED") == "INFO"


def test_src_dynamic_code_exec_is_high():
    assert confidence_for("SRC_DYNAMIC_CODE_EXEC") == "HIGH"


def test_confidence_never_exceeds_severity():
    """Global invariant: a LOW-severity finding can't be reported at HIGH
    confidence even if a rule's static prefix bucket would otherwise say so
    -- this is the generic fix for the ST_SENSITIVE severity=LOW/
    confidence=HIGH contradiction, applied to every rule, not just that one."""
    assert confidence_for("ST_BYPASS", "LOW") == "LOW"
    assert confidence_for("ST_BYPASS", "MEDIUM") == "MEDIUM"
    assert confidence_for("ST_BYPASS", "HIGH") == "HIGH"
    assert confidence_for("ST_BYPASS", "CRITICAL") == "HIGH"
    # Severity above LOW never lowers a genuinely LOW-confidence rule.
    assert confidence_for("HEUR_IMPERATIVE", "CRITICAL") == "LOW"


def test_severity_none_skips_the_ceiling_clamp():
    """Callers that don't know the severity yet (e.g. direct confidence_for
    lookups elsewhere in the codebase) get the unclamped static-bucket
    result, preserving existing behavior for two-arg-agnostic callers."""
    assert confidence_for("ST_BYPASS") == "HIGH"


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
