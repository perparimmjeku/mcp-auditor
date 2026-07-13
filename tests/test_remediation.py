from mcp_tool_auditor.auditor import remediation


def test_rule_specific_remediation_matches_by_prefix():
    assert "baseline" in remediation.get_remediation("RUGPULL_FINGERPRINT_MISMATCH").lower()
    assert "call" in remediation.get_remediation("BEHAV_ATPA_TRANSITION").lower()


def test_owasp_fallback_when_rule_unknown():
    text = remediation.get_remediation("TOTALLY_UNKNOWN_RULE", owasp_id="MCP05")
    assert text and "TODO" not in text


def test_default_when_nothing_matches():
    text = remediation.get_remediation("WHATEVER", owasp_id="ZZZ")
    assert text == remediation.DEFAULT_REMEDIATION


def test_known_rule_families_listed():
    families = remediation.list_families()
    assert "BEHAV_ATPA_TRANSITION" in families
    assert "FSP" in families


def test_flow_rules_have_specific_remediation():
    assert "exfiltration" in remediation.get_remediation("FLOW_CROSS_SERVER_EXFIL").lower()
    assert "composition" in remediation.get_remediation("FLOW_SENSITIVE_SINK").lower()


def test_keyword_rules_no_longer_cite_the_generic_signature_catchall():
    """These rules previously fell through to the "ST_" catch-all text (which
    cites 'ignore previous'/'bypass' -- phrases they never matched). Each must
    now describe what it actually matched, and none may quote a phrase from
    an unrelated signature family."""
    generic_phrases = ("ignore previous", "bypass")
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
        text = remediation.get_remediation(rule).lower()
        assert not any(phrase in text for phrase in generic_phrases), rule
        # And it must reuse the surface-prefixed form identically (RES_/PROMPT_/INSTR_).
        assert remediation.get_remediation(f"RES_{rule}") == remediation.get_remediation(rule)


def test_archive_and_dynamic_code_exec_have_specific_remediation():
    assert "archive" in remediation.get_remediation("ST_ARCHIVE_UNINSPECTED").lower()
    assert "eval" in remediation.get_remediation("SRC_DYNAMIC_CODE_EXEC").lower()
