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
