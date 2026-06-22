from mcp_tool_auditor.auditor import discovery


def test_discover_configs_filters_to_existing_files(tmp_path):
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text("{}", encoding="utf-8")
    missing = tmp_path / "nope.json"
    found = discovery.discover_configs([cfg, missing])
    assert found == [cfg]


def test_discover_configs_dedupes(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{}", encoding="utf-8")
    assert discovery.discover_configs([cfg, cfg]) == [cfg]


def test_default_candidates_includes_known_clients():
    cands = [str(c).lower() for c in discovery.default_candidates()]
    blob = " ".join(cands)
    assert "claude" in blob
    assert "cursor" in blob
    assert any("windsurf" in c or "zed" in c for c in cands)
