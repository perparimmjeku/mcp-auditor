import json

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


# --- parse_server_entries: no execution, redaction-by-construction ---


def test_parse_server_entries_never_spawns_a_process(tmp_path, monkeypatch):
    """A bogus, unrunnable command must still parse cleanly, and no subprocess
    is ever started -- this is the static, no-execution tier."""

    def _boom(*args, **kwargs):
        raise AssertionError("parse_server_entries must never spawn a process")

    monkeypatch.setattr("subprocess.Popen", _boom)

    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "/definitely/not/a/real/binary",
                        "args": ["--root", "/data"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    entries = discovery.parse_server_entries(cfg)
    assert len(entries) == 1
    assert entries[0].command == "/definitely/not/a/real/binary"
    assert entries[0].transport == "stdio"


def test_parse_server_entries_env_names_only_never_values(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "slack": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-slack"],
                        "env": {"SLACK_BOT_TOKEN": "xoxb-super-secret-real-value-12345"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    entries = discovery.parse_server_entries(cfg)
    assert entries[0].env_names == ["SLACK_BOT_TOKEN"]
    rendered = json.dumps(entries[0].__dict__)
    assert "xoxb-super-secret-real-value-12345" not in rendered


def test_parse_server_entries_redacts_secret_looking_args():
    cfg_dict = {
        "mcpServers": {
            "svc": {
                "command": "npx",
                "args": ["--api-key=sk-live-abcdef123456", "--verbose"],
            }
        }
    }
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        cfg = Path(d) / "mcp.json"
        cfg.write_text(json.dumps(cfg_dict), encoding="utf-8")
        entries = discovery.parse_server_entries(cfg)
    assert "sk-live-abcdef123456" not in entries[0].args
    assert "--api-key=<redacted>" in entries[0].args
    assert "--verbose" in entries[0].args


def test_parse_server_entries_redacts_space_separated_secret_flag():
    args = discovery._redact_args(["--token", "sk-live-abcdef123456", "--verbose"])
    assert args == ["--token", "<redacted>", "--verbose"]


def test_parse_server_entries_redacts_url_userinfo():
    redacted = discovery._redact_url("https://user:hunter2@example.com/mcp")
    assert "hunter2" not in redacted
    assert redacted == "https://<redacted>@example.com/mcp"


def test_parse_server_entries_url_transport(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "url": "https://user:secretpass@mcp.example.com/sse",
                        "headers": {"Authorization": "Bearer super-secret-token"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    entries = discovery.parse_server_entries(cfg)
    assert entries[0].transport == "url"
    assert "secretpass" not in entries[0].url
    assert entries[0].env_names == ["Authorization"]


def test_parse_server_entries_first_party_guess(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    },
                    "custom": {"command": "node", "args": ["./my-server.js"]},
                }
            }
        ),
        encoding="utf-8",
    )
    entries = {e.name: e for e in discovery.parse_server_entries(cfg)}
    assert entries["fs"].origin_guess == "first-party"
    assert entries["custom"].origin_guess == "third-party"
    assert entries["custom"].origin_reason  # non-empty reasoning, not a bare label


def test_parse_server_entries_client_label(tmp_path):
    claude_dir = tmp_path / "Claude"
    claude_dir.mkdir()
    cfg = claude_dir / "claude_desktop_config.json"
    cfg.write_text(
        json.dumps({"mcpServers": {"fs": {"command": "npx", "args": []}}}), encoding="utf-8"
    )
    entries = discovery.parse_server_entries(cfg)
    assert entries[0].client == "Claude Desktop"


def test_parse_server_entries_malformed_config_returns_empty(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text("not valid json{{{", encoding="utf-8")
    assert discovery.parse_server_entries(cfg) == []


def test_parse_server_entries_missing_file_returns_empty(tmp_path):
    assert discovery.parse_server_entries(tmp_path / "nope.json") == []


def test_discovered_server_redacts_on_direct_construction_too():
    """Redaction must not depend on going through parse_server_entries() --
    a DiscoveredServer built any other way (e.g. reconstructed from a saved
    document by a future caller) must still never carry a raw secret."""
    server = discovery.DiscoveredServer(
        name="creds",
        client="Claude Desktop",
        config_path="/tmp/config.json",
        transport="stdio",
        command="npx",
        args=["--api-key=sk-live-realsecretvalue999"],
        url="https://user:hunter2@example.com/mcp",
    )
    assert "sk-live-realsecretvalue999" not in server.args
    assert "--api-key=<redacted>" in server.args
    assert "hunter2" not in server.url
