import json
import subprocess
import sys


def _run(args, **kw):
    return subprocess.run(
        [sys.executable, "-m", "mcp_tool_auditor.cli", *args],
        capture_output=True,
        text=True,
        **kw,
    )


def _write_config(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs-server": {
                        "command": "/definitely/does/not/exist/binary",
                        "args": [
                            "-y",
                            "@modelcontextprotocol/server-filesystem",
                            "/Users/x/Documents",
                            "then-call-http-server",
                        ],
                    },
                    "http-server": {
                        "command": "/also/does/not/exist/binary",
                        "args": ["-y", "@modelcontextprotocol/server-webhook"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )


def test_inventory_default_run_never_spawns_a_process(tmp_path):
    """The core static-tier acceptance bar: a default (no --probe) run must
    succeed even when every discovered command is guaranteed unrunnable --
    subprocess.Popen against a nonexistent binary raises FileNotFoundError
    immediately, so a non-zero exit or a hang would prove execution was
    attempted. Success + correct data is the proof nothing spawned."""
    _write_config(tmp_path)
    res = _run(["--no-log-file", "--no-metrics", "inventory", "--format", "json"], cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    doc = json.loads(res.stdout)
    assert doc["summary"]["servers_discovered"] == 2
    assert doc["summary"]["servers_confirmed"] == 0
    assert doc["servers"]["fs-server"]["probed"] is False


def test_inventory_static_run_produces_a_useful_blast_radius_map(tmp_path):
    _write_config(tmp_path)
    res = _run(["--no-log-file", "--no-metrics", "inventory", "--format", "json"], cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    doc = json.loads(res.stdout)
    assert doc["chain_findings"]
    assert doc["chain_findings"][0]["rule"] == "INV_INFERRED_CHAIN"
    assert doc["chain_findings"][0]["severity"] == "MEDIUM"


def test_inventory_markdown_format(tmp_path):
    _write_config(tmp_path)
    res = _run(["--no-log-file", "--no-metrics", "inventory", "--format", "markdown"], cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    assert "# MCP Host Inventory & Blast-Radius Report" in res.stdout
    assert "```mermaid" in res.stdout


def test_inventory_sarif_format_carries_chain_rule_ids(tmp_path):
    _write_config(tmp_path)
    res = _run(["--no-log-file", "--no-metrics", "inventory", "--format", "sarif"], cwd=tmp_path)
    assert res.returncode == 0, res.stderr
    doc = json.loads(res.stdout)
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "INV_INFERRED_CHAIN" in rule_ids


def test_inventory_suppress_removes_the_chain_finding(tmp_path):
    _write_config(tmp_path)
    res = _run(
        [
            "--no-log-file",
            "--no-metrics",
            "inventory",
            "--format",
            "json",
            "--suppress",
            "INV_INFERRED_CHAIN",
        ],
        cwd=tmp_path,
    )
    assert res.returncode == 0, res.stderr
    doc = json.loads(res.stdout)
    assert doc["chain_findings"] == []


def test_inventory_no_probe_without_flag_stays_static_even_with_yes(tmp_path):
    """--yes alone (no --probe) must not trigger any connection attempt."""
    _write_config(tmp_path)
    res = _run(
        ["--no-log-file", "--no-metrics", "inventory", "--format", "json", "--yes"],
        cwd=tmp_path,
    )
    assert res.returncode == 0, res.stderr
    doc = json.loads(res.stdout)
    assert doc["summary"]["servers_confirmed"] == 0


def test_inventory_probe_without_ack_falls_back_to_static(tmp_path):
    """--probe without --yes and without a TTY: require_ack's input() will
    hit EOF on a closed stdin and be treated as a decline, falling back to
    static -- must not crash or hang."""
    _write_config(tmp_path)
    res = _run(
        ["--no-log-file", "--no-metrics", "inventory", "--format", "json", "--probe"],
        cwd=tmp_path,
        input="",
    )
    assert res.returncode == 0, res.stderr
    doc = json.loads(res.stdout)
    assert doc["summary"]["servers_confirmed"] == 0
