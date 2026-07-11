"""Tests that --engagement scope enforcement actually blocks out-of-scope
targets at the CLI level (not just the Engagement unit itself)."""

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


def test_out_of_scope_url_target_is_refused(tmp_path):
    engagement_path = tmp_path / "engagement.json"
    engagement_path.write_text(
        json.dumps({"client": "Acme", "allowed_targets": ["https://target.example.com/mcp"]}),
        encoding="utf-8",
    )

    res = _run(
        [
            "--no-log-file",
            "--no-metrics",
            "--engagement",
            str(engagement_path),
            "scan",
            "url",
            "https://not-in-scope.example.com/mcp",
        ]
    )
    assert res.returncode == 1
    assert "not in the authorized engagement scope" in res.stderr


def test_in_scope_still_fails_to_connect_but_passes_scope_check(tmp_path):
    """The point isn't that the scan succeeds (nothing's listening) -- it's
    that scope enforcement doesn't block an in-scope target."""
    engagement_path = tmp_path / "engagement.json"
    engagement_path.write_text(
        json.dumps({"allowed_targets": ["http://127.0.0.1:1/mcp"]}),
        encoding="utf-8",
    )

    res = _run(
        [
            "--no-log-file",
            "--no-metrics",
            "--engagement",
            str(engagement_path),
            "scan",
            "url",
            "http://127.0.0.1:1/mcp",
        ]
    )
    assert "not in the authorized engagement scope" not in res.stderr


def test_no_allowed_targets_means_no_restriction(tmp_path):
    engagement_path = tmp_path / "engagement.json"
    engagement_path.write_text(json.dumps({"client": "Acme"}), encoding="utf-8")

    res = _run(
        [
            "--no-log-file",
            "--no-metrics",
            "--engagement",
            str(engagement_path),
            "scan",
            "url",
            "https://anything.example.com/mcp",
        ]
    )
    assert "not in the authorized engagement scope" not in res.stderr


def test_missing_engagement_file_fails_fast(tmp_path):
    res = _run(
        [
            "--no-log-file",
            "--no-metrics",
            "--engagement",
            str(tmp_path / "does_not_exist.json"),
            "scan",
            "import",
            "tests/fixtures/poisoned_tools.json",
        ]
    )
    assert res.returncode == 1
    assert "not found" in res.stderr
