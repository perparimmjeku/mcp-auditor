import json
import os
import subprocess
import sys


def _run(args, **kw):
    return subprocess.run(
        [sys.executable, "-m", "mcp_tool_auditor.cli", *args],
        capture_output=True,
        text=True,
        **kw,
    )


def _env(tmp_path, key="cli-test-key"):
    # Full env, not a replacement -- PATH/PYTHONPATH etc. must survive, only
    # the signing key and HOME (so the local key-file fallback path, if
    # exercised, never touches the real developer's ~/.mcp-tool-auditor)
    # are overridden per test.
    return {**os.environ, "MCP_TOOL_AUDITOR_REPORT_KEY": key, "HOME": str(tmp_path)}


def test_sign_then_verify_report_is_valid(tmp_path):
    report_path = tmp_path / "report.md"
    res = _run(
        [
            "--no-log-file",
            "--no-metrics",
            "scan",
            "import",
            "tests/fixtures/poisoned_tools.json",
            "--format",
            "pentest",
            "--output",
            str(report_path),
            "--sign",
        ],
        env=_env(tmp_path),
    )
    assert res.returncode == 0, res.stderr
    sig_path = tmp_path / "report.md.sig"
    assert sig_path.exists()

    verify = _run(
        ["--no-log-file", "--no-metrics", "verify-report", str(sig_path)], env=_env(tmp_path)
    )
    assert verify.returncode == 0, verify.stderr
    assert "Status: VALID" in verify.stdout


def test_sign_without_output_is_rejected(tmp_path):
    res = _run(
        [
            "--no-log-file",
            "--no-metrics",
            "scan",
            "import",
            "tests/fixtures/poisoned_tools.json",
            "--format",
            "pentest",
            "--sign",
        ],
        env=_env(tmp_path),
    )
    assert res.returncode != 0
    assert "--sign requires --output" in res.stderr


def test_reformatted_report_still_verifies_valid(tmp_path):
    report_path = tmp_path / "report.md"
    _run(
        [
            "--no-log-file",
            "--no-metrics",
            "scan",
            "import",
            "tests/fixtures/poisoned_tools.json",
            "--format",
            "pentest",
            "--output",
            str(report_path),
            "--sign",
        ],
        env=_env(tmp_path),
    )
    sig_path = tmp_path / "report.md.sig"

    original = report_path.read_text(encoding="utf-8")
    report_path.write_text(
        "<!-- annotated by legal review -->\n" + original + "\n<!-- end -->\n", encoding="utf-8"
    )

    verify = _run(
        ["--no-log-file", "--no-metrics", "verify-report", str(sig_path)], env=_env(tmp_path)
    )
    assert verify.returncode == 0, verify.stderr
    assert "Status: VALID" in verify.stdout


def test_tampered_sidecar_payload_is_tampered(tmp_path):
    report_path = tmp_path / "report.md"
    _run(
        [
            "--no-log-file",
            "--no-metrics",
            "scan",
            "import",
            "tests/fixtures/poisoned_tools.json",
            "--format",
            "pentest",
            "--output",
            str(report_path),
            "--sign",
        ],
        env=_env(tmp_path),
    )
    sig_path = tmp_path / "report.md.sig"
    sidecar = json.loads(sig_path.read_text(encoding="utf-8"))
    sidecar["payload"]["findings"][0]["severity"] = "LOW"
    sig_path.write_text(json.dumps(sidecar), encoding="utf-8")

    verify = _run(
        ["--no-log-file", "--no-metrics", "verify-report", str(sig_path)], env=_env(tmp_path)
    )
    assert verify.returncode == 2
    assert "Status: TAMPERED" in verify.stdout


def test_wrong_key_reports_invalid(tmp_path):
    report_path = tmp_path / "report.md"
    _run(
        [
            "--no-log-file",
            "--no-metrics",
            "scan",
            "import",
            "tests/fixtures/poisoned_tools.json",
            "--format",
            "pentest",
            "--output",
            str(report_path),
            "--sign",
        ],
        env=_env(tmp_path),
    )
    sig_path = tmp_path / "report.md.sig"

    verify = _run(
        ["--no-log-file", "--no-metrics", "verify-report", str(sig_path)],
        env=_env(tmp_path, key="a-totally-different-key"),
    )
    assert verify.returncode == 2
    assert "Status: INVALID" in verify.stdout
    doc = json.loads(sig_path.read_text(encoding="utf-8"))
    assert f"Key id (signature):  {doc['key_id']}" in verify.stdout
