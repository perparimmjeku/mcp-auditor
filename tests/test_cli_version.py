import subprocess
import sys

from mcp_tool_auditor import __version__


def _run(args, **kw):
    return subprocess.run(
        [sys.executable, "-m", "mcp_tool_auditor.cli", *args],
        capture_output=True,
        text=True,
        **kw,
    )


def test_version_flag_prints_the_single_source_of_truth_version():
    res = _run(["--version"])
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == f"mcp-tool-auditor {__version__}"
