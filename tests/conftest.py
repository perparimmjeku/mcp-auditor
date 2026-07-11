"""Makes coverage.py measure the CLI subprocesses the test suite spawns.

Several tests (e.g. tests/test_cli_behavior.py, test_source_scan.py) invoke
``python -m mcp_tool_auditor.cli`` via subprocess.run() instead of calling
into cli.py in-process. Without this hook, coverage.py never sees those
subprocess runs and mcp_tool_auditor/cli.py reports as 0% covered even
though it's exercised by real tests — a misleading blind spot for the
project's main entry point. See:
https://coverage.readthedocs.io/en/latest/subprocess.html
"""

from __future__ import annotations

import os

_HOOK_DIR = os.path.join(os.path.dirname(__file__), "_coverage_subprocess_hook")
_PYPROJECT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "pyproject.toml")


def pytest_configure(config) -> None:
    if not config.getoption("cov_source", default=None):
        return
    os.environ.setdefault("COVERAGE_PROCESS_START", _PYPROJECT)
    existing = os.environ.get("PYTHONPATH", "")
    parts = [_HOOK_DIR] + ([existing] if existing else [])
    os.environ["PYTHONPATH"] = os.pathsep.join(parts)
