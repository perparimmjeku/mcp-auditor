"""Starts coverage measurement in subprocesses launched during the test run.

Only takes effect when COVERAGE_PROCESS_START is set (done by tests/conftest.py
when pytest-cov is active) and this directory is on PYTHONPATH. See
https://coverage.readthedocs.io/en/latest/subprocess.html
"""

import os

if os.environ.get("COVERAGE_PROCESS_START"):
    import coverage

    coverage.process_startup()
