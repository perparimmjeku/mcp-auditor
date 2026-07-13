import json
import subprocess
import sys

from mcp_tool_auditor.auditor.source import js_analyzer, python_analyzer
from mcp_tool_auditor.auditor.source.scanner import SourceScanner

# --- Python analyzer ---

VULN_PY = """
import mcp
import subprocess

def handle(arg):
    return subprocess.run(f"echo {arg}", shell=True)
"""

SAFE_PY = """
from mcp.server import Server
import subprocess, os

def handle(arg):
    os.system("ls -la")              # constant literal -> not injectable
    return subprocess.run(["ls", arg])  # no shell=True
"""

NOT_MCP_PY = """
import os
def handle(arg):
    os.system(arg)   # tainted, but this file is not an MCP server
"""


def test_python_detects_fstring_shell_injection_as_critical():
    findings = python_analyzer.analyze(VULN_PY, "server.py")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "SRC_SHELL_INJECTION"
    assert f.severity.value == "CRITICAL"
    assert f.owasp_id == "MCP05"
    assert f.file == "server.py"
    assert f.line == 6


def test_python_safe_patterns_produce_no_findings():
    assert python_analyzer.analyze(SAFE_PY, "safe.py") == []


def test_is_mcp_source_python():
    assert python_analyzer.is_mcp_source(VULN_PY) is True
    assert python_analyzer.is_mcp_source(NOT_MCP_PY) is False


EVAL_PY = """
import mcp

def handle(arg):
    return eval(arg)
"""

EXEC_PY = """
import mcp

def handle(arg):
    exec(arg)
"""

SAFE_EVAL_PY = """
import mcp

def handle(arg):
    return eval("1 + 1")
"""


def test_python_detects_eval_as_dynamic_code_exec():
    findings = python_analyzer.analyze(EVAL_PY, "server.py")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "SRC_DYNAMIC_CODE_EXEC"
    assert f.severity.value == "HIGH"
    assert f.owasp_id == "MCP05"
    assert f.attack_type == "code_injection"


def test_python_detects_exec_as_dynamic_code_exec():
    findings = python_analyzer.analyze(EXEC_PY, "server.py")
    assert len(findings) == 1
    assert findings[0].rule == "SRC_DYNAMIC_CODE_EXEC"


def test_python_constant_eval_is_not_reported():
    assert python_analyzer.analyze(SAFE_EVAL_PY, "safe.py") == []


# --- JS analyzer ---

VULN_JS = """
const { Server } = require("@modelcontextprotocol/sdk/server");
const cp = require("child_process");
function handle(arg) {
  return cp.exec(`git log ${arg}`);
}
"""

SAFE_JS = """
import { Server } from "@modelcontextprotocol/sdk/server";
import cp from "child_process";
function handle(arg) {
  return cp.exec("git status");   // constant literal
}
"""


def test_js_detects_template_literal_injection_as_critical():
    findings = js_analyzer.analyze(VULN_JS, "server.js")
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"
    assert findings[0].rule == "SRC_SHELL_INJECTION"
    assert findings[0].line == 5


def test_js_constant_literal_is_not_reported():
    assert js_analyzer.analyze(SAFE_JS, "safe.js") == []


EVAL_JS = """
const { Server } = require("@modelcontextprotocol/sdk/server");
function handle(arg) {
  return eval(arg);
}
"""

NEW_FUNCTION_JS = """
const { Server } = require("@modelcontextprotocol/sdk/server");
function handle(arg) {
  const f = new Function(arg);
  return f();
}
"""

SAFE_EVAL_JS = """
const { Server } = require("@modelcontextprotocol/sdk/server");
function handle(arg) {
  return eval("1 + 1");
}
"""


def test_js_detects_eval_as_dynamic_code_exec():
    findings = js_analyzer.analyze(EVAL_JS, "server.js")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "SRC_DYNAMIC_CODE_EXEC"
    assert f.severity.value == "HIGH"
    assert f.owasp_id == "MCP05"
    assert f.attack_type == "code_injection"


def test_js_detects_new_function_as_dynamic_code_exec():
    findings = js_analyzer.analyze(NEW_FUNCTION_JS, "server.js")
    assert any(f.rule == "SRC_DYNAMIC_CODE_EXEC" for f in findings)


def test_js_constant_eval_is_not_reported():
    assert js_analyzer.analyze(SAFE_EVAL_JS, "safe.js") == []


# --- Scanner over a directory ---


def test_scanner_only_flags_mcp_files(tmp_path):
    (tmp_path / "server.py").write_text(VULN_PY, encoding="utf-8")
    (tmp_path / "not_mcp.py").write_text(NOT_MCP_PY, encoding="utf-8")
    (tmp_path / "server.js").write_text(VULN_JS, encoding="utf-8")

    results = SourceScanner().scan(str(tmp_path))
    findings = [f for r in results.values() for f in r.findings]
    files = {f.file for f in findings}
    # the non-MCP python file is skipped; both MCP files flagged
    assert any(p.endswith("server.py") for p in files)
    assert any(p.endswith("server.js") for p in files)
    assert not any(p.endswith("not_mcp.py") for p in files)


def _run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "mcp_tool_auditor.cli", *args],
        capture_output=True,
        text=True,
    )


def test_source_scan_cli_sarif_and_fail_on(tmp_path):
    (tmp_path / "server.py").write_text(VULN_PY, encoding="utf-8")

    res = _run_cli(
        ["--no-log-file", "--no-metrics", "source-scan", str(tmp_path), "--format", "sarif"]
    )
    assert res.returncode == 0, res.stderr
    doc = json.loads(res.stdout)
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "SRC_SHELL_INJECTION"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 6

    res2 = _run_cli(
        ["--no-log-file", "--no-metrics", "source-scan", str(tmp_path), "--fail-on", "CRITICAL"]
    )
    assert res2.returncode == 2
