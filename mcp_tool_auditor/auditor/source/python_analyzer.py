"""AST-based detection of shell-injection sinks in Python MCP server source."""

import ast

from ..models import Finding, Severity

_MCP_ROOTS = {"mcp", "fastmcp"}

_OS_SINKS = {"os.system", "os.popen"}
_SUBPROCESS_ALWAYS = {"subprocess.getoutput"}
_SUBPROCESS_SHELL = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_output",
    "subprocess.check_call",
}
# Bare builtin calls only (ast.Name, not ast.Attribute) -- `obj.exec()` on
# some unrelated object is a different call entirely and _func_name would
# return "obj.exec", not "exec", so it's naturally excluded.
_CODE_EXEC_SINKS = {"eval", "exec"}


def is_mcp_source(source: str) -> bool:
    """True if the file imports an MCP SDK (mcp / fastmcp)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] in _MCP_ROOTS for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in _MCP_ROOTS:
                return True
    return False


def analyze(source: str, path: str) -> list[Finding]:
    """Flag shell-spawning sinks called with non-constant (injectable) arguments."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _func_name(node)

        if name in _CODE_EXEC_SINKS:
            cmd_arg = node.args[0] if node.args else None
            if cmd_arg is None:
                continue
            severity = _classify(cmd_arg)
            if severity is None:
                continue  # constant literal — not injectable
            findings.append(
                Finding(
                    severity=severity,
                    rule="SRC_DYNAMIC_CODE_EXEC",
                    message=(
                        f"{path}:{node.lineno}: '{name}' called with a non-constant argument — "
                        f"dynamic code execution risk."
                    ),
                    owasp_id="MCP05",
                    attack_type="code_injection",
                    file=path,
                    line=node.lineno,
                )
            )
            continue

        cmd_arg = _sink_command_arg(name, node)
        if cmd_arg is None:
            continue
        severity = _classify(cmd_arg)
        if severity is None:
            continue  # constant literal — not injectable
        findings.append(
            Finding(
                severity=severity,
                rule="SRC_SHELL_INJECTION",
                message=(
                    f"{path}:{node.lineno}: '{name}' called with a non-constant argument — "
                    f"Prompt-In-Shell-Out shell injection risk."
                ),
                owasp_id="MCP05",
                attack_type="command_injection",
                file=path,
                line=node.lineno,
            )
        )
    return findings


def _func_name(call: ast.Call) -> str:
    parts: list[str] = []
    func = call.func
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _sink_command_arg(name: str, call: ast.Call):
    if name in _OS_SINKS or name in _SUBPROCESS_ALWAYS:
        return call.args[0] if call.args else None
    if name in _SUBPROCESS_SHELL and _has_shell_true(call):
        return call.args[0] if call.args else None
    return None


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _classify(arg: ast.AST) -> Severity | None:
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return None  # constant string literal — not injectable
    if isinstance(arg, ast.JoinedStr):  # f-string interpolation
        return Severity.CRITICAL
    if isinstance(arg, ast.BinOp):  # "x" + var  or  "x" % var
        return Severity.CRITICAL
    if isinstance(arg, ast.Call):  # e.g. "...".format(arg)
        if isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
            return Severity.CRITICAL
        return Severity.HIGH
    if isinstance(arg, ast.Name):  # bare variable
        return Severity.HIGH
    return Severity.HIGH
