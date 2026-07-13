"""Regex-heuristic detection of shell-injection sinks in JS/TS MCP server source.

JavaScript/TypeScript has no stdlib parser, so this uses line-scoped heuristics:
a shell-spawning sink whose argument interpolates or concatenates a value is flagged.
"""

import re

from ..models import Finding, Severity

_MCP_MARKER = re.compile(r"@?modelcontextprotocol", re.IGNORECASE)

_SINK = re.compile(
    r"(?:child_process\.|cp\.)?exec(?:Sync)?\s*\(|"
    r"promisify\s*\(\s*(?:child_process\.|cp\.)?exec\s*\)|"
    r"\bexecAsync\s*\(|"
    r"\bspawn\s*\(",
    re.IGNORECASE,
)

# Dynamic code execution, as distinct from the shell-spawning sinks above --
# `eval(` alone (not `child_process.exec(`, which _SINK already covers) and
# the `new Function(...)` constructor, JS's other route to running a string
# as code.
_CODE_EXEC_SINK = re.compile(
    r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(",
    re.IGNORECASE,
)


def is_mcp_source(source: str) -> bool:
    """True if the file references the MCP SDK."""
    return bool(_MCP_MARKER.search(source))


def analyze(source: str, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        code_exec_match = _CODE_EXEC_SINK.search(line)
        if code_exec_match:
            severity = _classify(line[code_exec_match.end() :])
            if severity is not None:
                findings.append(
                    Finding(
                        severity=severity,
                        rule="SRC_DYNAMIC_CODE_EXEC",
                        message=(
                            f"{path}:{lineno}: dynamic code execution with a non-constant "
                            f"argument — code injection risk."
                        ),
                        owasp_id="MCP05",
                        attack_type="code_injection",
                        file=path,
                        line=lineno,
                    )
                )

        match = _SINK.search(line)
        if not match:
            continue
        sink_text = line[match.start() :]
        # spawn() is only a shell sink when shell:true is set on the line
        if (
            re.match(r"spawn\s*\(", sink_text.lstrip(), re.IGNORECASE)
            and "shell" not in line.lower()
        ):
            continue
        severity = _classify(line[match.end() :])
        if severity is None:
            continue
        findings.append(
            Finding(
                severity=severity,
                rule="SRC_SHELL_INJECTION",
                message=(
                    f"{path}:{lineno}: shell-spawning call with a non-constant argument — "
                    f"Prompt-In-Shell-Out shell injection risk."
                ),
                owasp_id="MCP05",
                attack_type="command_injection",
                file=path,
                line=lineno,
            )
        )
    return findings


def _classify(arg_region: str) -> Severity | None:
    if "${" in arg_region:  # template literal interpolation
        return Severity.CRITICAL
    if re.search(r"['\"]\s*\+|\+\s*['\"]", arg_region):  # string concatenation
        return Severity.CRITICAL
    first = arg_region.lstrip()
    if first.startswith(("'", '"', "`")):
        # leading string literal with no interpolation/concatenation — constant
        return None
    if re.match(r"[A-Za-z_$][\w$]*", first):  # bare variable argument
        return Severity.HIGH
    return None
