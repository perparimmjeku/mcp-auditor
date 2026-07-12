"""Cross-SERVER toxic-flow analysis.

CompositionAnalyzer flags a confused-deputy pairing WITHIN a single server's
tool list. The real-world exfiltration risk on a live engagement is usually
ACROSS servers: an agent session has tools from several MCP servers active at
once, and a read-then-exfil path can span two servers that individually look
clean. This module looks at the COMBINED tool surface -- the whole `results`
dict a scan produces -- for that cross-server pairing.

Deliberately narrower than composition.py in one respect: it only considers
tool pairs from DIFFERENT servers. A same-server SOURCE+SINK pair is
composition.py's job (COMPOSITION_CONFUSED_DEPUTY already covers it); this
analyzer would just be a noisy second opinion on the same finding.

Two rules, matching the false-positive posture the task demands:

  FLOW_SENSITIVE_SINK      A SOURCE tool on one server and a SINK tool on a
                            different server coexist, with no evidence they're
                            wired together. Generic, restrained: MEDIUM,
                            aggregated per server-pair-direction (like
                            composition.py, names every tool on each side
                            rather than emitting one finding per tool pair --
                            this is the rule that must NOT scream on every
                            multi-server host with unrelated file and http
                            tools).

  FLOW_CROSS_SERVER_EXFIL  A SOURCE/SINK pair where one tool's description
                            references the other tool by name -- evidence the
                            pairing is intentional, not incidental co-presence.
                            One finding per coupled pair (this is the rare,
                            specific case, not the noisy generic one).
                            CRITICAL if the SOURCE is credential/secret-grade
                            (capability.is_high_value_source), HIGH otherwise.

SENSITIVE_ACTION is tagged by the capability classifier but not yet wired
into a rule here -- a future SOURCE -> SENSITIVE_ACTION privilege-chain rule
is a natural extension, out of scope for this pass.
"""

from __future__ import annotations

from typing import Any

from ..models import CROSS_SERVER_KEY, Finding, ScanResult, Severity
from . import capability

_MIN_REFERENCE_NAME_LEN = 3


def _name_variants(name: str) -> set[str]:
    return {name, name.replace("_", " "), name.replace("-", " ")}


def _references(text: str, name: str) -> bool:
    """True if `name` (or an underscore/hyphen-desnaked form of it) appears in `text`."""
    if not name or len(name) < _MIN_REFERENCE_NAME_LEN:
        return False
    lowered = text.lower()
    return any(variant.lower() in lowered for variant in _name_variants(name))


def _is_coupled(
    source_tool: dict[str, Any], source_name: str, sink_tool: dict[str, Any], sink_name: str
) -> bool:
    source_text = f"{source_tool.get('name', '')} {source_tool.get('description', '')}"
    sink_text = f"{sink_tool.get('name', '')} {sink_tool.get('description', '')}"
    return _references(source_text, sink_name) or _references(sink_text, source_name)


def _classify_server_tools(
    tools: list[dict[str, Any]],
) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    sources: list[tuple[str, dict[str, Any]]] = []
    sinks: list[tuple[str, dict[str, Any]]] = []
    for tool in tools:
        name = str(tool.get("name", "unknown"))
        roles = capability.classify(tool)
        if capability.SOURCE in roles:
            sources.append((name, tool))
        if capability.SINK in roles:
            sinks.append((name, tool))
    return sources, sinks


def _direction_findings(
    server_a: str,
    sources_a: list[tuple[str, dict[str, Any]]],
    server_b: str,
    sinks_b: list[tuple[str, dict[str, Any]]],
) -> list[Finding]:
    if not sources_a or not sinks_b:
        return []

    findings: list[Finding] = []
    for source_name, source_tool in sources_a:
        for sink_name, sink_tool in sinks_b:
            if not _is_coupled(source_tool, source_name, sink_tool, sink_name):
                continue
            high_value = capability.is_high_value_source(source_tool)
            findings.append(
                Finding(
                    severity=Severity.CRITICAL if high_value else Severity.HIGH,
                    rule="FLOW_CROSS_SERVER_EXFIL",
                    message=(
                        f"Cross-server toxic flow: tool '{source_name}' on server "
                        f"'{server_a}' ({'reads credential/secret-grade data' if high_value else 'reads sensitive data'}) "
                        f"and tool '{sink_name}' on server '{server_b}' (outbound network/"
                        "send capability) reference each other by name — evidence this "
                        "pairing is wired together, not incidental co-presence. An agent "
                        "with both tools active in one session can chain them to "
                        "exfiltrate data."
                    ),
                    owasp_id="MCP02",
                    attack_type="cross_server_exfil_chain",
                    tool_name=source_name,
                    field=f"source_server:{server_a}",
                    related_tool=sink_name,
                    related_server=server_b,
                )
            )

    source_list = ", ".join(f"'{n}'" for n, _ in sorted(sources_a, key=lambda x: x[0]))
    sink_list = ", ".join(f"'{n}'" for n, _ in sorted(sinks_b, key=lambda x: x[0]))
    findings.append(
        Finding(
            severity=Severity.MEDIUM,
            rule="FLOW_SENSITIVE_SINK",
            message=(
                f"Cross-server composition risk: server '{server_a}' exposes "
                f"sensitive-data-access tool(s) ({source_list}) while server '{server_b}' "
                f"exposes outbound network/send tool(s) ({sink_list}). Both are reachable "
                "by an agent in the same session; no specific coupling was detected "
                "between them, but the combination is a plausible exfiltration path. "
                "Generic pairing — review before treating as confirmed."
            ),
            owasp_id="MCP02",
            attack_type="cross_server_composition_risk",
            field=f"source_server:{server_a}",
            related_server=server_b,
        )
    )
    return findings


def analyze(results: dict[str, ScanResult]) -> list[Finding]:
    """Find cross-server SOURCE -> SINK pairs across the combined tool surface.

    Returns a flat list of findings; callers decide where to store them (see
    CROSS_SERVER_KEY). Never mutates `results`.
    """
    server_names = [name for name in results if name != CROSS_SERVER_KEY]
    if len(server_names) < 2:
        return []

    classified = {name: _classify_server_tools(results[name].tools or []) for name in server_names}

    findings: list[Finding] = []
    for server_a in server_names:
        sources_a, _sinks_a = classified[server_a]
        if not sources_a:
            continue
        for server_b in server_names:
            if server_a == server_b:
                continue
            _sources_b, sinks_b = classified[server_b]
            findings.extend(_direction_findings(server_a, sources_a, server_b, sinks_b))
    return findings
