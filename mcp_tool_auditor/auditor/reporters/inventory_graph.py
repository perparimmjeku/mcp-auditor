"""Mermaid graph rendering for MCP host inventory: servers as nodes,
toxic-flow chains as edges.

Mermaid over Graphviz DOT: both are pure text generation, zero new
dependency either way, but Mermaid fenced ```mermaid blocks render natively
in GitHub/GitLab markdown -- so the exact same artifact this module
produces can be embedded directly inside the markdown/pentest report (see
InventoryReporter.generate_markdown) as well as emitted standalone. DOT
would need Graphviz installed locally or a separate viewer just to see
anything; a client reading a report in their browser sees the Mermaid graph
for free.

Edge/node styling carries two INDEPENDENT visual dimensions, matching the
two distinct honesty requirements this feature set:
  - color      = severity tier (muted grey for MEDIUM, orange for HIGH, red
                 for CRITICAL) -- "generic pairing = muted, coupled chain =
                 critical."
  - line style = evidence origin (solid = confirmed via --probe, dashed =
                 inferred from launch config alone) -- confirmed and
                 inferred must never look the same regardless of severity.
A host with only muted/generic pairings (or none at all) must render as
visually calm -- a graph that's all-red for a benign host is exactly the
failure mode this feature exists to avoid.
"""

from __future__ import annotations

import re

from ..inventory import InventoryResult
from ..models import Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#c62828",
    Severity.HIGH: "#ef6c00",
    Severity.MEDIUM: "#9e9e9e",
    Severity.LOW: "#9e9e9e",
    Severity.INFO: "#9e9e9e",
}

_INFERRED_RULE = "INV_INFERRED_CHAIN"


def _node_id(name: str) -> str:
    """Mermaid node ids can't contain most punctuation -- sanitize while
    keeping the real name in the visible label."""
    sanitized = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return sanitized or "server"


def _source_server_of(finding) -> str:
    return (finding.field or "").removeprefix("source_server:")


def generate_mermaid(result: InventoryResult) -> str:
    """Return a Mermaid flowchart body (no fence markers -- callers wrap it
    in ```mermaid for embedding, or write it verbatim to a standalone .mmd
    file). Every discovered server is a node, even one with no capability
    and no edges -- an isolated, unstyled node IS the "quiet/low-risk"
    signal for that server, not something to omit.
    """
    lines = ["flowchart LR"]
    lines.append("    classDef confirmedNode fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;")
    lines.append(
        "    classDef inferredNode fill:#f5f5f5,stroke:#9e9e9e,stroke-width:1px,"
        "stroke-dasharray:4 2;"
    )
    lines.append("")

    node_ids: dict[str, str] = {}
    for record in sorted(result.servers, key=lambda s: s.server.name):
        node_id = _node_id(record.server.name)
        node_ids[record.server.name] = node_id
        roles = sorted({role for c in record.capabilities for role in c.roles})
        role_label = ", ".join(roles) if roles else "no declared capability"
        lines.append(f'    {node_id}["{record.server.name}<br/>{role_label}"]')
        css_class = "confirmedNode" if record.probed else "inferredNode"
        lines.append(f"    class {node_id} {css_class}")
    lines.append("")

    link_styles: list[str] = []
    for finding in sorted(result.chain_findings, key=lambda f: (f.rule, f.tool_name or "")):
        source_name = _source_server_of(finding)
        sink_name = finding.related_server or ""
        if source_name not in node_ids or sink_name not in node_ids:
            continue
        is_inferred = finding.rule == _INFERRED_RULE
        edge_label = finding.severity.value + (" (possible)" if is_inferred else "")
        lines.append(f'    {node_ids[source_name]} -->|"{edge_label}"| {node_ids[sink_name]}')
        color = _SEVERITY_COLOR.get(finding.severity, "#9e9e9e")
        dasharray = "5 3" if is_inferred else "0"
        link_styles.append(
            f"    linkStyle {len(link_styles)} stroke:{color},stroke-width:2px,"
            f"stroke-dasharray:{dasharray};"
        )

    lines.extend(link_styles)
    return "\n".join(lines)
