"""Host inventory / blast-radius report: identity, declared reach,
capability tags, and cross-server chains for every discovered MCP server.

Distinct from the other reporters: those render a Finding list keyed by
server (`dict[str, ScanResult]`); this renders an `inventory.InventoryResult`,
which additionally carries identity/reach/capability data that isn't itself
a Finding -- a server's command/args/env-var names is descriptive inventory
data, not a graded vulnerability (see inventory.py's module docstring for why
compute_chain_findings() draws that line). Chain findings ARE real Findings
and reuse Finding.to_dict() verbatim for the JSON output, so they round-trip
through the same shape as every other reporter's findings.

Confirmed-vs-inferred is a headline distinction here, not a footnote: every
server and every chain finding is visually badged CONFIRMED or INFERRED, and
an inferred chain's own message text already says "run --probe to confirm"
(see inventory.py's _relabel_as_inferred) -- this reporter doesn't invent
that wording, just surfaces it prominently rather than burying it in a JSON
field nobody reads.
"""

from __future__ import annotations

import json
from typing import Any

from ... import __version__
from ..analyzers import capability
from ..inventory import ORIGIN_CONFIRMED, ORIGIN_INFERRED, InventoryResult, ServerInventory
from ..models import SEVERITY_LEVELS, Severity
from .inventory_graph import generate_mermaid

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
    Severity.ERROR: "❌",
}

ORIGIN_BADGE = {
    ORIGIN_CONFIRMED: "✅ CONFIRMED",
    ORIGIN_INFERRED: "🔍 INFERRED",
}


def _is_confirmed_chain(rule: str) -> bool:
    return rule != "INV_INFERRED_CHAIN"


def _server_to_dict(record: ServerInventory) -> dict[str, Any]:
    server = record.server
    return {
        "client": server.client,
        "config_path": server.config_path,
        "transport": server.transport,
        "command": server.command,
        "args": server.args,
        "env_names": sorted(server.env_names),
        "url": server.url,
        "origin_guess": server.origin_guess,
        "origin_reason": server.origin_reason,
        "probed": record.probed,
        "probe_skipped_reason": record.probe_skipped_reason,
        "capabilities": [
            {
                "tool_name": c.tool_name,
                "roles": sorted(c.roles),
                "origin": c.origin,
                "high_value_source": c.high_value_source,
            }
            for c in sorted(record.capabilities, key=lambda c: c.tool_name)
        ],
    }


def _count_by_rule(findings) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.rule] = counts.get(f.rule, 0) + 1
    return counts


class InventoryReporter:
    @staticmethod
    def generate_json(result: InventoryResult) -> str:
        servers_confirmed = sum(1 for s in result.servers if s.probed)
        doc = {
            "scan_metadata": {
                "tool": "mcp-tool-auditor",
                "version": __version__,
                "kind": "inventory",
            },
            "summary": {
                "servers_discovered": len(result.servers),
                "servers_confirmed": servers_confirmed,
                "servers_inferred_only": len(result.servers) - servers_confirmed,
                "chain_findings_total": len(result.chain_findings),
                "chain_findings_by_rule": _count_by_rule(result.chain_findings),
            },
            "servers": {s.server.name: _server_to_dict(s) for s in result.servers},
            "chain_findings": [
                f.to_dict()
                for f in sorted(
                    result.chain_findings,
                    key=lambda f: (f.rule, f.tool_name or "", f.related_tool or ""),
                )
            ],
        }
        return json.dumps(doc, indent=2, sort_keys=True, default=str)

    @staticmethod
    def generate_markdown(result: InventoryResult) -> str:
        lines: list[str] = []
        lines.append("# MCP Host Inventory & Blast-Radius Report")
        lines.append("")
        lines.append(f"**Tool:** mcp-tool-auditor v{__version__}")
        lines.append("")

        servers_confirmed = sum(1 for s in result.servers if s.probed)
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Servers Discovered | {len(result.servers)} |")
        lines.append(f"| Servers Confirmed (`--probe`) | {servers_confirmed} |")
        lines.append(f"| Servers Inferred-Only | {len(result.servers) - servers_confirmed} |")
        lines.append(f"| Cross-Server Chains Found | {len(result.chain_findings)} |")
        lines.append("")

        if result.chain_findings:
            worst = min(result.chain_findings, key=lambda f: SEVERITY_LEVELS.get(f.severity, 99))
            badge = ORIGIN_BADGE[
                ORIGIN_CONFIRMED if _is_confirmed_chain(worst.rule) else ORIGIN_INFERRED
            ]
            lines.append(
                f"**Worst chain found:** {SEVERITY_EMOJI.get(worst.severity, '')} "
                f"{worst.severity.value} {badge}"
            )
            lines.append("")
            lines.append(f"> {worst.message}")
        else:
            lines.append(
                "**No cross-server chain found** — this host reads as low-risk for "
                "toxic-flow purposes at the current scan depth."
            )
        lines.append("")

        lines.append("## Cross-Server Chains")
        lines.append("")
        if not result.chain_findings:
            lines.append("✅ None found.")
        else:
            for f in sorted(
                result.chain_findings, key=lambda f: (SEVERITY_LEVELS.get(f.severity, 99), f.rule)
            ):
                badge = ORIGIN_BADGE[
                    ORIGIN_CONFIRMED if _is_confirmed_chain(f.rule) else ORIGIN_INFERRED
                ]
                lines.append(
                    f"- {SEVERITY_EMOJI.get(f.severity, '')} **{f.severity.value}** {badge} "
                    f"`{f.rule}` — {f.message}"
                )
        lines.append("")

        lines.append("## Toxic-Flow Graph")
        lines.append("")
        lines.append(
            "_Solid border/edge = confirmed via `--probe`; dashed = inferred from launch "
            "config only. Edge color = severity (grey = generic/muted, orange = HIGH, red "
            "= CRITICAL) -- a calm, mostly-uncolored graph is the expected, healthy result "
            "on a benign host, not a bug._"
        )
        lines.append("")
        lines.append("```mermaid")
        lines.append(generate_mermaid(result))
        lines.append("```")
        lines.append("")

        lines.append("## Servers")
        lines.append("")
        for record in sorted(result.servers, key=lambda s: s.server.name):
            lines.extend(InventoryReporter._server_section(record))

        return "\n".join(lines)

    @staticmethod
    def _server_section(record: ServerInventory) -> list[str]:
        server = record.server
        lines = [f"### `{server.name}` ({server.client})", ""]
        lines.append(f"- **Transport:** {server.transport}")
        if server.transport == "stdio":
            cmdline = " ".join([server.command, *server.args]).strip()
            lines.append(f"- **Command:** `{cmdline}`")
        else:
            lines.append(f"- **URL:** `{server.url}`")
        if server.env_names:
            names = ", ".join(f"`{n}`" for n in sorted(server.env_names))
            lines.append(f"- **Env vars declared (names only):** {names}")
        lines.append(f"- **Origin guess:** {server.origin_guess} — {server.origin_reason}")

        evidence_badge = ORIGIN_BADGE[ORIGIN_CONFIRMED if record.probed else ORIGIN_INFERRED]
        evidence_note = "" if record.probed else " — static guess from launch config, not connected"
        lines.append(f"- **Capability evidence:** {evidence_badge}{evidence_note}")
        if record.probe_skipped_reason:
            lines.append(f"- **`--probe` attempted, failed:** {record.probe_skipped_reason}")

        sources = sorted({c.tool_name for c in record.capabilities if capability.SOURCE in c.roles})
        sinks = sorted({c.tool_name for c in record.capabilities if capability.SINK in c.roles})
        actions = sorted(
            {c.tool_name for c in record.capabilities if capability.SENSITIVE_ACTION in c.roles}
        )
        if sources or sinks or actions:
            lines.append("- **Blast radius if compromised:**")
            if sources:
                lines.append(f"  - Can READ: {', '.join(sources)}")
            if sinks:
                lines.append(f"  - Can REACH (egress): {', '.join(sinks)}")
            if actions:
                lines.append(f"  - Can PERFORM (destructive/state-changing): {', '.join(actions)}")
        else:
            lines.append("- **Blast radius:** no SOURCE/SINK/SENSITIVE_ACTION capability detected")
        lines.append("")
        return lines
