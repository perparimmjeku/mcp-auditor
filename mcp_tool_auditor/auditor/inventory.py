"""Host inventory: turns discovered MCP servers into a blast-radius map.

Layer 1 (this module, static tier): synthesize a pseudo-tool per discovered
server from its command/args/env-var NAMES/url (see discovery.py's
DiscoveredServer -- already redacted at parse time), and run it through the
existing capability classifier. This is a GUESS, not a fact: no tool ever
ran, so no real tool description exists yet, only a launch command and a
package name. Every capability produced here is tagged ORIGIN_INFERRED, and
every caller downstream (report prose, JSON, graph styling, SARIF) must
carry that label through rather than presenting it as confirmed.

Layer 3 (--probe, this module's run_inventory): connects read-only and
enumerates real tools/resources/prompts to CONFIRM the static guess, per
server, subject to engagement scope. Reuses MCPScanner.scan_server_stdio()/
scan_server_url() as-is -- those already only call initialize/tools-list/
resources-list/prompts-list, never tools/call, so "enumeration only, never
invoke a tool" is enforced by construction, not by a new safety check here.
The authorization ack (print_security_warning + require_ack, same as the
existing `behavior`/`attack` commands) is a CLI-level concern and lives in
cli.py, not here -- run_inventory() takes an already-decided `probe: bool`
so it stays testable without mocking stdin.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .analyzers import capability, flow
from .discovery import DiscoveredServer
from .models import Finding, ScanResult, Severity

ORIGIN_INFERRED = "inferred"
ORIGIN_CONFIRMED = "confirmed"

INV_INFERRED_CHAIN = "INV_INFERRED_CHAIN"

# capability.py's high-value SOURCE pattern is prose-oriented -- it requires
# two-word phrases like "access token"/"auth token" specifically to avoid
# matching a bare "token" in unrelated prose. Env var NAMES follow a
# different, more reliable convention: SCREAMING_SNAKE_CASE with a
# TOKEN/KEY/SECRET/PASSWORD/CREDENTIAL suffix is about as close to a direct
# credential signal as static analysis gets (e.g. SLACK_BOT_TOKEN,
# GITHUB_TOKEN, API_KEY). Deliberately a separate, narrowly-scoped check
# here rather than broadening capability.py's shared prose pattern, which
# would also change already-shipped composition.py/flow.py behavior for
# tool description text.
_SECRET_ENV_NAME_PATTERN = re.compile(
    r"(TOKEN|API[_-]?KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE[_-]?KEY|AUTH)", re.IGNORECASE
)


def _has_secret_env_name(server: DiscoveredServer) -> bool:
    return any(_SECRET_ENV_NAME_PATTERN.search(name) for name in server.env_names)


@dataclass
class ToolCapability:
    """One tool's (or, for Layer 1, one server's pseudo-tool's) capability
    roles, tagged with where the evidence came from."""

    tool_name: str
    roles: set[str] = field(default_factory=set)
    origin: str = ORIGIN_INFERRED
    high_value_source: bool = False


def _pseudo_tool_text(server: DiscoveredServer) -> str:
    """Everything declared about a server in its config, joined into one
    string -- the only "tool text" that exists without connecting to it."""
    parts = [server.name, server.command, *server.args, *server.env_names, server.url]
    return " ".join(p for p in parts if p)


def synthesize_pseudo_tool(server: DiscoveredServer) -> dict:
    """Build a tool-shaped dict from a DiscoveredServer's declared config.

    Used ONLY to feed capability.classify()/flow.analyze() -- never rendered
    or presented as if it were a real tool definition. The "description" is
    literally the server's own command/args/env-names/url, not anything a
    real tool said about itself.
    """
    return {"name": server.name, "description": _pseudo_tool_text(server)}


def infer_capabilities(server: DiscoveredServer) -> list[ToolCapability]:
    """Guess a server's capability roles from its declared config alone.

    Returns a list (length 1: the single whole-server pseudo-tool) so the
    shape matches confirmed_capabilities()'s per-real-tool list once Layer 3
    exists -- callers that aggregate across both tiers don't need to special
    case which one they're looking at.
    """
    pseudo_tool = synthesize_pseudo_tool(server)
    roles = capability.classify(pseudo_tool)
    high_value = capability.is_high_value_source(pseudo_tool)
    if _has_secret_env_name(server):
        roles = roles | {capability.SOURCE}
        high_value = True
    return [
        ToolCapability(
            tool_name=server.name,
            roles=roles,
            origin=ORIGIN_INFERRED,
            high_value_source=high_value,
        )
    ]


# --- Blast-radius / cross-server chains (reuses flow.analyze() unmodified) -


def _source_server_of(f: Finding) -> str:
    return (f.field or "").removeprefix("source_server:")


def _relabel_as_inferred(f: Finding) -> Finding:
    """Turn a flow.py finding computed over PSEUDO-tools into an
    INV_INFERRED_CHAIN finding: MEDIUM ceiling regardless of what flow.py's
    own tiering would have called it, and a message that reads as a
    provisional guess, not a confirmed vulnerability -- rule id, severity,
    and wording are all part of the same honesty requirement, not just a
    field nobody reads.
    """
    source_server = _source_server_of(f)
    sink_server = f.related_server or "?"
    if f.tool_name and f.related_tool:
        detail = (
            f"server '{source_server}' and server '{sink_server}' declare launch "
            "config (command/args/env-var names) that cross-references each other"
        )
    else:
        detail = (
            f"server '{source_server}' declares SOURCE-like config and server "
            f"'{sink_server}' declares SINK-like config"
        )
    message = (
        "Possible cross-server chain -- INFERRED from server launch config, NOT yet "
        f"verified: {detail}. Neither server's real tools have been inspected. Run "
        "`mcp-tool-auditor inventory --probe` (with authorization) to confirm or rule "
        "this out."
    )
    return Finding(
        severity=Severity.MEDIUM,
        rule="INV_INFERRED_CHAIN",
        message=message,
        owasp_id=f.owasp_id,
        attack_type="inferred_cross_server_chain",
        tool_name=f.tool_name,
        field=f.field,
        related_tool=f.related_tool,
        related_server=f.related_server,
        confidence="MEDIUM",
    )


def compute_chain_findings(
    discovered: list[DiscoveredServer],
    confirmed_tools: dict[str, list[dict[str, Any]]] | None = None,
) -> list[Finding]:
    """Cross-server chain findings over the full discovered set.

    Reuses flow.analyze()'s pairing/coupling logic twice, unmodified -- never
    reimplements it:
      1. Over `confirmed_tools` (real tool definitions from --probe, if any)
         -> real FLOW_SENSITIVE_SINK/FLOW_CROSS_SERVER_EXFIL findings.
      2. Over ALL discovered servers as pseudo-tools -> candidate pairs,
         relabeled INV_INFERRED_CHAIN (MEDIUM ceiling) UNLESS both endpoint
         servers are already in `confirmed_tools`, in which case the pair is
         dropped entirely -- confirmed data is authoritative for that pair
         whether or not it found a chain, so the same pair is never reported
         as both INV_INFERRED_CHAIN and FLOW_* at once (promotion/dedup).

    Exactly one INV_INFERRED_CHAIN per (source_server, sink_server) direction
    even if flow.py's pseudo-tool pass produced both a generic and a
    coupled-looking finding for the same pair -- the coupled-shaped one wins
    (more specific), so inference stays a single, restrained "possible chain"
    per pair rather than two overlapping ones.
    """
    confirmed_tools = confirmed_tools or {}
    confirmed_server_names = set(confirmed_tools.keys())

    confirmed_results = {
        name: ScanResult(tools_scanned=len(tools), findings=[], tools=tools)
        for name, tools in confirmed_tools.items()
    }
    confirmed_findings = flow.analyze(confirmed_results) if len(confirmed_results) >= 2 else []

    pseudo_results = {
        server.name: ScanResult(
            tools_scanned=1, findings=[], tools=[synthesize_pseudo_tool(server)]
        )
        for server in discovered
    }
    pseudo_findings = flow.analyze(pseudo_results) if len(pseudo_results) >= 2 else []

    by_pair: dict[tuple[str, str], Finding] = {}
    for f in pseudo_findings:
        source_server = _source_server_of(f)
        sink_server = f.related_server or ""
        if source_server in confirmed_server_names and sink_server in confirmed_server_names:
            continue
        pair = (source_server, sink_server)
        existing = by_pair.get(pair)
        if existing is None or (
            f.rule == "FLOW_CROSS_SERVER_EXFIL" and existing.rule != "FLOW_CROSS_SERVER_EXFIL"
        ):
            by_pair[pair] = f

    inferred_findings = [_relabel_as_inferred(f) for f in by_pair.values()]
    return confirmed_findings + inferred_findings


# --- Layer 3: gated live enrichment -----------------------------------


def confirmed_capabilities(tools: list[dict[str, Any]]) -> list[ToolCapability]:
    """Real capability tags from real tool definitions -- one per tool.

    Unlike infer_capabilities(), this needs no pseudo-tool synthesis: the
    tool dicts came straight from a live tools/list response.
    """
    return [
        ToolCapability(
            tool_name=str(tool.get("name", "unknown")),
            roles=capability.classify(tool),
            origin=ORIGIN_CONFIRMED,
            high_value_source=capability.is_high_value_source(tool),
        )
        for tool in tools
    ]


@dataclass
class ServerInventory:
    """One discovered server's inventory record: its identity, its
    capability tags (inferred unless `probed`), and whether/why a --probe
    attempt against it succeeded, failed, or was never attempted."""

    server: DiscoveredServer
    capabilities: list[ToolCapability]
    probed: bool = False
    probe_skipped_reason: str | None = None


@dataclass
class InventoryResult:
    servers: list[ServerInventory]
    chain_findings: list[Finding]


def run_inventory(
    discovered: list[DiscoveredServer],
    scanner: Any = None,
    probe: bool = False,
    engagement: Any = None,
) -> InventoryResult:
    """Build the full inventory: Layer 1 always, Layer 3 per-server when
    `probe` is True (an already-decided boolean -- the authorization ack
    itself is a CLI-level concern, not this function's).

    A server is left at Layer 1 (inferred) whenever: `probe` is False,
    it's out of engagement scope (engagement.check_target raises), or the
    connection itself fails (timeout, refused, protocol error) -- inventory
    degrades to the static map for that one server rather than aborting the
    whole run, exactly as required. Live probing here is enumeration only:
    it calls scan_server_stdio()/scan_server_url(), which only ever issue
    initialize/tools-list/resources-list/prompts-list -- never tools/call.
    """
    confirmed_tools: dict[str, list[dict[str, Any]]] = {}
    server_records: list[ServerInventory] = []

    for server in discovered:
        capabilities = infer_capabilities(server)
        probed = False
        skipped_reason: str | None = None

        if probe and scanner is not None:
            target = server.url if server.transport == "url" else server.command
            try:
                if engagement is not None:
                    engagement.check_target(target)
                if server.transport == "url":
                    result = scanner.scan_server_url(server.url)
                else:
                    result = scanner.scan_server_stdio(server.command, server.args)
                confirmed_tools[server.name] = result.tools
                capabilities = confirmed_capabilities(result.tools)
                probed = True
            except Exception as exc:  # noqa: BLE001 - one server's failure must not abort the run
                skipped_reason = str(exc)

        server_records.append(
            ServerInventory(
                server=server,
                capabilities=capabilities,
                probed=probed,
                probe_skipped_reason=skipped_reason,
            )
        )

    chain_findings = compute_chain_findings(discovered, confirmed_tools=confirmed_tools)
    return InventoryResult(servers=server_records, chain_findings=chain_findings)
