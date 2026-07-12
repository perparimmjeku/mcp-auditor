"""Host inventory: turns discovered MCP servers into a blast-radius map.

Layer 1 (this module, static tier): synthesize a pseudo-tool per discovered
server from its command/args/env-var NAMES/url (see discovery.py's
DiscoveredServer -- already redacted at parse time), and run it through the
existing capability classifier. This is a GUESS, not a fact: no tool ever
ran, so no real tool description exists yet, only a launch command and a
package name. Every capability produced here is tagged ORIGIN_INFERRED, and
every caller downstream (report prose, JSON, graph styling, SARIF) must
carry that label through rather than presenting it as confirmed.

Layer 3 (--probe, added later) produces the ORIGIN_CONFIRMED version of the
same ToolCapability shape from real tools/list data, so blast-radius code
can treat both uniformly once collected.
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
