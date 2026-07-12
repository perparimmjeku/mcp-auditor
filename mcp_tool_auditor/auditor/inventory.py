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

from .analyzers import capability
from .discovery import DiscoveredServer

ORIGIN_INFERRED = "inferred"
ORIGIN_CONFIRMED = "confirmed"

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
