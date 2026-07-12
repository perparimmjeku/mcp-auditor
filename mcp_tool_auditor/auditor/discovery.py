"""Discovery of MCP client config locations on the local machine.

Finds where Claude Desktop, Cursor, VS Code (Continue), Windsurf, and Zed store
their MCP server configuration so ``scan local`` can audit configured servers
without the user pointing at each file.

Also parses those configs WITHOUT executing anything (`parse_server_entries`)
-- distinct from `scanner.scan_config_file()`, which parses AND immediately
spawns every stdio server to fetch real tool definitions. `inventory`'s static
tier needs the former: identity/declared-reach data with zero execution, so it
stays useful on engagements where running a client's servers isn't permitted.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def default_candidates() -> list[Path]:
    """Return the standard MCP config locations for this platform."""
    home = Path.home()
    candidates: list[Path] = []

    # Claude Desktop (platform-specific)
    if sys.platform == "darwin":
        candidates.append(home / "Library/Application Support/Claude/claude_desktop_config.json")
    elif sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "Claude/claude_desktop_config.json")
    else:
        candidates.append(home / ".config/Claude/claude_desktop_config.json")

    # Editors / agents (cross-platform home paths)
    candidates.append(home / ".cursor/mcp.json")
    candidates.append(home / ".codeium/windsurf/mcp_config.json")
    candidates.append(home / ".config/zed/settings.json")
    candidates.append(home / ".continue/config.json")

    # Project-local configs in the current working directory
    cwd = Path.cwd()
    candidates.append(cwd / ".mcp.json")
    candidates.append(cwd / ".cursor/mcp.json")
    candidates.append(cwd / "mcp.json")

    return candidates


def discover_configs(candidates: list[Path] | None = None) -> list[Path]:
    """Return existing config files from the candidate locations, de-duplicated."""
    cands = candidates if candidates is not None else default_candidates()
    found: list[Path] = []
    for path in cands:
        try:
            if path.is_file() and path not in found:
                found.append(path)
        except OSError:
            continue
    return found


# --- Read-only server-entry parsing (no execution) -------------------------

_CLIENT_LABELS: list[tuple[str, str]] = [
    ("Claude/claude_desktop_config.json", "Claude Desktop"),
    (".cursor/mcp.json", "Cursor"),
    (".codeium/windsurf/mcp_config.json", "Windsurf"),
    ("zed/settings.json", "Zed"),
    (".continue/config.json", "Continue"),
    (".mcp.json", "Project-local"),
    ("mcp.json", "Project-local"),
]

# First-party MCP server package namespaces/publishers. Anything else is
# labeled third-party/unknown -- not "malicious", just "not verified as
# official", so the reasoning string always says why, never asserts more
# than the evidence supports.
_FIRST_PARTY_MARKERS = ("@modelcontextprotocol/", "modelcontextprotocol/")

# Flag/key names that look secret-ish, for redacting VALUES out of args/
# command/url strings. Deliberately reuses the same vocabulary as
# capability.py's high-value SOURCE pattern -- same "does this name suggest
# a credential" question, applied to config text instead of tool text.
_SECRET_KEY_PATTERN = re.compile(
    r"(credential|secret|password|passwd|api[-_]?key|token|auth)", re.IGNORECASE
)

_URL_USERINFO = re.compile(r"://([^/@\s:]+):([^/@\s]+)@")


def _redact_url(text: str) -> str:
    """Redact userinfo (user:pass@) embedded in a URL-shaped string."""
    return _URL_USERINFO.sub("://<redacted>@", text)


def _redact_args(args: list[str]) -> list[str]:
    """Redact the VALUE half of any secret-looking `--flag=value` or
    `--flag value` pair in a stdio server's argv -- never the flag name
    itself, only what looks like the secret. Args are the one place a
    config can carry a live credential outside `env` (e.g. `--api-key=sk-...`
    instead of an environment variable), so this gets the same "never a
    value, only a name" treatment as `env` below.
    """
    redacted: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        arg = _redact_url(arg)
        if "=" in arg:
            key, sep, _value = arg.partition("=")
            bare_key = key.lstrip("-")
            if _SECRET_KEY_PATTERN.search(bare_key):
                redacted.append(f"{key}{sep}<redacted>")
                continue
        elif arg.startswith("-") and _SECRET_KEY_PATTERN.search(arg.lstrip("-")):
            redacted.append(arg)
            skip_next = True
            continue
        redacted.append(arg)
    return redacted


def _client_label_for_path(path: Path) -> str:
    text = str(path)
    for suffix, label in _CLIENT_LABELS:
        if text.endswith(suffix.replace("/", os.sep)) or text.endswith(suffix):
            return label
    return "Unknown client"


def _origin_guess(command: str, args: list[str]) -> tuple[str, str]:
    haystack = " ".join([command, *args])
    for marker in _FIRST_PARTY_MARKERS:
        if marker in haystack:
            return (
                "first-party",
                f"command/args reference the official '{marker.rstrip('/')}' package namespace",
            )
    return (
        "third-party",
        "command/args don't reference a known first-party MCP server namespace "
        "-- not evidence of anything malicious, just not independently verified as official",
    )


@dataclass
class DiscoveredServer:
    """One MCP server entry parsed from a client config, WITHOUT execution.

    Every string field here has already been through redaction at parse time
    -- `env_names` only ever holds keys (values are never read at all, not
    just filtered out after the fact), and `command`/`args`/`url` have had
    any secret-looking value replaced with `<redacted>`.
    """

    name: str
    client: str
    config_path: str
    transport: str  # "stdio" | "url"
    command: str = ""
    args: list[str] = field(default_factory=list)
    env_names: list[str] = field(default_factory=list)
    url: str = ""
    origin_guess: str = "unknown"
    origin_reason: str = ""


def _parse_stdio_entry(
    name: str, entry: dict[str, Any], client: str, config_path: str
) -> DiscoveredServer:
    command = _redact_url(str(entry.get("command", "")))
    raw_args = [str(a) for a in entry.get("args", []) if isinstance(a, (str, int, float))]
    args = _redact_args(raw_args)
    env = entry.get("env", {})
    env_names = sorted(str(k) for k in env.keys()) if isinstance(env, dict) else []
    origin_guess, origin_reason = _origin_guess(command, raw_args)
    return DiscoveredServer(
        name=name,
        client=client,
        config_path=config_path,
        transport="stdio",
        command=command,
        args=args,
        env_names=env_names,
        origin_guess=origin_guess,
        origin_reason=origin_reason,
    )


def _parse_url_entry(
    name: str, entry: dict[str, Any], client: str, config_path: str
) -> DiscoveredServer:
    url = _redact_url(str(entry.get("url", "")))
    headers = entry.get("headers", {})
    env_names = sorted(str(k) for k in headers.keys()) if isinstance(headers, dict) else []
    return DiscoveredServer(
        name=name,
        client=client,
        config_path=config_path,
        transport="url",
        url=url,
        env_names=env_names,
        origin_guess="unknown",
        origin_reason="url-based servers carry no package/command name to guess origin from",
    )


def parse_server_entries(config_path: Path) -> list[DiscoveredServer]:
    """Parse a client config's server entries WITHOUT executing anything.

    Returns [] (never raises) for a missing/malformed config -- discovery is
    best-effort across however many client configs exist on the machine; one
    bad file shouldn't abort the rest.
    """
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        return []

    client = _client_label_for_path(config_path)
    path_str = str(config_path)
    discovered: list[DiscoveredServer] = []
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        if "url" in entry:
            discovered.append(_parse_url_entry(str(name), entry, client, path_str))
        elif "command" in entry:
            discovered.append(_parse_stdio_entry(str(name), entry, client, path_str))
    return discovered
