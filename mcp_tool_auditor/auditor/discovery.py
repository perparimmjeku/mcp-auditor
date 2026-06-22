"""Discovery of MCP client config locations on the local machine.

Finds where Claude Desktop, Cursor, VS Code (Continue), Windsurf, and Zed store
their MCP server configuration so ``scan local`` can audit configured servers
without the user pointing at each file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


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
