"""Suppression of known/accepted findings by rule (optionally scoped to a tool)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a dependency
    yaml = None


def load(path: str) -> list[dict[str, Any]]:
    """Load suppression entries from a YAML/JSON list of {rule, tool?} objects."""
    p = Path(path).expanduser()
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"} and yaml is not None:
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("Suppressions file must be a list of {rule, tool?} entries")
    entries: list[dict[str, Any]] = []
    for item in data:
        if isinstance(item, dict) and item.get("rule"):
            entry = {"rule": item["rule"]}
            if item.get("tool"):
                entry["tool"] = item["tool"]
            entries.append(entry)
    return entries


def _is_suppressed(finding, rules: list[str], entries: list[dict[str, Any]]) -> bool:
    if finding.rule in rules:
        return True
    for entry in entries:
        if entry.get("rule") != finding.rule:
            continue
        tool = entry.get("tool")
        if tool is None or tool == finding.tool_name:
            return True
    return False


def apply(results, rules: list[str] | None = None, entries: list[dict[str, Any]] | None = None):
    """Return results with suppressed findings removed."""
    rules = rules or []
    entries = entries or []
    if not rules and not entries:
        return results
    for result in results.values():
        result.findings = [f for f in result.findings if not _is_suppressed(f, rules, entries)]
    return results
