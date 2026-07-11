"""Shared labeling for the different MCP surfaces static/heuristic analyzers scan.

Poisoning isn't limited to tool descriptions — MCP servers also expose
resources, prompts, and a top-level `instructions` string from `initialize`,
and all three are documented injection vectors. Rather than duplicate the
signature/heuristic engines per surface, analyzers accept a `kind` and this
module maps it to a rule-id prefix and a human label for messages.
"""

from __future__ import annotations

KIND_PREFIX = {
    "resource": "RES_",
    "prompt": "PROMPT_",
    "instructions": "INSTR_",
}

KIND_LABEL = {
    "tool": "Tool",
    "resource": "Resource",
    "prompt": "Prompt",
    "instructions": "Server instructions",
}


def rule_for_kind(rule: str, kind: str) -> str:
    """Prefix a base rule id for non-tool surfaces; tools keep bare rule ids."""
    prefix = KIND_PREFIX.get(kind, "")
    return f"{prefix}{rule}" if prefix else rule


def label_for_kind(kind: str) -> str:
    """Human-readable label used in finding messages, e.g. "Resource 'x': ..."."""
    return KIND_LABEL.get(kind, "Tool")
