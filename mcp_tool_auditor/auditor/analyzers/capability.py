"""Coarse tool-capability classification, shared raw material for
composition-style risk analysis.

Three roles, deliberately small and non-exhaustive — a tool can carry more
than one, and most tools carry none:

  SOURCE            reads sensitive data (files, secrets, env, db, browser,
                     credentials).
  SINK              can egress data (outbound http/network, email/messaging,
                     external writes).
  SENSITIVE_ACTION  destructive/state-changing (delete, revoke, deploy,
                     transfer funds, ...).

SOURCE/SINK reuse composition.py's access/egress regex approach (same
name+description+schema text scan), broadened for SOURCE to also cover
generic file/db/browser reads per this classifier's wider brief — composition.py
itself is left untouched, so its existing COMPOSITION_CONFUSED_DEPUTY behavior
doesn't shift. `is_high_value_source` exposes the original, narrower
credential/secret pattern separately, for callers that need to distinguish
"reads *a* file" from "reads credentials."

SENSITIVE_ACTION reuses heuristic.py's AGENCY_PATTERNS only as inspiration —
the raw list (`read|write|delete|modify`, `access|retrieve|fetch|download`)
is far too broad to gate a HIGH/CRITICAL finding on (it matches nearly any
tool). Only the destructive subset survives, tightened with concrete
high-consequence phrases.
"""

from __future__ import annotations

import re
from typing import Any

SOURCE = "SOURCE"
SINK = "SINK"
SENSITIVE_ACTION = "SENSITIVE_ACTION"

ALL_ROLES = (SOURCE, SINK, SENSITIVE_ACTION)

# The original composition.py sensitive-access pattern — credential/secret
# grade only. Kept separate (not folded into _SOURCE_PATTERN) so a caller can
# ask "is this specifically a credential-grade source" for severity tiering.
_HIGH_VALUE_SOURCE_PATTERN = re.compile(
    r"\b(credential|secret|password|passwd|api[\s_-]?key|access[\s_-]?token|private[\s_-]?key|"
    r"ssh[\s_-]?key|environment\s+variable|\.env\b|browser\s+cookie|session\s+cookie|"
    r"auth(?:orization)?\s+token|keychain|wallet\s+seed|mnemonic)\b",
    re.IGNORECASE,
)

# Broader SOURCE: the high-value pattern above, plus generic file/db/browser
# reads that carry no credential-grade signal on their own but still make a
# tool a plausible read-side of an exfil chain.
_GENERIC_SOURCE_PATTERN = re.compile(
    r"\b(read\s+(?:a\s+)?file|file\s+contents?|filesystem|list\s+directory|"
    r"query\s+(?:the\s+)?database|database\s+records?|browser\s+history|"
    r"browsing\s+history|clipboard\s+contents?)\b",
    re.IGNORECASE,
)

_SINK_PATTERN = re.compile(
    r"\b(send\s+(?:an?\s+)?(?:http|request|email|message)|http\s+post|webhook|upload|"
    r"publish\s+to|post\s+(?:data\s+)?to\s+a?\s*url|exfiltrat\w*|outbound\s+request|"
    r"fetch\s+(?:a\s+)?url|make\s+a\s+network\s+request)\b",
    re.IGNORECASE,
)

_SINK_PARAM_NAMES = {
    "url",
    "endpoint",
    "webhook_url",
    "callback_url",
    "destination",
    "target_url",
}

_SENSITIVE_ACTION_PATTERN = re.compile(
    r"\b(delete|remove|drop|destroy|wipe|erase|format|truncate|overwrite|revoke|"
    r"terminate|kill|shut\s?down|deploy|execute\s+(?:a\s+)?command|run\s+(?:a\s+)?command|"
    r"transfer\s+funds?|send\s+(?:a\s+)?payment|make\s+a\s+payment|purchase|"
    r"charge\s+(?:the\s+)?card|grant\s+access|modify\s+permissions?|change\s+password|"
    r"reset\s+password|disable\s+(?:security|firewall|authentication)|"
    r"elevate\s+privileges?)\b",
    re.IGNORECASE,
)


def _tool_text(tool: dict[str, Any]) -> str:
    parts = [
        str(tool.get("name", "")),
        str(tool.get("title", "")),
        str(tool.get("description", "")),
    ]
    schema = tool.get("inputSchema", {}) or {}
    for param_name, param in (schema.get("properties", {}) or {}).items():
        parts.append(str(param_name))
        if isinstance(param, dict):
            parts.append(str(param.get("description", "")))
    return " ".join(parts)


def _has_sink_param(tool: dict[str, Any]) -> bool:
    schema = tool.get("inputSchema", {}) or {}
    properties = schema.get("properties", {}) or {}
    return any(str(name).lower() in _SINK_PARAM_NAMES for name in properties)


def is_high_value_source(tool: dict[str, Any]) -> bool:
    """True if this tool's SOURCE role is specifically credential/secret-grade."""
    return bool(_HIGH_VALUE_SOURCE_PATTERN.search(_tool_text(tool)))


def classify(tool: dict[str, Any]) -> set[str]:
    """Return the coarse capability role(s) this tool plausibly carries."""
    text = _tool_text(tool)
    roles: set[str] = set()
    if _HIGH_VALUE_SOURCE_PATTERN.search(text) or _GENERIC_SOURCE_PATTERN.search(text):
        roles.add(SOURCE)
    if _SINK_PATTERN.search(text) or _has_sink_param(tool):
        roles.add(SINK)
    if _SENSITIVE_ACTION_PATTERN.search(text):
        roles.add(SENSITIVE_ACTION)
    return roles
