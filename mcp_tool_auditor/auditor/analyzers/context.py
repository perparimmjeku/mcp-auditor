"""Context classifiers for the bare-keyword static signatures.

ST_CREDENTIAL/ST_DATA_EXFIL/ST_CODE_EXEC/ST_SENSITIVE match a single word or
short phrase with no regard for what's around it -- "token" fires identically
for "token offset for pagination" and "leak the API token", and a `private`
field in a tool's OUTPUT schema (describing what it *returns*) fires the same
as "private" in a description asking the model to access private data. This
module looks at the surrounding text and the match's schema location to
decide, per match, whether the finding should be suppressed outright (no
security signal at all), kept at the rule's LOW baseline, escalated to MEDIUM
on real corroborating evidence, or dropped a further tier because the match
only appears in output-schema metadata.

confidence.py's static prefix buckets set the *default* tier for these rules
when this classifier isn't involved (e.g. a custom signature reusing the rule
name); this module is what actually runs for the real signatures.
"""

from __future__ import annotations

import re

from ..models import Severity

# "token" specifically, when it's pagination/model-context terminology, not
# a credential reference -- "token offset", "max_tokens", "context window".
_PAGINATION_CONTEXT = re.compile(
    r"\b(offset|pagination|paginat\w*|chunk(?:ed|ing)?|max[\s_-]?tokens?|"
    r"context\s+window|context\s+length|token\s+limit|truncat\w*)\b",
    re.IGNORECASE,
)

# Real corroborating evidence for a credential match: an action verb near a
# credential noun, in either order ("reveals the token" / "token... leaked").
_ACTION_VERB = (
    r"reveal\w*|expose\w*|exfiltrat\w*|leak\w*|transmit\w*|dump\w*|embed\w*|"
    r"include\w*|attach\w*|append\w*|submit\w*"
)
_CREDENTIAL_NOUN = (
    r"credential\w*|password\w*|secret\w*|token\w*|api[\s_-]?key\w*|"
    r"ssh[\s_-]?key\w*|environment\s+variables?"
)
_STRONG_CREDENTIAL_SIGNAL = re.compile(
    rf"\b(?:{_ACTION_VERB})\b(?:\W+\w+){{0,6}}\W+\b(?:{_CREDENTIAL_NOUN})\b"
    rf"|"
    rf"\b(?:{_CREDENTIAL_NOUN})\b(?:\W+\w+){{0,6}}\W+\b(?:{_ACTION_VERB})\b",
    re.IGNORECASE,
)

# Real corroborating evidence for a data-exfiltration match: a sink verb near
# a sensitive-data noun, in either order.
_SENSITIVE_NOUN = (
    r"sensitive\w*|private\w*|confidential\w*|personal\w*|credential\w*|secret\w*|password\w*"
)
_SINK_VERB = r"send\w*|post\w*|transmit\w*|upload\w*|exfiltrat\w*|submit\w*|include\w*"
_STRONG_EXFIL_SIGNAL = re.compile(
    rf"\b(?:{_SENSITIVE_NOUN})\b(?:\W+\w+){{0,8}}\W+\b(?:{_SINK_VERB})\b"
    rf"|"
    rf"\b(?:{_SINK_VERB})\b(?:\W+\w+){{0,8}}\W+\b(?:{_SENSITIVE_NOUN})\b",
    re.IGNORECASE,
)

# A concrete URL literal (an actual destination, not just the bare capability
# word "http") is itself strong evidence -- "sends the query via an HTTP GET
# request" describes a mechanism, but "send the contents to
# https://attacker.example.com/log" names a specific place data goes, which
# is a materially different, stronger claim.
_URL_LITERAL = re.compile(r"https?://[\w.\-]+", re.IGNORECASE)

_SEVERITY_TIER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_CONFIDENCE_TIER = ["INFO", "LOW", "MEDIUM", "HIGH"]

# The four rule families that get per-match context classification. ST_CODE_EXEC
# has no escalation path (see module docstring in remediation.py / RULES.md:
# a real dynamic-execution finding is source-scan's SRC_DYNAMIC_CODE_EXEC's
# job, not a text match's), it only participates for the output-schema
# tier-down and to route through one call site rather than two.
CLASSIFIED_RULES = frozenset({"ST_CREDENTIAL", "ST_DATA_EXFIL", "ST_SENSITIVE", "ST_CODE_EXEC"})


def _one_tier_down(severity: Severity, confidence: str) -> tuple[Severity, str]:
    sev_idx = max(_SEVERITY_TIER.index(severity) - 1, 0)
    conf_idx = max(_CONFIDENCE_TIER.index(confidence) - 1, 0)
    return _SEVERITY_TIER[sev_idx], _CONFIDENCE_TIER[conf_idx]


def _output_schema_only(pattern: str, core_text: str, output_text: str) -> bool:
    """True if `pattern` matches only inside output-schema text -- i.e. it
    describes what the tool returns, not what it does or requests."""
    if not output_text:
        return False
    try:
        matches_output = re.search(pattern, output_text, re.IGNORECASE) is not None
        matches_core = re.search(pattern, core_text, re.IGNORECASE) is not None
    except re.error:
        return False
    return matches_output and not matches_core


def classify(
    rule: str,
    pattern: str,
    full_text: str,
    core_text: str,
    output_text: str,
) -> tuple[Severity, str] | None:
    """Return (severity, confidence) for a keyword match after applying
    context, or None to suppress the finding entirely (no security signal).

    Only call this for rules in CLASSIFIED_RULES; the caller (static.py)
    checks membership before invoking it.
    """
    if rule == "ST_CREDENTIAL":
        # Only the "token" signature has a legitimate pagination/model-context
        # reading -- "password"/"secret"/"api_key"/"ssh"/"aws" don't. Matched
        # by pattern content rather than exact string so a future regex tweak
        # (e.g. adding another plural form) doesn't silently disable this.
        if "token" in pattern and _PAGINATION_CONTEXT.search(full_text):
            return None
        severity, confidence = (
            (Severity.MEDIUM, "MEDIUM")
            if _STRONG_CREDENTIAL_SIGNAL.search(full_text)
            else (Severity.LOW, "LOW")
        )
    elif rule == "ST_DATA_EXFIL":
        severity, confidence = (
            (Severity.MEDIUM, "MEDIUM")
            if _STRONG_EXFIL_SIGNAL.search(full_text) or _URL_LITERAL.search(full_text)
            else (Severity.LOW, "LOW")
        )
    else:  # ST_SENSITIVE, ST_CODE_EXEC -- no escalation path, LOW baseline only
        severity, confidence = Severity.LOW, "LOW"

    if _output_schema_only(pattern, core_text, output_text):
        severity, confidence = _one_tier_down(severity, confidence)

    return severity, confidence
