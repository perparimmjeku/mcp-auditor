"""Confidence levels for findings, derived from the rule that produced them.

HIGH   — definitive matches (known signatures, exact poison content, runtime ATPA).
LOW    — fuzzy heuristics prone to false positives (length/imperative scoring).
MEDIUM — everything else.
"""

_HIGH_PREFIXES = (
    "ST_",
    "SRC_SHELL_INJECTION",
    "BEHAV_ATPA_TRANSITION",
    "BEHAV_OUTPUT_INJECTION",
    "RUGPULL_FINGERPRINT_MISMATCH",
    "HEUR_UNICODE",
    "FSP_DESC_INJECTION",
    "FSP_ENUM_POISON",
    "FSP_REQUIRED_LENGTH",
    "PROMPT_ARG_DESC_INJECTION",
    "RUGPULL_BASELINE_TAMPERED",
    "STI_EXACT",
    "STI_NORMALIZED",
    "STI_TOKENIZER",
    "BEHAV_STI_TRANSITION",
    "BEHAV_STI_OUTPUT",
    # A specific coupled pair (one tool's description names the other) is
    # concrete evidence of wiring, not a generic co-presence guess -- unlike
    # FLOW_SENSITIVE_SINK below, which is deliberately left at the MEDIUM
    # default (see the comment there) precisely because it has no such
    # evidence.
    "FLOW_CROSS_SERVER_EXFIL",
)

_LOW_PREFIXES = (
    "HEUR_DESC_LENGTH",
    "HEUR_IMPERATIVE",
    "HEUR_AGENCY",
    "HEUR_PARAM_DESC_LONG",
    "SCHEMA_UNTYPED",
    "SCHEMA_GENERIC_TYPE",
    "BEHAV_RESPONSE_DIVERGENCE",
    "PROMPT_ARG_DESC_LONG",
)

# Resource/prompt/instructions findings reuse tool rule ids with a surface
# prefix (see analyzers/surface.py) — strip it so e.g. "RES_ST_IGNORE_PREVIOUS"
# is classified the same as "ST_IGNORE_PREVIOUS".
_KIND_PREFIXES = ("RES_", "PROMPT_", "INSTR_")

# COMPOSITION_CONFUSED_DEPUTY and FLOW_SENSITIVE_SINK are intentionally in
# neither list above, so both fall through to the MEDIUM default. Both are
# Severity.HIGH/MEDIUM-impact-if-real but generic co-presence heuristics (a
# sensitive-access tool and an egress tool happen to both exist) with no
# evidence the pairing is actually wired together -- severity reflects
# potential impact, confidence reflects certainty of the specific match, and
# these deliberately score high on the former and modest on the latter so
# they don't fire as hard as a definitive signature match. Contrast
# FLOW_CROSS_SERVER_EXFIL above, which requires a name cross-reference
# between the two tools and is scored HIGH confidence accordingly.
#
# INV_INFERRED_CHAIN (inventory.py) is also intentionally absent from both
# lists, for a stronger reason than the two above: it's not backed by real
# tool text at all, only a guess synthesized from server launch config
# (command/args/env-var names). It always sets confidence="MEDIUM" explicitly
# on the Finding rather than relying on this fallthrough, as a second,
# independent guard against it ever being promoted to HIGH by a future change
# here -- an inferred chain must never carry more certainty than a guess.


def confidence_for(rule: str) -> str:
    bare = rule
    for prefix in _KIND_PREFIXES:
        if bare.startswith(prefix):
            bare = bare[len(prefix) :]
            break
    if bare.startswith(_HIGH_PREFIXES):
        return "HIGH"
    if bare.startswith(_LOW_PREFIXES):
        return "LOW"
    return "MEDIUM"
