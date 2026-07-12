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
