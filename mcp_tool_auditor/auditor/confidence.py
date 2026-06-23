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
)

_LOW_PREFIXES = (
    "HEUR_DESC_LENGTH",
    "HEUR_IMPERATIVE",
    "HEUR_AGENCY",
    "HEUR_PARAM_DESC_LONG",
    "SCHEMA_UNTYPED",
    "SCHEMA_GENERIC_TYPE",
    "BEHAV_RESPONSE_DIVERGENCE",
)


def confidence_for(rule: str) -> str:
    if rule.startswith(_HIGH_PREFIXES):
        return "HIGH"
    if rule.startswith(_LOW_PREFIXES):
        return "LOW"
    return "MEDIUM"
