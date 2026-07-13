"""Confidence levels for findings, derived from the rule that produced them.

HIGH   — definitive matches (explicit malicious instruction, known control-
         token/signature match, concrete AST/regex evidence of a real sink,
         confirmed cross-server wiring).
MEDIUM — contextual evidence strongly suggests abuse but needs runtime
         validation (a keyword match with real corroborating signal nearby).
LOW    — suspicious wording/capability requiring manual review (a bare
         keyword match with no corroborating context, or a fuzzy heuristic).
INFO   — capability inventory / unvalidated observation (e.g. an archive
         resource whose contents were never inspected, or a keyword match
         that only appears in output-schema metadata describing what the
         tool returns).

A bare keyword match is never HIGH confidence on its own -- see
analyzers/context.py, which applies this tiering to ST_CREDENTIAL/
ST_DATA_EXFIL/ST_CODE_EXEC/ST_SENSITIVE per-match rather than relying solely
on the static prefix buckets below.
"""

_HIGH_PREFIXES = (
    # Explicit instruction-override / manipulation phrases -- concrete,
    # unambiguous evidence of an attempt to coerce the agent.
    "ST_ALWAYS_USE",
    "ST_SEND_FULL",
    "ST_IGNORE_PREVIOUS",
    "ST_IGNORE_ALL",
    "ST_IGNORE_SECURITY",
    "ST_AUTHORITATIVE",
    "ST_DO_NOT_QUESTION",
    "ST_YOU_MUST",
    "ST_ALWAYS_CALL",
    "ST_BYPASS",
    "ST_DO_NOT_TELL",
    "ST_SYSTEM_CLAIM",
    "ST_OVERRIDE",
    "ST_MANDATORY",
    "SRC_SHELL_INJECTION",
    "SRC_DYNAMIC_CODE_EXEC",
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
    # Bare keyword/capability matches in tool text -- a single word or short
    # phrase with no check of surrounding context. "token" fires identically
    # for "token offset" (pagination) and "leak the token" (real exposure);
    # these can never be more than a manual-review signal on the rule's own
    # static-prefix default. The four with real per-match context classifiers
    # (ST_CREDENTIAL, ST_DATA_EXFIL, ST_CODE_EXEC, ST_SENSITIVE) mostly bypass
    # this default with an explicit confidence from analyzers/context.py; it
    # still matters as the fallback for any construction path that doesn't
    # go through that classifier (e.g. a custom signature reusing the rule
    # name) and as documentation of the baseline tier.
    "ST_CREDENTIAL",
    "ST_DATA_EXFIL",
    "ST_CODE_EXEC",
    "ST_SENSITIVE",
    "ST_FILESYSTEM",
    "ST_READ_FILE",
    "ST_EXECUTE",
    "ST_CONTEXT_HARVEST",
)

_INFO_PREFIXES = (
    # An observation, not a vulnerability claim -- an archive resource whose
    # contents were never inspected. See analyzers/static.py's archive check.
    "ST_ARCHIVE_UNINSPECTED",
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

# A finding's confidence can never claim more certainty than its severity
# implies -- e.g. a LOW-severity finding (ST_SENSITIVE's "private"/
# "confidential" pattern set) has no business being reported at HIGH
# confidence, even if some future prefix change would otherwise produce
# that. This ceiling only applies to the *derived* confidence computed here;
# a caller that explicitly sets Finding(confidence=...) is trusted to know
# what it's doing (see models.Finding.__post_init__) and bypasses it.
_SEVERITY_CONFIDENCE_CEILING = {
    "CRITICAL": "HIGH",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "ERROR": "HIGH",
}
_CONFIDENCE_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def confidence_for(rule: str, severity: str | None = None) -> str:
    bare = rule
    for prefix in _KIND_PREFIXES:
        if bare.startswith(prefix):
            bare = bare[len(prefix) :]
            break

    if bare.startswith(_HIGH_PREFIXES):
        level = "HIGH"
    elif bare.startswith(_INFO_PREFIXES):
        level = "INFO"
    elif bare.startswith(_LOW_PREFIXES):
        level = "LOW"
    else:
        level = "MEDIUM"

    if severity is not None:
        ceiling = _SEVERITY_CONFIDENCE_CEILING.get(str(severity).upper(), "HIGH")
        if _CONFIDENCE_RANK[level] > _CONFIDENCE_RANK[ceiling]:
            level = ceiling

    return level
