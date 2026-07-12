"""Guard against docs/RULES.md drifting from the rule ids the scanner
actually emits.

A prior session found RULES.md entries that didn't correspond to any real
rule (a "phantom" rule) -- caught and fixed by hand, not by any test. This
derives the real emitted rule-id set straight from source (plus the
data-driven ST_*/STI_* families) and compares it against RULES.md's table
rows, so that class of drift fails CI instead of waiting to be noticed.

Deliberately does NOT hardcode an expected rule-id list -- that would just
relocate the same manual-sync problem RULES.md itself has. Both sides are
derived, one from the doc, one from the code that actually runs.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PACKAGE_ROOT = _REPO_ROOT / "mcp_tool_auditor"
_RULES_MD = _REPO_ROOT / "docs" / "RULES.md"

# Matches `rule="LITERAL"` and `rule=rule_for_kind("LITERAL", kind)` call
# sites. Deliberately does NOT match dynamic forms (f-strings, dict/attribute
# lookups like `_TIER_RULE[match.tier]` or `signature.get("rule", ...)`) --
# those are either not part of the fixed catalog (custom signatures) or are
# pulled in separately below from their real source (sti.py's tier table,
# the ST_* signature YAML via the real loader).
_RULE_LITERAL = re.compile(r'rule=(?:rule_for_kind\()?"([A-Z][A-Z0-9_]*)"')

# RULES.md table rows only (`| \`ID\` | CONFIDENCE |`), anchored to line
# start so prose mentions of a bare surface prefix (`RES_`, `PROMPT_`) or a
# worked example (`RES_ST_IGNORE_PREVIOUS`) elsewhere in the doc don't count.
_DOC_TABLE_ROW = re.compile(r"^\| `([A-Z][A-Z0-9_]*)` \|", re.MULTILINE)

# Rule ids that exist for internal/legacy reasons and are deliberately not in
# RULES.md's catalog (not user-facing detection rules).
_DOC_EXEMPT = set()


def _emitted_rule_ids() -> set[str]:
    ids: set[str] = set()
    for py_file in _PACKAGE_ROOT.rglob("*.py"):
        ids.update(_RULE_LITERAL.findall(py_file.read_text(encoding="utf-8")))

    from mcp_tool_auditor.auditor.analyzers.sti import _TIER_RULE

    ids.update(_TIER_RULE.values())

    from mcp_tool_auditor.auditor.analyzers.static import StaticAnalyzer

    ids.update(sig["rule"] for sig in StaticAnalyzer()._builtin if sig.get("rule"))

    return ids - _DOC_EXEMPT


def _documented_rule_ids() -> set[str]:
    return set(_DOC_TABLE_ROW.findall(_RULES_MD.read_text(encoding="utf-8")))


def test_every_emitted_rule_is_documented():
    emitted = _emitted_rule_ids()
    documented = _documented_rule_ids()
    missing = emitted - documented
    assert (
        not missing
    ), f"Rule(s) emitted by the scanner but missing from docs/RULES.md: {sorted(missing)}"


def test_no_phantom_rules_in_docs():
    emitted = _emitted_rule_ids()
    documented = _documented_rule_ids()
    phantom = documented - emitted
    assert (
        not phantom
    ), f"docs/RULES.md documents rule(s) the scanner never emits: {sorted(phantom)}"


def test_extraction_sanity():
    """Guard the guard: fail loudly if the extractors themselves break instead
    of silently returning an empty/trivial set that would make the two tests
    above vacuously pass."""
    emitted = _emitted_rule_ids()
    assert len(emitted) > 40
    assert "FLOW_CROSS_SERVER_EXFIL" in emitted
    assert "ST_IGNORE_PREVIOUS" in emitted
    assert "STI_EXACT" in emitted
