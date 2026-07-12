"""Offline, real-tokenizer-backed Special Token Injection detection.

The four tiers in `sti.py` answer "does this text look like a known control
token?" by string matching. This module answers a stronger question: "will
THIS string actually be parsed as a special / added-vocabulary token ID by
the tokenizer a target deployment runs, rather than being split into
ordinary byte-pair pieces?" That's not answerable from our own token
registry, no matter how it's phrased -- it requires a real tokenizer's real
vocabulary. Seeding a tokenizer with our own registry strings and checking
they round-trip would be circular (it could only ever confirm what the
string tiers already catch); this deliberately loads real, offline,
license-verified `tokenizer.json` assets from actual model tokenizers
instead. See tokenizer_assets/THIRD_PARTY_NOTICES.md for provenance.

Opt-in only (CLI --sti-tokenizer, never a scan default), and strictly
offline: assets are vendored in the package and loaded via
`Tokenizer.from_str()` + `importlib.resources` -- never
`Tokenizer.from_pretrained()`, never a hub call, at any point, in any code
path. If the optional `tokenizers` dependency is absent, or a requested
family has no offline-redistributable asset, this degrades to a warning
and the four string tiers keep running unaffected -- this tier never
crashes a scan and never disables anything else.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# CLI-facing alias -> vendored asset filename under tokenizer_assets/.
# "chatml" and "qwen" intentionally share one asset: Qwen's tokenizer is a
# ChatML-family tokenizer, so there's no second real asset to justify a
# separate entry. "mistral" covers the llama2_mistral registry family.
_SUPPORTED_TOKENIZERS: dict[str, str] = {
    "chatml": "chatml_qwen.tokenizer.json",
    "qwen": "chatml_qwen.tokenizer.json",
    "mistral": "mistral.tokenizer.json",
    "deepseek": "deepseek.tokenizer.json",
}

# Requested by name in --sti-tokenizer's target vocabulary, but no
# offline-redistributable asset is vendored (see THIRD_PARTY_NOTICES.md for
# why) -- named explicitly so the failure message is specific, not a generic
# "unknown name".
_KNOWN_BUT_UNAVAILABLE_OFFLINE = {"llama3", "gemma"}


@dataclass
class ResolvedTokenizer:
    """A loaded, ready-to-use real tokenizer for one target family."""

    name: str  # the CLI-facing alias that resolved to this (e.g. "qwen")
    tokenizer: Any  # a tokenizers.Tokenizer instance
    special_ids: frozenset[int]  # every added/special-vocabulary token id


def parse_tokenizer_spec(spec: str | None) -> list[str]:
    """Parse a --sti-tokenizer comma list into lowercase, deduped names."""
    if not spec:
        return []
    seen: list[str] = []
    for raw in spec.split(","):
        name = raw.strip().lower()
        if name and name not in seen:
            seen.append(name)
    return seen


class TokenizerRegistry:
    """Resolves --sti-tokenizer names to loaded, offline ResolvedTokenizers.

    Every failure mode (missing dependency, unavailable family, unknown
    name, a bad asset) produces a logged warning and is skipped -- never an
    exception, since the caller only opted into "try the tokenizer tier",
    not "abort the entire scan if one target can't be resolved".
    """

    def __init__(self) -> None:
        self._cache: dict[str, ResolvedTokenizer | None] = {}

    def resolve(self, names: list[str]) -> list[ResolvedTokenizer]:
        if not names:
            return []
        try:
            import tokenizers as tokenizers_lib
        except ImportError:
            logger.warning(
                "--sti-tokenizer requires the optional 'tokenizers' dependency: "
                "pip install 'mcp-tool-auditor[tokenizers]' (requested: %s). "
                "Skipping the tokenizer-aware tier; the four string tiers still run.",
                ", ".join(names),
            )
            return []

        resolved: list[ResolvedTokenizer] = []
        for name in names:
            rt = self._resolve_one(name, tokenizers_lib)
            if rt is not None:
                resolved.append(rt)
        return resolved

    def _resolve_one(self, name: str, tokenizers_lib: Any) -> ResolvedTokenizer | None:
        if name in _KNOWN_BUT_UNAVAILABLE_OFFLINE:
            logger.warning(
                "--sti-tokenizer: no offline-redistributable tokenizer asset is vendored "
                "for '%s' yet (see tokenizer_assets/THIRD_PARTY_NOTICES.md). Skipped; "
                "the four string tiers still cover this family's known tokens.",
                name,
            )
            return None
        if name not in _SUPPORTED_TOKENIZERS:
            supported = sorted(set(_SUPPORTED_TOKENIZERS) | _KNOWN_BUT_UNAVAILABLE_OFFLINE)
            logger.warning(
                "--sti-tokenizer: unknown tokenizer name '%s' (supported: %s). Skipped.",
                name,
                ", ".join(supported),
            )
            return None
        return self._load(name, tokenizers_lib)

    def _load(self, name: str, tokenizers_lib: Any) -> ResolvedTokenizer | None:
        raise NotImplementedError  # filled in by the next commit
