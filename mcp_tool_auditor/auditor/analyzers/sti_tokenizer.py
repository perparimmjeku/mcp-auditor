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
from importlib import resources
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
        # Keyed by asset filename (not CLI alias) -- "chatml" and "qwen" share
        # one file, so this avoids parsing the same ~11MB JSON twice while
        # still letting each alias produce a correctly-named ResolvedTokenizer.
        self._asset_cache: dict[str, tuple[Any, frozenset[int]] | None] = {}

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
        filename = _SUPPORTED_TOKENIZERS[name]
        asset = self._load_asset(filename, tokenizers_lib)
        if asset is None:
            return None
        tok, special_ids = asset
        # Always build a fresh ResolvedTokenizer with the alias actually
        # requested -- "chatml" and "qwen" share a cached asset, but a
        # result labeled "chatml" when the caller asked for "qwen" would be
        # a real (if minor) correctness bug in the finding's provenance.
        return ResolvedTokenizer(name=name, tokenizer=tok, special_ids=special_ids)

    def _load_asset(self, filename: str, tokenizers_lib: Any) -> tuple[Any, frozenset[int]] | None:
        if filename in self._asset_cache:
            return self._asset_cache[filename]

        try:
            json_text = (
                resources.files("mcp_tool_auditor.auditor.tokenizer_assets")
                .joinpath(filename)
                .read_text(encoding="utf-8")
            )
            tok = tokenizers_lib.Tokenizer.from_str(json_text)
        except Exception:
            logger.warning(
                "--sti-tokenizer: failed to load the vendored asset '%s'. Skipped.",
                filename,
                exc_info=True,
            )
            self._asset_cache[filename] = None
            return None

        # Every added/special-vocabulary token id, not just ones with the
        # JSON's own "special": true flag -- e.g. DeepSeek's <｜User｜> is
        # "special": false in its tokenizer.json but still gets a dedicated
        # added-vocabulary id rather than being BPE-split, which is the
        # actual property this tier cares about (a real tokenizer treats it
        # as one atomic unit, not ordinary text).
        special_ids = frozenset(tok.get_added_tokens_decoder().keys())
        asset = (tok, special_ids)
        self._asset_cache[filename] = asset
        return asset


def find_tokenizer_matches(text: str, resolved: ResolvedTokenizer) -> list[tuple[int, int, str]]:
    """Return (start, end, substring) for every span of `text` that the

    real tokenizer resolves to one of its added/special-vocabulary ids --
    i.e. an atomic token, not several ordinary BPE pieces. Encodes the raw,
    unmodified text (no normalization) so offsets line up with the exact/
    structural string tiers, which also operate on the original text.
    add_special_tokens=False only suppresses template tokens (e.g. BOS/EOS)
    the tokenizer would otherwise add; it does not affect whether special
    tokens embedded in the input text are recognized.
    """
    if not text:
        return []
    encoding = resolved.tokenizer.encode(text, add_special_tokens=False)
    matches: list[tuple[int, int, str]] = []
    for token_id, (start, end) in zip(encoding.ids, encoding.offsets, strict=True):
        if token_id in resolved.special_ids and end > start:
            matches.append((start, end, text[start:end]))
    return matches
