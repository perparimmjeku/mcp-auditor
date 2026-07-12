"""Special Token Injection (STI) detection.

STI is text that spoofs or closes a model's native chat-template control
tokens -- <|im_start|>, [INST], <|start_header_id|>, DeepSeek's fullwidth
<｜User｜>, etc. -- to hijack the conversation-turn boundary of whatever
prompt an MCP client eventually builds from this text. It reads as inert to
a human reviewer but can be structurally meaningful to the model.

Four matching tiers, most to least certain:
  exact       Literal registry token present verbatim.
  normalized  A registry token is present after Unicode NFKC normalization +
              homoglyph folding (Cyrillic/Greek lookalikes -- NFKC already
              handles fullwidth-form compatibility decomposition like U+FF5C
              "｜" -> "|" on its own) + stripping zero-width/bidi control
              characters + whitespace collapse.
  structural  Text has the *shape* of a control token (<|...|>, [INST],
              <<SYS>>, <start_of_turn>) even though it isn't in the
              registry -- catches new/uncatalogued model families.
  encoded     A length-bounded base64/hex substring decodes to a registry
              token. Opt-in (decode_encoded=True / CLI --sti-decode): the
              decoded bytes are compared only against the registry
              (exact + normalized), never fed back into the structural
              regex, to keep this tier's false-positive rate low.

Matching returns structured STIMatch objects (never a bare bool/string) so
a future batch/corpus tool can aggregate tier hit-rates without a refactor.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised in minimal local installs
    yaml = None  # type: ignore[assignment]

from ..models import Finding, Severity
from .surface import label_for_kind, rule_for_kind

# Same-shape characters from a *different script* than Latin, with no
# Unicode compatibility-decomposition relationship to it -- NFKC won't fold
# these on its own (unlike fullwidth forms, which NFKC does handle).
_HOMOGLYPH_MAP = {
    # Cyrillic lookalikes
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "А": "A",
    "Е": "E",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Х": "X",
    "У": "Y",
    "І": "I",
    "ѕ": "s",
    # Greek lookalikes
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Χ": "X",
}

# U+200B/C/D zero-width space/non-joiner/joiner, U+2060 word joiner, U+FEFF
# BOM/zero-width no-break space, U+200E/F LTR/RTL marks, U+202A-E bidi
# embedding/override controls, U+2066-9 bidi isolate controls. Written as
# explicit escapes rather than literal characters -- invisible characters
# in the source of a detector for invisible characters is an audit hazard.
_ZERO_WIDTH_AND_BIDI = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u200e\u200f\u202a-\u202e\u2066-\u2069]"
)

_WHITESPACE_RUN = re.compile(r"\s+")

_STRUCTURAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"<\|[^>]{1,40}\|>"),
    re.compile(r"\[/?(?:INST|SYS|TOOL_[A-Z]+)\]"),
    re.compile(r"<<?/?SYS>?>"),
    re.compile(r"<(?:start|end)_of_turn>"),
]

# Length-banded candidates only -- never "decode every string" (encoded tier,
# opt-in). 16-512 chars for base64, 16-256 bytes (32-512 hex chars) for hex.
_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/=]{16,512}")
_HEX_CANDIDATE = re.compile(r"(?:[0-9a-fA-F]{2}){8,256}")


def _normalize(text: str) -> str:
    folded = "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)
    folded = unicodedata.normalize("NFKC", folded)
    folded = _ZERO_WIDTH_AND_BIDI.sub("", folded)
    folded = _WHITESPACE_RUN.sub(" ", folded)
    return folded


@lru_cache(maxsize=1)
def _load_registry() -> tuple[tuple[str, str, str], ...]:
    """Return (token, family, note) triples from signatures/sti_tokens.yaml."""
    with (
        resources.files("mcp_tool_auditor.auditor.signatures")
        .joinpath("sti_tokens.yaml")
        .open("r", encoding="utf-8") as fh
    ):
        text = fh.read()
    if yaml is None:
        raise RuntimeError("PyYAML is required to load the STI token registry")
    data = yaml.safe_load(text) or {}
    entries: list[tuple[str, str, str]] = []
    for family, tokens in data.items():
        for item in tokens or []:
            entries.append((item["token"], family, item.get("note", "")))
    return tuple(entries)


@dataclass
class STIMatch:
    """One Special Token Injection match, tier-tagged for confidence scoring."""

    tier: str  # "exact" | "normalized" | "structural" | "encoded" | "tokenizer"
    token: str  # the registry token (or matched shape, for structural) that fired
    family: str  # model family, e.g. "chatml_openai_qwen"; "unknown" for structural
    surface: str  # "tool" | "resource" | "prompt" | "instructions"
    offset: int  # character offset of the match (see tier notes on which string)
    raw_match: str  # the actual substring found
    # Only set for tier="tokenizer" (None for the four string tiers): which
    # --sti-tokenizer target(s) confirmed this via a real tokenizer's
    # encode(), comma-joined if more than one target agreed.
    tokenizer: str | None = None
    resolved_special: bool | None = None


class STIMatcher:
    """Runs the four string-based STI matching tiers, plus an optional fifth

    tokenizer-backed tier, over a single text string.
    """

    def __init__(self, decode_encoded: bool = False, tokenizer_names: list[str] | None = None):
        self.decode_encoded = decode_encoded
        self._registry = _load_registry()
        # normalized-form -> (canonical registry token, family). Built from
        # every registry token (including already-non-ASCII ones like
        # DeepSeek's), so this also catches an attacker writing the
        # ASCII-normalized *equivalent* of a token whose canonical registry
        # form happens to be non-ASCII.
        self._normalized_index: dict[str, tuple[str, str]] = {
            _normalize(token): (token, family) for token, family, _note in self._registry
        }
        # Resolved once at construction (same pattern as decode_encoded) so
        # a scan doesn't re-log the same missing-dependency/unknown-name
        # warnings on every tool/resource/prompt/instructions item.
        self._resolved_tokenizers: list[Any] = []
        if tokenizer_names:
            from .sti_tokenizer import TokenizerRegistry

            self._resolved_tokenizers = TokenizerRegistry().resolve(tokenizer_names)

    def find(self, text: str, surface: str = "tool") -> list[STIMatch]:
        if not text:
            return []
        exact_matches = self._match_exact(text, surface)
        exact_tokens = {m.token for m in exact_matches}
        normalized_matches = self._match_normalized(text, surface, exact_tokens)
        structural_matches = self._match_structural(
            text, surface, exact_matches + normalized_matches
        )
        matches = exact_matches + normalized_matches + structural_matches
        if self.decode_encoded:
            matches += self._match_encoded(text, surface)
        if self._resolved_tokenizers:
            matches = self._apply_tokenizer_tier(
                text, surface, matches, exact_matches, structural_matches
            )
        return matches

    def _apply_tokenizer_tier(
        self,
        text: str,
        surface: str,
        matches: list[STIMatch],
        exact_matches: list[STIMatch],
        structural_matches: list[STIMatch],
    ) -> list[STIMatch]:
        """Cross-reference real-tokenizer spans against the string tiers.

        Only exact/structural share both a coordinate system (offsets into
        the original, unmodified text) and literal-text semantics with the
        tokenizer tier -- normalized operates on folded text (an obfuscated
        string was never going to be recognized as its own literal token by
        a real tokenizer anyway) and encoded's span is an opaque blob, not
        the literal token text. Neither participates in confirm/diverge.

        A span the tokenizer confirms that overlaps a string-tier match:
        replace it with ONE tier="tokenizer" finding (the confirmation is
        strictly more certain, so the plain string finding would be
        redundant). A span the tokenizer confirms that no string tier
        found: append as a new, standalone finding -- a token our registry
        doesn't list. A string-tier match no configured tokenizer confirms:
        left completely unchanged -- that divergence ("looks like a token,
        but this tokenizer won't parse it as one") is itself signal and
        must not be silently dropped.
        """
        from .sti_tokenizer import find_tokenizer_matches

        confirmable = {(m.offset, m.raw_match): m for m in exact_matches + structural_matches}
        confirmations: dict[tuple[int, str], list[str]] = {}
        novel: dict[tuple[int, str], str] = {}  # key -> confirming tokenizer name

        for resolved in self._resolved_tokenizers:
            for start, _end, substring in find_tokenizer_matches(text, resolved):
                key = (start, substring)
                if key in confirmable:
                    confirmations.setdefault(key, []).append(resolved.name)
                elif key not in novel:
                    novel[key] = resolved.name

        result: list[STIMatch] = []
        for m in matches:
            key = (m.offset, m.raw_match)
            names = confirmations.get(key) if key in confirmable else None
            if names:
                result.append(
                    STIMatch(
                        tier="tokenizer",
                        token=m.token,
                        family=m.family,
                        surface=surface,
                        offset=m.offset,
                        raw_match=m.raw_match,
                        tokenizer=", ".join(sorted(names)),
                        resolved_special=True,
                    )
                )
            else:
                result.append(m)

        for (start, substring), tokenizer_name in novel.items():
            result.append(
                STIMatch(
                    tier="tokenizer",
                    token=substring,
                    family=tokenizer_name,
                    surface=surface,
                    offset=start,
                    raw_match=substring,
                    tokenizer=tokenizer_name,
                    resolved_special=True,
                )
            )
        return result

    def _match_exact(self, text: str, surface: str) -> list[STIMatch]:
        found: list[STIMatch] = []
        for token, family, _note in self._registry:
            start = 0
            while True:
                idx = text.find(token, start)
                if idx == -1:
                    break
                found.append(
                    STIMatch(
                        tier="exact",
                        token=token,
                        family=family,
                        surface=surface,
                        offset=idx,
                        raw_match=token,
                    )
                )
                start = idx + len(token)
        return found

    def _match_normalized(self, text: str, surface: str, exact_tokens: set[str]) -> list[STIMatch]:
        normalized = _normalize(text)
        found: list[STIMatch] = []
        for norm_token, (orig_token, family) in self._normalized_index.items():
            if orig_token in exact_tokens:
                continue  # already reported at higher certainty by the exact tier
            idx = normalized.find(norm_token)
            if idx == -1:
                continue
            found.append(
                STIMatch(
                    tier="normalized",
                    token=orig_token,
                    family=family,
                    # Offset/raw_match are into the *normalized* string --
                    # folding can change length, so this isn't always a
                    # direct offset into the original text.
                    surface=surface,
                    offset=idx,
                    raw_match=normalized[idx : idx + len(norm_token)],
                )
            )
        return found

    def _match_structural(
        self, text: str, surface: str, higher_tier_matches: list[STIMatch]
    ) -> list[STIMatch]:
        already = {m.raw_match for m in higher_tier_matches}
        found: list[STIMatch] = []
        for pattern in _STRUCTURAL_PATTERNS:
            for m in pattern.finditer(text):
                if m.group(0) in already:
                    continue  # a known registry token, already reported above
                found.append(
                    STIMatch(
                        tier="structural",
                        token=m.group(0),
                        family="unknown",
                        surface=surface,
                        offset=m.start(),
                        raw_match=m.group(0),
                    )
                )
        return found

    def _match_encoded(self, text: str, surface: str) -> list[STIMatch]:
        found: list[STIMatch] = []
        candidates = (
            (_BASE64_CANDIDATE, self._try_base64),
            (_HEX_CANDIDATE, self._try_hex),
        )
        for pattern, decoder in candidates:
            for m in pattern.finditer(text):
                decoded = decoder(m.group(0))
                if decoded is None:
                    continue
                hit = self._registry_hit(decoded)
                if hit is None:
                    continue
                token, family = hit
                found.append(
                    STIMatch(
                        tier="encoded",
                        token=token,
                        family=family,
                        surface=surface,
                        offset=m.start(),
                        raw_match=m.group(0),
                    )
                )
        return found

    def _registry_hit(self, decoded: str) -> tuple[str, str] | None:
        """Compare decoded bytes against the registry -- exact + normalized

        tiers only, deliberately never the structural regex (that would
        turn "decodes to something token-shaped" into a false-positive
        generator; "decodes to a *known* control token" stays low-FP).
        """
        for token, family, _note in self._registry:
            if token in decoded:
                return token, family
        normalized_decoded = _normalize(decoded)
        for norm_token, (orig_token, family) in self._normalized_index.items():
            if norm_token in normalized_decoded:
                return orig_token, family
        return None

    @staticmethod
    def _try_base64(candidate: str) -> str | None:
        try:
            padded = candidate + "=" * (-len(candidate) % 4)
            return base64.b64decode(padded, validate=False).decode("utf-8", errors="strict")
        except Exception:
            return None

    @staticmethod
    def _try_hex(candidate: str) -> str | None:
        try:
            return bytes.fromhex(candidate).decode("utf-8", errors="strict")
        except (ValueError, binascii.Error):
            return None


_TIER_RULE = {
    "exact": "STI_EXACT",
    "normalized": "STI_NORMALIZED",
    "structural": "STI_STRUCTURAL",
    "encoded": "STI_ENCODED",
    "tokenizer": "STI_TOKENIZER",
}

_TIER_DESCRIPTION = {
    "exact": "contains a special chat-template control token",
    "normalized": "contains a Unicode-obfuscated (fullwidth/homoglyph/zero-width) form of a "
    "special chat-template control token",
    "structural": "contains text shaped like an unrecognized model control token",
    "encoded": "contains a base64/hex-encoded special chat-template control token",
    "tokenizer": "resolves to a special/added-vocabulary token id",
}


def safe_snippet(raw: str, max_len: int = 60) -> str:
    """Escape control/invisible characters so a finding message is safe to

    render in a terminal or markdown viewer -- an STI payload is exactly
    the kind of text that could otherwise manipulate the report's own
    display if echoed verbatim.
    """
    truncated = raw[:max_len]
    escaped_chars = []
    for ch in truncated:
        if ch == "`":
            escaped_chars.append("'")
        elif ch in ("\r", "\n") or not ch.isprintable():
            escaped_chars.append(f"\\u{ord(ch):04x}")
        else:
            escaped_chars.append(ch)
    escaped = "".join(escaped_chars)
    suffix = "…" if len(raw) > max_len else ""
    return f"`{escaped}{suffix}`"


class STIAnalyzer:
    """Static-surface Special Token Injection analyzer.

    Follows the multi-surface convention (kind="tool"/"resource"/"prompt"/
    "instructions") used by StaticAnalyzer/HeuristicAnalyzer so the same
    detection logic covers all four MCP surfaces via rule_for_kind/label_for_kind.
    """

    def __init__(self, decode_encoded: bool = False, tokenizer_names: list[str] | None = None):
        self._matcher = STIMatcher(decode_encoded=decode_encoded, tokenizer_names=tokenizer_names)

    def analyze(self, tool: dict[str, Any], kind: str = "tool") -> list[Finding]:
        tool_name = tool.get("name", "unknown")
        text = self._get_text(tool)
        matches = self._matcher.find(text, surface=kind)
        return [self._finding_from_match(m, tool_name, kind) for m in matches]

    def _finding_from_match(self, match: STIMatch, tool_name: str, kind: str) -> Finding:
        severity = (
            Severity.HIGH if match.tier in {"exact", "normalized", "tokenizer"} else Severity.MEDIUM
        )
        offset_note = (
            f"offset {match.offset} (post-normalization)"
            if match.tier == "normalized"
            else f"offset {match.offset}"
        )
        confirmed_by = (
            f", confirmed by real tokenizer: {match.tokenizer}" if match.tokenizer else ""
        )
        field = (
            f"sti.tokenizer.{match.tokenizer}" if match.tier == "tokenizer" else f"sti.{match.tier}"
        )
        return Finding(
            severity=severity,
            rule=rule_for_kind(_TIER_RULE[match.tier], kind),
            message=(
                f"{label_for_kind(kind)} '{tool_name}': {_TIER_DESCRIPTION[match.tier]} "
                f"({match.family}{confirmed_by}) at {offset_note}: {safe_snippet(match.raw_match)}"
            ),
            owasp_id="MCP03",
            attack_type="special_token_injection",
            tool_name=tool_name,
            field=field,
        )

    @staticmethod
    def _get_text(tool: dict[str, Any]) -> str:
        return " ".join(STIAnalyzer._iter_strings(tool))

    @classmethod
    def _iter_strings(cls, value: Any):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for key, inner in value.items():
                yield str(key)
                yield from cls._iter_strings(inner)
        elif isinstance(value, list):
            for inner in value:
                yield from cls._iter_strings(inner)
