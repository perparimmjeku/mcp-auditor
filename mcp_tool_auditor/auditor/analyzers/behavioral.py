"""Behavioral/runtime analysis of MCP tool responses (ATPA detection)."""

from dataclasses import dataclass
from typing import Any

from ..models import Finding, Severity
from . import patterns
from .sti import STIMatcher, safe_snippet


@dataclass
class CallResult:
    """One invocation of a tool: its 0-based index, response text, and error."""

    index: int
    text: str
    error: str | None = None


_DUMMY_BY_TYPE: dict[str, Any] = {
    "string": "test",
    "integer": 1,
    "number": 1,
    "boolean": True,
    "array": [],
    "object": {},
    "null": None,
}


def synthesize_arguments(input_schema: Any) -> dict[str, Any]:
    """Build minimal valid dummy arguments from a JSON-Schema inputSchema."""
    if not isinstance(input_schema, dict):
        return {}
    props = input_schema.get("properties", {})
    if not isinstance(props, dict):
        return {}
    args: dict[str, Any] = {}
    for pname, spec in props.items():
        if not isinstance(spec, dict):
            args[pname] = "test"
        elif "default" in spec:
            args[pname] = spec["default"]
        elif spec.get("enum"):
            args[pname] = spec["enum"][0]
        else:
            args[pname] = _DUMMY_BY_TYPE.get(spec.get("type", "string"), "test")
    return args


class BehavioralAnalyzer:
    """Detects ATPA time-bomb behavior and injection content in tool responses.

    Runs two independent checks over the same call transcript: the original
    keyword/pattern-based injection scan (patterns.scan_response), and a
    Special Token Injection scan (STIMatcher) for chat-template control
    tokens emitted only at call time -- a definition-only scan can't see a
    token a tool only returns after N calls. Both can fire for the same
    tool if both classes of poisoning are present.
    """

    def __init__(self, sti_matcher: STIMatcher | None = None):
        # decode_encoded defaults to False here, same as everywhere else --
        # not wired to a CLI flag for behavioral probing in this pass.
        self._sti_matcher = sti_matcher or STIMatcher()

    def analyze(self, tool: dict[str, Any], responses: list[CallResult]) -> list[Finding]:
        name = tool.get("name", "unknown")
        findings: list[Finding] = []

        successful = [r for r in responses if r.error is None]
        errored = [r for r in responses if r.error is not None]

        findings.extend(self._analyze_sti(name, successful))

        injections = [(r.index, patterns.scan_response(r.text)) for r in successful]
        injections = [(idx, labels) for idx, labels in injections if labels]

        if injections:
            injection_indices = {idx for idx, _ in injections}
            first_idx, first_labels = min(injections, key=lambda x: x[0])
            prior_benign = [
                r for r in successful if r.index < first_idx and r.index not in injection_indices
            ]
            if prior_benign:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        rule="BEHAV_ATPA_TRANSITION",
                        message=(
                            f"Tool '{name}': benign for {len(prior_benign)} call(s), then call "
                            f"#{first_idx + 1} returned poisoned content "
                            f"({', '.join(first_labels)}) — ATPA time-bomb behavior."
                        ),
                        owasp_id="MCP03",
                        attack_type="atpa",
                        tool_name=name,
                    )
                )
            else:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        rule="BEHAV_OUTPUT_INJECTION",
                        message=(
                            f"Tool '{name}': response contains injection/exfil indicators "
                            f"({', '.join(first_labels)})."
                        ),
                        owasp_id="MCP03",
                        attack_type="behavioral_injection",
                        tool_name=name,
                    )
                )
        else:
            texts = {r.text for r in successful}
            if len(successful) > 1 and len(texts) > 1:
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        rule="BEHAV_RESPONSE_DIVERGENCE",
                        message=(
                            f"Tool '{name}': identical inputs produced {len(texts)} different "
                            f"responses across {len(successful)} calls — non-deterministic behavior."
                        ),
                        owasp_id="MCP03",
                        attack_type="behavioral_nondeterminism",
                        tool_name=name,
                    )
                )

        if errored:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    rule="BEHAV_CALL_ERROR",
                    message=(
                        f"Tool '{name}': {len(errored)} of {len(responses)} call(s) errored "
                        f"(e.g. {errored[0].error})."
                    ),
                    owasp_id="N/A",
                    attack_type="behavioral_error",
                    tool_name=name,
                )
            )

        return findings

    def _analyze_sti(self, name: str, successful: list[CallResult]) -> list[Finding]:
        """Same transition-detection shape as the main ATPA check above, but

        for Special Token Injection: a chat-template control token emitted
        only after benign calls is the same time-bomb pattern, just STI-
        tagged so it's distinguishable in reports/suppressions from generic
        keyword-based ATPA findings.
        """
        hits = [(r.index, self._sti_matcher.find(r.text, surface="tool")) for r in successful]
        hits = [(idx, matches) for idx, matches in hits if matches]
        if not hits:
            return []

        hit_indices = {idx for idx, _ in hits}
        first_idx, first_matches = min(hits, key=lambda x: x[0])
        prior_benign = [r for r in successful if r.index < first_idx and r.index not in hit_indices]
        tiers = ", ".join(sorted({m.tier for m in first_matches}))
        families = ", ".join(sorted({m.family for m in first_matches}))
        snippet = safe_snippet(first_matches[0].raw_match)

        if prior_benign:
            return [
                Finding(
                    severity=Severity.CRITICAL,
                    rule="BEHAV_STI_TRANSITION",
                    message=(
                        f"Tool '{name}': benign for {len(prior_benign)} call(s), then call "
                        f"#{first_idx + 1} emitted a special chat-template control token "
                        f"({tiers} tier, {families}): {snippet} — STI time-bomb behavior."
                    ),
                    owasp_id="MCP03",
                    attack_type="sti_atpa",
                    tool_name=name,
                )
            ]
        return [
            Finding(
                severity=Severity.HIGH,
                rule="BEHAV_STI_OUTPUT",
                message=(
                    f"Tool '{name}': response contains a special chat-template control token "
                    f"from the first call ({tiers} tier, {families}): {snippet}."
                ),
                owasp_id="MCP03",
                attack_type="behavioral_sti",
                tool_name=name,
            )
        ]
