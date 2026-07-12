"""Cryptographic signing/verification for pentest report chain-of-custody.

Reuses the exact HMAC-SHA256 primitive rug-pull baselines already use
(auditor/signing.py) -- not a new crypto scheme. A SEPARATE key from the
baseline key, though: MCP_TOOL_AUDITOR_REPORT_KEY / ~/.mcp-tool-auditor/
reports/.hmac_key, not MCP_TOOL_AUDITOR_BASELINE_KEY. A report signature may
need to leave the machine entirely (a client verifies it independently);
the baseline key never should -- handing out one key for both would put an
unrelated trust boundary (local baseline integrity) at risk the moment the
report key needs to travel. Same primitive, different key, same reasoning
the baseline key's own docstring already gives for supplying it out-of-band.

WHAT GETS SIGNED (the decision this module exists to implement correctly):
NOT the rendered markdown bytes. A pentest report is prose that legitimately
gets reformatted, annotated, or exported to PDF after generation --
signing raw bytes means any edit, even whitespace, breaks the signature,
and a report that shows INVALID after every routine edit teaches people to
ignore the check, which is worse than no signature at all. Instead: a
canonical, deterministic JSON payload (findings + engagement scope + tool
version, explicitly sorted -- see build_canonical_payload) is what's
signed, and the signature + payload travel together as a sidecar document
alongside the human-readable report. The report text stays freely
editable; verification confirms the FINDINGS/SCOPE/VERSION haven't been
altered, independent of prose formatting.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Any

from . import signing
from .models import CROSS_SERVER_KEY, Finding, ScanResult

SCHEMA = "mcp-tool-auditor.pentest-report-signature.v1"

_KEY_DIR = os.path.expanduser("~/.mcp-tool-auditor/reports/")
_KEY_FILENAME = ".hmac_key"
_KEY_ENV_VAR = "MCP_TOOL_AUDITOR_REPORT_KEY"


def _engagement_payload(engagement: Any) -> dict[str, Any]:
    return {
        "client": getattr(engagement, "client", "") if engagement else "",
        "tester": getattr(engagement, "tester", "") if engagement else "",
        "start_date": getattr(engagement, "start_date", "") if engagement else "",
        "end_date": getattr(engagement, "end_date", "") if engagement else "",
        "notes": getattr(engagement, "notes", "") if engagement else "",
        "allowed_targets": (
            sorted(getattr(engagement, "allowed_targets", None) or []) if engagement else []
        ),
    }


def _finding_payload(server_name: str, finding: Finding) -> dict[str, Any]:
    payload = finding.to_dict()
    payload["server"] = server_name
    return payload


def _sort_key(d: dict[str, Any]) -> tuple:
    return (
        d.get("server") or "",
        d.get("rule") or "",
        d.get("tool_name") or "",
        d.get("field") or "",
        d.get("message") or "",
    )


def build_canonical_payload(
    results: dict[str, ScanResult],
    tool_version: str,
    engagement: Any = None,
    fixed: list[tuple[str, Finding]] | None = None,
) -> dict[str, Any]:
    """The deterministic machine-readable core of a pentest report -- the
    part a signature attests to, independent of markdown prose/formatting.

    `"server"` is attached to each finding explicitly (Finding itself has no
    such field -- origin is normally implicit via dict nesting) so that
    scope-tampering -- re-attributing a finding to hide it was in-scope --
    is caught by the signature too, not just finding-content tampering.
    """
    findings = [
        _finding_payload(server_name, f)
        for server_name, result in results.items()
        for f in result.findings
    ]
    findings.sort(key=_sort_key)

    targets = sorted(name for name in results if name != CROSS_SERVER_KEY)

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "tool_version": tool_version,
        "engagement": _engagement_payload(engagement),
        "targets": targets,
        "findings": findings,
        "is_retest": fixed is not None,
    }
    if fixed is not None:
        fixed_payload = [_finding_payload(server_name, f) for server_name, f in fixed]
        fixed_payload.sort(key=_sort_key)
        payload["fixed_findings"] = fixed_payload
    return payload


def sign_report(
    results: dict[str, ScanResult],
    tool_version: str,
    engagement: Any = None,
    fixed: list[tuple[str, Finding]] | None = None,
    key_dir: str | None = None,
) -> dict[str, Any]:
    """Build the canonical payload and sign it. Returns the full sidecar
    document -- payload included (not just its hash), so a verifier can see
    exactly what was attested, plus payload_sha256 as a cheap fixed-length
    pointer for external tooling that just wants a fingerprint.
    """
    payload = build_canonical_payload(results, tool_version, engagement=engagement, fixed=fixed)
    key = signing.load_or_create_key(key_dir or _KEY_DIR, _KEY_FILENAME, _KEY_ENV_VAR)
    return {
        "schema": SCHEMA,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": tool_version,
        "key_id": signing.key_id(key),
        "payload_sha256": hashlib.sha256(signing.canonical_bytes(payload)).hexdigest(),
        "signature": signing.sign(key, payload),
        "payload": payload,
    }


def verify_report(sidecar: dict[str, Any], key_dir: str | None = None) -> dict[str, Any]:
    """Verify a sidecar document. Returns a result dict with a "status" of
    VALID, TAMPERED, or INVALID, plus context for a human/CI to act on.

    key_id is the discriminator between TAMPERED and INVALID -- both look
    identical at the HMAC layer (a bad signature is a bad signature,
    whether from a different key or an altered payload), but key_id lets
    the verifier tell them apart without needing to guess: if the key
    loaded for verification doesn't match the key_id recorded at signing
    time, that's the wrong key (INVALID), not evidence of tampering. If the
    key_id matches but the HMAC still doesn't check out, the payload itself
    was altered after signing (TAMPERED).
    """
    key = signing.load_or_create_key(key_dir or _KEY_DIR, _KEY_FILENAME, _KEY_ENV_VAR)
    local_key_id = signing.key_id(key)
    sidecar_key_id = sidecar.get("key_id")

    result: dict[str, Any] = {
        "tool_version": sidecar.get("tool_version"),
        "signed_at": sidecar.get("signed_at"),
        "key_id": sidecar_key_id,
        "verifying_key_id": local_key_id,
    }

    payload = sidecar.get("payload")
    if not isinstance(payload, dict) or not sidecar.get("signature"):
        result["status"] = "INVALID"
        result["reason"] = "sidecar is missing its payload or signature"
        return result

    if sidecar_key_id != local_key_id:
        result["status"] = "INVALID"
        result["reason"] = (
            "the key used to verify does not match the key_id recorded at signing "
            "time -- wrong key, not necessarily a tampered report"
        )
        return result

    if not signing.verify(key, payload, sidecar["signature"]):
        result["status"] = "TAMPERED"
        result["reason"] = (
            "payload does not match the recorded signature -- findings, scope, or "
            "version may have been altered after signing"
        )
        return result

    result["status"] = "VALID"
    return result
