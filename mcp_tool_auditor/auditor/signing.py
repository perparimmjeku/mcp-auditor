"""Shared HMAC-SHA256 signing primitive.

Extracted from RugPullDetector's baseline signing (analyzers/rugpull.py),
which was the first thing in this codebase that needed tamper-evidence.
Report signing (report_signing.py) reuses this exact primitive rather than
inventing a second crypto scheme -- one HMAC implementation, one key-loading
implementation, used by both features with DIFFERENT keys (see
report_signing.py's module docstring for why the keys are deliberately not
shared).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from typing import Any


def load_or_create_key(key_dir: str, key_filename: str, env_var: str) -> bytes:
    """Return a signing key: env var override, else a local key file.

    Auto-generates and persists a new key on first use if neither exists.
    `os.O_CREAT | os.O_EXCL` avoids a TOCTOU race if two processes both hit
    "no key file yet" concurrently -- whichever loses the race reads back
    the winner's key instead of silently using its own.
    """
    env_key = os.environ.get(env_var)
    if env_key:
        return env_key.encode("utf-8")

    os.makedirs(key_dir, exist_ok=True)
    key_path = os.path.join(key_dir, key_filename)
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()

    key = secrets.token_bytes(32)
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    except FileExistsError:
        with open(key_path, "rb") as f:
            key = f.read()
    return key


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic serialization of a payload dict: sorted keys, no
    incidental whitespace -- the same payload always serializes identically,
    which is required for a signature over it to be reproducible."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(key: bytes, payload: dict[str, Any]) -> str:
    return hmac.new(key, canonical_bytes(payload), hashlib.sha256).hexdigest()


def verify(key: bytes, payload: dict[str, Any], signature: str) -> bool:
    if not signature:
        return False
    return hmac.compare_digest(sign(key, payload), signature)


def key_id(key: bytes) -> str:
    """Short fingerprint of a key -- safe to disclose (SHA256 is one-way,
    can't be reversed to recover the key) so a verifier/signature block can
    say WHICH key was used without exposing key material. 16 hex chars,
    matching common short-fingerprint conventions (e.g. GPG short key ids)."""
    return hashlib.sha256(key).hexdigest()[:16]
