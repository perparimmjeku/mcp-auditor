import hashlib
import hmac
import json
import logging
import os
from typing import Any

from .. import signing
from ..models import Finding, Severity

logger = logging.getLogger(__name__)


class RugPullDetector:
    """Detects MCP rug-pull attacks by comparing tool schema fingerprints.

    Baselines are HMAC-SHA256 signed so `check()` can tell a legitimate
    change from a tampered/forged baseline file — plain JSON on disk is
    only as trustworthy as whoever can write to the fingerprint directory.
    The signing key is auto-generated locally by default (protects against
    accidental corruption and less-privileged tampering), or can be supplied
    out-of-band via MCP_TOOL_AUDITOR_BASELINE_KEY (e.g. a CI secret) so the
    baseline file and the key don't have to share a trust boundary.
    """

    FINGERPRINT_DIR = os.path.expanduser("~/.mcp-tool-auditor/fingerprints/")
    KEY_FILENAME = ".hmac_key"
    KEY_ENV_VAR = "MCP_TOOL_AUDITOR_BASELINE_KEY"

    def __init__(self, fingerprint_dir: str | None = None):
        self._fp_dir = fingerprint_dir or self.FINGERPRINT_DIR

    def _server_id(self, server_url: str) -> str:
        return hashlib.sha256(server_url.encode()).hexdigest()

    def _fingerprint_tool(self, tool: dict[str, Any]) -> str:
        """Create a deterministic hash of a tool definition."""

        def deep_sort(obj):
            if isinstance(obj, dict):
                return {k: deep_sort(v) for k, v in sorted(obj.items())}
            if isinstance(obj, list):
                return [deep_sort(item) for item in obj]
            return obj

        normalized = {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "title": tool.get("title", ""),
            "inputSchema": tool.get("inputSchema", {}),
            "outputSchema": tool.get("outputSchema", {}),
        }
        normalized = deep_sort(normalized)
        return hashlib.sha256(json.dumps(normalized, separators=(",", ":")).encode()).hexdigest()

    def _load_or_create_key(self) -> bytes:
        """Return the HMAC signing key: env override, else a local key file."""
        return signing.load_or_create_key(self._fp_dir, self.KEY_FILENAME, self.KEY_ENV_VAR)

    def _sign(self, registry: dict[str, str]) -> str:
        return signing.sign(self._load_or_create_key(), registry)

    def register(self, server_url: str, tools: list[dict[str, Any]]) -> str:
        """Register current tool fingerprints as the approved, signed baseline."""
        registry: dict[str, str] = {}
        for tool in tools:
            registry[tool.get("name", "unknown")] = self._fingerprint_tool(tool)

        os.makedirs(self._fp_dir, exist_ok=True)
        fp_path = os.path.join(self._fp_dir, f"{self._server_id(server_url)}.json")
        document = {"tools": registry, "hmac": self._sign(registry)}

        temp_path = f"{fp_path}.tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(document, f, indent=2, sort_keys=True)
            os.replace(temp_path, fp_path)
        except OSError:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise

        logger.info("Registered %d tool fingerprints for %s", len(registry), server_url)
        return fp_path

    def check(self, server_url: str, tools: list[dict[str, Any]]) -> list[Finding]:
        """Compare current tool fingerprints against registered baseline."""
        findings: list[Finding] = []
        fp_path = os.path.join(self._fp_dir, f"{self._server_id(server_url)}.json")

        if not os.path.exists(fp_path):
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    rule="RUGPULL_NO_BASELINE",
                    message=f"Server '{server_url}': No baseline registered — run register() first.",
                    owasp_id="MCP03",
                    attack_type="rug_pull",
                )
            )
            return findings

        try:
            with open(fp_path, encoding="utf-8") as f:
                document = json.load(f)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Corrupted baseline fingerprint at {fp_path}: {e}. "
                "Run 'mcp-tool-auditor register' to reset it."
            ) from e
        except OSError as e:
            raise RuntimeError(f"Cannot read baseline fingerprint at {fp_path}: {e}") from e

        baseline, verify_findings = self._verify_and_unwrap(document, server_url)
        findings.extend(verify_findings)
        if baseline is None:
            # Signature didn't verify — the file isn't trustworthy as a
            # comparison point, so don't reason about what "changed".
            return findings

        current_fps = {t.get("name", "unknown"): self._fingerprint_tool(t) for t in tools}

        # New tools (potential shadowing)
        new_tools = set(current_fps.keys()) - set(baseline.keys())
        for name in sorted(new_tools):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    rule="RUGPULL_NEW_TOOL",
                    message=f"Server '{server_url}': New tool '{name}' appeared — possible tool shadowing.",
                    owasp_id="MCP03",
                    attack_type="tool_shadowing",
                )
            )

        # Removed tools
        removed_tools = set(baseline.keys()) - set(current_fps.keys())
        for name in sorted(removed_tools):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    rule="RUGPULL_REMOVED_TOOL",
                    message=f"Server '{server_url}': Tool '{name}' has been removed since baseline registration.",
                    owasp_id="MCP03",
                    attack_type="rug_pull",
                )
            )

        # Changed fingerprints (rug pull!)
        for name, current_fp in current_fps.items():
            if name in baseline:
                if current_fp != baseline[name]:
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            rule="RUGPULL_FINGERPRINT_MISMATCH",
                            message=f"Server '{server_url}': Tool '{name}' schema has CHANGED since baseline — POSSIBLE RUG PULL ATTACK.",
                            owasp_id="MCP03",
                            attack_type="rug_pull",
                        )
                    )

        return findings

    def _verify_and_unwrap(
        self, document: Any, server_url: str
    ) -> tuple[dict[str, str] | None, list[Finding]]:
        """Validate a loaded baseline's HMAC signature and return its tool map.

        Returns (None, [CRITICAL finding]) if a signed baseline's signature
        doesn't verify — the caller must not use it as a comparison point.
        Baselines from before signing was added (a flat {name: fingerprint}
        dict, no "tools"/"hmac" wrapper) are accepted with a lower-severity
        nudge to re-register, so upgrading doesn't break existing baselines.
        """
        if not isinstance(document, dict):
            return None, [
                Finding(
                    severity=Severity.CRITICAL,
                    rule="RUGPULL_BASELINE_TAMPERED",
                    message=f"Server '{server_url}': Baseline file is not a valid document — "
                    "refusing to trust it. Re-register after confirming current tools are legitimate.",
                    owasp_id="MCP03",
                    attack_type="rug_pull",
                )
            ]

        if "tools" not in document and "hmac" not in document:
            return document, [
                Finding(
                    severity=Severity.MEDIUM,
                    rule="RUGPULL_BASELINE_UNSIGNED",
                    message=f"Server '{server_url}': Baseline predates integrity signing — "
                    "run 'mcp-tool-auditor register' to protect it against tampering.",
                    owasp_id="MCP03",
                    attack_type="rug_pull",
                )
            ]

        baseline = document.get("tools", {})
        signature = document.get("hmac", "")
        expected = self._sign(baseline)
        if not signature or not hmac.compare_digest(signature, expected):
            return None, [
                Finding(
                    severity=Severity.CRITICAL,
                    rule="RUGPULL_BASELINE_TAMPERED",
                    message=f"Server '{server_url}': Baseline signature does not verify — the "
                    "file may have been edited or replaced outside mcp-tool-auditor. Refusing to "
                    "trust it; re-register after confirming current tools are legitimate.",
                    owasp_id="MCP03",
                    attack_type="rug_pull",
                )
            ]
        return baseline, []

    def list_registrations(self) -> dict[str, str]:
        """List all registered server baselines."""
        registrations: dict[str, str] = {}
        if not os.path.isdir(self._fp_dir):
            return registrations
        for fname in os.listdir(self._fp_dir):
            if fname == self.KEY_FILENAME or not fname.endswith(".json"):
                continue
            fpath = os.path.join(self._fp_dir, fname)
            with open(fpath) as f:
                data = json.load(f)
            tool_map = data.get("tools", data) if isinstance(data, dict) else {}
            registrations[fname.replace(".json", "")] = f"{len(tool_map)} tools | {fpath}"
        return registrations
