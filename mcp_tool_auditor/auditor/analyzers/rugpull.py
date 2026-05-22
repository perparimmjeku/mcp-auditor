import hashlib
import json
import os
from typing import Dict, Any, List, Optional
from ..models import Finding, Severity


class RugPullDetector:
    """Detects MCP rug-pull attacks by comparing tool schema fingerprints."""

    FINGERPRINT_DIR = os.path.expanduser("~/.mcp-tool-auditor/fingerprints/")

    def __init__(self, fingerprint_dir: Optional[str] = None):
        self._fp_dir = fingerprint_dir or self.FINGERPRINT_DIR

    def _server_id(self, server_url: str) -> str:
        return hashlib.sha256(server_url.encode()).hexdigest()

    def _fingerprint_tool(self, tool: Dict[str, Any]) -> str:
        """Create a deterministic hash of a tool definition."""
        normalized = {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "title": tool.get("title", ""),
            "inputSchema": tool.get("inputSchema", {}),
            "outputSchema": tool.get("outputSchema", {}),
        }
        return hashlib.sha256(
            json.dumps(normalized, sort_keys=True).encode()
        ).hexdigest()

    def register(
        self, server_url: str, tools: List[Dict[str, Any]]
    ) -> str:
        """Register current tool fingerprints as the approved baseline."""
        registry: Dict[str, str] = {}
        for tool in tools:
            registry[tool.get("name", "unknown")] = self._fingerprint_tool(tool)

        os.makedirs(self._fp_dir, exist_ok=True)
        fp_path = os.path.join(self._fp_dir, f"{self._server_id(server_url)}.json")
        with open(fp_path, "w") as f:
            json.dump(registry, f, indent=2, sort_keys=True)
        return fp_path

    def check(
        self, server_url: str, tools: List[Dict[str, Any]]
    ) -> List[Finding]:
        """Compare current tool fingerprints against registered baseline."""
        findings: List[Finding] = []
        fp_path = os.path.join(self._fp_dir, f"{self._server_id(server_url)}.json")

        if not os.path.exists(fp_path):
            findings.append(Finding(
                severity=Severity.INFO,
                rule="RUGPULL_NO_BASELINE",
                message=f"Server '{server_url}': No baseline registered — run register() first.",
                owasp_id="MCP03",
                attack_type="rug_pull",
            ))
            return findings

        with open(fp_path) as f:
            baseline: Dict[str, str] = json.load(f)

        current_fps = {
            t.get("name", "unknown"): self._fingerprint_tool(t) for t in tools
        }

        # New tools (potential shadowing)
        new_tools = set(current_fps.keys()) - set(baseline.keys())
        for name in sorted(new_tools):
            findings.append(Finding(
                severity=Severity.HIGH,
                rule="RUGPULL_NEW_TOOL",
                message=f"Server '{server_url}': New tool '{name}' appeared that was not in the registered baseline — possible tool shadowing.",
                owasp_id="MCP03",
                attack_type="tool_shadowing",
            ))

        # Removed tools
        removed_tools = set(baseline.keys()) - set(current_fps.keys())
        for name in sorted(removed_tools):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                rule="RUGPULL_REMOVED_TOOL",
                message=f"Server '{server_url}': Tool '{name}' has been removed since baseline registration.",
                owasp_id="MCP03",
                attack_type="rug_pull",
            ))

        # Changed fingerprints (rug pull!)
        for name, current_fp in current_fps.items():
            if name in baseline:
                if current_fp != baseline[name]:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        rule="RUGPULL_FINGERPRINT_MISMATCH",
                        message=f"Server '{server_url}': Tool '{name}' schema has CHANGED since baseline — POSSIBLE RUG PULL ATTACK.",
                        owasp_id="MCP03",
                        attack_type="rug_pull",
                    ))

        return findings

    def list_registrations(self) -> Dict[str, str]:
        """List all registered server baselines."""
        registrations = {}
        if not os.path.isdir(self._fp_dir):
            return registrations
        for fname in os.listdir(self._fp_dir):
            if fname.endswith(".json"):
                fpath = os.path.join(self._fp_dir, fname)
                with open(fpath) as f:
                    data = json.load(f)
                registrations[fname.replace(".json", "")] = (
                    f"{len(data)} tools | {fpath}"
                )
        return registrations
