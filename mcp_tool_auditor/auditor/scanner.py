import json
import selectors
import subprocess
from typing import Dict, Any, List, Optional
from .models import Finding, Severity, ScanResult
from .analyzers.static import StaticAnalyzer
from .analyzers.heuristic import HeuristicAnalyzer
from .analyzers.schema import SchemaAnalyzer
from .analyzers.rugpull import RugPullDetector


class MCPScanner:
    """Orchestrates all scanning modes against MCP servers."""

    def __init__(
        self,
        custom_signatures: Optional[List[Dict[str, Any]]] = None,
    ):
        self.static = StaticAnalyzer(custom_signatures=custom_signatures)
        self.heuristic = HeuristicAnalyzer()
        self.schema = SchemaAnalyzer()
        self.rugpull = RugPullDetector()

    def scan_tool_list(
        self,
        tools: List[Dict[str, Any]],
        server_url: Optional[str] = None,
        check_rugpull: bool = False,
    ) -> ScanResult:
        """Scan a list of MCP tool definitions."""
        all_findings: List[Finding] = []

        for tool in tools:
            all_findings.extend(self.static.analyze(tool))
            all_findings.extend(self.heuristic.score_tool(tool))
            all_findings.extend(self.schema.analyze(tool))

        if server_url and check_rugpull:
            all_findings.extend(self.rugpull.check(server_url, tools))

        return ScanResult(
            tools_scanned=len(tools),
            findings=all_findings,
            server_url=server_url,
            tools=tools,
        )

    def scan_server_stdio(
        self, command: str, args: List[str], timeout: int = 10
    ) -> ScanResult:
        """Connect to a stdio-based MCP server and retrieve tool definitions."""
        try:
            proc = subprocess.Popen(
                [command] + args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Initialize
            self._send_jsonrpc(proc, {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-tool-auditor", "version": "1.0.0"},
                },
            })
            self._recv_jsonrpc(proc, timeout=timeout)

            # Notify initialized
            self._send_jsonrpc(proc, {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            })

            # Request tool list
            self._send_jsonrpc(proc, {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
            })
            response = self._recv_jsonrpc(proc, timeout=timeout)

            tools = response.get("result", {}).get("tools", [])
        except Exception as e:
            raise RuntimeError(f"Failed to scan stdio server '{command}': {e}")
        finally:
            if "proc" in locals() and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        return self.scan_tool_list(tools)

    def scan_server_url(
        self,
        url: str,
        timeout: int = 15,
        check_rugpull: bool = False,
    ) -> ScanResult:
        """Connect to a URL-based (HTTP/SSE) MCP server."""
        import requests

        try:
            # Initialize
            resp = requests.post(
                url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-tool-auditor", "version": "1.0.0"},
                    },
                },
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            resp.raise_for_status()

            resp = requests.post(
                url,
                json={
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                },
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            resp.raise_for_status()

            # Request tool list
            resp = requests.post(
                url,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            resp.raise_for_status()
            result = resp.json()
            if "error" in result:
                raise RuntimeError(result["error"])
            tools = result.get("result", {}).get("tools", [])
        except Exception as e:
            raise RuntimeError(f"Failed to scan URL server '{url}': {e}")

        return self.scan_tool_list(
            tools,
            server_url=url,
            check_rugpull=check_rugpull,
        )

    def scan_config_file(self, config_path: str) -> Dict[str, ScanResult]:
        """Scan all MCP servers defined in a configuration file."""
        with open(config_path) as f:
            config = json.load(f)

        results: Dict[str, ScanResult] = {}
        servers = config.get("mcpServers", {})

        if not servers:
            # Try alternate formats
            if isinstance(config, list):
                for i, entry in enumerate(config):
                    server_name = entry.get("name", f"server_{i}")
                    command = entry.get("command", "")
                    args = entry.get("args", [])
                    self._scan_stdio_safe(results, server_name, command, args)
                return results

        for server_name, server_config in servers.items():
            command = server_config.get("command", "")
            args = server_config.get("args", [])
            self._scan_stdio_safe(results, server_name, command, args)

        return results

    def _scan_stdio_safe(
        self,
        results: Dict[str, ScanResult],
        name: str,
        command: str,
        args: List[str],
    ):
        try:
            if not command:
                raise RuntimeError("Missing server command")
            result = self.scan_server_stdio(command, args)
            results[name] = result
        except Exception as e:
            results[name] = ScanResult(
                tools_scanned=0,
                findings=[
                    Finding(
                        severity=Severity.ERROR,
                        rule="SCAN_FAILED",
                        message=f"Failed to scan server '{name}': {e}",
                        owasp_id="N/A",
                    )
                ],
            )

    @staticmethod
    def _send_jsonrpc(proc, msg: Dict[str, Any]):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

    @staticmethod
    def _recv_jsonrpc(proc, timeout: int = 10):
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        events = selector.select(timeout=timeout)
        selector.close()
        if not events:
            raise TimeoutError("Timed out waiting for MCP server response")
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("MCP server closed connection prematurely")
        return json.loads(line)
