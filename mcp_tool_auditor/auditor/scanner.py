import json
import logging
import selectors
import subprocess
from typing import Any

from ..config import get_config
from ..validation import ValidationError, validate_file_exists, validate_json_file, validate_url
from .analyzers.behavioral import CallResult, synthesize_arguments
from .analyzers.heuristic import HeuristicAnalyzer
from .analyzers.rugpull import RugPullDetector
from .analyzers.schema import SchemaAnalyzer
from .analyzers.static import StaticAnalyzer
from .models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


class MCPScanner:
    """Orchestrates all scanning modes against MCP servers."""

    def __init__(
        self,
        custom_signatures: list[dict[str, Any]] | None = None,
        config=None,
    ):
        self.config = config or get_config()
        self.static = StaticAnalyzer(custom_signatures=custom_signatures)
        self.heuristic = HeuristicAnalyzer(config=self.config)
        self.schema = SchemaAnalyzer(config=self.config)
        self.rugpull = RugPullDetector(fingerprint_dir=self.config.fingerprint_dir)

    def scan_tool_list(
        self,
        tools: list[dict[str, Any]],
        server_url: str | None = None,
        check_rugpull: bool = False,
    ) -> ScanResult:
        """Scan a list of MCP tool definitions."""
        all_findings: list[Finding] = []

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
        self, command: str, args: list[str], timeout: int | None = None
    ) -> ScanResult:
        """Connect to a stdio-based MCP server and retrieve tool definitions."""
        timeout = timeout or self.config.timeout_stdio
        args = args or []
        logger.info("Scanning stdio server: %s %s", command, " ".join(args))

        proc = None
        try:
            proc = subprocess.Popen(
                [command] + args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            logger.debug("Started process %s", proc.pid)

            # Initialize
            self._send_jsonrpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-tool-auditor", "version": "1.0.0"},
                    },
                },
            )
            self._recv_jsonrpc(proc, timeout=timeout)

            # Notify initialized
            self._send_jsonrpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                },
            )

            # Request tool list
            self._send_jsonrpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                },
            )
            response = self._recv_jsonrpc(proc, timeout=timeout)
            if "error" in response:
                raise RuntimeError(
                    f"Server returned tools/list error: {self._format_jsonrpc_error(response['error'])}"
                )

            tools = response.get("result", {}).get("tools", [])
            if not isinstance(tools, list):
                raise RuntimeError("Server tools/list response did not contain a tools array")
            logger.info("Retrieved %d tools from %s", len(tools), command)
        except TimeoutError as e:
            raise RuntimeError(
                f"Failed to scan stdio server '{command}': timeout after {timeout}s"
            ) from e
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Failed to scan stdio server '{command}': invalid JSON response: {e}"
            ) from e
        except Exception as e:
            raise RuntimeError(f"Failed to scan stdio server '{command}': {e}") from e
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

        return self.scan_tool_list(tools)

    def scan_server_url(
        self,
        url: str,
        timeout: int | None = None,
        check_rugpull: bool = False,
    ) -> ScanResult:
        """Connect to a URL-based (HTTP/SSE) MCP server."""
        import requests

        timeout = timeout or self.config.timeout_url
        try:
            validate_url(url)
        except ValidationError as e:
            raise RuntimeError(f"Invalid URL: {e}") from e

        logger.info("Scanning URL server: %s", url)
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
                raise RuntimeError(self._format_jsonrpc_error(result["error"]))
            tools = result.get("result", {}).get("tools", [])
            if not isinstance(tools, list):
                raise RuntimeError("Server tools/list response did not contain a tools array")
            logger.info("Retrieved %d tools from %s", len(tools), url)
        except requests.exceptions.Timeout as e:
            raise RuntimeError(f"Server did not respond (timeout: {timeout}s)") from e
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(f"Cannot connect to '{url}': {e}") from e
        except requests.exceptions.HTTPError as e:
            response = getattr(e, "response", None)
            status_code = response.status_code if response is not None else "unknown"
            raise RuntimeError(f"Server returned HTTP {status_code}") from e
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Request failed: {e}") from e
        except ValueError as e:
            raise RuntimeError(f"Server returned invalid JSON: {e}") from e
        except Exception as e:
            raise RuntimeError(f"Failed to scan URL server '{url}': {e}") from e

        return self.scan_tool_list(
            tools,
            server_url=url,
            check_rugpull=check_rugpull,
        )

    @staticmethod
    def _extract_response_text(result: Any) -> str:
        """Extract human-readable text from an MCP tools/call result."""
        if isinstance(result, dict):
            content = result.get("content", [])
            if isinstance(content, list):
                parts = [
                    str(block.get("text", ""))
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "text"
                ]
                if parts:
                    return "\n".join(parts)
        return json.dumps(result, sort_keys=True)

    def probe_url(
        self, url: str, calls: int = 6, timeout: int | None = None
    ) -> tuple[list[dict[str, Any]], dict[str, list[CallResult]]]:
        """Call each tool on a URL server `calls` times and collect responses."""
        import requests

        timeout = timeout or self.config.timeout_url
        validate_url(url)
        headers = {"Content-Type": "application/json"}

        def _post(payload: dict[str, Any]) -> dict[str, Any]:
            resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp.json()

        _post(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-tool-auditor", "version": "1.0.0"},
                },
            }
        )
        _post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        listed = _post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = listed.get("result", {}).get("tools", [])

        transcripts: dict[str, list[CallResult]] = {}
        for tool in tools:
            name = tool.get("name", "unknown")
            arguments = synthesize_arguments(tool.get("inputSchema", {}))
            results: list[CallResult] = []
            for i in range(calls):
                try:
                    body = _post(
                        {
                            "jsonrpc": "2.0",
                            "id": 100 + i,
                            "method": "tools/call",
                            "params": {"name": name, "arguments": arguments},
                        }
                    )
                    if "error" in body:
                        results.append(
                            CallResult(i, "", error=self._format_jsonrpc_error(body["error"]))
                        )
                    else:
                        results.append(
                            CallResult(i, self._extract_response_text(body.get("result", {})))
                        )
                except Exception as exc:  # noqa: BLE001 - isolate per-call failures
                    results.append(CallResult(i, "", error=str(exc)))
            transcripts[name] = results
        return tools, transcripts

    def probe_stdio(
        self, command: str, args: list[str], calls: int = 6, timeout: int | None = None
    ) -> tuple[list[dict[str, Any]], dict[str, list[CallResult]]]:
        """Call each tool on a stdio server `calls` times over one session."""
        timeout = timeout or self.config.timeout_stdio
        args = args or []
        proc = None
        try:
            proc = subprocess.Popen(
                [command] + args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._send_jsonrpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-tool-auditor", "version": "1.0.0"},
                    },
                },
            )
            self._recv_jsonrpc(proc, timeout=timeout)
            self._send_jsonrpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
            self._send_jsonrpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            listed = self._recv_jsonrpc(proc, timeout=timeout)
            tools = listed.get("result", {}).get("tools", [])

            transcripts: dict[str, list[CallResult]] = {}
            for tool in tools:
                name = tool.get("name", "unknown")
                arguments = synthesize_arguments(tool.get("inputSchema", {}))
                results: list[CallResult] = []
                for i in range(calls):
                    try:
                        self._send_jsonrpc(
                            proc,
                            {
                                "jsonrpc": "2.0",
                                "id": 100 + i,
                                "method": "tools/call",
                                "params": {"name": name, "arguments": arguments},
                            },
                        )
                        body = self._recv_jsonrpc(proc, timeout=timeout)
                        if "error" in body:
                            results.append(
                                CallResult(i, "", error=self._format_jsonrpc_error(body["error"]))
                            )
                        else:
                            results.append(
                                CallResult(i, self._extract_response_text(body.get("result", {})))
                            )
                    except Exception as exc:  # noqa: BLE001 - isolate per-call failures
                        results.append(CallResult(i, "", error=str(exc)))
                transcripts[name] = results
            return tools, transcripts
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

    def scan_config_file(self, config_path: str) -> dict[str, ScanResult]:
        """Scan all MCP servers defined in a configuration file."""
        try:
            validate_file_exists(config_path)
            config = validate_json_file(config_path)
        except ValidationError as e:
            raise RuntimeError(f"Failed to parse config: {e}") from e

        if not isinstance(config, (dict, list)):
            raise RuntimeError("Config must be a JSON object or array")

        results: dict[str, ScanResult] = {}
        servers = config.get("mcpServers", {}) if isinstance(config, dict) else {}

        if not servers:
            # Try alternate formats
            if isinstance(config, list):
                for i, entry in enumerate(config):
                    if not isinstance(entry, dict):
                        results[f"server_{i}"] = ScanResult(
                            tools_scanned=0,
                            findings=[
                                Finding(
                                    severity=Severity.ERROR,
                                    rule="SCAN_FAILED",
                                    message=f"Failed to scan server 'server_{i}': config entry is not an object",
                                    owasp_id="N/A",
                                )
                            ],
                        )
                        continue
                    server_name = entry.get("name", f"server_{i}")
                    command = entry.get("command", "")
                    args = entry.get("args", [])
                    self._scan_stdio_safe(results, server_name, command, args)
                return results

        for server_name, server_config in servers.items():
            if not isinstance(server_config, dict):
                results[server_name] = ScanResult(
                    tools_scanned=0,
                    findings=[
                        Finding(
                            severity=Severity.ERROR,
                            rule="SCAN_FAILED",
                            message=f"Failed to scan server '{server_name}': config entry is not an object",
                            owasp_id="N/A",
                        )
                    ],
                )
                continue
            command = server_config.get("command", "")
            args = server_config.get("args", [])
            self._scan_stdio_safe(results, server_name, command, args)

        return results

    def _scan_stdio_safe(
        self,
        results: dict[str, ScanResult],
        name: str,
        command: str,
        args: list[str],
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
    def _send_jsonrpc(proc, msg: dict[str, Any]):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

    @staticmethod
    def _recv_jsonrpc(proc, timeout: int = 10):
        selector = selectors.DefaultSelector()
        try:
            selector.register(proc.stdout, selectors.EVENT_READ)
            events = selector.select(timeout=timeout)
        finally:
            selector.close()
        if not events:
            raise TimeoutError("Timed out waiting for MCP server response")
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("MCP server closed connection prematurely")
        return json.loads(line)

    @staticmethod
    def _format_jsonrpc_error(error: Any) -> str:
        if isinstance(error, dict):
            return error.get("message", str(error))
        return str(error)
