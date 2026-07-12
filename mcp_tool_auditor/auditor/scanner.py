import json
import logging
import selectors
import subprocess
from typing import Any
from urllib.parse import urlparse

from .. import __version__
from ..config import get_config
from ..validation import ValidationError, validate_file_exists, validate_json_file, validate_url
from .analyzers.behavioral import CallResult, synthesize_arguments
from .analyzers.composition import CompositionAnalyzer
from .analyzers.heuristic import HeuristicAnalyzer
from .analyzers.rugpull import RugPullDetector
from .analyzers.schema import SchemaAnalyzer
from .analyzers.static import StaticAnalyzer
from .analyzers.sti import STIAnalyzer
from .models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

_PROTOCOL_VERSION = "2025-06-18"


class MCPScanner:
    """Orchestrates all scanning modes against MCP servers."""

    def __init__(
        self,
        custom_signatures: list[dict[str, Any]] | None = None,
        config=None,
        sti_decode: bool = False,
        sti_tokenizer_names: list[str] | None = None,
    ):
        self.config = config or get_config()
        self.static = StaticAnalyzer(custom_signatures=custom_signatures)
        self.heuristic = HeuristicAnalyzer(config=self.config)
        self.schema = SchemaAnalyzer(config=self.config)
        self.rugpull = RugPullDetector(fingerprint_dir=self.config.fingerprint_dir)
        self.composition = CompositionAnalyzer()
        self.sti = STIAnalyzer(decode_encoded=sti_decode, tokenizer_names=sti_tokenizer_names)

    def scan_tool_list(
        self,
        tools: list[dict[str, Any]],
        resources: list[dict[str, Any]] | None = None,
        prompts: list[dict[str, Any]] | None = None,
        instructions: str | None = None,
        server_url: str | None = None,
        check_rugpull: bool = False,
    ) -> ScanResult:
        """Scan MCP tool/resource/prompt definitions and server instructions.

        Only `tools` drives `tools_scanned` (kept for backward compatibility);
        resources/prompts/instructions are optional MCP surfaces that are just
        as capable of carrying poisoned text as tool descriptions are.
        """
        resources = resources or []
        prompts = prompts or []
        all_findings: list[Finding] = []

        for tool in tools:
            all_findings.extend(self.static.analyze(tool))
            all_findings.extend(self.heuristic.score_tool(tool))
            all_findings.extend(self.schema.analyze(tool))
            all_findings.extend(self.sti.analyze(tool))

        for resource in resources:
            all_findings.extend(self.static.analyze(resource, kind="resource"))
            all_findings.extend(self.heuristic.score_tool(resource, kind="resource"))
            all_findings.extend(self.sti.analyze(resource, kind="resource"))

        for prompt in prompts:
            all_findings.extend(self.static.analyze(prompt, kind="prompt"))
            all_findings.extend(self.heuristic.score_tool(prompt, kind="prompt"))
            all_findings.extend(self.schema.analyze_prompt_arguments(prompt))
            all_findings.extend(self.sti.analyze(prompt, kind="prompt"))

        if instructions:
            instructions_doc = {"name": "server_instructions", "description": instructions}
            all_findings.extend(self.static.analyze(instructions_doc, kind="instructions"))
            all_findings.extend(self.heuristic.score_tool(instructions_doc, kind="instructions"))
            all_findings.extend(self.sti.analyze(instructions_doc, kind="instructions"))

        all_findings.extend(self.composition.analyze(tools))

        if server_url and check_rugpull:
            all_findings.extend(self.rugpull.check(server_url, tools))

        return ScanResult(
            tools_scanned=len(tools),
            findings=all_findings,
            server_url=server_url,
            tools=tools,
            resources_scanned=len(resources),
            prompts_scanned=len(prompts),
            resources=resources,
            prompts=prompts,
            instructions=instructions,
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
                        "protocolVersion": _PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-tool-auditor", "version": __version__},
                    },
                },
            )
            init_response = self._recv_jsonrpc(proc, timeout=timeout)
            instructions = init_response.get("result", {}).get("instructions")

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

            resources = self._fetch_stdio_list(proc, "resources/list", "resources", timeout, 3)
            prompts = self._fetch_stdio_list(proc, "prompts/list", "prompts", timeout, 4)
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

        return self.scan_tool_list(
            tools, resources=resources, prompts=prompts, instructions=instructions
        )

    def _fetch_stdio_list(
        self, proc, method: str, result_key: str, timeout: int, request_id: int
    ) -> list[dict[str, Any]]:
        """Best-effort fetch of an optional MCP list endpoint (resources/prompts).

        Servers that don't implement the capability return a JSON-RPC "method
        not found" error, or nothing at all — either way that's an absent
        capability, not a scan failure.
        """
        try:
            self._send_jsonrpc(proc, {"jsonrpc": "2.0", "id": request_id, "method": method})
            response = self._recv_jsonrpc(proc, timeout=timeout)
        except Exception:
            logger.debug("No response for %s", method, exc_info=True)
            return []
        if "error" in response:
            return []
        items = response.get("result", {}).get(result_key, [])
        return items if isinstance(items, list) else []

    @staticmethod
    def _proxies(proxy: str | None) -> dict[str, str] | None:
        return {"http": proxy, "https": proxy} if proxy else None

    def _open_http_session(
        self,
        url: str,
        timeout: int,
        extra_headers: dict[str, str] | None,
        proxies: dict[str, str] | None,
    ) -> tuple[dict[str, str], str | None]:
        """Initialize an MCP HTTP session and return headers for follow-up requests.

        Handles auth/extra headers, captures the Mcp-Session-Id, and adds the
        MCP-Protocol-Version required on requests after initialize. Also
        returns the server's top-level `instructions` string, if any — it's
        as capable of carrying poisoned text as a tool description is.
        """
        import requests

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if extra_headers:
            headers.update(extra_headers)

        resp = requests.post(
            url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": _PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-tool-auditor", "version": __version__},
                },
            },
            headers=headers,
            timeout=timeout,
            proxies=proxies,
        )
        resp.raise_for_status()
        init_result = self._response_to_jsonrpc(resp)
        instructions = init_result.get("result", {}).get("instructions")

        post_headers = dict(headers)
        post_headers["MCP-Protocol-Version"] = _PROTOCOL_VERSION
        session_id = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
        if session_id:
            post_headers["Mcp-Session-Id"] = session_id

        resp = requests.post(
            url,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=post_headers,
            timeout=timeout,
            proxies=proxies,
        )
        resp.raise_for_status()
        return post_headers, instructions

    def _fetch_http_list(
        self,
        url: str,
        method: str,
        result_key: str,
        headers: dict[str, str],
        timeout: int,
        proxies: dict[str, str] | None,
        request_id: int,
    ) -> list[dict[str, Any]]:
        """Best-effort fetch of an optional MCP list endpoint (resources/prompts).

        Servers that don't implement the capability return a JSON-RPC "method
        not found" error, or an HTTP error — either way that's an absent
        capability, not a scan failure.
        """
        import requests

        try:
            resp = requests.post(
                url,
                json={"jsonrpc": "2.0", "id": request_id, "method": method},
                headers=headers,
                timeout=timeout,
                proxies=proxies,
            )
            resp.raise_for_status()
            result = self._response_to_jsonrpc(resp)
        except Exception:
            logger.debug("No response for %s", method, exc_info=True)
            return []
        if "error" in result:
            return []
        items = result.get("result", {}).get(result_key, [])
        return items if isinstance(items, list) else []

    @staticmethod
    def _looks_like_oauth(response: Any) -> bool:
        """A 401 signals OAuth 2.1 specifically when it carries WWW-Authenticate
        (RFC 6750 / RFC 9728), distinguishing it from a plain wrong-bearer-token
        401 that a simple auth server might return without that header.
        """
        return bool(
            response.headers.get("WWW-Authenticate") or response.headers.get("www-authenticate")
        )

    def _oauth_required_result(self, url: str, response: Any) -> ScanResult:
        """Build an informational result for a server that requires OAuth 2.1.

        MCP 2025-06-18 servers protect HTTP endpoints with OAuth 2.1; an
        unauthenticated request gets HTTP 401 with a WWW-Authenticate header.
        This tool doesn't perform an interactive login — it reports what it
        found so the operator can supply a bearer token via --header.
        """
        import requests

        www_auth = response.headers.get("WWW-Authenticate") or response.headers.get(
            "www-authenticate", ""
        )
        metadata_note = ""
        try:
            parsed = urlparse(url)
            prm_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-protected-resource"
            prm_resp = requests.get(prm_url, timeout=5)
            if prm_resp.ok:
                data = prm_resp.json()
                servers = data.get("authorization_servers") or data.get("authorization_server")
                if servers:
                    metadata_note = f" Authorization server(s): {servers}."
        except Exception:
            logger.debug("No OAuth protected-resource metadata at %s", url, exc_info=True)

        message = (
            f"Server '{url}' requires OAuth 2.1 authentication (HTTP 401)."
            + (f" WWW-Authenticate: {www_auth}." if www_auth else "")
            + metadata_note
            + " This scanner does not perform interactive OAuth login — complete the flow "
            "yourself and re-run with the resulting bearer token via --header "
            "'Authorization: Bearer <token>'."
        )
        finding = Finding(
            severity=Severity.INFO,
            rule="OAUTH_REQUIRED",
            message=message,
            owasp_id="MCP01",
            attack_type="auth_required",
        )
        return ScanResult(tools_scanned=0, findings=[finding], server_url=url, oauth_required=True)

    def scan_server_url(
        self,
        url: str,
        timeout: int | None = None,
        check_rugpull: bool = False,
        extra_headers: dict[str, str] | None = None,
        proxy: str | None = None,
    ) -> ScanResult:
        """Connect to a URL-based (Streamable HTTP / SSE) MCP server."""
        import requests

        timeout = timeout or self.config.timeout_url
        try:
            validate_url(url)
        except ValidationError as e:
            raise RuntimeError(f"Invalid URL: {e}") from e

        proxies = self._proxies(proxy)
        logger.info("Scanning URL server: %s", url)
        try:
            post_headers, instructions = self._open_http_session(
                url, timeout, extra_headers, proxies
            )
            resp = requests.post(
                url,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                headers=post_headers,
                timeout=timeout,
                proxies=proxies,
            )
            resp.raise_for_status()
            result = self._response_to_jsonrpc(resp)
            if "error" in result:
                raise RuntimeError(self._format_jsonrpc_error(result["error"]))
            tools = result.get("result", {}).get("tools", [])
            if not isinstance(tools, list):
                raise RuntimeError("Server tools/list response did not contain a tools array")
            logger.info("Retrieved %d tools from %s", len(tools), url)

            resources = self._fetch_http_list(
                url, "resources/list", "resources", post_headers, timeout, proxies, 3
            )
            prompts = self._fetch_http_list(
                url, "prompts/list", "prompts", post_headers, timeout, proxies, 4
            )
        except requests.exceptions.Timeout as e:
            raise RuntimeError(f"Server did not respond (timeout: {timeout}s)") from e
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(f"Cannot connect to '{url}': {e}") from e
        except requests.exceptions.HTTPError as e:
            response = getattr(e, "response", None)
            if (
                response is not None
                and response.status_code == 401
                and self._looks_like_oauth(response)
            ):
                return self._oauth_required_result(url, response)
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
            resources=resources,
            prompts=prompts,
            instructions=instructions,
            server_url=url,
            check_rugpull=check_rugpull,
        )

    @staticmethod
    def _parse_sse(body: str) -> dict[str, Any]:
        """Extract a JSON-RPC message from a Server-Sent Events response body."""
        last: dict[str, Any] = {}
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped.startswith("data:"):
                continue
            data = stripped[len("data:") :].strip()
            if not data or data == "[DONE]":
                continue
            try:
                obj = json.loads(data)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                last = obj
                if "result" in obj or "error" in obj:
                    return obj
        return last

    @staticmethod
    def _response_to_jsonrpc(resp: Any) -> dict[str, Any]:
        """Decode a requests response as JSON or SSE depending on Content-Type."""
        headers = getattr(resp, "headers", {}) or {}
        ctype = headers.get("Content-Type", "") or headers.get("content-type", "")
        if "text/event-stream" in ctype.lower():
            return MCPScanner._parse_sse(resp.text)
        return resp.json()

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
        self,
        url: str,
        calls: int = 6,
        timeout: int | None = None,
        extra_headers: dict[str, str] | None = None,
        proxy: str | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, list[CallResult]]]:
        """Call each tool on a URL server `calls` times and collect responses."""
        import requests

        timeout = timeout or self.config.timeout_url
        validate_url(url)
        proxies = self._proxies(proxy)
        headers, _instructions = self._open_http_session(url, timeout, extra_headers, proxies)

        def _post(payload: dict[str, Any]) -> dict[str, Any]:
            resp = requests.post(
                url, json=payload, headers=headers, timeout=timeout, proxies=proxies
            )
            resp.raise_for_status()
            return self._response_to_jsonrpc(resp)

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
                        "protocolVersion": _PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-tool-auditor", "version": __version__},
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
