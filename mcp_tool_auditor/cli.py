#!/usr/bin/env python3
"""
mcp-tool-auditor — MCP Tool Poisoning Scanner
OWASP MCP Top 10 Compliant | Defensive + Offensive tooling
"""

import argparse
import json
import sys
import os

from .auditor.scanner import MCPScanner
from .auditor.models import Severity
from .auditor.analyzers.rugpull import RugPullDetector
from .auditor.reporters.json_reporter import JSONReporter
from .auditor.reporters.markdown_reporter import MarkdownReporter
from .offensive.poisoner import PoisonedServerGenerator


def _get_tools_from_result(result):
    """Return raw tool definitions captured during scanning."""
    return getattr(result, "tools", [])


def _print_rugpull_findings(findings):
    if not findings:
        print("[+] ✅ No rug pull detected. Tool fingerprints match baseline.")
        return
    for f in findings:
        emoji = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🔵", "INFO": "⚪", "ERROR": "❌",
        }.get(f.severity.value if hasattr(f.severity, "value") else str(f.severity), "?")
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        print(f"  {emoji} [{sev}] {f.message}")


def _add_scan_options(parser, include_rugpull: bool = False):
    parser.add_argument(
        "--format", choices=["json", "markdown"], default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--output", "-o", help="Write output to file instead of stdout"
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="INFO",
        help="Minimum severity to report (default: INFO)",
    )
    if include_rugpull:
        parser.add_argument(
            "--check-rugpull",
            action="store_true",
            help="Also compare URL results against a registered rug-pull baseline",
        )


def main():
    parser = argparse.ArgumentParser(
        prog="mcp-tool-auditor",
        description="MCP Tool Poisoning Scanner — Defensive scanning + offensive pentest tooling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a stdio-based MCP server
  mcp-tool-auditor scan stdio -- npx @modelcontextprotocol/server-filesystem /tmp

  # Scan a URL-based MCP server
  mcp-tool-auditor scan url http://localhost:8080/mcp

  # Scan all servers in a config file (Claude Desktop, Cursor, Windsurf)
  mcp-tool-auditor scan config ~/.config/Claude/claude_desktop_config.json

  # Import a JSON array of tool definitions
  mcp-tool-auditor scan import tools.json

  # Register current tool fingerprints (rug-pull baseline)
  mcp-tool-auditor register url http://localhost:8080/mcp

  # Check for rug pulls against baseline
  mcp-tool-auditor check url http://localhost:8080/mcp

  # Generate offensive pentest servers
  mcp-tool-auditor generate all --output-dir ./poisoned_servers

  # Start an ATPA simulation server
  mcp-tool-auditor attack atpa --port 8080 --threshold 3

  # Start a rug-pull simulation server
  mcp-tool-auditor attack rugpull --port 8081 --switch-after 5
        """,
    )

    subparsers = parser.add_subparsers(dest="command")

    # ===== SCAN =====
    scan_parser = subparsers.add_parser("scan", help="Scan MCP servers for tool poisoning")
    scan_sub = scan_parser.add_subparsers(dest="scan_type")

    stdio_p = scan_sub.add_parser("stdio", help="Scan a stdio-based MCP server")
    stdio_p.add_argument("server_command", help="Command to run the server")
    stdio_p.add_argument("args", nargs=argparse.REMAINDER, help="Arguments")

    url_p = scan_sub.add_parser("url", help="Scan a URL-based MCP server")
    url_p.add_argument("url", help="Server URL")

    config_p = scan_sub.add_parser("config", help="Scan all MCP servers in a config file")
    config_p.add_argument("path", help="Path to MCP config file (JSON)")

    import_p = scan_sub.add_parser("import", help="Scan tool definitions from a JSON file")
    import_p.add_argument("path", help="Path to JSON file with tool definitions")

    for parser_with_scan_options in (stdio_p, config_p, import_p):
        _add_scan_options(parser_with_scan_options)
    _add_scan_options(url_p, include_rugpull=True)

    # ===== REGISTER =====
    reg_parser = subparsers.add_parser(
        "register", help="Register tool fingerprints for rug-pull detection"
    )
    reg_sub = reg_parser.add_subparsers(dest="register_type")
    reg_url = reg_sub.add_parser("url", help="Register a URL-based server")
    reg_url.add_argument("url")
    reg_stdio = reg_sub.add_parser("stdio", help="Register a stdio-based server")
    reg_stdio.add_argument("server_command")
    reg_stdio.add_argument("args", nargs=argparse.REMAINDER)

    # ===== CHECK =====
    chk_parser = subparsers.add_parser(
        "check", help="Check for rug pulls against registered baseline"
    )
    chk_sub = chk_parser.add_subparsers(dest="check_type")
    chk_url = chk_sub.add_parser("url")
    chk_url.add_argument("url")
    chk_stdio = chk_sub.add_parser("stdio")
    chk_stdio.add_argument("server_command")
    chk_stdio.add_argument("args", nargs=argparse.REMAINDER)

    # ===== GENERATE (offensive) =====
    gen_parser = subparsers.add_parser(
        "generate", help="Generate poisoned MCP servers for authorized testing"
    )
    gen_parser.add_argument(
        "type",
        nargs="?",
        default="all",
        choices=[
            "all", "description_injection", "full_schema_poisoning",
            "tool_shadowing", "rug_pull_prep", "atpa_error_based",
        ],
        help="Attack type to generate (default: all)",
    )
    gen_parser.add_argument(
        "--output-dir", default="./poisoned_servers",
        help="Output directory for generated servers",
    )
    gen_parser.add_argument(
        "--port", type=int, default=8080, help="Port for generated server"
    )

    # ===== ATTACK =====
    atk_parser = subparsers.add_parser(
        "attack", help="Start offensive simulation servers"
    )
    atk_sub = atk_parser.add_subparsers(dest="attack_type")

    atpa_p = atk_sub.add_parser("atpa", help="Start ATPA simulation server")
    atpa_p.add_argument("--port", type=int, default=8080)
    atpa_p.add_argument(
        "--threshold", type=int, default=3,
        help="Number of benign calls before poison triggers",
    )

    rugpull_p = atk_sub.add_parser("rugpull", help="Start rug-pull simulation server")
    rugpull_p.add_argument("--port", type=int, default=8081)
    rugpull_p.add_argument(
        "--switch-after", type=int, default=5,
        help="Number of requests before swapping to poisoned tools",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    scanner = MCPScanner()

    # ===== SCAN =====
    if args.command == "scan":
        results = {}

        try:
            if args.scan_type == "stdio":
                result = scanner.scan_server_stdio(args.server_command, args.args)
                results[f"stdio:{args.server_command}"] = result
            elif args.scan_type == "url":
                result = scanner.scan_server_url(
                    args.url,
                    check_rugpull=args.check_rugpull,
                )
                results[args.url] = result
            elif args.scan_type == "config":
                results = scanner.scan_config_file(args.path)
            elif args.scan_type == "import":
                with open(args.path, encoding="utf-8") as f:
                    data = json.load(f)
                tools = data if isinstance(data, list) else data.get(
                    "tools",
                    data.get("result", {}).get("tools", []),
                )
                result = scanner.scan_tool_list(tools)
                results[args.path] = result
            else:
                print("[-] Specify 'stdio', 'url', 'config', or 'import'")
                sys.exit(1)
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

        # Filter by severity
        sev_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }
        min_sev = sev_map.get(args.severity, Severity.INFO)
        results = {
            k: v.filter_by_severity(min_sev) if hasattr(v, "filter_by_severity") else v
            for k, v in results.items()
        }

        if args.format == "json":
            output = JSONReporter.generate(results)
        else:
            output = MarkdownReporter.generate(results)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"[+] Report written to {args.output}")
        else:
            print(output)

    # ===== REGISTER =====
    elif args.command == "register":
        detector = RugPullDetector()
        try:
            if args.register_type == "url":
                result = scanner.scan_server_url(args.url)
                sid = args.url
            elif args.register_type == "stdio":
                result = scanner.scan_server_stdio(args.server_command, args.args)
                sid = f"stdio:{args.server_command} {' '.join(args.args)}"
            else:
                print("[-] Specify 'url' or 'stdio'")
                sys.exit(1)
            fpath = detector.register(sid, _get_tools_from_result(result))
            print(f"[+] Registered {result.tools_scanned} tools from {sid}")
            print(f"[+] Fingerprint stored at: {fpath}")
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

    # ===== CHECK =====
    elif args.command == "check":
        detector = RugPullDetector()
        try:
            if args.check_type == "url":
                result = scanner.scan_server_url(args.url)
                findings = detector.check(args.url, _get_tools_from_result(result))
            elif args.check_type == "stdio":
                result = scanner.scan_server_stdio(args.server_command, args.args)
                sid = f"stdio:{args.server_command} {' '.join(args.args)}"
                findings = detector.check(sid, _get_tools_from_result(result))
            else:
                print("[-] Specify 'url' or 'stdio'")
                sys.exit(1)
            _print_rugpull_findings(findings)
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

    # ===== GENERATE =====
    elif args.command == "generate":
        try:
            if args.type == "all":
                out = PoisonedServerGenerator.generate_all_variants(args.output_dir)
                print(f"[+] All attack variants generated in {out}")
            else:
                code = PoisonedServerGenerator.generate_server(
                    attack_type=args.type, port=args.port
                )
                os.makedirs(args.output_dir, exist_ok=True)
                path = os.path.join(args.output_dir, f"server_{args.type}.py")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(code)
                print(f"[+] Generated: {path}")
                print(f"\n  To test: python {path}")
                print(f"  Connect any MCP client to: http://localhost:{args.port}")
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

    # ===== ATTACK =====
    elif args.command == "attack":
        if args.attack_type == "atpa":
            from .offensive.atpa_server import main as atpa_main
            sys.argv = [sys.argv[0], str(args.port), str(args.threshold)]
            atpa_main()
        elif args.attack_type == "rugpull":
            from .offensive.rugpull_sim import main as rugpull_main
            sys.argv = [sys.argv[0], str(args.port), str(args.switch_after)]
            rugpull_main()
        else:
            print("[-] Specify 'atpa' or 'rugpull'")
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
