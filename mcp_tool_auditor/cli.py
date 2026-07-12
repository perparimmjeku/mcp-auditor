#!/usr/bin/env python3
"""
mcp-tool-auditor - MCP Tool Poisoning Scanner
OWASP MCP Top 10 Compliant | Defensive + Offensive tooling
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

from . import __version__
from .auditor import discovery, inventory, remediation, report_signing, suppressions
from .auditor.analyzers.behavioral import BehavioralAnalyzer, CallResult
from .auditor.analyzers.rugpull import RugPullDetector
from .auditor.analyzers.sti_tokenizer import parse_tokenizer_spec
from .auditor.models import CROSS_SERVER_KEY, SEVERITY_LEVELS, Finding, ScanResult, Severity
from .auditor.reporters.inventory_reporter import InventoryReporter
from .auditor.reporters.json_reporter import JSONReporter
from .auditor.reporters.markdown_reporter import MarkdownReporter
from .auditor.reporters.pentest_reporter import PentestReporter
from .auditor.reporters.sarif_reporter import SarifReporter
from .auditor.scanner import MCPScanner
from .config import load_config, set_config
from .engagement import Engagement
from .logging_config import LoggerFactory
from .metrics import MetricsCollector, ScanMetrics
from .offensive.poisoner import PoisonedServerGenerator
from .security import print_security_warning, require_ack
from .validation import (
    ArgparseValidation,
    ValidationError,
    validate_json_file,
    validate_output_path,
)

logger = logging.getLogger(__name__)


def _init_logging(debug: bool = False, log_file: bool = True) -> None:
    level = logging.DEBUG if debug else logging.INFO
    LoggerFactory.setup(level=level, log_file=log_file)


def _get_tools_from_result(result):
    """Return raw tool definitions captured during scanning."""
    return getattr(result, "tools", [])


def _print_rugpull_findings(findings) -> None:
    if not findings:
        print("[+] No rug pull detected. Tool fingerprints match baseline.")
        return
    for finding in findings:
        severity = (
            finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        )
        print(f"  [{severity}] {finding.message}")


def _add_scan_options(parser, include_rugpull: bool = False) -> None:
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "sarif", "pentest"],
        default=None,
        help="Output format (default: config value or markdown). 'pentest' is a "
        "client-ready report with engagement header, executive summary, and evidence.",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="Also write a signed chain-of-custody sidecar (<output>.sig) binding the "
        "findings, engagement scope, and tool version -- not the report bytes, so "
        "the report stays freely editable/reformattable without invalidating the "
        "signature. Requires --output. Verify with 'verify-report <output>.sig'. Key: "
        "MCP_TOOL_AUDITOR_REPORT_KEY (out-of-band, e.g. a CI secret) or an "
        "auto-generated local key file.",
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Minimum severity to report (default: config value or INFO)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Exit non-zero (code 2) if any finding at or above this severity is present (CI gate)",
    )
    parser.add_argument(
        "--min-confidence",
        choices=["HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Only report findings at or above this confidence level",
    )
    parser.add_argument(
        "--suppress",
        action="append",
        default=[],
        metavar="RULE",
        help="Suppress a finding rule (repeatable)",
    )
    parser.add_argument(
        "--suppressions",
        default=None,
        metavar="FILE",
        help="YAML/JSON file of {rule, tool?} suppression entries",
    )
    parser.add_argument(
        "--llm-judge",
        action="store_true",
        dest="llm_judge",
        help="Also judge tool/resource/prompt text with an LLM (Anthropic) to catch "
        "semantically-poisoned phrasing static signatures miss. Opt-in only: sends "
        "third-party server content to Anthropic's API. Requires ANTHROPIC_API_KEY.",
    )
    parser.add_argument(
        "--sti-decode",
        action="store_true",
        dest="sti_decode",
        help="Also check bounded-length base64/hex substrings for encoded Special Token "
        "Injection (STI) payloads. Off by default: decoding is opt-in to bound cost and "
        "false positives even with the length-banded candidate regex.",
    )
    parser.add_argument(
        "--sti-tokenizer",
        default=None,
        metavar="SPEC",
        dest="sti_tokenizer",
        help="Comma list of real, offline tokenizers to additionally check STI matches "
        "against (chatml, qwen, mistral, deepseek; llama3/gemma are recognized names "
        "but have no offline-redistributable asset yet). Confirms a match against the "
        "target's real vocabulary instead of just string shape, and can catch tokens "
        "our registry doesn't list. Off by default; requires "
        "'pip install mcp-tool-auditor[tokenizers]'.",
    )
    parser.add_argument(
        "--no-cross-server-flow",
        action="store_false",
        dest="cross_server_flow",
        default=True,
        help="Disable cross-server toxic-flow analysis (FLOW_*). On by default when 2+ "
        "servers are scanned in one run (config/local): pure local static analysis over "
        "already-fetched tool definitions, no extra cost or external calls, same "
        "FP-restraint posture as the always-on composition analyzer. No-ops on a "
        "single-server scan.",
    )
    if include_rugpull:
        parser.add_argument(
            "--check-rugpull",
            action="store_true",
            help="Also compare URL results against a registered rug-pull baseline",
        )
        parser.add_argument(
            "--header",
            "-H",
            action="append",
            default=[],
            metavar="K:V",
            help="Extra HTTP header for URL servers, e.g. 'Authorization: Bearer ...' (repeatable)",
        )
        parser.add_argument(
            "--proxy",
            default=None,
            help="Route URL requests through an HTTP proxy (e.g. Burp at http://127.0.0.1:8080)",
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-tool-auditor",
        description="MCP Tool Poisoning Scanner - Defensive scanning + offensive pentest tooling",
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
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--config",
        help="Path to mcp-tool-auditor JSON/YAML config",
    )
    parser.add_argument(
        "--engagement",
        metavar="FILE",
        help="Path to an engagement/scope JSON/YAML file (client, tester, dates, "
        "allowed_targets). Scans against stdio/url targets refuse to proceed if the "
        "target isn't in allowed_targets, and --format pentest reports use it for "
        "the engagement header. See README for the file format.",
    )
    parser.add_argument(
        "--no-log-file",
        action="store_true",
        help="Disable log files under ~/.mcp-tool-auditor/logs",
    )
    parser.add_argument(
        "--metrics-file",
        help="Write scan metrics to this JSONL file",
    )
    parser.add_argument(
        "--no-metrics",
        action="store_true",
        help="Disable scan metrics collection",
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan MCP servers for tool poisoning")
    scan_sub = scan_parser.add_subparsers(dest="scan_type")

    stdio_p = scan_sub.add_parser("stdio", help="Scan a stdio-based MCP server")
    stdio_p.add_argument(
        "server_command",
        type=ArgparseValidation.command,
        help="Command to run the server",
    )
    stdio_p.add_argument("args", nargs=argparse.REMAINDER, help="Arguments")

    url_p = scan_sub.add_parser("url", help="Scan a URL-based MCP server")
    url_p.add_argument("url", type=ArgparseValidation.url, help="Server URL")

    config_p = scan_sub.add_parser("config", help="Scan all MCP servers in a config file")
    config_p.add_argument(
        "path",
        type=ArgparseValidation.file,
        help="Path to MCP config file (JSON)",
    )

    import_p = scan_sub.add_parser("import", help="Scan tool definitions from a JSON file")
    import_p.add_argument(
        "path",
        type=ArgparseValidation.file,
        help="Path to JSON file with tool definitions",
    )

    local_p = scan_sub.add_parser(
        "local", help="Auto-discover and scan MCP configs on this machine"
    )

    for parser_with_scan_options in (stdio_p, config_p, import_p, local_p):
        _add_scan_options(parser_with_scan_options)
    _add_scan_options(url_p, include_rugpull=True)

    reg_parser = subparsers.add_parser(
        "register",
        help="Register tool fingerprints for rug-pull detection",
    )
    reg_sub = reg_parser.add_subparsers(dest="register_type")
    reg_url = reg_sub.add_parser("url", help="Register a URL-based server")
    reg_url.add_argument("url", type=ArgparseValidation.url)
    reg_stdio = reg_sub.add_parser("stdio", help="Register a stdio-based server")
    reg_stdio.add_argument("server_command", type=ArgparseValidation.command)
    reg_stdio.add_argument("args", nargs=argparse.REMAINDER)

    chk_parser = subparsers.add_parser(
        "check",
        help="Check for rug pulls against registered baseline",
    )
    chk_sub = chk_parser.add_subparsers(dest="check_type")
    chk_url = chk_sub.add_parser("url")
    chk_url.add_argument("url", type=ArgparseValidation.url)
    chk_stdio = chk_sub.add_parser("stdio")
    chk_stdio.add_argument("server_command", type=ArgparseValidation.command)
    chk_stdio.add_argument("args", nargs=argparse.REMAINDER)

    gen_parser = subparsers.add_parser(
        "generate",
        help="Generate poisoned MCP servers for authorized testing",
    )
    gen_parser.add_argument(
        "type",
        nargs="?",
        default="all",
        choices=[
            "all",
            "description_injection",
            "full_schema_poisoning",
            "tool_shadowing",
            "rug_pull_prep",
            "atpa_error_based",
            "sti_chatml_injection",
            "sti_deepseek_homoglyph",
        ],
        help="Attack type to generate (default: all)",
    )
    gen_parser.add_argument(
        "--output-dir",
        default="./poisoned_servers",
        help="Output directory for generated servers",
    )
    gen_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for generated server",
    )

    atk_parser = subparsers.add_parser(
        "attack",
        help="Start offensive simulation servers",
    )
    atk_parser.add_argument(
        "--yes",
        action="store_true",
        help="Acknowledge authorization warning non-interactively",
    )
    atk_sub = atk_parser.add_subparsers(dest="attack_type")

    atpa_p = atk_sub.add_parser("atpa", help="Start ATPA simulation server")
    atpa_p.add_argument("--port", type=int, default=8080)
    atpa_p.add_argument(
        "--yes",
        action="store_true",
        help="Acknowledge authorization warning non-interactively",
    )
    atpa_p.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Number of benign calls before poison triggers",
    )

    rugpull_p = atk_sub.add_parser("rugpull", help="Start rug-pull simulation server")
    rugpull_p.add_argument("--port", type=int, default=8081)
    rugpull_p.add_argument(
        "--yes",
        action="store_true",
        help="Acknowledge authorization warning non-interactively",
    )
    rugpull_p.add_argument(
        "--switch-after",
        type=int,
        default=5,
        help="Number of requests before swapping to poisoned tools",
    )

    sti_p = atk_sub.add_parser("sti", help="Start STI (Special Token Injection) simulation server")
    sti_p.add_argument("--port", type=int, default=8082)
    sti_p.add_argument(
        "--yes",
        action="store_true",
        help="Acknowledge authorization warning non-interactively",
    )
    sti_p.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Number of benign calls before a chat-template control token is injected",
    )

    # --- behavior ---
    beh_parser = subparsers.add_parser(
        "behavior", help="Behavioral/runtime probing for ATPA & response injection"
    )
    beh_sub = beh_parser.add_subparsers(dest="behavior_type")

    beh_stdio = beh_sub.add_parser("stdio", help="Probe a stdio-based MCP server")
    beh_stdio.add_argument("server_command", type=ArgparseValidation.command)
    beh_stdio.add_argument("args", nargs=argparse.REMAINDER)
    beh_url = beh_sub.add_parser("url", help="Probe a URL-based MCP server")
    beh_url.add_argument("url", type=ArgparseValidation.url)
    beh_url.add_argument("--header", "-H", action="append", default=[], metavar="K:V")
    beh_url.add_argument("--proxy", default=None)
    beh_import = beh_sub.add_parser("import", help="Analyze a recorded response transcript")
    beh_import.add_argument("path", type=ArgparseValidation.file)

    for sub in (beh_stdio, beh_url, beh_import):
        sub.add_argument("--calls", type=int, default=6, help="Calls per tool (default 6)")
        sub.add_argument("--format", choices=["json", "markdown", "sarif", "pentest"], default=None)
        sub.add_argument("--severity", default=None)
        sub.add_argument("--output", default=None)
        sub.add_argument(
            "--fail-on",
            choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            default=None,
            help="Exit non-zero (code 2) if a finding at or above this severity is present",
        )
        sub.add_argument("--min-confidence", choices=["HIGH", "MEDIUM", "LOW"], default=None)
        sub.add_argument("--suppress", action="append", default=[], metavar="RULE")
        sub.add_argument("--suppressions", default=None, metavar="FILE")
    for sub in (beh_stdio, beh_url):
        sub.add_argument("--yes", action="store_true", help="Assume authorization (skip ack)")

    # --- watch ---
    watch_parser = subparsers.add_parser(
        "watch", help="Continuously monitor MCP servers and alert a webhook on new findings"
    )
    watch_sub = watch_parser.add_subparsers(dest="watch_type")

    watch_url = watch_sub.add_parser("url", help="Watch a URL-based MCP server")
    watch_url.add_argument("url", type=ArgparseValidation.url)
    watch_url.add_argument("--header", "-H", action="append", default=[], metavar="K:V")
    watch_url.add_argument("--proxy", default=None)
    watch_url.add_argument(
        "--check-rugpull",
        action="store_true",
        help="Also compare against a registered rug-pull baseline each interval",
    )

    watch_config = watch_sub.add_parser("config", help="Watch all MCP servers in a config file")
    watch_config.add_argument("path", type=ArgparseValidation.file)

    for sub in (watch_url, watch_config):
        sub.add_argument(
            "--interval",
            type=int,
            default=300,
            help="Seconds between checks (default 300)",
        )
        sub.add_argument(
            "--webhook",
            default=None,
            metavar="URL",
            help="POST newly-observed findings to this webhook URL as JSON",
        )

    # --- retest ---
    retest_parser = subparsers.add_parser(
        "retest",
        help="Re-scan and diff against a prior --format json report (Fixed/Still Present/New)",
    )
    retest_parser.add_argument(
        "--baseline",
        required=True,
        metavar="FILE",
        help="Prior scan report produced with 'scan ... --format json -o FILE'",
    )
    retest_sub = retest_parser.add_subparsers(dest="scan_type")

    rt_stdio = retest_sub.add_parser("stdio", help="Retest a stdio-based MCP server")
    rt_stdio.add_argument("server_command", type=ArgparseValidation.command)
    rt_stdio.add_argument("args", nargs=argparse.REMAINDER)

    rt_url = retest_sub.add_parser("url", help="Retest a URL-based MCP server")
    rt_url.add_argument("url", type=ArgparseValidation.url)

    rt_config = retest_sub.add_parser("config", help="Retest all MCP servers in a config file")
    rt_config.add_argument("path", type=ArgparseValidation.file)

    rt_import = retest_sub.add_parser("import", help="Retest tool definitions from a JSON file")
    rt_import.add_argument("path", type=ArgparseValidation.file)

    for retest_p in (rt_stdio, rt_config, rt_import):
        _add_scan_options(retest_p)
    _add_scan_options(rt_url, include_rugpull=True)

    # --- source-scan ---
    src_parser = subparsers.add_parser(
        "source-scan", help="Scan MCP server source code for shell-injection (Prompt-In-Shell-Out)"
    )
    src_parser.add_argument("path", help="File or directory of MCP server source to scan")
    _add_scan_options(src_parser)

    # --- explain ---
    exp_parser = subparsers.add_parser(
        "explain", help="Explain a finding rule and show remediation guidance"
    )
    exp_parser.add_argument(
        "rule", nargs="?", help="Rule id or family (e.g. BEHAV_ATPA_TRANSITION)"
    )
    exp_parser.add_argument(
        "--list", action="store_true", help="List rule families with specific guidance"
    )

    # --- inventory ---
    inv_parser = subparsers.add_parser(
        "inventory",
        help="Discover MCP servers and map cross-server blast radius (host risk report + graph)",
    )
    inv_parser.add_argument(
        "--format",
        choices=["json", "markdown", "sarif", "pentest"],
        default=None,
        help="Output format (default: config value or markdown). 'pentest' renders the same "
        "host-risk report as 'markdown' -- inventory's identity/reach/blast-radius shape "
        "doesn't fit the per-tool evidence format the other commands' 'pentest' uses. "
        "'sarif' carries only the cross-server chain findings (FLOW_*/INV_INFERRED_CHAIN), "
        "not identity/reach data -- SARIF has no natural field for that.",
    )
    inv_parser.add_argument("--output", "-o", help="Write output to file instead of stdout")
    inv_parser.add_argument(
        "--suppress", action="append", default=[], metavar="RULE", help="Suppress a chain rule"
    )
    inv_parser.add_argument(
        "--suppressions", default=None, metavar="FILE", help="YAML/JSON suppressions file"
    )
    inv_parser.add_argument(
        "--probe",
        action="store_true",
        help="Also connect read-only to each discovered server and confirm its declared "
        "capabilities against real tools/list data (enumeration only -- never calls a "
        "tool). Off by default: static discovery alone already produces a useful, clearly "
        "labeled INFERRED blast-radius map. Requires authorization (see --yes).",
    )
    inv_parser.add_argument(
        "--yes",
        action="store_true",
        help="Acknowledge the --probe authorization warning non-interactively",
    )

    # --- verify-report ---
    verify_parser = subparsers.add_parser(
        "verify-report",
        help="Verify a signed report's chain-of-custody sidecar (VALID/TAMPERED/INVALID)",
    )
    verify_parser.add_argument(
        "sidecar",
        type=ArgparseValidation.file,
        help="Path to the .sig sidecar written by --sign (e.g. report.md.sig)",
    )

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    _init_logging(debug=args.verbose, log_file=not args.no_log_file)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        config = load_config(args.config)
        set_config(config)
    except Exception as exc:
        logger.error("Failed to load config: %s", exc)
        sys.exit(1)

    engagement = None
    if args.engagement:
        try:
            engagement = Engagement.from_file(args.engagement)
        except Exception as exc:
            logger.error("Failed to load engagement/scope file: %s", exc)
            sys.exit(1)

    metrics_collector = MetricsCollector(
        metrics_file=args.metrics_file,
        enabled=not args.no_metrics,
    )
    scanner = MCPScanner(
        config=config,
        sti_decode=getattr(args, "sti_decode", False),
        sti_tokenizer_names=parse_tokenizer_spec(getattr(args, "sti_tokenizer", None)),
    )

    try:
        if args.command == "scan":
            _handle_scan(args, scanner, config, metrics_collector, engagement=engagement)
        elif args.command == "register":
            _handle_register(args, scanner, engagement=engagement)
        elif args.command == "check":
            _handle_check(args, scanner, engagement=engagement)
        elif args.command == "generate":
            _handle_generate(args)
        elif args.command == "attack":
            _handle_attack(args)
        elif args.command == "behavior":
            _handle_behavior(args, scanner, config, engagement=engagement)
        elif args.command == "watch":
            _handle_watch(args, scanner, engagement=engagement)
        elif args.command == "retest":
            _handle_retest(args, scanner, config, engagement=engagement)
        elif args.command == "explain":
            _handle_explain(args)
        elif args.command == "source-scan":
            _handle_source_scan(args, config, engagement=engagement)
        elif args.command == "inventory":
            _handle_inventory(args, scanner, config, engagement=engagement)
        elif args.command == "verify-report":
            _handle_verify_report(args)
        else:
            parser.print_help()
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        sys.exit(130)
    except Exception as exc:
        logger.error("%s", exc, exc_info=args.verbose)
        sys.exit(1)


def _apply_llm_judge(results: dict[str, ScanResult], enabled: bool) -> None:
    """Optionally judge each result's tools/resources/prompts/instructions with an LLM.

    No-op unless the caller opted in via --llm-judge; never runs by default.
    """
    if not enabled:
        return
    from .auditor.analyzers.llm_judge import LLMJudgeAnalyzer

    judge = LLMJudgeAnalyzer()
    for result in results.values():
        result.findings.extend(judge.analyze(result.tools, kind="tool"))
        result.findings.extend(judge.analyze(result.resources, kind="resource"))
        result.findings.extend(judge.analyze(result.prompts, kind="prompt"))
        if result.instructions:
            result.findings.extend(
                judge.analyze(
                    [{"name": "server_instructions", "description": result.instructions}],
                    kind="instructions",
                )
            )


def _apply_cross_server_flow(results: dict[str, ScanResult], enabled: bool) -> None:
    """Optionally add a CROSS_SERVER_KEY entry with cross-server toxic-flow findings.

    On by default (unlike --llm-judge/--sti-decode/--sti-tokenizer, which are
    opt-in for cost/dependency/FP-volume reasons that don't apply here: this
    is local static analysis over tool definitions already in `results`, no
    network call, no extra dependency). Adds nothing when disabled or when
    flow.analyze() finds nothing -- in particular, a true single-target scan
    can never produce a cross-server finding (it needs 2+ servers), so the
    synthetic key never appears for one, and `len(results) == 1` still holds
    wherever that's relied on (e.g. retest's single_target detection).
    """
    if not enabled:
        return
    from .auditor.analyzers import flow

    findings = flow.analyze(results)
    if findings:
        results[CROSS_SERVER_KEY] = ScanResult(tools_scanned=0, findings=findings)


def _handle_scan(
    args, scanner: MCPScanner, config, metrics_collector: MetricsCollector, engagement=None
) -> None:
    start = time.time()
    try:
        results = _run_scan(args, scanner, engagement=engagement)
        _apply_llm_judge(results, getattr(args, "llm_judge", False))
        _apply_cross_server_flow(results, getattr(args, "cross_server_flow", True))
        severity = args.severity or config.min_severity
        results = _filter_results(results, severity)
        results = _apply_triage(results, args)

        output_format = args.format or config.output_format
        output = _render_report(results, output_format, engagement=engagement)
        _write_report_output(args, output, results, engagement=engagement)

        metrics_collector.record(_metrics_from_results(results, time.time() - start, True))
        logger.info("Scan completed in %.2fs", time.time() - start)
        _apply_fail_on(results, getattr(args, "fail_on", None))
    except Exception as exc:
        metrics_collector.record(
            ScanMetrics.now(
                duration_seconds=time.time() - start,
                tools_scanned=0,
                findings_total=0,
                findings_by_severity={},
                findings_by_owasp={},
                server_count=0,
                success=False,
                error_message=str(exc),
            )
        )
        raise


def _parse_headers(raw: list[str]) -> dict[str, str]:
    """Parse 'Key: Value' header strings into a dict."""
    headers: dict[str, str] = {}
    for item in raw or []:
        if ":" not in item:
            raise ValidationError(f"Invalid --header '{item}', expected 'Key: Value'")
        key, value = item.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def _run_scan(args, scanner: MCPScanner, engagement=None):
    if args.scan_type == "stdio":
        if engagement is not None:
            engagement.check_target(args.server_command)
        result = scanner.scan_server_stdio(args.server_command, args.args)
        return {f"stdio:{args.server_command}": result}
    if args.scan_type == "url":
        if engagement is not None:
            engagement.check_target(args.url)
        result = scanner.scan_server_url(
            args.url,
            check_rugpull=args.check_rugpull,
            extra_headers=_parse_headers(getattr(args, "header", [])),
            proxy=getattr(args, "proxy", None),
        )
        return {args.url: result}
    if args.scan_type == "config":
        return scanner.scan_config_file(args.path)
    if args.scan_type == "local":
        configs = discovery.discover_configs()
        if not configs:
            logger.warning("No MCP client configs discovered in known locations.")
            return {}
        merged: dict = {}
        for cfg in configs:
            try:
                for name, result in scanner.scan_config_file(str(cfg)).items():
                    merged[f"{cfg.name}:{name}"] = result
            except Exception as exc:
                logger.warning("Skipping %s: %s", cfg, exc)
        return merged
    if args.scan_type == "import":
        data = validate_json_file(args.path)
        if isinstance(data, list):
            tools = data
        elif isinstance(data, dict):
            tools = data.get("tools", data.get("result", {}).get("tools", []))
        else:
            raise ValidationError("Imported JSON must be an object or an array")
        if not isinstance(tools, list):
            raise ValidationError("Imported JSON must contain a tools array")
        return {args.path: scanner.scan_tool_list(tools)}
    raise ValidationError("Specify 'stdio', 'url', 'config', or 'import'")


_CONFIDENCE_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _apply_triage(results, args):
    """Apply suppressions and the min-confidence filter to results."""
    entries = []
    suppress_file = getattr(args, "suppressions", None)
    if suppress_file:
        entries = suppressions.load(suppress_file)
    results = suppressions.apply(results, rules=getattr(args, "suppress", []), entries=entries)

    min_conf = getattr(args, "min_confidence", None)
    if min_conf:
        threshold = _CONFIDENCE_RANK[min_conf]
        for result in results.values():
            result.findings = [
                f
                for f in result.findings
                if _CONFIDENCE_RANK.get(f.confidence or "MEDIUM", 1) <= threshold
            ]
    return results


def _render_report(
    results, output_format: str, engagement=None, fixed: list[tuple[str, Finding]] | None = None
) -> str:
    if output_format == "json":
        return JSONReporter.generate(results)
    if output_format == "sarif":
        return SarifReporter.generate(results)
    if output_format == "pentest":
        return PentestReporter.generate(results, engagement=engagement, fixed=fixed)
    return MarkdownReporter.generate(results)


def _write_report_output(
    args,
    output: str,
    results,
    engagement=None,
    fixed: list[tuple[str, Finding]] | None = None,
) -> None:
    """Write `output` to --output (or stdout), and -- if --sign was passed --
    a chain-of-custody sidecar (<output>.sig) alongside it.

    The sidecar signs a canonical payload built straight from `results`/
    `engagement`, never `output` itself: reformatting the human-readable
    report afterward doesn't touch the signature at all. --sign requires
    --output -- a sidecar has nowhere to live for a stdout-only report.
    """
    if getattr(args, "sign", False) and not args.output:
        raise ValidationError("--sign requires --output (the sidecar needs a file to pair with)")

    if args.output:
        output_path = validate_output_path(args.output)
        output_path.write_text(output, encoding="utf-8")
        print(f"[+] Report written to {output_path}")
    else:
        print(output)

    if getattr(args, "sign", False):
        sidecar = report_signing.sign_report(
            results, __version__, engagement=engagement, fixed=fixed
        )
        sig_path = output_path.with_name(output_path.name + ".sig")
        sig_path.write_text(json.dumps(sidecar, indent=2, sort_keys=True), encoding="utf-8")
        print(
            f"[+] Signed chain-of-custody sidecar written to {sig_path} (key_id: {sidecar['key_id']})"
        )


def _apply_fail_on(results, fail_on: str | None) -> None:
    """Exit non-zero (code 2) if any finding meets the --fail-on severity threshold."""
    if not fail_on:
        return
    threshold = SEVERITY_LEVELS.get(Severity(fail_on.upper()))
    if threshold is None:
        return
    for result in results.values():
        for finding in result.findings:
            level = SEVERITY_LEVELS.get(finding.severity)
            if level is not None and level <= threshold:
                logger.warning(
                    "Failing build: finding '%s' (%s) meets --fail-on %s",
                    finding.rule,
                    finding.severity.value,
                    fail_on.upper(),
                )
                sys.exit(2)


def _filter_results(results, min_severity: str):
    sev_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }
    severity = sev_map.get(str(min_severity).upper())
    if severity is None:
        raise ValidationError(f"Unknown severity: {min_severity}")
    return {
        name: (
            result.filter_by_severity(severity) if hasattr(result, "filter_by_severity") else result
        )
        for name, result in results.items()
    }


def _finding_from_dict(data: dict) -> Finding:
    """Reconstruct a Finding from a prior `--format json` report entry."""
    return Finding(
        severity=data["severity"],
        rule=data["rule"],
        message=data["message"],
        owasp_id=data["owasp_id"],
        attack_type=data.get("attack_type", "unknown"),
        field=data.get("field"),
        tool_name=data.get("tool_name"),
        file=data.get("file"),
        line=data.get("line"),
        confidence=data.get("confidence"),
        retest_status="FIXED",
        related_tool=data.get("related_tool"),
        related_server=data.get("related_server"),
    )


def _load_baseline_report(path: str) -> dict[str, list[dict]]:
    """Load a prior `scan ... --format json` report as server_name -> findings."""
    data = validate_json_file(path)
    if not isinstance(data, dict) or "servers" not in data:
        raise ValidationError(
            f"'{path}' doesn't look like an mcp-tool-auditor JSON report (missing 'servers')"
        )
    return {name: server.get("findings", []) for name, server in data["servers"].items()}


def _handle_retest(args, scanner: MCPScanner, config, engagement=None) -> None:
    baseline_servers = _load_baseline_report(args.baseline)

    results = _run_scan(args, scanner, engagement=engagement)
    _apply_llm_judge(results, getattr(args, "llm_judge", False))
    _apply_cross_server_flow(results, getattr(args, "cross_server_flow", True))
    severity = args.severity or config.min_severity
    results = _filter_results(results, severity)
    results = _apply_triage(results, args)

    # With exactly one target on each side, match findings by (rule, tool,
    # field) alone -- the baseline and this run's target identifier strings
    # often differ even for "the same target" (e.g. two `import` snapshots
    # with different filenames, or a URL scanned with different query
    # params). With multiple targets (config/local), keep server_name in the
    # key so distinct servers aren't conflated with each other.
    single_target = len(results) == 1 and len(baseline_servers) == 1

    def _scope(server_name: str) -> str:
        return "__single_target__" if single_target else server_name

    def _key(server_name: str, rule, tool_name, field) -> tuple:
        return (_scope(server_name), rule, tool_name, field)

    baseline_index: dict[tuple, tuple[str, dict]] = {}
    for server_name, findings in baseline_servers.items():
        for finding_dict in findings:
            key = _key(
                server_name,
                finding_dict.get("rule"),
                finding_dict.get("tool_name"),
                finding_dict.get("field"),
            )
            baseline_index[key] = (server_name, finding_dict)

    current_keys: set[tuple] = set()
    for server_name, result in results.items():
        for finding in result.findings:
            key = _key(server_name, finding.rule, finding.tool_name, finding.field)
            current_keys.add(key)
            finding.retest_status = "STILL_PRESENT" if key in baseline_index else "NEW"

    fixed: list[tuple[str, Finding]] = [
        (orig_server_name, _finding_from_dict(finding_dict))
        for key, (orig_server_name, finding_dict) in baseline_index.items()
        if key not in current_keys
    ]

    output_format = args.format or config.output_format
    output = _render_report(results, output_format, engagement=engagement, fixed=fixed)
    _write_report_output(args, output, results, engagement=engagement, fixed=fixed)

    still_present = sum(
        1 for r in results.values() for f in r.findings if f.retest_status == "STILL_PRESENT"
    )
    new = sum(1 for r in results.values() for f in r.findings if f.retest_status == "NEW")
    print(f"[+] Retest: {len(fixed)} fixed, {still_present} still present, {new} new")
    _apply_fail_on(results, getattr(args, "fail_on", None))


def _metrics_from_results(results, duration: float, success: bool) -> ScanMetrics:
    severity_counts: dict[str, int] = {}
    owasp_counts: dict[str, int] = {}
    findings_total = 0
    tools_scanned = 0

    for result in results.values():
        tools_scanned += result.tools_scanned
        findings_total += len(result.findings)
        for severity, count in result.severity_counts.items():
            severity_counts[severity] = severity_counts.get(severity, 0) + count
        for finding in result.findings:
            owasp_counts[finding.owasp_id] = owasp_counts.get(finding.owasp_id, 0) + 1

    return ScanMetrics.now(
        duration_seconds=duration,
        tools_scanned=tools_scanned,
        findings_total=findings_total,
        findings_by_severity=severity_counts,
        findings_by_owasp=owasp_counts,
        server_count=sum(1 for name in results if name != CROSS_SERVER_KEY),
        success=success,
    )


def _responses_from_transcript(value) -> list[CallResult]:
    results: list[CallResult] = []
    for i, item in enumerate(value):
        if isinstance(item, str):
            results.append(CallResult(index=i, text=item))
        elif isinstance(item, dict):
            results.append(
                CallResult(index=i, text=str(item.get("text", "")), error=item.get("error"))
            )
        else:
            results.append(CallResult(index=i, text=str(item)))
    return results


def _behavior_result(tools, transcripts, server_url=None) -> ScanResult:
    analyzer = BehavioralAnalyzer()
    by_name = {t.get("name", "unknown"): t for t in tools}
    findings = []
    for name, responses in transcripts.items():
        findings.extend(analyzer.analyze(by_name.get(name, {"name": name}), responses))
    return ScanResult(
        tools_scanned=len(transcripts),
        findings=findings,
        server_url=server_url,
        tools=list(by_name.values()),
    )


def _handle_behavior(args, scanner: MCPScanner, config, engagement=None) -> None:
    if args.behavior_type == "import":
        data = validate_json_file(args.path)
        if not isinstance(data, dict):
            raise ValidationError(
                "Transcript file must be a JSON object mapping tool name to responses"
            )
        transcripts = {name: _responses_from_transcript(v) for name, v in data.items()}
        tools = [{"name": name} for name in transcripts]
        results = {args.path: _behavior_result(tools, transcripts)}
    elif args.behavior_type in {"stdio", "url"}:
        print_security_warning()
        if not require_ack(auto_ack=getattr(args, "yes", False)):
            print("[*] Operation cancelled")
            sys.exit(1)
        if args.behavior_type == "url":
            if engagement is not None:
                engagement.check_target(args.url)
            tools, transcripts = scanner.probe_url(
                args.url,
                calls=args.calls,
                extra_headers=_parse_headers(getattr(args, "header", [])),
                proxy=getattr(args, "proxy", None),
            )
            results = {args.url: _behavior_result(tools, transcripts, server_url=args.url)}
        else:
            if engagement is not None:
                engagement.check_target(args.server_command)
            tools, transcripts = scanner.probe_stdio(
                args.server_command, args.args, calls=args.calls
            )
            results = {f"stdio:{args.server_command}": _behavior_result(tools, transcripts)}
    else:
        raise ValidationError("Specify 'stdio', 'url', or 'import'")

    severity = args.severity or config.min_severity
    results = _filter_results(results, severity)
    results = _apply_triage(results, args)
    output_format = args.format or config.output_format
    output = _render_report(results, output_format, engagement=engagement)
    if args.output:
        output_path = validate_output_path(args.output)
        output_path.write_text(output, encoding="utf-8")
        print(f"[+] Report written to {output_path}")
    else:
        print(output)
    _apply_fail_on(results, getattr(args, "fail_on", None))


def _handle_source_scan(args, config, engagement=None) -> None:
    from .auditor.source.scanner import SourceScanner

    if not os.path.exists(args.path):
        raise ValidationError(f"Path not found: {args.path}")
    results = SourceScanner().scan(args.path)

    severity = args.severity or config.min_severity
    results = _filter_results(results, severity)
    results = _apply_triage(results, args)
    output_format = args.format or config.output_format
    output = _render_report(results, output_format, engagement=engagement)
    _write_report_output(args, output, results, engagement=engagement)
    _apply_fail_on(results, getattr(args, "fail_on", None))


def _handle_inventory(args, scanner: MCPScanner, config, engagement=None) -> None:
    """Discover MCP servers and map cross-server blast radius.

    Layer 1+2 (static discovery + capability inference + INV_INFERRED_CHAIN
    blast-radius) always run -- no execution, no network call, nothing to
    gate. Layer 3 (--probe) is opt-in and gated exactly like `behavior`/
    `attack`: the same authorization banner + require_ack(), and per-server
    engagement scope enforcement happens inside run_inventory() itself.
    Declining the ack (or --probe never being passed) falls back to the
    static map cleanly rather than aborting -- inventory without --probe is
    still a complete, useful command on its own.
    """
    configs = discovery.discover_configs()
    discovered: list[discovery.DiscoveredServer] = []
    for cfg in configs:
        discovered.extend(discovery.parse_server_entries(cfg))

    probe = False
    if getattr(args, "probe", False):
        print_security_warning()
        try:
            acked = require_ack(auto_ack=getattr(args, "yes", False))
        except EOFError:
            # No TTY to prompt against (e.g. --probe run non-interactively
            # without --yes, common in CI) -- must fall back cleanly like
            # any other declined/unauthorized case, not crash the command.
            acked = False
        if acked:
            probe = True
        else:
            # Processing continues and still writes a report to stdout below
            # (unlike behavior/attack, which exit immediately on decline) --
            # this status line must go to stderr, or it corrupts a piped/
            # redirected json/sarif report the same way the banner would.
            print(
                "[*] --probe declined -- falling back to static (Layer 1+2) inventory.",
                file=sys.stderr,
            )

    result = inventory.run_inventory(
        discovered, scanner=scanner, probe=probe, engagement=engagement
    )

    suppress_rules = getattr(args, "suppress", None) or []
    suppress_file = getattr(args, "suppressions", None)
    if suppress_rules or suppress_file:
        entries = suppressions.load(suppress_file) if suppress_file else []
        wrapped = {CROSS_SERVER_KEY: ScanResult(tools_scanned=0, findings=result.chain_findings)}
        wrapped = suppressions.apply(wrapped, rules=suppress_rules, entries=entries)
        result.chain_findings = wrapped[CROSS_SERVER_KEY].findings

    output_format = args.format or config.output_format
    if output_format == "json":
        output = InventoryReporter.generate_json(result)
    elif output_format == "sarif":
        # SARIF carries only the chain findings -- identity/reach/blast-
        # radius data has no natural SARIF field, same reasoning as the
        # existing reporters staying finding-shaped.
        wrapped = {CROSS_SERVER_KEY: ScanResult(tools_scanned=0, findings=result.chain_findings)}
        output = SarifReporter.generate(wrapped)
    else:
        # "pentest" renders the same host-risk report as "markdown" here --
        # inventory's identity/reach shape doesn't fit PentestReporter's
        # per-tool evidence-lookup model.
        output = InventoryReporter.generate_markdown(result)

    if args.output:
        output_path = validate_output_path(args.output)
        output_path.write_text(output, encoding="utf-8")
        print(f"[+] Report written to {output_path}")
    else:
        print(output)


def _handle_explain(args) -> None:
    if args.list or not args.rule:
        print("Rule families with specific remediation guidance:\n")
        for family in remediation.list_families():
            print(f"  {family}")
        print("\nRun 'mcp-tool-auditor explain <RULE>' for guidance on a specific rule.")
        return
    rule = args.rule
    print(f"Rule: {rule}\n")
    print("Remediation:")
    print(f"  {remediation.get_remediation(rule)}")


def _handle_verify_report(args) -> None:
    sidecar = validate_json_file(args.sidecar)
    if not isinstance(sidecar, dict):
        raise ValidationError(
            f"'{args.sidecar}' is not a valid signature sidecar (not a JSON object)"
        )

    result = report_signing.verify_report(sidecar)
    status = result["status"]
    print(f"Status: {status}")
    print(f"Tool version (signed): {result.get('tool_version')}")
    print(f"Signed at: {result.get('signed_at')}")
    print(f"Key id (signature):  {result.get('key_id')}")
    print(f"Key id (verifying):  {result.get('verifying_key_id')}")
    if result.get("reason"):
        print(f"Reason: {result['reason']}")

    if status == "VALID":
        payload = sidecar.get("payload", {})
        print(f"Findings attested: {len(payload.get('findings', []))}")
        print(f"Targets attested: {', '.join(payload.get('targets', [])) or '(none)'}")
    else:
        sys.exit(2)


def _handle_register(args, scanner: MCPScanner, engagement=None) -> None:
    detector = RugPullDetector(fingerprint_dir=scanner.config.fingerprint_dir)
    if args.register_type == "url":
        if engagement is not None:
            engagement.check_target(args.url)
        result = scanner.scan_server_url(args.url)
        server_id = args.url
    elif args.register_type == "stdio":
        if engagement is not None:
            engagement.check_target(args.server_command)
        result = scanner.scan_server_stdio(args.server_command, args.args)
        server_id = f"stdio:{args.server_command} {' '.join(args.args)}"
    else:
        raise ValidationError("Specify 'url' or 'stdio'")

    fingerprint_path = detector.register(server_id, _get_tools_from_result(result))
    print(f"[+] Registered {result.tools_scanned} tools from {server_id}")
    print(f"[+] Fingerprint stored at: {fingerprint_path}")


def _handle_check(args, scanner: MCPScanner, engagement=None) -> None:
    detector = RugPullDetector(fingerprint_dir=scanner.config.fingerprint_dir)
    if args.check_type == "url":
        if engagement is not None:
            engagement.check_target(args.url)
        result = scanner.scan_server_url(args.url)
        findings = detector.check(args.url, _get_tools_from_result(result))
    elif args.check_type == "stdio":
        if engagement is not None:
            engagement.check_target(args.server_command)
        result = scanner.scan_server_stdio(args.server_command, args.args)
        server_id = f"stdio:{args.server_command} {' '.join(args.args)}"
        findings = detector.check(server_id, _get_tools_from_result(result))
    else:
        raise ValidationError("Specify 'url' or 'stdio'")
    _print_rugpull_findings(findings)


def _handle_watch(args, scanner: MCPScanner, engagement=None) -> None:
    from .watch import WatchDaemon

    if args.watch_type == "url":
        if engagement is not None:
            engagement.check_target(args.url)

        def scan_once():
            result = scanner.scan_server_url(
                args.url,
                check_rugpull=getattr(args, "check_rugpull", False),
                extra_headers=_parse_headers(getattr(args, "header", [])),
                proxy=getattr(args, "proxy", None),
            )
            return {args.url: result}

        target = args.url
    elif args.watch_type == "config":

        def scan_once():
            return scanner.scan_config_file(args.path)

        target = args.path
    else:
        raise ValidationError("Specify 'url' or 'config'")

    daemon = WatchDaemon(webhook_url=args.webhook, interval=args.interval)
    alert_note = f"alerting to {args.webhook}" if args.webhook else "no --webhook set, logging only"
    print(f"[*] Watching {target} every {args.interval}s ({alert_note}). Ctrl+C to stop.")
    daemon.run(scan_once)
    print("[*] Watch stopped.")


def _handle_generate(args) -> None:
    if args.type == "all":
        output_dir = PoisonedServerGenerator.generate_all_variants(args.output_dir)
        print(f"[+] All attack variants generated in {output_dir}")
        return

    code = PoisonedServerGenerator.generate_server(
        attack_type=args.type,
        port=args.port,
    )
    os.makedirs(args.output_dir, exist_ok=True)
    path = os.path.join(args.output_dir, f"server_{args.type}.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(code)
    print(f"[+] Generated: {path}")
    print(f"\n  To test: python {path}")
    print(f"  Connect any MCP client to: http://localhost:{args.port}")


def _handle_attack(args) -> None:
    if args.yes:
        os.environ["MCP_TOOL_AUDITOR_ASSUME_AUTHORIZED"] = "1"

    if args.attack_type == "atpa":
        from .offensive.atpa_server import main as atpa_main

        sys.argv = [sys.argv[0], str(args.port), str(args.threshold)]
        atpa_main()
    elif args.attack_type == "rugpull":
        from .offensive.rugpull_sim import main as rugpull_main

        sys.argv = [sys.argv[0], str(args.port), str(args.switch_after)]
        rugpull_main()
    elif args.attack_type == "sti":
        from .offensive.sti_server import main as sti_main

        sys.argv = [sys.argv[0], str(args.port), str(args.threshold)]
        sti_main()
    else:
        raise ValidationError("Specify 'atpa', 'rugpull', or 'sti'")


if __name__ == "__main__":
    main()
