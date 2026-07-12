# MCP Tool Auditor

**Scan MCP server tool definitions for poisoning, injection, and OWASP MCP Top 10 vulnerabilities.**

[![CI](https://github.com/perparimmjeku/mcp-tool-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/perparimmjeku/mcp-tool-auditor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-tool-auditor)](https://pypi.org/project/mcp-tool-auditor/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP-MCP03%20Tool%20Poisoning-red)](https://owasp.org/www-project-mcp-top-10/)

> **Most MCP scanners read tool definitions. This one also watches tool _behavior_** — it calls tools and catches Advanced Tool Poisoning Attacks (ATPA) that look benign on paper and turn malicious at runtime.

`mcp-tool-auditor` is a comprehensive security scanner for Model Context Protocol (MCP) servers. It detects tool poisoning, full-schema poisoning (FSP), rug-pull attacks (including tool shadowing and tampered baselines), cross-tool composition risk, and ATPA (Advanced Tool Poisoning Attacks) — across tool, resource, prompt, and server-instruction definitions, not just tool descriptions — while mapping findings to the OWASP MCP Top 10 framework.

The project also includes authorized offensive tooling for penetration testers and security researchers to simulate realistic MCP attack scenarios in controlled environments.

---

## Features

### Defensive Scanner

| Feature | What It Detects |
|---|---|
| Static Signatures | 40+ patterns such as "ignore security", "always use this tool", "send full conversation", and "authoritative source" |
| Heuristic Analysis | Imperative language scoring, authority spoofing, Unicode hidden characters, and excessive agency claims |
| Multi-Surface Scanning | The same signature/heuristic engine also runs on `resources`, `prompts`, and the server's `initialize` `instructions` string — not just tool descriptions |
| Schema Anomaly Detection | Full-Schema Poisoning (FSP), sidenote parameter injection, enum injection, poisoned defaults, and required-array abuse |
| Special Token Injection (STI) | Chat-template control tokens (`<\|im_start\|>`, `[INST]`, DeepSeek's fullwidth `<｜User｜>`, ...) via exact/Unicode-normalized/structural/encoded matching — in definitions *and* tool call output |
| Cross-Tool Composition Risk | Flags a server exposing both a sensitive-data-access tool and an egress-capable tool — individually benign, chainable into exfiltration |
| Rug-Pull Detection | HMAC-signed SHA-256 schema fingerprinting; `check` detects both unexpected tool changes *and* tampered baseline files |
| Behavioral / ATPA Detection | Calls tools and inspects responses for the benign→malicious time-bomb signature, output injection, and exfil instructions |
| LLM Semantic Judge (opt-in) | `--llm-judge` sends descriptions to Claude to catch paraphrased poisoning that dodges static signatures |
| OAuth 2.1 Detection | Reports MCP 2025-06-18 OAuth-protected servers clearly (401 + `WWW-Authenticate`) instead of a generic error |
| Continuous Monitoring | `watch` re-scans on an interval and alerts a webhook on newly-observed findings |
| Engagement Scope Guardrails | `--engagement` refuses to scan targets outside an authorized-scope file |
| Client-Ready Reporting | `--format pentest` — engagement header, executive summary, methodology, evidence, remediation |
| Retest Workflow | `retest --baseline <report>` diffs a re-scan into Fixed / Still Present / New |
| OWASP Mapping | Labels findings across the OWASP MCP Top 10 (active detection for MCP01, MCP02, MCP03, MCP05) |

### Offensive Tooling

| Tool | What It Simulates |
|---|---|
| Description Injection Server | Classic Tool Poisoning Attacks using malicious tool descriptions |
| FSP Generator | CyberArk-style schema poisoning variants |
| ATPA Server | Behavioral poisoning that becomes malicious after a configurable threshold |
| Rug-Pull Server | Serves clean tools initially, then swaps to malicious definitions |
| Tool Shadowing Server | Mimics trusted tool names while embedding injected payloads |
| STI Simulation Server | Benign tool definitions; injects a chat-template control token into responses after a configurable call threshold |

---

## Installation

### From PyPI (recommended)

```bash
pip install mcp-tool-auditor
```

Or run it without installing anything into your environment, via [uv](https://docs.astral.sh/uv/):

```bash
uvx mcp-tool-auditor --help
```

The default install is offline and needs no API key or token — it's `pyyaml` and
`requests`, nothing else. The optional LLM semantic judge (`--llm-judge`) is a separate
extra so it doesn't pull in an API client or require credentials for everyone:

```bash
pip install 'mcp-tool-auditor[llm]'
```

### From source (development)

```bash
git clone https://github.com/perparimmjeku/mcp-tool-auditor.git
cd mcp-tool-auditor
python -m pip install -e ".[dev]"
python -m pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow and
[RELEASING.md](RELEASING.md) for how versions get published to PyPI.

---

## Quick Start

### Scan an MCP Server

```bash
mcp-tool-auditor scan url http://localhost:8080/mcp
```

### Generate a Markdown Report

```bash
mcp-tool-auditor scan url http://localhost:8080/mcp \
  --format markdown \
  -o report.md
```

### Scan MCP Servers from a Configuration File

```bash
mcp-tool-auditor scan config \
  ~/.config/Claude/claude_desktop_config.json
```

### Register a Baseline Fingerprint

```bash
mcp-tool-auditor register url http://localhost:8080/mcp
```

Baselines are HMAC-SHA256 signed, so `check` can tell a legitimate tool change from a
tampered/forged baseline file (`RUGPULL_BASELINE_TAMPERED`). By default the signing key is
a local file (`~/.mcp-tool-auditor/fingerprints/.hmac_key`); for CI use, supply your own
out-of-band key so the key and the baseline file don't share a trust boundary:

```bash
export MCP_TOOL_AUDITOR_BASELINE_KEY="$(openssl rand -hex 32)"   # store in your CI secrets
```

### Check for Rug-Pull Changes

```bash
mcp-tool-auditor check url http://localhost:8080/mcp
```

### Continuous Monitoring

Point-in-time scans miss drift that happens between runs. `watch` re-scans on an interval
and POSTs newly-observed findings to a webhook (Slack/Discord/PagerDuty/anything with a
webhook endpoint):

```bash
mcp-tool-auditor watch url http://localhost:8080/mcp \
  --interval 300 \
  --check-rugpull \
  --webhook https://hooks.example.com/services/T000/B000/XXXX
```

Each finding is alerted once (in-memory dedup for the process's lifetime), so a standing
issue doesn't repeat-alert every interval.

### Behavioral / ATPA Detection

Static scans read tool *definitions*; behavioral probing actually calls tools and
inspects their *responses* to catch Advanced Tool Poisoning Attacks (ATPA) — tools
that act benign, then return poisoned output after a few calls.

```bash
# Live probe (executes real tool calls — authorized testing only)
mcp-tool-auditor behavior url http://localhost:8080/mcp --calls 6 --yes
mcp-tool-auditor behavior stdio --calls 6 -- npx @modelcontextprotocol/server-everything

# Offline: analyze a recorded transcript (tool name -> list of response strings)
mcp-tool-auditor behavior import responses.json --format json
```

Findings: `BEHAV_ATPA_TRANSITION` (benign→malicious time-bomb), `BEHAV_OUTPUT_INJECTION`,
`BEHAV_RESPONSE_DIVERGENCE`, and `BEHAV_CALL_ERROR`. Live modes require an
authorization acknowledgement (`--yes` or `MCP_TOOL_AUDITOR_ASSUME_AUTHORIZED=1`).

### Authenticated Scanning (real engagements)

```bash
# Auth header + route through Burp; tune signal with confidence and suppressions
mcp-tool-auditor scan url https://target/mcp \
  -H "Authorization: Bearer $TOKEN" \
  --proxy http://127.0.0.1:8080 \
  --min-confidence HIGH \
  --suppress HEUR_IMPERATIVE
```

Findings carry a **confidence** level (HIGH/MEDIUM/LOW); `--min-confidence` filters
noisy heuristics and `--suppressions <file>` silences accepted false positives.
URL transport speaks full MCP Streamable HTTP (session id + protocol-version headers) at
protocol version `2025-06-18`. If the server requires OAuth 2.1, the scan reports a clear
`OAUTH_REQUIRED` finding (with protected-resource metadata, if discoverable) instead of a
generic HTTP error — complete the OAuth flow yourself and pass the resulting bearer token
via `--header`; this tool does not perform interactive OAuth login.

### LLM Semantic Judge (opt-in)

Static signatures and heuristics match fixed phrases; an attacker can dodge them by
rephrasing the same intent differently. `--llm-judge` sends tool/resource/prompt text to
Claude and asks it to judge intent instead of pattern-match text:

```bash
pip install 'mcp-tool-auditor[llm]'
export ANTHROPIC_API_KEY="sk-ant-..."
mcp-tool-auditor scan url http://localhost:8080/mcp --llm-judge
```

This is opt-in only and never runs by default — it sends third-party server content to
Anthropic's API, which is a data-handling decision the operator must make explicitly.
Flagged items get the `LLM_SEMANTIC_POISONING` rule (MEDIUM confidence; review the exact
wording before rejecting a tool on this alone).

### Real Pentest Engagements: Scope, Client Reports, Retest

Three pieces built specifically for running this as part of a real, authorized
engagement rather than a CI job:

**1. Engagement/scope file** — declare the authorized scope once; scans against a
stdio/url target outside it are refused before anything touches the network:

```json
{
  "client": "Acme Corp",
  "tester": "J. Doe",
  "start_date": "2026-07-01",
  "end_date": "2026-07-15",
  "notes": "Authorized MCP tool poisoning assessment, ref. SOW-1234",
  "allowed_targets": ["https://*.acme-client.example.com/*", "https://mcp.acme.example.com/mcp"]
}
```

```bash
mcp-tool-auditor --engagement engagement.json scan url https://mcp.acme.example.com/mcp
# scan url https://other-company.example.com/mcp would be refused before connecting
```

`allowed_targets` entries are exact strings or shell-glob patterns. An engagement file
with no `allowed_targets` still works — it just carries report metadata (client/tester/
dates) without restricting scope. Scope is enforced for `scan stdio`/`url`, `behavior
stdio`/`url`, `watch url`, `register`, and `check`; `scan config`/`local`/`watch config`
don't currently enforce it per-server since they aggregate arbitrary local configs.

**2. Client-ready reports** — `--format pentest` produces an engagement header,
executive summary, methodology section, and full evidence (the actual tool/resource/
prompt text) plus remediation guidance per finding — built to hand to a client, not
just a CI log:

```bash
mcp-tool-auditor --engagement engagement.json scan url https://mcp.acme.example.com/mcp \
  --format pentest -o report.md
```

**3. Retest** — after the client remediates, re-scan and diff against the original
report to show what's Fixed / Still Present / New:

```bash
mcp-tool-auditor scan url https://mcp.acme.example.com/mcp --format json -o baseline.json
# ... client remediates ...
mcp-tool-auditor retest --baseline baseline.json url https://mcp.acme.example.com/mcp \
  --format pentest -o retest-report.md
```

`--fail-on` on `retest` gates on unresolved findings only (Still Present + New) — a
clean retest where everything's Fixed exits 0.

### Auto-Discover and Scan Local MCP Configs

```bash
# Finds and scans configs for Claude Desktop, Cursor, VS Code, Windsurf, Zed
mcp-tool-auditor scan local
```

### Export SARIF and Explain Findings

```bash
# SARIF for GitHub code-scanning / GitLab / DefectDojo ingestion
mcp-tool-auditor scan import tools.json --format sarif -o results.sarif

# Get remediation guidance for any finding rule
mcp-tool-auditor explain BEHAV_ATPA_TRANSITION
mcp-tool-auditor explain --list
```

SARIF 2.1.0 output is deterministic — `driver.rules[]` sorted by rule id and
`results[]` sorted by `(ruleId, tool_name, field, message)`, so re-scanning
unchanged findings produces byte-identical output and diffs cleanly in CI. Each
`reportingDescriptor` carries `helpUri` (links `docs/RULES.md`) alongside the existing
remediation text, plus an empty `atlas_ids` placeholder in `properties` so a future
MITRE ATLAS mapping can be added without a schema change. Each result's `properties`
bag carries `owasp_id`, `attack_type`, `confidence`, and `retest_status` (present —
`null` on a plain scan, set on `retest --format sarif`) so nothing from a `Finding` is
lost in translation, and DefectDojo's generic SARIF importer picks all of it up.

### Source-Scan (Prompt-In-Shell-Out)

Goes one level deeper than definitions/behavior: reads an MCP server's **source code**
(Python via AST, JS/TS via heuristics) and flags shell-injection sinks fed by
LLM-controlled tool arguments — `subprocess(shell=True)`, `os.system`, `child_process.exec`, etc.

```bash
mcp-tool-auditor source-scan ./my-mcp-server                 # human-readable
mcp-tool-auditor source-scan ./my-mcp-server --format sarif  # code-scanning
mcp-tool-auditor source-scan ./my-mcp-server --fail-on CRITICAL  # CI gate
```

It only opens files that import an MCP SDK, so it won't flag shell calls in unrelated code.

### Special Token Injection (STI)

Chat-template control tokens (`<|im_start|>`, `[INST]`, `<|start_header_id|>`, DeepSeek's
fullwidth `<｜User｜>`, and more — registry in `signatures/sti_tokens.yaml`, grouped by
model family, easy to extend via PR) spoof or close a conversation turn in whatever prompt
an MCP client eventually builds from tool/resource/prompt text. Runs by default across all
four surfaces, plus tool call *output* (`behavior` command) to catch a token a tool only
emits after N calls:

```bash
mcp-tool-auditor scan url http://localhost:8080/mcp          # exact/normalized/structural tiers
mcp-tool-auditor scan url http://localhost:8080/mcp --sti-decode  # + bounded base64/hex tier
mcp-tool-auditor behavior url http://localhost:8080/mcp --calls 6 --yes  # scans tool output too
```

`--sti-decode` is opt-in and off by default: it only considers length-banded base64/hex
substrings (never "decode every string"), and only compares decoded bytes against the
token registry, never the looser structural shape check — bounding both cost and false
positives. Findings: `STI_EXACT`/`STI_NORMALIZED` (HIGH confidence — obfuscation is *more*
suspicious than the plain token, not less), `STI_STRUCTURAL`/`STI_ENCODED` (MEDIUM). A tool
that legitimately documents a token (e.g. a Llama-2 prompt-formatting helper mentioning
`[INST]`) still produces a finding — detection can't tell intent from text alone — but it's
suppressible like any other rule (`--suppress STI_EXACT` or a suppressions file entry).

### Generate Offensive Test Servers

```bash
mcp-tool-auditor generate all --output-dir ./pentest_servers
```

---

## CI/CD Integration

Gate merges on poisoning findings and upload results to GitHub Security.

### GitHub Action

```yaml
# .github/workflows/mcp-audit.yml
name: MCP Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # to upload SARIF
    steps:
      - uses: actions/checkout@v4

      - name: Scan tool definitions
        uses: perparimmjeku/mcp-tool-auditor@main
        with:
          command: scan import tools.json --format sarif -o mcp.sarif --fail-on HIGH

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp.sarif
```

> Until the package is on PyPI, point the action at the repo:
> `with: { install-spec: "git+https://github.com/perparimmjeku/mcp-tool-auditor.git" }`

### Plain CLI in any pipeline

```bash
# Exit code 2 if any HIGH+ finding is present — fails the build
mcp-tool-auditor scan import tools.json --fail-on HIGH
```

### Verbose Output, Logs, and Metrics

```bash
mcp-tool-auditor -v scan import tests/fixtures/poisoned_tools.json
```

By default, structured logs are written under `~/.mcp-tool-auditor/logs` and scan
metrics are appended to `~/.mcp-tool-auditor/metrics.jsonl`. Use `--no-log-file`
or `--no-metrics` to disable those side effects for a run.

### Configuration

```bash
mcp-tool-auditor --config ./config.yaml scan url http://localhost:8080/mcp
```

The CLI accepts JSON or YAML config files. CLI flags still take precedence for
scan output format and minimum severity.

### Offensive Simulation Acknowledgement

```bash
mcp-tool-auditor attack --yes atpa --port 8080 --threshold 3
```

Offensive simulation servers show an authorization warning before they start.
Use `--yes` only for non-interactive, authorized lab runs.

---

## Detection Coverage & Sample Reports

- **[docs/RULES.md](docs/RULES.md)** — full catalog of all 74 detection rules with confidence levels.
- **Sample output** from a poisoned fixture: [markdown](docs/samples/sample-report.md) ·
  [json](docs/samples/sample-report.json) · [sarif](docs/samples/sample-report.sarif).

---

## OWASP MCP Top 10 Mapping

| OWASP ID | Issue | Detection |
|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | `ST_IGNORE_PREVIOUS`, `ST_BYPASS`, `ST_IGNORE_SECURITY` |
| MCP02 | Privilege Escalation via Scope Creep | `HEUR_AGENCY`, `COMPOSITION_CONFUSED_DEPUTY`, credential-related signatures |
| MCP03 | Tool Poisoning | Signatures, heuristics, FSP, rug-pull/shadowing, STI (`STI_EXACT`/`STI_NORMALIZED`/`STI_STRUCTURAL`/`STI_ENCODED`), and behavioral/ATPA detection |
| MCP05 | Command Injection & Execution | `ST_EXECUTE`, `ST_CODE_EXEC`, command-related schema findings |

Findings are actively emitted for **MCP01, MCP02, MCP03, and MCP05**. Reports also
recognize the remaining OWASP MCP Top 10 IDs (MCP04, MCP06–MCP10) by label, but the
current analyzers do not yet emit findings for them.

---

## Offensive Testing Examples

```bash
# Start an ATPA simulation server
mcp-tool-auditor attack atpa --port 8080 --threshold 3

# Start a rug-pull simulation server
mcp-tool-auditor attack rugpull --port 8081 --switch-after 5

# Start an STI (Special Token Injection) simulation server -- benign
# definitions, injects a chat-template control token into responses
# after --threshold calls
mcp-tool-auditor attack sti --port 8082 --threshold 3

# Generate standalone attack servers
mcp-tool-auditor generate all --output-dir ./test_servers

python ./test_servers/server_description_injection.py
```

---

## Architecture

```text
mcp-tool-auditor/
├── mcp_tool_auditor/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── logging_config.py
│   ├── metrics.py
│   ├── security.py
│   ├── validation.py
│   ├── watch.py
│   ├── engagement.py
│   ├── auditor/
│   │   ├── __init__.py
│   │   ├── scanner.py
│   │   ├── models.py
│   │   ├── discovery.py
│   │   ├── remediation.py
│   │   ├── analyzers/
│   │   │   ├── __init__.py
│   │   │   ├── static.py
│   │   │   ├── heuristic.py
│   │   │   ├── schema.py
│   │   │   ├── rugpull.py
│   │   │   ├── behavioral.py
│   │   │   ├── composition.py
│   │   │   ├── llm_judge.py
│   │   │   ├── sti.py
│   │   │   ├── surface.py
│   │   │   └── patterns.py
│   │   ├── signatures/
│   │   │   ├── __init__.py
│   │   │   ├── descriptions.yaml
│   │   │   ├── parameters.yaml
│   │   │   └── sti_tokens.yaml
│   │   └── reporters/
│   │       ├── __init__.py
│   │       ├── json_reporter.py
│   │       ├── markdown_reporter.py
│   │       ├── pentest_reporter.py
│   │       └── sarif_reporter.py
│   └── offensive/
│       ├── __init__.py
│       ├── poisoner.py
│       ├── atpa_server.py
│       ├── rugpull_sim.py
│       └── sti_server.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_scanner.py
│   ├── test_patterns.py
│   ├── test_behavioral.py
│   ├── test_behavior_integration.py
│   ├── test_cli_behavior.py
│   ├── test_confidence_suppressions.py
│   ├── test_discovery.py
│   ├── test_engagement.py
│   ├── test_http_auth_session.py
│   ├── test_llm_judge.py
│   ├── test_pentest_reporter.py
│   ├── test_remediation.py
│   ├── test_retest.py
│   ├── test_rugpull_signing.py
│   ├── test_sarif_reporter.py
│   ├── test_scope_enforcement.py
│   ├── test_source_scan.py
│   ├── test_sti_analyzer.py
│   ├── test_sti_behavioral.py
│   ├── test_sti_offensive.py
│   ├── test_surface_scanning.py
│   ├── test_watch.py
│   └── fixtures/
│       ├── __init__.py
│       ├── poisoned_tools.json
│       └── source/
├── config.yaml
├── pyproject.toml
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── README.md
```

---

## Configuration

See `config.yaml` for example scanner settings. Pass a config file with `--config`
(JSON or YAML); CLI flags override the file for output format and minimum severity.

### Default Configuration

```yaml
auditor:
  severity_threshold: MEDIUM

  heuristic_analysis:
    description_length_threshold: 500
    imperative_threshold: 2

  schema_analysis:
    check_fsp_params: true
    check_required_array: true
    check_enum_values: true
```

---

## Contributing

Pull requests are welcome.

Please see `CONTRIBUTING.md` for development guidelines, coding standards, and testing procedures.

Security issues should follow `SECURITY.md`.

---

## License

MIT License — see the `LICENSE` file for details.

---

## Legal Disclaimer

This tool is intended strictly for:

- Authorized penetration testing
- Defensive security research
- Educational and lab environments
- Controlled validation of MCP security controls

Users must have explicit permission before testing any target systems.

The authors assume no liability for misuse, unauthorized testing, or damages caused by improper use of this software.

---

## Package Metadata

### `mcp_tool_auditor/__init__.py`

```python
"""MCP Tool Auditor package."""

__version__ = "1.6.0"
__author__ = "Përparim Mjeku"
__license__ = "MIT"
```
