# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] - 2026-07-12

### Added
- **PyPI-installable packaging, verified end-to-end** — the `pyproject.toml`,
  `importlib.resources`-based signature loaders, and OIDC-based
  `.github/workflows/publish.yml` already supported this; this release is the
  verification and documentation to actually rely on it: built a wheel and sdist,
  installed the wheel into a throwaway venv, and ran a real scan *from outside the
  repo* confirming both `descriptions.yaml`- and `sti_tokens.yaml`-backed rules fire
  from the installed package (not a source-tree fallback). `twine check` passes on
  both artifacts.
- **`RELEASING.md`** — one-time PyPI Trusted Publisher setup plus the per-release
  steps (version bump, build, twine check, throwaway-venv smoke test, optional
  TestPyPI dry run, tag, GitHub Release to trigger the real publish).
- README Installation section now leads with `pip install mcp-tool-auditor` and
  `uvx mcp-tool-auditor --help`; git-clone moved to a "From source (development)"
  section. Notes the default install is offline/no-API-key (`pyyaml` + `requests`
  only) and that `--llm-judge` is the separate `[llm]` extra.

### Removed
- **`signatures/parameters.yaml`** — shipped in every wheel/sdist but never loaded
  by any code path (`StaticAnalyzer` loads `descriptions.yaml` by explicit name, not
  a directory glob). Confirmed via repo-wide grep before deleting; verified the
  rebuilt wheel no longer includes it. `docs/RULES.md` documents several rule ids
  matching this file's content that were never actually emitted even before this
  change (`SchemaAnalyzer` emits generic `FSP_PARAM_NAME`/`FSP_INJECTION_PARAM`
  instead) — pre-existing doc drift, left for a future pass.

## [1.6.0] - 2026-07-12

### Fixed
- **Non-deterministic SARIF output** — `driver.rules[]` and `results[]` followed
  scan/insertion order, not a stable sort, so two identical re-scans could produce
  byte-different SARIF and break clean CI diffing. Both are now sorted (rules by
  id; results by `(ruleId, tool_name, field, message)`).

### Added
- **SARIF `helpUri`** on every `reportingDescriptor`, alongside the existing
  remediation `help.text` — links `docs/RULES.md`.
- **SARIF `atlas_ids` placeholder** (empty array) in rule `properties`, so a future
  MITRE ATLAS mapping can be added without a schema/structure change.
- **SARIF `retest_status` in result `properties`** — was silently dropped, so
  `retest --format sarif` lost the Fixed/Still Present/New distinction on render.
  Present (`null` on a plain scan) rather than absent, so consumers can rely on
  the key existing.
- Regenerated `docs/samples/sample-report.sarif` to reflect the above; confirmed
  re-generating it twice produces byte-identical output.

## [1.5.0] - 2026-07-12

### Added
- **Special Token Injection (STI) detection** — a new analyzer catches text that spoofs
  or closes a model's native chat-template control tokens (`<|im_start|>`, `[INST]`,
  `<|start_header_id|>`, DeepSeek's fullwidth `<｜User｜>`, and more) to hijack the
  conversation-turn boundary of whatever prompt an MCP client builds from tool/resource/
  prompt/instructions text.
  - Token registry as data (`signatures/sti_tokens.yaml`), grouped by model family
    (ChatML/OpenAI/Qwen, Llama 2/Mistral, Llama 3, Gemma, Phi, Command R, DeepSeek,
    Anthropic-legacy), easy to extend via PR.
  - Four matching tiers: `STI_EXACT`/`STI_NORMALIZED` (HIGH confidence — Unicode
    NFKC + homoglyph-folded obfuscation is *more* suspicious than the plain token, not
    less), `STI_STRUCTURAL` (MEDIUM — unrecognized-but-token-shaped text), `STI_ENCODED`
    (MEDIUM, opt-in via `--sti-decode`, off by default — bounded-length base64/hex only,
    decoded bytes compared only against the registry, never the structural check).
  - Runs across all four surfaces (tools/resources/prompts/instructions) automatically.
  - Also scans tool call *output*, not just definitions: `BEHAV_STI_TRANSITION`
    (CRITICAL — a control token appears only after benign calls, the time-bomb pattern
    a definition-only scan can't see) and `BEHAV_STI_OUTPUT` (HIGH — present from the
    first call), independent of the existing keyword-based ATPA detection.
  - New offensive tooling: two static `generate` vectors (plain ChatML injection,
    homoglyph-obfuscated DeepSeek token) and a live `attack sti` time-bomb simulation
    server mirroring the existing ATPA server's call-count-gated structure.
  - A tool that legitimately documents a token (e.g. a Llama-2 prompt-formatting helper)
    still produces a finding — detection can't tell intent from text alone — but it's
    suppressible through the existing suppressions mechanism like any other rule.

## [1.4.0] - 2026-07-12

### Added
- **Engagement/scope guardrails (`--engagement <file>`)** — declare authorized targets
  (`allowed_targets`, exact or glob) plus client/tester/date metadata once; `scan
  stdio`/`url`, `behavior stdio`/`url`, `watch url`, `register`, and `check` refuse to
  touch a target outside scope before making any network/subprocess call.
- **Client-ready reports (`--format pentest`)** — engagement header, executive summary,
  methodology (derived from what actually ran), and per-finding evidence (the real
  tool/resource/prompt text that triggered it) plus remediation guidance. The existing
  markdown/JSON/SARIF formats stay CI/dev-facing; this one is built to hand to a client.
- **`retest --baseline <report>`** — re-scans and diffs against a prior `--format json`
  report into Fixed / Still Present / New. Matches findings by (rule, tool, field) when
  there's one target on each side (so two differently-named snapshots of "the same
  target" still diff correctly), or by server name for multi-target config/local
  baselines. `--fail-on` gates on unresolved (Still Present + New) findings only.

## [1.3.0] - 2026-07-12

### Added
- **Multi-surface scanning** — `resources/list`, `prompts/list`, and the server's top-level
  `instructions` string from `initialize` are now scanned alongside tools, since all three
  are documented poisoning vectors. Findings from these surfaces reuse the tool rule ids
  with a `RES_`/`PROMPT_`/`INSTR_` prefix.
- **MCP 2025-06-18 protocol version** (was 2025-03-26), plus **OAuth 2.1 detection** —
  a 401 with `WWW-Authenticate` is now reported as a clear `OAUTH_REQUIRED` finding
  (with protected-resource metadata, if discoverable) instead of a generic HTTP error.
  No interactive OAuth login is performed; supply a bearer token via `--header` once
  you've completed the flow yourself.
- **Cross-tool composition risk (`COMPOSITION_CONFUSED_DEPUTY`)** — flags a server that
  exposes both a sensitive-data-access tool and a separate egress-capable tool, since an
  agent with both in one session can chain them to exfiltrate data even when neither tool
  looks poisoned alone.
- **HMAC-signed rug-pull baselines** — `register`/`check` now sign baselines with
  HMAC-SHA256 so tampering with the fingerprint file on disk is detected
  (`RUGPULL_BASELINE_TAMPERED`) instead of silently trusted. The signing key is local by
  default, or supply `MCP_TOOL_AUDITOR_BASELINE_KEY` (e.g. a CI secret) so the key and the
  baseline file don't share a trust boundary. Pre-signing baselines still work
  (`RUGPULL_BASELINE_UNSIGNED` nudges you to re-register).
- **Optional LLM semantic judge (`--llm-judge`)** — sends tool/resource/prompt text to
  Claude to catch paraphrased poisoning that dodges static signatures. Opt-in only, never
  a scan default (it sends third-party server content to Anthropic's API); requires
  `ANTHROPIC_API_KEY` and `pip install 'mcp-tool-auditor[llm]'`.
- **`watch` command** — continuously re-scans a server/config on an interval and POSTs
  newly-observed findings to a webhook URL (`--webhook`), for production monitoring
  beyond the point-in-time `scan`/`check` commands.

### Fixed
- **Coverage measurement blind spot** — CLI-invoking tests spawn `mcp_tool_auditor.cli`
  in a subprocess, which coverage.py never traced; `cli.py`, `logging_config.py`, and
  the reporters showed as 0-40% covered despite being exercised by real tests. Added
  subprocess coverage tracking (`tests/conftest.py` + `sitecustomize.py` hook,
  `parallel`/`relative_files` in `[tool.coverage.run]`); true coverage is over 70%, not 50%.

### CI/CD & supply chain
- **CI coverage gate** (`--cov-fail-under=68`) so coverage can't silently regress.
- **CodeQL analysis** (`.github/workflows/codeql.yml`) for Python static analysis on
  push/PR/weekly schedule.
- **Dependency vulnerability audit** (`pip-audit`) as a CI job.
- **Dependabot** for pip and GitHub Actions dependency updates.
- **`.dockerignore`** so the published image doesn't ship `.git`, tests, docs, and caches.
- `ci.yml` now sets explicit least-privilege `permissions: contents: read`.
- `action.yml` passes `install-spec`/`command` inputs through `env:` instead of
  interpolating them directly into `run:`, closing a shell-injection footgun for
  downstream workflows that source those inputs from untrusted values.
- `.gitignore` now covers `.mypy_cache/`, `.ruff_cache/`, and parallel `.coverage.*` files.

## [1.2.0] - 2026-06-23

### Added
- **Authenticated scanning & proxy** — `--header "Authorization: Bearer ..."` (repeatable)
  and `--proxy` on URL scan/behavior, so the tool works against auth-protected MCP
  servers and can route through an intercepting proxy (Burp) in real engagements.
- **Full MCP Streamable HTTP** — captures `Mcp-Session-Id` and sends it plus
  `MCP-Protocol-Version` on post-initialize requests.
- **Confidence scoring** — findings carry HIGH/MEDIUM/LOW confidence (in JSON/SARIF);
  `--min-confidence` filters noisy heuristics.
- **Suppressions** — `--suppress RULE` and `--suppressions FILE` to silence accepted
  false positives by rule (optionally scoped to a tool).
- **mypy** type-checking in CI (clean across the codebase).

## [1.1.0] - 2026-06-23

### Added
- **Behavioral / ATPA detection** — a runtime analyzer (`behavior` command) that
  calls tools and inspects their responses to catch Advanced Tool Poisoning
  Attacks: benign-then-malicious "time-bomb" output (`BEHAV_ATPA_TRANSITION`),
  output injection, response divergence, and call errors. Works live
  (`behavior stdio` / `behavior url`) or offline (`behavior import`).
- **SARIF 2.1.0 output** (`--format sarif`) for GitHub code-scanning / GitLab,
  with severity mapping, security-severity scores, OWASP tags, and remediation
  in rule help text.
- **`--fail-on SEVERITY` CI gate** — exits non-zero (code 2) when a finding meets
  the threshold, so pipelines can fail builds on poisoning findings.
- **`explain <rule>` command** and per-rule remediation guidance.
- **`scan local`** — auto-discovers and scans MCP configs for Claude Desktop,
  Cursor, VS Code (Continue), Windsurf, and Zed, plus project-local `mcp.json`.
- **SSE / streamable-HTTP transport** for URL scanning and probing, so `scan url`
  and `behavior url` work against real-world MCP servers, not just simple servers.
- **GitHub Action** (`action.yml`) for one-step CI integration.

### Changed
- Consolidated packaging into `pyproject.toml` (removed `setup.py`); version is
  single-sourced from `mcp_tool_auditor.__version__`.
- Shared injection patterns extracted into `analyzers/patterns.py`.

### Fixed
- Restored the MIT `LICENSE`; stopped tracking `egg-info` build artifacts.
- Corrected README OWASP/architecture/test-command documentation to match the code.

## [1.0.0] - 2026

### Added
- Initial release: static signature, heuristic, schema/FSP, and rug-pull analyzers
  mapped to the OWASP MCP Top 10, plus offensive ATPA/rug-pull simulators.

[1.7.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.7.0
[1.6.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.6.0
[1.5.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.5.0
[1.4.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.4.0
[1.3.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.3.0
[1.2.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.2.0
[1.1.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.1.0
[1.0.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.0.0
