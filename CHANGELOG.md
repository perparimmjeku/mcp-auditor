# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.10.0] - 2026-07-13 — Detection precision & honest confidence

The signature engine no longer treats a security-relevant *word* as a security
*vulnerability*. Keyword matches without corroborating context no longer emit
HIGH-confidence findings.

### Fixed
- **Confidence calibration:** removed a blanket rule that promoted every signature
  match to HIGH. Keyword rules (credential/exfil/code-exec/sensitive) now baseline to
  LOW/INFO and only escalate with real corroborating context. Enforced invariant:
  confidence never exceeds severity.
- **Context classifiers:** "token offset" (pagination) no longer reads as a credential;
  a `.tar.gz` resource is reported as an uninspected archive (INFO), not code execution;
  open-world/HTTP capability alone is not exfiltration; a keyword in an *output* schema
  is weaker signal than in an input. Word-boundary matching kills substring false
  positives (e.g. "eval" inside a filename).
- **Rule-specific remediation:** each finding now describes what it actually matched,
  instead of a generic tool-poisoning message.
- **New `ST_ARCHIVE_UNINSPECTED` (INFO)** and **`SRC_DYNAMIC_CODE_EXEC`** (routes real
  eval/exec detection to source-scan, where it can be proven against actual code).
- Restored `ST_DATA_EXFIL` detection on `https://` URLs (word-boundary regression).

### Added
- Two-sided regression fixtures: a real-world-modeled benign server (produces only
  INFO/LOW) and the existing known-poisoned fixture (still fires at intended severity)
  — permanent guards against both false positives and missed detections.

## [1.9.0] - 2026-07-12

### Added
- **Cross-server toxic-flow analysis** — the real exfiltration risk on a live engagement
  is usually ACROSS servers, not within one: an agent session has tools from several MCP
  servers active at once, and a data-reading tool on one server plus an egress-capable
  tool on a different server form a chain that no single-server scan can see, even
  though neither tool looks poisoned alone. `scan config`/`scan local` now check the
  combined multi-server tool surface for this automatically.
  - New reusable capability classifier (`analyzers/capability.py`) tags each tool SOURCE
    (reads sensitive data: files, secrets, env, db, browser, credentials), SINK (can
    egress: http/network, email/messaging, external writes), or SENSITIVE_ACTION
    (destructive/state-changing), reusing the existing composition.py/heuristic.py
    signature-matching approach rather than a fresh classifier.
  - New `analyzers/flow.py` (sibling to `composition.py`, not merged into it — needs the
    whole multi-server results dict, not one server's tool list). Two rules:
    `FLOW_SENSITIVE_SINK` (MEDIUM) for a generic cross-server SOURCE+SINK pairing with no
    evidence of wiring — deliberately restrained so it doesn't fire on every multi-server
    host with unrelated file and http tools; `FLOW_CROSS_SERVER_EXFIL` (HIGH, or CRITICAL
    when the source is credential/secret-grade) for a pair where one tool's description
    references the other by name — concrete evidence the pairing is intentional.
    Same-server pairs are still `COMPOSITION_CONFUSED_DEPUTY`'s job, not this family's.
  - New multi-origin `Finding` fields (`related_tool`, `related_server`) and a synthetic
    `__cross_server__` results-dict entry for findings that implicate two servers at
    once — purely additive, every existing single-origin finding is unchanged. Excluded
    from "servers scanned"/"targets assessed" counts across all reporters and scan
    metrics; its findings still count toward severity/OWASP totals.
  - On by default (pure local static analysis over tool definitions already fetched
    during the scan — unlike `--llm-judge`/`--sti-decode`/`--sti-tokenizer`, no external
    call, no cost, no extra dependency to justify opt-in). Disable with
    `--no-cross-server-flow`. Findings are suppressible like any other rule.
  - New `tests/test_rules_doc_drift.py` guards `docs/RULES.md`'s rule catalog against
    the rule ids the scanner actually emits (derived from source, not hardcoded) in both
    directions — catches an emitted-but-undocumented rule and a documented-but-phantom
    one, the exact class of drift a prior session found and fixed by hand.
- **`inventory` — host discovery + blast-radius mapping.** Turns the existing config
  discovery (`discovery.py`) into a first-class recon deliverable: every MCP server
  configured on the machine, its declared capabilities, its blast radius if
  compromised, and the worst cross-server chain reaching it — reusing the capability
  classifier and `flow.analyze()` rather than reinventing either.
  - **Static tier (default, no execution):** a new read-only parser
    (`discovery.parse_server_entries`) reads every client config's server entries
    without spawning anything — command/args/env-var **names** (never values, and
    never even read past `.keys()`), url-based entries `scan config` silently ignores
    today, and a first-/third-party origin guess with reasoning. A tool never ran, so
    capability tags here are a guess from launch metadata — always labeled INFERRED,
    never presented as confirmed.
  - **New rule `INV_INFERRED_CHAIN`** (MEDIUM, hard ceiling — inference alone can never
    reach HIGH/CRITICAL regardless of how "coupled" the guess looks): reuses
    `flow.analyze()`'s real pairing/coupling logic unmodified over synthesized
    pseudo-tools, never reimplements it. Message always says "run `--probe` to
    confirm." Once `--probe` confirms both endpoints, the pairing reports as a real
    `FLOW_SENSITIVE_SINK`/`FLOW_CROSS_SERVER_EXFIL` finding instead and the inferred
    one is dropped for that pair — never both at once.
  - **`--probe` (opt-in, gated):** connects read-only and enumerates real
    tools/resources/prompts to confirm the static guess — reuses
    `scan_server_stdio`/`scan_server_url` unmodified, which only ever call
    initialize/tools-list/resources-list/prompts-list, so "enumeration only, never
    invoke a tool" is enforced by construction. Same authorization gate as
    `behavior`/`attack` (banner + ack, `--yes`/`MCP_TOOL_AUDITOR_ASSUME_AUTHORIZED`),
    plus per-server engagement scope enforcement — an out-of-scope or unreachable
    server falls back to the static guess for that one server rather than aborting
    the run.
  - **Three outputs, one run:** a markdown/pentest host-risk report (confirmed vs.
    inferred visibly badged ✅/🔍 on every server and every chain, not just a JSON
    field nobody reads) with an embedded Mermaid graph (servers as nodes,
    chains as edges, edge color = severity tier, edge/node line style = confirmed
    vs. inferred — a benign host renders calm, not red); deterministic JSON and SARIF
    (secret-redacted by construction, reusing `Finding.to_dict()`/`SarifReporter`
    for the chain findings) for SOC/CMDB/DefectDojo ingestion.
  - Found and fixed two real bugs while building this: `require_ack()`'s prompt
    crashed with an uncaught `EOFError` when `--probe` ran non-interactively without a
    TTY (now falls back to static cleanly, same as any other declined case), and the
    authorization banner/prompt wrote to stdout by default, which would have
    corrupted a piped/redirected `--format json`/`sarif` report — both moved to
    stderr, fixing the same latent gap in the existing `behavior`/`attack` commands
    too.
- **Signed, verifiable pentest reports (chain-of-custody).** `--sign` (any
  `scan`/`retest`/`source-scan`, any `--format`) writes a `.sig` sidecar binding the
  findings, engagement scope (client/tester/dates/targets), and tool version — not the
  report's bytes, so the human-readable report stays freely editable (reformatted,
  annotated, exported to PDF) without invalidating the signature. New `verify-report`
  subcommand reports VALID/TAMPERED/INVALID (exit 0/2, CI-gate-ready).
  - New `auditor/signing.py`: the HMAC-SHA256 primitive extracted verbatim from
    `RugPullDetector`'s existing baseline signing (`load_or_create_key`/`sign`,
    identical key-file/env-var-override logic and canonical-JSON construction),
    reused rather than duplicated — verified the extraction against the existing
    rug-pull signing test suite unchanged (5/5 still pass).
  - New `auditor/report_signing.py` builds a canonical, deterministic payload
    (findings — each stamped with which server it came from, so re-attributing a
    finding to hide it was in-scope is caught too — engagement metadata, tool
    version, explicitly sorted) straight from the same `results`/`engagement` data
    `PentestReporter` already renders from, and signs *that*, not the rendered
    markdown. Verified with the load-bearing test: reformatting/annotating an
    already-signed report's text doesn't affect verification at all.
  - Deliberately a **separate key** from the baseline key
    (`MCP_TOOL_AUDITOR_REPORT_KEY` / `~/.mcp-tool-auditor/reports/.hmac_key`, not
    `..._BASELINE_KEY`) — a report signature may need to leave the machine for a
    client to verify independently; the baseline key never should. Same primitive,
    same out-of-band-key trust-boundary reasoning, different key.
  - `key_id` (a short, one-way key fingerprint, never the key itself) is the
    discriminator between `TAMPERED` and `INVALID`: both look identical at the raw
    HMAC layer, but a `key_id` mismatch means the verifier used the wrong key
    (`INVALID`), while a matching `key_id` with a failed HMAC check means the
    payload was altered after signing (`TAMPERED`).
  - Determinism verified explicitly: the same findings/metadata produce a
    byte-identical canonical payload regardless of dict insertion order, and
    re-signing identical data twice reproduces the same signature (only `signed_at`
    differs) — required for signing a canonical payload to work at all.

## [1.8.0] - 2026-07-12

### Added
- **Tokenizer-aware STI detection (`--sti-tokenizer`, optional)** — a fifth STI tier
  that answers a stronger question than the existing four string-based tiers: will
  this string actually be parsed as a special token by the tokenizer a target
  deployment runs, not just "does it look like a known token." Backed by real, vendored,
  offline `tokenizer.json` assets (never a synthetic tokenizer seeded with our own
  registry strings, which would only ever confirm what string matching already
  catches) — loaded via `Tokenizer.from_str()` + `importlib.resources`, never
  `Tokenizer.from_pretrained()`, no network call at scan time or anywhere else.
  - Launch scope: `chatml`/`qwen` (Qwen3, Apache 2.0), `mistral` (Apache 2.0),
    `deepseek` (DeepSeek-R1, MIT). `llama3`/`gemma` deferred — no redistributable
    offline asset found (Meta's Llama Community License and Gemma's Terms of Use both
    require attribution/notice machinery incompatible with a silent `pip install`);
    requesting them prints a clear message rather than silently doing nothing.
  - New `[tokenizers]` extra (`tokenizers>=0.15`); without it, `--sti-tokenizer` warns
    with an install hint and the four string tiers still run — never crashes, never
    disables anything else. Per explicit decision, the vendored assets (~21 MB) ship
    in the main wheel unconditionally rather than a separate companion package.
  - Confirm/diverge/novel interaction with the string tiers: a string-tier match a
    real tokenizer confirms is upgraded to one `STI_TOKENIZER` finding (HIGH
    confidence); a match the tokenizer does *not* confirm is left completely
    unchanged (verified end-to-end: `[INST]`/`[/INST]` are Llama-2-style prompt
    convention, not actual special tokens in Mistral's real tokenizer, so
    `--sti-tokenizer mistral` correctly leaves them as plain `STI_EXACT` rather than
    hiding the divergence); a token the string tiers never catalogued at all but the
    real tokenizer resolves as special is added as a new, standalone finding.
  - Verified network-free by construction, not just assumption: ran the relevant test
    suite with `HTTP_PROXY`/`HTTPS_PROXY` pointed at a closed port plus
    `HF_HUB_OFFLINE=1` — any accidental network call would fail loudly and fast; all
    52 relevant tests still passed.

### Fixed
- Repo URLs updated for the GitHub rename `mcp-tool-auditor` → `mcp-auditor`: SARIF
  output (`informationUri`, `helpUri`), `pyproject.toml` `[project.urls]`, and README
  links/badges/clone instructions. The PyPI package name (`mcp-tool-auditor`) and CLI
  command are unaffected — only the repo it points to changed.

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

[1.9.0]: https://github.com/perparimmjeku/mcp-auditor/releases/tag/v1.9.0
[1.8.0]: https://github.com/perparimmjeku/mcp-auditor/releases/tag/v1.8.0
[1.7.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.7.0
[1.6.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.6.0
[1.5.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.5.0
[1.4.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.4.0
[1.3.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.3.0
[1.2.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.2.0
[1.1.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.1.0
[1.0.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.0.0
