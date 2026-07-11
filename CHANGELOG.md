# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Coverage measurement blind spot** — CLI-invoking tests spawn `mcp_tool_auditor.cli`
  in a subprocess, which coverage.py never traced; `cli.py`, `logging_config.py`, and
  the reporters showed as 0-40% covered despite being exercised by real tests. Added
  subprocess coverage tracking (`tests/conftest.py` + `sitecustomize.py` hook,
  `parallel`/`relative_files` in `[tool.coverage.run]`); true coverage is 70%, not 50%.

### Added
- **CI coverage gate** (`--cov-fail-under=68`) so coverage can't silently regress.
- **CodeQL analysis** (`.github/workflows/codeql.yml`) for Python static analysis on
  push/PR/weekly schedule.
- **Dependency vulnerability audit** (`pip-audit`) as a CI job.
- **Dependabot** for pip and GitHub Actions dependency updates.
- **`.dockerignore`** so the published image doesn't ship `.git`, tests, docs, and caches.

### Changed
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

[1.1.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.1.0
[1.0.0]: https://github.com/perparimmjeku/mcp-tool-auditor/releases/tag/v1.0.0
