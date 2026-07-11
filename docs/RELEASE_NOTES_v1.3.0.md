# v1.3.0 — Beyond tool descriptions

Paste this into the GitHub Release for tag `v1.3.0`.

---

Every previous release scanned tool definitions. This one widens what "the tool surface"
means, adds a semantic layer for poisoning that dodges keyword matching, and makes the
rug-pull baseline itself tamper-evident.

## Highlights

- **Multi-surface scanning** — `resources/list`, `prompts/list`, and the server's
  top-level `instructions` string are now scanned, not just tools. All three are
  documented injection vectors; findings use `RES_`/`PROMPT_`/`INSTR_`-prefixed rule ids.
- **MCP 2025-06-18 + OAuth detection** — protocol version bumped from 2025-03-26; a 401
  with `WWW-Authenticate` now produces a clear `OAUTH_REQUIRED` finding instead of a
  generic HTTP error.
- **Cross-tool composition risk** — `COMPOSITION_CONFUSED_DEPUTY` flags a server whose
  tools, combined, form a confused-deputy chain (one reads secrets, another can send data
  out) even when no single tool looks poisoned.
- **Signed rug-pull baselines** — `register`/`check` now HMAC-sign baselines so a tampered
  or forged fingerprint file is caught (`RUGPULL_BASELINE_TAMPERED`) instead of silently
  trusted. Supply your own key via `MCP_TOOL_AUDITOR_BASELINE_KEY` for CI use.
- **Optional LLM semantic judge** — `--llm-judge` (requires `ANTHROPIC_API_KEY` and
  `pip install 'mcp-tool-auditor[llm]'`) sends descriptions to Claude to catch paraphrased
  poisoning that static signatures miss. Opt-in only.
- **`watch` command** — continuous monitoring with webhook alerts on newly-observed
  findings, for production use beyond point-in-time scans.
- **CI/supply-chain hardening** — CodeQL, `pip-audit`, Dependabot, a real coverage gate
  (a subprocess-coverage blind spot meant `cli.py` was untracked and showing misleadingly
  low numbers), and least-privilege Action permissions.

## Install

```bash
pip install mcp-tool-auditor
# optional, for --llm-judge:
pip install 'mcp-tool-auditor[llm]'
```

See the [CHANGELOG](../CHANGELOG.md) for the full list and [docs/RULES.md](RULES.md) for the
detection rule catalog (68 rules now).
