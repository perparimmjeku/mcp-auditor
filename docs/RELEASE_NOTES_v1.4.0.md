# v1.4.0 — Built for real engagements

Paste this into the GitHub Release for tag `v1.4.0`.

---

Detection has been the focus of every release so far. This one is about the workflow
around a real, authorized pentest: scoping what you're allowed to touch, producing a
report you can actually hand to a client, and proving a finding got fixed.

## Highlights

- **Engagement/scope file (`--engagement`)** — declare authorized targets once
  (exact strings or glob patterns) plus client/tester/date metadata. Scans against a
  stdio/url target outside scope are refused before any network/subprocess call is made.
- **Client-ready reports (`--format pentest`)** — an engagement header, executive
  summary, a methodology section that reflects what actually ran, and per-finding
  evidence (the real tool/resource/prompt text that triggered it) plus remediation
  guidance. Markdown/JSON/SARIF stay CI-facing; this one is for the deliverable.
- **`retest --baseline <report>`** — re-scan and diff against a prior report into
  Fixed / Still Present / New, the standard initial-report-then-retest cycle every
  engagement follows. `--fail-on` gates on unresolved findings only, so a clean retest
  (everything fixed) exits 0.

## Install

```bash
pip install mcp-tool-auditor
```

See the [CHANGELOG](../CHANGELOG.md) for the full list.
