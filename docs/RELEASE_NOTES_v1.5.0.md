# v1.5.0 — Special Token Injection detection

Paste this into the GitHub Release for tag `v1.5.0`.

---

A new class of attack this scanner didn't cover before: text that spoofs or closes a
model's native chat-template control tokens (`<|im_start|>`, `[INST]`, DeepSeek's
fullwidth `<｜User｜>`, and more) to hijack the conversation-turn boundary of whatever
prompt an MCP client eventually builds from tool/resource/prompt text.

## Highlights

- **Four-tier STI matching** — exact (literal registry token), normalized (Unicode NFKC +
  homoglyph folding — fullwidth forms, Cyrillic/Greek lookalikes, zero-width stripping;
  obfuscation is *more* suspicious than the plain token, not less, so this stays HIGH
  confidence), structural (unrecognized-but-token-shaped text, catches uncatalogued model
  families), and encoded (bounded-length base64/hex, opt-in via `--sti-decode`, off by
  default).
- **Token registry as data** (`signatures/sti_tokens.yaml`) — grouped by model family
  (ChatML/OpenAI/Qwen, Llama 2/Mistral, Llama 3, Gemma, Phi, Command R, DeepSeek,
  Anthropic-legacy), easy to extend via PR.
- **Scans tool call output, not just definitions** — `BEHAV_STI_TRANSITION` catches a
  control token that only appears after benign calls (the time-bomb pattern a
  definition-only scan can't see), `BEHAV_STI_OUTPUT` catches one present from the first
  call.
- **New offensive tooling** — two static `generate` vectors and a live `attack sti`
  time-bomb simulation server, mirroring the existing ATPA simulator.

## Install

```bash
pip install mcp-tool-auditor
```

See the [CHANGELOG](../CHANGELOG.md) for the full list and [docs/RULES.md](RULES.md) for
the detection rule catalog (74 rules now).
