# Third-party tokenizer assets

These `tokenizer.json` files are vendored from upstream model repositories so the
tokenizer-aware STI tier (`--sti-tokenizer`) works fully offline — no network call at
scan time, ever. Each was verified redistributable before being added here; see
`docs/RULES.md` / `RELEASING.md` history for the license research. Only `[tokenizers]`
extra users load them at runtime (via `tokenizers.Tokenizer.from_str()`,
`importlib.resources` — no `Tokenizer.from_pretrained()`, no hub access anywhere in
this codebase).

| File | Source | Fetched from | License |
|---|---|---|---|
| `chatml_qwen.tokenizer.json` | Qwen3-8B (Alibaba Cloud) | `huggingface.co/Qwen/Qwen3-8B/resolve/main/tokenizer.json` | Apache 2.0 (whole repo) |
| `mistral.tokenizer.json` | Mistral-7B-Instruct-v0.2 (Mistral AI) | `huggingface.co/mistralai/Mistral-7B-Instruct-v0.2/resolve/main/tokenizer.json` | Apache 2.0 |
| `deepseek.tokenizer.json` | DeepSeek-R1 (DeepSeek AI) | `huggingface.co/deepseek-ai/DeepSeek-R1/resolve/main/tokenizer.json` | MIT |

Fetched 2026-07-12. Deliberately **not** vendored, pending a redistributable offline
asset: Llama 3 (Meta's Community License requires attribution/notice machinery
incompatible with a silent `pip install`) and Gemma (Gemma 1-3's Terms of Use has
similar redistribution requirements; a reportedly Apache-2.0 "Gemma 4" exists per
Google's terms page but wasn't independently verified). `--sti-tokenizer llama3` or
`gemma` prints a clear "not available offline yet" message rather than silently doing
nothing or trying to fetch one.
