# Detection Rule Catalog

Auto-derived from the source. **62 rules** across 11 analyzers. Confidence reflects false-positive likelihood: **HIGH** = definitive, **MEDIUM** = contextual, **LOW** = fuzzy heuristic (tune with `--min-confidence`).

**Multi-surface scanning:** every static signature and heuristic rule below also runs against
resources, prompts, and the server's top-level `instructions` string, not just tools — poisoning
isn't limited to tool descriptions. Findings from those surfaces reuse the same rule id with a
prefix: `RES_` (resource), `PROMPT_` (prompt), `INSTR_` (server instructions), e.g.
`RES_ST_IGNORE_PREVIOUS`. Confidence is unchanged by the prefix.


## Static signatures

_Known tool-poisoning phrases in tool text_

| Rule | Confidence |
|---|---|
| `ST_ALWAYS_CALL` | HIGH |
| `ST_ALWAYS_USE` | HIGH |
| `ST_AUTHORITATIVE` | HIGH |
| `ST_BYPASS` | HIGH |
| `ST_CODE_EXEC` | HIGH |
| `ST_CONTEXT_HARVEST` | HIGH |
| `ST_CREDENTIAL` | HIGH |
| `ST_DATA_EXFIL` | HIGH |
| `ST_DO_NOT_QUESTION` | HIGH |
| `ST_DO_NOT_TELL` | HIGH |
| `ST_EXECUTE` | HIGH |
| `ST_FILESYSTEM` | HIGH |
| `ST_IGNORE_ALL` | HIGH |
| `ST_IGNORE_PREVIOUS` | HIGH |
| `ST_IGNORE_SECURITY` | HIGH |
| `ST_MANDATORY` | HIGH |
| `ST_OVERRIDE` | HIGH |
| `ST_READ_FILE` | HIGH |
| `ST_SEND_FULL` | HIGH |
| `ST_SENSITIVE` | HIGH |
| `ST_SYSTEM_CLAIM` | HIGH |
| `ST_YOU_MUST` | HIGH |

## Schema / Full-Schema Poisoning

_Suspicious params, enum/default/required injection_

| Rule | Confidence |
|---|---|
| `FSP_DESC_INJECTION` | HIGH |
| `FSP_ENUM_POISON` | HIGH |
| `FSP_REQUIRED_LENGTH` | HIGH |
| `PROMPT_ARG_DESC_INJECTION` | HIGH |
| `FSP_DEFAULT_INJECTION` | MEDIUM |
| `FSP_ENUM_INJECTION` | MEDIUM |
| `FSP_INJECTION_PARAM` | MEDIUM |
| `FSP_MISSING_REQUIRED` | MEDIUM |
| `FSP_PARAM_NAME` | MEDIUM |
| `PROMPT_ARG_DESC_LONG` | LOW |

`FSP_PARAM_NAME` fires for any suspicious parameter name (`sidenote`, `note`, `comment`,
`remark`, `metadata`, `context`, `extra`, `additional`, `auxiliary` — see
`SchemaAnalyzer.FSP_SUSPICIOUS_PARAM_NAMES`) and `FSP_INJECTION_PARAM` for any known
prompt-injection vector name (`system_prompt`, `instructions`, `directive`, `command`,
`override`, `priority`, `mode` — see `SchemaAnalyzer.PROMPT_INJECTION_PARAMS`); the
specific matched name is in the finding's message, not a per-keyword rule id.

_MCP prompts carry a flat `arguments` list, not a JSON Schema like tools, so
`PROMPT_ARG_*` mirrors the description-injection/length checks above for that shape._

## Heuristics

_Length, imperative/agency language, hidden Unicode_

| Rule | Confidence |
|---|---|
| `HEUR_UNICODE_HIDDEN` | HIGH |
| `HEUR_AUTHORITY_SPOOF` | MEDIUM |
| `HEUR_AGENCY` | LOW |
| `HEUR_DESC_LENGTH` | LOW |
| `HEUR_IMPERATIVE` | LOW |
| `HEUR_PARAM_DESC_LONG` | LOW |

## Schema hygiene

_Permissive/untyped parameters_

| Rule | Confidence |
|---|---|
| `SCHEMA_GENERIC_TYPE` | LOW |
| `SCHEMA_UNTYPED` | LOW |

## Rug-pull

_Fingerprint drift vs. registered baseline_

| Rule | Confidence |
|---|---|
| `RUGPULL_FINGERPRINT_MISMATCH` | HIGH |
| `RUGPULL_BASELINE_TAMPERED` | HIGH |
| `RUGPULL_NEW_TOOL` | MEDIUM |
| `RUGPULL_NO_BASELINE` | MEDIUM |
| `RUGPULL_REMOVED_TOOL` | MEDIUM |
| `RUGPULL_BASELINE_UNSIGNED` | MEDIUM |

_Baselines are HMAC-SHA256 signed (`register`). `RUGPULL_BASELINE_TAMPERED` means the
signature didn't verify — `check` refuses to trust the file as a comparison point.
`RUGPULL_BASELINE_UNSIGNED` means the baseline predates signing; it still works, but
re-run `register` to upgrade it. See `MCP_TOOL_AUDITOR_BASELINE_KEY` in the README to
supply the signing key out-of-band (e.g. a CI secret) instead of the local key file._

## Cross-tool composition risk

_Individually-benign tools that combine into a confused-deputy chain_

| Rule | Confidence |
|---|---|
| `COMPOSITION_CONFUSED_DEPUTY` | MEDIUM |

_Flags a server that exposes both a sensitive-data-access tool (credentials, secrets,
tokens, ...) and a separate outbound-network/send-capable tool — an agent with both in
one session can chain them to exfiltrate data, even though neither tool looks poisoned
on its own._

## Special Token Injection (STI)

_Text that spoofs/closes a model's native chat-template control tokens (`<|im_start|>`,
`[INST]`, `<|start_header_id|>`, DeepSeek's fullwidth `<｜User｜>`, etc.) to hijack the
conversation-turn boundary of whatever prompt an MCP client builds from this text_

| Rule | Confidence |
|---|---|
| `STI_EXACT` | HIGH |
| `STI_NORMALIZED` | HIGH |
| `STI_TOKENIZER` | HIGH |
| `STI_STRUCTURAL` | MEDIUM |
| `STI_ENCODED` | MEDIUM |

Five matching tiers, most to least certain: **exact** (literal registry token, registry
in `signatures/sti_tokens.yaml` grouped by model family — ChatML/OpenAI/Qwen, Llama 2/
Mistral, Llama 3, Gemma, Phi, Command R, DeepSeek, Anthropic-legacy); **normalized**
(Unicode NFKC + homoglyph folding — fullwidth forms, Cyrillic/Greek lookalikes — plus
zero-width/bidi stripping, then re-matched against the registry — obfuscation is *more*
suspicious than the plain token, not less, so this stays HIGH); **tokenizer** (opt-in via
`--sti-tokenizer chatml|qwen|mistral|deepseek`, off by default — encodes the text with a
*real*, vendored, offline tokenizer and checks whether a span resolves to an actual
special/added-vocabulary token id under that specific model family, rather than being
BPE-split; see "Tokenizer-aware STI" in the README for why this isn't just string
matching in disguise, and what it catches that the other tiers can't); **structural**
(unknown token with the right *shape*, e.g. `<|...|>`, catches uncatalogued model
families); **encoded** (bounded-length base64/hex substring that decodes to a registry
token — opt-in via `--sti-decode`, off by default, and the decoded bytes are only ever
compared against the registry, never fed back into the structural regex). All five get
the `RES_`/`PROMPT_`/`INSTR_` surface prefix like the static/heuristic rules; the string
tiers (not yet `--sti-tokenizer`) also run against tool call *output* via the behavioral
rules below, not just definitions.

## LLM semantic judge (opt-in)

_Catches paraphrased poisoning that dodges static signatures_

| Rule | Confidence |
|---|---|
| `LLM_SEMANTIC_POISONING` | MEDIUM |

_Only runs with `--llm-judge` and `ANTHROPIC_API_KEY` set — never a scan default, since it
sends tool/resource/prompt text to Anthropic's API. Also gets the `RES_`/`PROMPT_`/`INSTR_`
surface prefix like the static/heuristic rules._

## Behavioral / ATPA

_Runtime response analysis_

| Rule | Confidence |
|---|---|
| `BEHAV_ATPA_TRANSITION` | HIGH |
| `BEHAV_OUTPUT_INJECTION` | HIGH |
| `BEHAV_STI_TRANSITION` | HIGH |
| `BEHAV_STI_OUTPUT` | HIGH |
| `BEHAV_CALL_ERROR` | MEDIUM |
| `BEHAV_RESPONSE_DIVERGENCE` | LOW |

`BEHAV_STI_*` runs the same STI four-tier matcher against tool call *responses*
(exact/normalized/structural tiers; `--sti-decode` isn't wired into behavioral probing
yet), independently of the keyword-based `BEHAV_ATPA_TRANSITION`/`BEHAV_OUTPUT_INJECTION`
checks — a response can trigger both if it contains both a control token and generic
injection language. `BEHAV_STI_TRANSITION` (CRITICAL severity) is the time-bomb case: a
control token appears only after benign calls, exactly the pattern a definition-only
scan can't see. `BEHAV_STI_OUTPUT` (HIGH severity) is present from the first call.

## Source-scan

_Shell-injection sinks in MCP server code_

| Rule | Confidence |
|---|---|
| `SRC_SHELL_INJECTION` | HIGH |

## Operational

_Scan errors and informational notices (not a vulnerability)_

| Rule | Confidence |
|---|---|
| `SCAN_FAILED` | MEDIUM |
| `OAUTH_REQUIRED` | MEDIUM |

_`OAUTH_REQUIRED` (severity INFO) means the server returned HTTP 401 with a
`WWW-Authenticate` header per MCP 2025-06-18's OAuth 2.1 requirement. The scanner reports
what it found (including protected-resource metadata, if discoverable) instead of failing;
it does not perform an interactive OAuth login — complete the flow yourself and re-run with
`--header "Authorization: Bearer <token>"`._
