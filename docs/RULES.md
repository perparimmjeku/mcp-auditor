# Detection Rule Catalog

Auto-derived from the source. **68 rules** across 10 analyzers. Confidence reflects false-positive likelihood: **HIGH** = definitive, **MEDIUM** = contextual, **LOW** = fuzzy heuristic (tune with `--min-confidence`).

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
| `FSP_ADDITIONAL_PARAM` | MEDIUM |
| `FSP_COMMAND_PARAM` | MEDIUM |
| `FSP_COMMENT_PARAM` | MEDIUM |
| `FSP_CONTEXT_PARAM` | MEDIUM |
| `FSP_DEFAULT_INJECTION` | MEDIUM |
| `FSP_DIRECTIVE_PARAM` | MEDIUM |
| `FSP_ENUM_INJECTION` | MEDIUM |
| `FSP_EXTRA_PARAM` | MEDIUM |
| `FSP_FEEDBACK_PARAM` | MEDIUM |
| `FSP_INJECTION_PARAM` | MEDIUM |
| `FSP_INSTRUCTION_PARAM` | MEDIUM |
| `FSP_MISSING_REQUIRED` | MEDIUM |
| `FSP_NOTE_PARAM` | MEDIUM |
| `FSP_OVERRIDE_PARAM` | MEDIUM |
| `FSP_PARAM_NAME` | MEDIUM |
| `FSP_REMARK_PARAM` | MEDIUM |
| `FSP_SIDENOTE` | MEDIUM |
| `FSP_SYSTEM_PROMPT_PARAM` | MEDIUM |
| `PROMPT_ARG_DESC_INJECTION` | HIGH |
| `PROMPT_ARG_DESC_LONG` | LOW |

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
| `BEHAV_CALL_ERROR` | MEDIUM |
| `BEHAV_RESPONSE_DIVERGENCE` | LOW |

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
