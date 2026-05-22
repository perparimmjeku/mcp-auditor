# Contributing

Thanks for helping improve `mcp-tool-auditor`.

## Development Setup

```bash
git clone https://github.com/perparimmjeku/mcp-tool-auditor.git
cd mcp-tool-auditor
python -m pip install -e ".[dev]"
```

## Run Tests

```bash
python -m unittest discover -v
```

## Contribution Guidelines

- Keep new detections defensive and clearly mapped to an MCP or LLM security risk.
- Add tests for every new analyzer rule, reporter change, or CLI behavior change.
- Avoid adding payloads that perform real credential access, network exfiltration, persistence, or destructive actions.
- Prefer safe synthetic examples such as `attacker.example.com` and lab-only file paths.
- Keep findings actionable: include the rule, severity, affected tool, field when known, and remediation value.

## Pull Request Checklist

- Tests pass locally.
- New rules include at least one positive and one clean/false-positive test.
- Documentation is updated for new commands, output formats, or configuration.
- Offensive simulation changes remain lab-safe and do not execute real harmful behavior.
