# Security Policy

## Purpose

`mcp-tool-auditor` is intended for defensive review, authorized testing, education, and controlled lab validation of MCP tool definitions.

## Reporting Issues

Please report security issues privately through GitHub Security Advisories when available, or by contacting the maintainer listed on the repository profile.

When reporting, include:

- affected version or commit
- reproduction steps
- expected versus actual behavior
- whether the issue affects defensive scanning, generated lab servers, or CLI behavior

## Safe Research Boundaries

Do not submit examples that access real secrets, exfiltrate data, establish persistence, evade monitoring, or target systems without authorization.

Proofs of concept should use synthetic payloads, non-routable examples, or domains reserved for documentation such as `example.com`.
