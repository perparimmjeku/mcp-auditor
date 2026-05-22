# MCP Tool Auditor

**Scan MCP server tool definitions for poisoning, injection, and OWASP MCP Top 10 vulnerabilities.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP-MCP03%20Tool%20Poisoning-red)](https://owasp.org/www-project-mcp-top-10/)

`mcp-tool-auditor` is a comprehensive security scanner for Model Context Protocol (MCP) servers. It detects tool poisoning, full-schema poisoning (FSP), rug-pull attacks, tool shadowing, and ATPA (Advanced Tool Poisoning Attacks), while mapping findings to the OWASP MCP Top 10 framework.

The project also includes authorized offensive tooling for penetration testers and security researchers to simulate realistic MCP attack scenarios in controlled environments.

---

## Features

### Defensive Scanner

| Feature | What It Detects |
|---|---|
| Static Signatures | 40+ patterns such as "ignore security", "always use this tool", "send full conversation", and "authoritative source" |
| Heuristic Analysis | Imperative language scoring, authority spoofing, Unicode hidden characters, and excessive agency claims |
| Schema Anomaly Detection | Full-Schema Poisoning (FSP), sidenote parameter injection, enum injection, poisoned defaults, and required-array abuse |
| Rug-Pull Detection | SHA-256 schema fingerprinting to detect unexpected tool definition changes |
| OWASP Mapping | Maps findings to MCP01–MCP10 classifications |

### Offensive Tooling

| Tool | What It Simulates |
|---|---|
| Description Injection Server | Classic Tool Poisoning Attacks using malicious tool descriptions |
| FSP Generator | CyberArk-style schema poisoning variants |
| ATPA Server | Behavioral poisoning that becomes malicious after a configurable threshold |
| Rug-Pull Server | Serves clean tools initially, then swaps to malicious definitions |
| Tool Shadowing Server | Mimics trusted tool names while embedding injected payloads |

---

## Installation

### Install from GitHub

```bash
git clone https://github.com/perparimmjeku/mcp-tool-auditor.git
cd mcp-tool-auditor
pip install -e .
```

### Development

```bash
python -m pip install -e ".[dev]"
python -m unittest discover -v
```

---

## Quick Start

### Scan an MCP Server

```bash
mcp-tool-auditor scan url http://localhost:8080/mcp
```

### Generate a Markdown Report

```bash
mcp-tool-auditor scan url http://localhost:8080/mcp \
  --format markdown \
  -o report.md
```

### Scan MCP Servers from a Configuration File

```bash
mcp-tool-auditor scan config \
  ~/.config/Claude/claude_desktop_config.json
```

### Register a Baseline Fingerprint

```bash
mcp-tool-auditor register url http://localhost:8080/mcp
```

### Check for Rug-Pull Changes

```bash
mcp-tool-auditor check url http://localhost:8080/mcp
```

### Generate Offensive Test Servers

```bash
mcp-tool-auditor generate all --output-dir ./pentest_servers
```

---

## OWASP MCP Top 10 Mapping

| OWASP ID | Issue | Detection |
|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | `ST_IGNORE_PREVIOUS`, `ST_BYPASS`, `ST_IGNORE_SECURITY` |
| MCP02 | Privilege Escalation via Scope Creep | `HEUR_AGENCY`, credential-related signatures |
| MCP03 | Tool Poisoning | Signatures, heuristics, FSP, rug-pull, and shadowing detection |
| MCP04 | Software Supply Chain Attacks | Rug-pull fingerprint mismatches and unexpected tool changes |
| MCP05 | Command Injection & Execution | `ST_EXECUTE`, `ST_CODE_EXEC`, command-related schema findings |

---

## Offensive Testing Examples

```bash
# Start an ATPA simulation server
mcp-tool-auditor attack atpa --port 8080 --threshold 3

# Start a rug-pull simulation server
mcp-tool-auditor attack rugpull --port 8081 --switch-after 5

# Generate standalone attack servers
mcp-tool-auditor generate all --output-dir ./test_servers

python ./test_servers/server_description_injection.py
```

---

## Architecture

```text
mcp-tool-auditor/
├── mcp_tool_auditor/
│   ├── __init__.py
│   ├── cli.py
│   ├── auditor/
│   │   ├── __init__.py
│   │   ├── scanner.py
│   │   ├── models.py
│   │   ├── analyzers/
│   │   │   ├── __init__.py
│   │   │   ├── static.py
│   │   │   ├── heuristic.py
│   │   │   ├── schema.py
│   │   │   └── rugpull.py
│   │   ├── signatures/
│   │   │   ├── __init__.py
│   │   │   ├── descriptions.yaml
│   │   │   └── parameters.yaml
│   │   └── reporters/
│   │       ├── __init__.py
│   │       ├── json_reporter.py
│   │       └── markdown_reporter.py
│   └── offensive/
│       ├── __init__.py
│       ├── poisoner.py
│       ├── atpa_server.py
│       └── rugpull_sim.py
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   └── fixtures/
│       ├── __init__.py
│       └── poisoned_tools.json
├── config.yaml
├── pyproject.toml
├── setup.py
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── README.md
```

---

## Configuration

See `config.yaml` for example scanner settings. CLI flags are currently the source of truth for runtime behavior.

### Default Configuration

```yaml
auditor:
  severity_threshold: MEDIUM

  heuristic_analysis:
    description_length_threshold: 500
    imperative_threshold: 2

  schema_analysis:
    check_fsp_params: true
    check_required_array: true
    check_enum_values: true
```

---

## Contributing

Pull requests are welcome.

Please see `CONTRIBUTING.md` for development guidelines, coding standards, and testing procedures.

Security issues should follow `SECURITY.md`.

---

## License

MIT License — see the `LICENSE` file for details.

---

## Legal Disclaimer

This tool is intended strictly for:

- Authorized penetration testing
- Defensive security research
- Educational and lab environments
- Controlled validation of MCP security controls

Users must have explicit permission before testing any target systems.

The authors assume no liability for misuse, unauthorized testing, or damages caused by improper use of this software.

---

## Package Metadata

### `mcp_tool_auditor/__init__.py`

```python
"""MCP Tool Auditor package."""

__version__ = "1.0.0"
__author__ = "Përparim Mjeku"
__license__ = "MIT"
```
