"""SARIF 2.1.0 reporter for GitHub code-scanning / GitLab / CI integration."""

import json

from ... import __version__
from .. import remediation
from ..models import ScanResult, Severity

# SARIF result levels
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.ERROR: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub security-severity score (0.0-10.0)
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.ERROR: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


class SarifReporter:
    @staticmethod
    def generate(results: dict[str, ScanResult]) -> str:
        rules: dict[str, dict] = {}
        sarif_results: list[dict] = []

        for server_name, scan_result in results.items():
            for finding in scan_result.findings:
                severity = (
                    finding.severity
                    if isinstance(finding.severity, Severity)
                    else Severity(str(finding.severity))
                )
                if finding.rule not in rules:
                    rules[finding.rule] = {
                        "id": finding.rule,
                        "name": finding.rule,
                        "shortDescription": {"text": finding.rule.replace("_", " ").title()},
                        "help": {
                            "text": remediation.get_remediation(
                                finding.rule, finding.owasp_id, finding.attack_type
                            )
                        },
                        "defaultConfiguration": {"level": _LEVEL.get(severity, "warning")},
                        "properties": {
                            "tags": ["security", "mcp", finding.owasp_id],
                            "security-severity": _SECURITY_SEVERITY.get(severity, "5.5"),
                        },
                    }

                location = {
                    "logicalLocations": [
                        {
                            "name": finding.tool_name or server_name,
                            "fullyQualifiedName": (
                                f"{server_name}/{finding.tool_name or '?'}"
                                f"{('/' + finding.field) if finding.field else ''}"
                            ),
                            "kind": "tool",
                        }
                    ]
                }
                if finding.file:
                    location["physicalLocation"] = {
                        "artifactLocation": {"uri": finding.file},
                        "region": {"startLine": finding.line or 1},
                    }
                sarif_results.append(
                    {
                        "ruleId": finding.rule,
                        "level": _LEVEL.get(severity, "warning"),
                        "message": {"text": finding.message},
                        "locations": [location],
                        "properties": {
                            "owasp_id": finding.owasp_id,
                            "attack_type": finding.attack_type,
                            "tool_name": finding.tool_name,
                            "field": finding.field,
                            "confidence": finding.confidence,
                        },
                    }
                )

        doc = {
            "$schema": _SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-tool-auditor",
                            "version": __version__,
                            "informationUri": "https://github.com/perparimmjeku/mcp-tool-auditor",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
        return json.dumps(doc, indent=2)
