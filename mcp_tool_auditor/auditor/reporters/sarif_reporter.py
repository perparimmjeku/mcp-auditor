"""SARIF 2.1.0 reporter for GitHub code-scanning / GitLab / CI integration."""

import json
from typing import Any

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

# RULES.md has no stable per-rule anchors (rule ids are table rows, not
# headers), so every rule points at the same catalog page rather than a
# rule-specific fragment.
_RULES_DOC_URI = "https://github.com/perparimmjeku/mcp-tool-auditor/blob/main/docs/RULES.md"


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
                        "helpUri": _RULES_DOC_URI,
                        "defaultConfiguration": {"level": _LEVEL.get(severity, "warning")},
                        "properties": {
                            "tags": ["security", "mcp", finding.owasp_id],
                            "security-severity": _SECURITY_SEVERITY.get(severity, "5.5"),
                            # Populated by a future ATLAS mapping; empty for now so
                            # that addition doesn't require a schema/structure change.
                            "atlas_ids": [],
                        },
                    }

                location: dict[str, Any] = {
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
                            "retest_status": finding.retest_status,
                        },
                    }
                )

        sorted_rules = sorted(rules.values(), key=lambda r: r["id"])
        sarif_results.sort(
            key=lambda r: (
                r["ruleId"],
                r["properties"].get("tool_name") or "",
                r["properties"].get("field") or "",
                r["message"]["text"],
            )
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
                            "rules": sorted_rules,
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
        return json.dumps(doc, indent=2)
