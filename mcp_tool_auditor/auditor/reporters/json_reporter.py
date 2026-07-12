import json
from typing import Any

from ... import __version__
from ..models import CROSS_SERVER_KEY, ScanResult


class JSONReporter:
    @staticmethod
    def generate(results: dict[str, ScanResult]) -> str:
        server_count = sum(1 for name in results if name != CROSS_SERVER_KEY)
        output: dict[str, Any] = {
            "scan_metadata": {
                "tool": "mcp-tool-auditor",
                "version": __version__,
                "owasp_version": "OWASP MCP Top 10 (2025)",
            },
            "summary": {
                "total_servers": server_count,
                "total_tools": sum(r.tools_scanned for r in results.values()),
                "total_findings": sum(len(r.findings) for r in results.values()),
                "by_severity": {},
                "by_owasp_id": {},
            },
            "servers": {},
        }

        for server_name, scan_result in results.items():
            # Count severity
            for sev_name, count in scan_result.severity_counts.items():
                sev_key = sev_name.value if hasattr(sev_name, "value") else str(sev_name)
                output["summary"]["by_severity"][sev_key] = (
                    output["summary"]["by_severity"].get(sev_key, 0) + count
                )

            # Count OWASP
            for f in scan_result.findings:
                oid = f.owasp_id
                output["summary"]["by_owasp_id"][oid] = (
                    output["summary"]["by_owasp_id"].get(oid, 0) + 1
                )

            # Server entry
            output["servers"][server_name] = {
                "tools_scanned": scan_result.tools_scanned,
                "findings": [f.to_dict() for f in scan_result.findings],
            }

        return json.dumps(output, indent=2, default=str)
