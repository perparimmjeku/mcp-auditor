from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    ERROR = "ERROR"


SEVERITY_LEVELS = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.ERROR: -1,
}


@dataclass
class Finding:
    """A single security finding from the scanner."""

    severity: Severity
    rule: str
    message: str
    owasp_id: str
    attack_type: str = "unknown"
    field: Optional[str] = None
    tool_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "rule": self.rule,
            "message": self.message,
            "owasp_id": self.owasp_id,
            "attack_type": self.attack_type,
            "field": self.field,
            "tool_name": self.tool_name,
        }


@dataclass
class ScanResult:
    """Result of scanning one MCP server."""

    tools_scanned: int
    findings: List[Finding]
    server_url: Optional[str] = None
    tools: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            severity = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def filter_by_severity(self, min_severity: Severity) -> "ScanResult":
        """Return a new ScanResult with only findings at or above min_severity."""
        min_level = SEVERITY_LEVELS.get(min_severity, 99)
        return ScanResult(
            tools_scanned=self.tools_scanned,
            findings=[
                f
                for f in self.findings
                if SEVERITY_LEVELS.get(f.severity, 99) <= min_level
            ],
            server_url=self.server_url,
            tools=self.tools,
            timestamp=self.timestamp,
        )
