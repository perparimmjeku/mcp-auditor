import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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
}


@dataclass
class Finding:
    """A single security finding from the scanner."""

    severity: Severity
    rule: str
    message: str
    owasp_id: str
    attack_type: str = "unknown"
    field: str | None = None
    tool_name: str | None = None
    file: str | None = None
    line: int | None = None
    confidence: str | None = None

    def __post_init__(self) -> None:
        """Normalize and validate finding fields."""
        if not isinstance(self.severity, Severity):
            self.severity = Severity(str(self.severity).upper())
        if self.confidence is None:
            from .confidence import confidence_for

            self.confidence = confidence_for(self.rule)
        if not self.rule:
            raise ValueError("Finding.rule cannot be empty")
        if not self.message:
            raise ValueError("Finding.message cannot be empty")
        if not self.owasp_id:
            raise ValueError("Finding.owasp_id cannot be empty")
        if self.owasp_id != "N/A" and not self.owasp_id.startswith("MCP"):
            raise ValueError(f"Invalid OWASP ID format '{self.owasp_id}' - must start with 'MCP'")

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "rule": self.rule,
            "message": self.message,
            "owasp_id": self.owasp_id,
            "attack_type": self.attack_type,
            "field": self.field,
            "tool_name": self.tool_name,
            "file": self.file,
            "line": self.line,
            "confidence": self.confidence,
        }


@dataclass
class ScanResult:
    """Result of scanning one MCP server."""

    tools_scanned: int
    findings: list[Finding]
    server_url: str | None = None
    tools: list[dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
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
                if f.severity == Severity.ERROR or SEVERITY_LEVELS.get(f.severity, 99) <= min_level
            ],
            server_url=self.server_url,
            tools=self.tools,
            timestamp=self.timestamp,
        )
