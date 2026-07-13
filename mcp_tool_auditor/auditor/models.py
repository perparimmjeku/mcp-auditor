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

# Every other finding's origin is implicit: it lives inside exactly one
# ScanResult, nested under exactly one key in the top-level `results` dict.
# A cross-server toxic-flow finding implicates two servers at once and
# doesn't belong to either one, so it's collected under this synthetic key
# instead. Reporters/suppressions/metrics that iterate `results` generically
# still work unchanged; code that counts "servers scanned" must exclude it
# explicitly (see analyzers/flow.py and the reporters).
CROSS_SERVER_KEY = "__cross_server__"


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
    # Set only by `retest` (STILL_PRESENT/NEW on current findings; FIXED on
    # findings from the baseline that no longer reproduce). None for a plain scan.
    retest_status: str | None = None
    # Second endpoint of a multi-origin finding (currently: cross-server
    # toxic-flow only). `tool_name` carries the first/primary tool as usual;
    # these name the other side of the pair. None for every single-origin
    # finding type -- purely additive, backward compatible.
    related_tool: str | None = None
    related_server: str | None = None

    def __post_init__(self) -> None:
        """Normalize and validate finding fields."""
        if not isinstance(self.severity, Severity):
            self.severity = Severity(str(self.severity).upper())
        if self.confidence is None:
            from .confidence import confidence_for

            self.confidence = confidence_for(self.rule, self.severity.value)
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
            "retest_status": self.retest_status,
            "related_tool": self.related_tool,
            "related_server": self.related_server,
        }


@dataclass
class ScanResult:
    """Result of scanning one MCP server."""

    tools_scanned: int
    findings: list[Finding]
    server_url: str | None = None
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources_scanned: int = 0
    prompts_scanned: int = 0
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    instructions: str | None = None
    oauth_required: bool = False
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
            resources_scanned=self.resources_scanned,
            prompts_scanned=self.prompts_scanned,
            resources=self.resources,
            prompts=self.prompts,
            instructions=self.instructions,
            oauth_required=self.oauth_required,
            timestamp=self.timestamp,
        )
