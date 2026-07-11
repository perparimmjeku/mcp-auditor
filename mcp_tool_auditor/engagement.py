"""Engagement scope and metadata for real pentest workflows.

A pentest is authorized against a specific, bounded scope, not "whatever
the CLI is pointed at." This lets an operator declare that scope once
(client, tester, dates, authorized targets) in a file, so:

- every scan can refuse to touch anything outside the authorized target
  list instead of trusting whatever URL/command was typed, and
- every report carries the engagement context instead of being anonymous
  CI output with no client, scope, or authorization record attached.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a package dependency
    yaml = None  # type: ignore[assignment]

from .validation import ValidationError


@dataclass
class Engagement:
    """Authorization scope and report metadata for a pentest engagement."""

    client: str = ""
    tester: str = ""
    start_date: str = ""
    end_date: str = ""
    notes: str = ""
    # Exact strings or fnmatch-style patterns (e.g. "https://*.client.example.com/*").
    # Empty means "no restriction configured" -- not "nothing is authorized" --
    # so opting into scope enforcement is a deliberate, visible choice.
    allowed_targets: list[str] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str) -> Engagement:
        file_path = Path(path).expanduser()
        if not file_path.is_file():
            raise ValidationError(f"Engagement/scope file not found: {file_path}")

        text = file_path.read_text(encoding="utf-8")
        try:
            if file_path.suffix.lower() in {".yaml", ".yml"}:
                if yaml is None:
                    raise ValidationError("PyYAML is required to parse a YAML scope file")
                data = yaml.safe_load(text) or {}
            else:
                data = json.loads(text)
        except ValidationError:
            raise
        except Exception as exc:
            raise ValidationError(f"Invalid engagement/scope file {file_path}: {exc}") from exc

        if not isinstance(data, dict):
            raise ValidationError("Engagement/scope file must be a JSON/YAML object")
        return cls.from_mapping(data)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> Engagement:
        known = set(cls.__dataclass_fields__)
        sanitized = {k: v for k, v in data.items() if k in known and v is not None}
        return cls(**sanitized)

    def check_target(self, target: str) -> None:
        """Raise ValidationError if `target` isn't covered by allowed_targets.

        No-op when allowed_targets is empty -- scope enforcement is opt-in
        per engagement file, not implied by merely passing --engagement
        (a file might exist purely to carry report metadata like client/tester).
        """
        if not self.allowed_targets:
            return
        for pattern in self.allowed_targets:
            if target == pattern or fnmatch.fnmatch(target, pattern):
                return
        raise ValidationError(
            f"Target '{target}' is not in the authorized engagement scope "
            f"({', '.join(self.allowed_targets)}). Refusing to scan an out-of-scope target."
        )
