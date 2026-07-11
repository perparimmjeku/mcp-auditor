import json

import pytest

from mcp_tool_auditor.engagement import Engagement
from mcp_tool_auditor.validation import ValidationError


def test_check_target_no_restriction_by_default():
    Engagement().check_target("https://anything.example.com/mcp")


def test_check_target_exact_match_allowed():
    engagement = Engagement(allowed_targets=["https://target.example.com/mcp"])
    engagement.check_target("https://target.example.com/mcp")


def test_check_target_glob_pattern_allowed():
    engagement = Engagement(allowed_targets=["https://*.client.example.com/*"])
    engagement.check_target("https://api.client.example.com/mcp")


def test_check_target_rejects_out_of_scope():
    engagement = Engagement(allowed_targets=["https://target.example.com/mcp"])
    with pytest.raises(ValidationError, match="not in the authorized engagement scope"):
        engagement.check_target("https://evil.example.com/mcp")


def test_from_file_loads_json(tmp_path):
    path = tmp_path / "engagement.json"
    path.write_text(
        json.dumps(
            {
                "client": "Acme Corp",
                "tester": "J. Doe",
                "allowed_targets": ["https://target.example.com/mcp"],
            }
        ),
        encoding="utf-8",
    )
    engagement = Engagement.from_file(str(path))
    assert engagement.client == "Acme Corp"
    assert engagement.tester == "J. Doe"
    engagement.check_target("https://target.example.com/mcp")
    with pytest.raises(ValidationError):
        engagement.check_target("https://other.example.com/mcp")


def test_from_file_missing_raises():
    with pytest.raises(ValidationError, match="not found"):
        Engagement.from_file("/nonexistent/engagement.json")


def test_from_file_rejects_non_object(tmp_path):
    path = tmp_path / "engagement.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValidationError, match="must be a JSON/YAML object"):
        Engagement.from_file(str(path))


def test_from_file_unknown_fields_ignored(tmp_path):
    path = tmp_path / "engagement.json"
    path.write_text(json.dumps({"client": "Acme", "unexpected_field": 123}), encoding="utf-8")
    engagement = Engagement.from_file(str(path))
    assert engagement.client == "Acme"
