"""Tests for the optional LLM semantic judge analyzer.

The real Anthropic client is never called in tests — a fake client stands
in so these run offline, deterministically, and without an API key/network.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from mcp_tool_auditor.auditor.analyzers.llm_judge import LLMJudgeAnalyzer
from mcp_tool_auditor.auditor.models import Severity
from mcp_tool_auditor.validation import ValidationError


class _FakeTextBlock:
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class _FakeMessages:
    def __init__(self, response_text: str):
        self._response_text = response_text
        self.last_kwargs = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        return SimpleNamespace(content=[_FakeTextBlock(self._response_text)])


class _FakeAnthropicClient:
    def __init__(self, response_text: str, api_key=None):
        self.messages = _FakeMessages(response_text)


def _fake_anthropic_module(response_text: str):
    return SimpleNamespace(Anthropic=lambda api_key=None: _FakeAnthropicClient(response_text))


def test_analyze_returns_empty_without_items():
    judge = LLMJudgeAnalyzer(api_key="test-key")
    assert judge.analyze([]) == []


def test_analyze_raises_without_api_key():
    judge = LLMJudgeAnalyzer(api_key=None)
    with pytest.raises(ValidationError, match="ANTHROPIC_API_KEY"):
        judge.analyze([{"name": "x", "description": "y"}])


def test_analyze_end_to_end_with_fake_client(monkeypatch):
    import sys

    verdict_json = '[{"name": "a", "severity": "MEDIUM", "reason": "borderline phrasing"}]'
    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic_module(verdict_json))

    judge = LLMJudgeAnalyzer(api_key="test-key")
    findings = judge.analyze([{"name": "a", "description": "..."}], kind="resource")
    assert len(findings) == 1
    assert findings[0].rule == "RES_LLM_SEMANTIC_POISONING"
    assert findings[0].severity == Severity.MEDIUM


def test_analyze_tolerates_markdown_fenced_response(monkeypatch):
    import sys

    fenced = '```json\n[{"name": "a", "severity": "CRITICAL", "reason": "bad"}]\n```'
    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic_module(fenced))

    judge = LLMJudgeAnalyzer(api_key="test-key")
    findings = judge.analyze([{"name": "a", "description": "..."}])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_analyze_returns_empty_on_non_json_response(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic_module("not json at all"))

    judge = LLMJudgeAnalyzer(api_key="test-key")
    findings = judge.analyze([{"name": "a", "description": "..."}])
    assert findings == []


def test_analyze_returns_empty_clean_verdict(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic_module("[]"))

    judge = LLMJudgeAnalyzer(api_key="test-key")
    findings = judge.analyze([{"name": "clean", "description": "Adds two numbers."}])
    assert findings == []
