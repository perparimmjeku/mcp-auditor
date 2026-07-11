.PHONY: help install install-dev test lint format clean docs

help:
	@echo "Available targets:"
	@echo "  install        - Install mcp-tool-auditor"
	@echo "  install-dev    - Install with dev dependencies"
	@echo "  test           - Run tests with coverage"
	@echo "  lint           - Run ruff and black checks"
	@echo "  format         - Format code with black and ruff"
	@echo "  clean          - Clean generated artifacts"
	@echo "  docs           - Show documentation files"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v --cov=mcp_tool_auditor --cov-report=term-missing --cov-fail-under=68

lint:
	ruff check mcp_tool_auditor tests
	black --check mcp_tool_auditor tests

format:
	black mcp_tool_auditor tests
	ruff check --fix mcp_tool_auditor tests

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/ dist/ htmlcov/ .coverage coverage.xml

docs:
	@echo "Documentation:"
	@echo "  README.md       - Project overview"
	@echo "  CONTRIBUTING.md - Developer guide"
	@echo "  SECURITY.md     - Security and responsible disclosure"
