from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mcp-tool-auditor",
    version="1.0.0",
    author="mcp-tool-auditor contributors",
    description="MCP Tool Poisoning Scanner — Defensive scanning + offensive pentest tooling for MCP servers. Maps to OWASP MCP Top 10.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/perparimmjeku/mcp-tool-auditor",
    packages=find_packages(include=["mcp_tool_auditor", "mcp_tool_auditor.*"]),
    package_data={
        "mcp_tool_auditor.auditor": ["signatures/*.yaml"],
    },
    include_package_data=True,
    install_requires=[
        "pyyaml>=6.0",
        "requests>=2.31.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "ruff>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mcp-tool-auditor=mcp_tool_auditor.cli:main",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    keywords="mcp, security, tool-poisoning, owasp, penetration-testing, llm, ai-security",
)
