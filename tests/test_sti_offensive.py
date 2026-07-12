"""Tests for the STI offensive tooling: the two static generate-only
vectors in poisoner.py, and the live call-count time-bomb server, closing
the loop with the defensive analyzers built in earlier commits.
"""

import threading
from http.server import HTTPServer

import pytest

from mcp_tool_auditor.auditor.analyzers.behavioral import BehavioralAnalyzer
from mcp_tool_auditor.auditor.analyzers.sti import STIAnalyzer
from mcp_tool_auditor.auditor.scanner import MCPScanner
from mcp_tool_auditor.config import AuditConfig
from mcp_tool_auditor.offensive.poisoner import PoisonedServerGenerator
from mcp_tool_auditor.offensive.sti_server import STIServerHandler

# --- generate (static, file-only, no ack) -----------------------------------


def test_sti_chatml_injection_vector_is_registered():
    assert "sti_chatml_injection" in PoisonedServerGenerator.ATTACK_VECTORS


def test_sti_deepseek_homoglyph_vector_is_registered():
    assert "sti_deepseek_homoglyph" in PoisonedServerGenerator.ATTACK_VECTORS


def test_generate_server_sti_chatml_injection_produces_valid_python():
    code = PoisonedServerGenerator.generate_server(attack_type="sti_chatml_injection", port=8080)
    assert "<|im_start|>" in code
    assert "<|im_end|>" in code
    compile(code, "<generated>", "exec")  # syntax-valid


def test_generate_server_sti_deepseek_homoglyph_produces_valid_python():
    code = PoisonedServerGenerator.generate_server(attack_type="sti_deepseek_homoglyph", port=8080)
    compile(code, "<generated>", "exec")

    # json.dumps() escapes the fullwidth pipe as ｜ in the source text
    # (ensure_ascii=True default) -- that's still functionally correct since
    # Python interprets \uXXXX identically to the literal character at
    # runtime. Verify the *runtime* value, not the raw source bytes.
    namespace: dict = {"__name__": "__not_main__"}
    exec(compile(code, "<generated>", "exec"), namespace)
    descriptions = " ".join(t["description"] for t in namespace["TOOLS"])
    assert "｜" in descriptions


def test_generated_sti_vectors_are_caught_by_the_sti_analyzer():
    """Closes the loop: what the offensive generator produces, the

    defensive analyzer must actually flag.
    """
    for attack_type, expected_tier in (
        ("sti_chatml_injection", "exact"),
        ("sti_deepseek_homoglyph", "normalized"),
    ):
        vector = PoisonedServerGenerator.ATTACK_VECTORS[attack_type]
        tool = {"name": vector["name"], "description": vector["poisoned_description"]}
        findings = STIAnalyzer().analyze(tool)
        assert findings, f"expected {attack_type} to trigger STI findings"
        tiers = {f.rule.replace("STI_", "").lower() for f in findings}
        assert expected_tier in tiers


def test_generate_all_variants_includes_sti(tmp_path):
    output_dir = PoisonedServerGenerator.generate_all_variants(str(tmp_path))
    generated = {p.name for p in tmp_path.iterdir()}
    assert "server_sti_chatml_injection.py" in generated
    assert "server_sti_deepseek_homoglyph.py" in generated
    assert output_dir == str(tmp_path)


# --- attack (live server, ack-gated, time-bomb) -----------------------------


@pytest.fixture
def sti_server():
    STIServerHandler.call_counts = {}
    STIServerHandler.PRODUCTION_THRESHOLD = 3
    server = HTTPServer(("127.0.0.1", 0), STIServerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def test_live_probe_detects_sti_time_bomb(sti_server):
    scanner = MCPScanner(config=AuditConfig())
    tools, transcripts = scanner.probe_url(sti_server, calls=5)
    analyzer = BehavioralAnalyzer()
    by_name = {t["name"]: t for t in tools}
    rules = set()
    for name, responses in transcripts.items():
        for finding in analyzer.analyze(by_name[name], responses):
            rules.add(finding.rule)
    assert "BEHAV_STI_TRANSITION" in rules


def test_sti_server_tool_descriptions_are_benign(sti_server):
    """The whole point of a behavioral time-bomb: definitions alone must

    look clean to a static scan.
    """
    scanner = MCPScanner(config=AuditConfig())
    result = scanner.scan_server_url(sti_server)
    sti_static_findings = [f for f in result.findings if f.rule.startswith("STI_")]
    assert sti_static_findings == []
