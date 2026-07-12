from mcp_tool_auditor import cli
from mcp_tool_auditor.auditor.models import CROSS_SERVER_KEY, ScanResult


def _result(tools):
    return ScanResult(tools_scanned=len(tools), findings=[], tools=tools)


def test_flag_defaults_to_enabled():
    parser = cli._build_parser()
    args = parser.parse_args(["scan", "import", "tests/fixtures/poisoned_tools.json"])
    assert args.cross_server_flow is True


def test_no_cross_server_flow_flag_disables_it():
    parser = cli._build_parser()
    args = parser.parse_args(
        ["scan", "import", "tests/fixtures/poisoned_tools.json", "--no-cross-server-flow"]
    )
    assert args.cross_server_flow is False


def test_apply_cross_server_flow_adds_synthetic_entry_when_findings_exist():
    results = {
        "fs-server": _result(
            [{"name": "read_local_file", "description": "Read file contents from disk."}]
        ),
        "http-server": _result(
            [{"name": "send_request", "description": "Send an HTTP POST to a webhook."}]
        ),
    }
    cli._apply_cross_server_flow(results, enabled=True)
    assert CROSS_SERVER_KEY in results
    assert results[CROSS_SERVER_KEY].findings
    assert results[CROSS_SERVER_KEY].tools_scanned == 0


def test_apply_cross_server_flow_noop_when_disabled():
    results = {
        "fs-server": _result(
            [{"name": "read_local_file", "description": "Read file contents from disk."}]
        ),
        "http-server": _result(
            [{"name": "send_request", "description": "Send an HTTP POST to a webhook."}]
        ),
    }
    cli._apply_cross_server_flow(results, enabled=False)
    assert CROSS_SERVER_KEY not in results


def test_apply_cross_server_flow_no_synthetic_entry_for_single_target():
    """A true single-target scan must never gain the synthetic key -- retest's
    `single_target = len(results) == 1` heuristic depends on this."""
    results = {
        "fs-server": _result(
            [{"name": "read_local_file", "description": "Read file contents from disk."}]
        )
    }
    cli._apply_cross_server_flow(results, enabled=True)
    assert CROSS_SERVER_KEY not in results
    assert len(results) == 1
