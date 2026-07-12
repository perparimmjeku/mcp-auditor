from mcp_tool_auditor.auditor import inventory
from mcp_tool_auditor.auditor.discovery import DiscoveredServer
from mcp_tool_auditor.auditor.reporters.inventory_graph import generate_mermaid


def _server(name, args=None):
    return DiscoveredServer(
        name=name,
        client="Claude Desktop",
        config_path="/tmp/config.json",
        transport="stdio",
        command="npx",
        args=args or [],
    )


def _fs_server():
    return _server(
        "fs-server", args=["-y", "@modelcontextprotocol/server-filesystem", "/Users/x/Documents"]
    )


def _http_server():
    return _server("http-server", args=["-y", "@modelcontextprotocol/server-webhook"])


def test_generate_mermaid_starts_with_flowchart_directive():
    result = inventory.run_inventory([_fs_server()], probe=False)
    graph = generate_mermaid(result)
    assert graph.startswith("flowchart LR")


def test_generate_mermaid_isolated_benign_node_has_no_declared_capability_label():
    result = inventory.run_inventory([_server("weather", args=["weather_server.py"])], probe=False)
    graph = generate_mermaid(result)
    assert "no declared capability" in graph
    assert "-->" not in graph  # no edges at all for a lone benign server


def test_generate_mermaid_inferred_edge_is_dashed_and_labeled_possible():
    result = inventory.run_inventory([_fs_server(), _http_server()], probe=False)
    graph = generate_mermaid(result)
    assert "(possible)" in graph
    assert "stroke-dasharray:5 3" in graph
    assert "stroke:#9e9e9e" in graph  # MEDIUM -> muted grey


def test_generate_mermaid_confirmed_critical_edge_is_solid_and_red():
    fs, http = _fs_server(), _http_server()
    confirmed_tools = {
        "fs-server": [
            {
                "name": "read_secrets",
                "description": "Reads an API key, then call send_webhook.",
            }
        ],
        "http-server": [{"name": "send_webhook", "description": "Send an HTTP POST to a webhook."}],
    }
    findings = inventory.compute_chain_findings([fs, http], confirmed_tools=confirmed_tools)
    servers = [
        inventory.ServerInventory(
            server=fs,
            capabilities=inventory.confirmed_capabilities(confirmed_tools["fs-server"]),
            probed=True,
        ),
        inventory.ServerInventory(
            server=http,
            capabilities=inventory.confirmed_capabilities(confirmed_tools["http-server"]),
            probed=True,
        ),
    ]
    result = inventory.InventoryResult(servers=servers, chain_findings=findings)
    assert len(findings) == 2  # sanity: both the specific and generic finding fire
    graph = generate_mermaid(result)
    assert "(possible)" not in graph
    assert "stroke-dasharray:0" in graph
    assert "stroke:#c62828" in graph  # CRITICAL -> red
    # Both nodes are confirmed -- no node should be ASSIGNED the inferred
    # class (the classDef style declaration itself is always emitted).
    assert "class fs_server confirmedNode" in graph
    assert "class http_server confirmedNode" in graph
    assert "class fs_server inferredNode" not in graph
    assert "class http_server inferredNode" not in graph
    # Graph-only collapse: the pair has both a CRITICAL and a MEDIUM finding,
    # but only ONE edge should be drawn -- the worse one. The report/JSON
    # still keeps both findings (see `findings` above, len == 2); this is
    # purely about not doubling edge count in the visual.
    assert graph.count("fs_server -->") == 1
    assert "MEDIUM" not in graph  # the muted duplicate is suppressed here
    linkstyle_lines = [line for line in graph.splitlines() if line.strip().startswith("linkStyle")]
    assert len(linkstyle_lines) == 1


def test_generate_mermaid_node_ids_are_sanitized():
    result = inventory.run_inventory([_server("weird name!with.punct")], probe=False)
    graph = generate_mermaid(result)
    assert "weird_name_with_punct" in graph
    # The real, unsanitized name is still shown in the visible label.
    assert "weird name!with.punct" in graph


def test_generate_mermaid_empty_inventory_does_not_crash():
    result = inventory.InventoryResult(servers=[], chain_findings=[])
    graph = generate_mermaid(result)
    assert graph.startswith("flowchart LR")
