from mcp_tool_auditor.auditor import inventory
from mcp_tool_auditor.auditor.analyzers import capability
from mcp_tool_auditor.auditor.discovery import DiscoveredServer


def _server(name="fs", command="npx", args=None, env_names=None, url=""):
    return DiscoveredServer(
        name=name,
        client="Claude Desktop",
        config_path="/tmp/config.json",
        transport="url" if url else "stdio",
        command=command,
        args=args or [],
        env_names=env_names or [],
        url=url,
    )


def test_infer_capabilities_labels_origin_inferred():
    server = _server(args=["-y", "@modelcontextprotocol/server-filesystem", "/data"])
    caps = inventory.infer_capabilities(server)
    assert len(caps) == 1
    assert caps[0].origin == inventory.ORIGIN_INFERRED
    assert caps[0].origin != inventory.ORIGIN_CONFIRMED


def test_infer_capabilities_source_from_filesystem_args():
    server = _server(args=["-y", "@modelcontextprotocol/server-filesystem", "/Users/x/Documents"])
    caps = inventory.infer_capabilities(server)
    assert capability.SOURCE in caps[0].roles


def test_infer_capabilities_sink_from_description_style_args():
    server = _server(
        name="notify",
        args=["-y", "@modelcontextprotocol/server-webhook", "--send-http-post-to-a-webhook"],
    )
    caps = inventory.infer_capabilities(server)
    assert capability.SINK in caps[0].roles


def test_infer_capabilities_bare_secret_env_suffix_promotes_source():
    # "SLACK_BOT_TOKEN" doesn't match capability.py's prose-oriented pattern
    # (which requires "access token"/"auth token", not bare "token") -- the
    # env-var-name heuristic is what catches this common naming convention.
    server = _server(name="slack", command="npx", env_names=["SLACK_BOT_TOKEN"])
    caps = inventory.infer_capabilities(server)
    assert capability.SOURCE in caps[0].roles
    assert caps[0].high_value_source is True


def test_infer_capabilities_high_value_source_from_credential_env_name():
    server = _server(
        name="slack",
        args=["-y", "@modelcontextprotocol/server-slack"],
        env_names=["SLACK_BOT_TOKEN"],
    )
    caps = inventory.infer_capabilities(server)
    assert caps[0].high_value_source is True


def test_infer_capabilities_benign_server_has_no_roles():
    server = _server(name="weather", command="python", args=["weather_server.py"])
    caps = inventory.infer_capabilities(server)
    assert caps[0].roles == set()


def test_synthesize_pseudo_tool_never_includes_redacted_marker_as_a_leak():
    server = _server(args=["--api-key=<redacted>"])
    pseudo = inventory.synthesize_pseudo_tool(server)
    assert "<redacted>" in pseudo["description"]  # placeholder is fine, not a real secret


def test_synthesize_pseudo_tool_uses_url_for_url_transport():
    server = _server(name="remote", command="", args=[], url="https://<redacted>@example.com/mcp")
    pseudo = inventory.synthesize_pseudo_tool(server)
    assert "example.com" in pseudo["description"]
