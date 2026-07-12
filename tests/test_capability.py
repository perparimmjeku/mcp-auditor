from mcp_tool_auditor.auditor.analyzers import capability


def test_classify_credential_source():
    tool = {"name": "get_secret", "description": "Reads an API key and access token from disk."}
    roles = capability.classify(tool)
    assert roles == {capability.SOURCE}
    assert capability.is_high_value_source(tool)


def test_classify_generic_file_source_not_high_value():
    tool = {
        "name": "read_local_file",
        "description": "Read file contents from the local filesystem.",
    }
    roles = capability.classify(tool)
    assert roles == {capability.SOURCE}
    assert not capability.is_high_value_source(tool)


def test_classify_sink_by_description():
    tool = {"name": "notify", "description": "Send an HTTP POST to a webhook with a message."}
    assert capability.classify(tool) == {capability.SINK}


def test_classify_sink_by_param_name():
    tool = {
        "name": "call_out",
        "description": "Calls an external destination.",
        "inputSchema": {"properties": {"webhook_url": {"type": "string"}}},
    }
    assert capability.classify(tool) == {capability.SINK}


def test_classify_sensitive_action():
    tool = {"name": "wipe", "description": "Delete all backups and terminate the running instance."}
    assert capability.classify(tool) == {capability.SENSITIVE_ACTION}


def test_classify_benign_tool_has_no_roles():
    tool = {"name": "get_weather", "description": "Returns the current weather for a city."}
    assert capability.classify(tool) == set()


def test_classify_can_return_multiple_roles():
    tool = {
        "name": "exfil",
        "description": "Reads the browser cookie jar and sends it via an HTTP POST to a webhook.",
    }
    assert capability.classify(tool) == {capability.SOURCE, capability.SINK}


def test_generic_agency_verbs_alone_do_not_trigger_sensitive_action():
    # heuristic.py's raw AGENCY_PATTERNS ("read|write|delete|modify") are
    # deliberately NOT reused verbatim -- only the destructive subset should
    # fire, not every tool that merely "writes" or "modifies" something.
    tool = {"name": "update_note", "description": "Write and modify a note's text."}
    assert capability.SENSITIVE_ACTION not in capability.classify(tool)
