import os

from mcp_tool_auditor.auditor import signing


def test_sign_then_verify_is_valid(tmp_path):
    key = signing.load_or_create_key(str(tmp_path), ".hmac_key", "MCP_TEST_KEY_VAR")
    payload = {"b": 2, "a": 1}
    sig = signing.sign(key, payload)
    assert signing.verify(key, payload, sig)


def test_verify_rejects_altered_payload(tmp_path):
    key = signing.load_or_create_key(str(tmp_path), ".hmac_key", "MCP_TEST_KEY_VAR")
    payload = {"severity": "MEDIUM"}
    sig = signing.sign(key, payload)
    tampered = {"severity": "CRITICAL"}
    assert not signing.verify(key, tampered, sig)


def test_verify_rejects_wrong_key(tmp_path):
    key_a = signing.load_or_create_key(str(tmp_path / "a"), ".hmac_key", "MCP_TEST_KEY_VAR_A")
    key_b = signing.load_or_create_key(str(tmp_path / "b"), ".hmac_key", "MCP_TEST_KEY_VAR_B")
    payload = {"x": 1}
    sig = signing.sign(key_a, payload)
    assert not signing.verify(key_b, payload, sig)


def test_verify_rejects_empty_signature(tmp_path):
    key = signing.load_or_create_key(str(tmp_path), ".hmac_key", "MCP_TEST_KEY_VAR")
    assert not signing.verify(key, {"x": 1}, "")


def test_canonical_bytes_is_key_order_independent():
    a = signing.canonical_bytes({"b": 2, "a": 1})
    b = signing.canonical_bytes({"a": 1, "b": 2})
    assert a == b


def test_sign_is_deterministic_for_same_payload(tmp_path):
    key = signing.load_or_create_key(str(tmp_path), ".hmac_key", "MCP_TEST_KEY_VAR")
    payload = {"findings": [1, 2, 3]}
    assert signing.sign(key, payload) == signing.sign(key, payload)


def test_key_id_is_stable_and_does_not_reveal_the_key(tmp_path):
    key = signing.load_or_create_key(str(tmp_path), ".hmac_key", "MCP_TEST_KEY_VAR")
    kid = signing.key_id(key)
    assert kid == signing.key_id(key)
    assert len(kid) == 16
    assert key.hex() != kid
    assert key not in kid.encode()


def test_env_var_key_overrides_local_key_file(tmp_path):
    os.environ["MCP_TEST_KEY_VAR"] = "explicit-secret"
    try:
        key = signing.load_or_create_key(str(tmp_path), ".hmac_key", "MCP_TEST_KEY_VAR")
        assert key == b"explicit-secret"
        assert not (tmp_path / ".hmac_key").exists()
    finally:
        os.environ.pop("MCP_TEST_KEY_VAR", None)


def test_load_or_create_key_persists_and_is_reused(tmp_path):
    key1 = signing.load_or_create_key(str(tmp_path), ".hmac_key", "MCP_TEST_KEY_VAR_UNSET")
    key2 = signing.load_or_create_key(str(tmp_path), ".hmac_key", "MCP_TEST_KEY_VAR_UNSET")
    assert key1 == key2
    assert (tmp_path / ".hmac_key").exists()
