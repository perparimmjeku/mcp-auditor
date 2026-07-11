"""Tests for HMAC-signed rug-pull baselines: tamper detection and the
upgrade path from pre-signing (flat JSON) baselines.
"""

import json
import tempfile
import unittest
from pathlib import Path

from mcp_tool_auditor.auditor.analyzers.rugpull import RugPullDetector


class TestBaselineSigning(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.detector = RugPullDetector(fingerprint_dir=self.tmpdir)
        self.server_url = "https://test-server.example.com/mcp"
        self.tools = [{"name": "tool1", "description": "desc"}]

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _baseline_path(self) -> str:
        return self.detector.register(self.server_url, self.tools)

    def test_register_writes_signed_document(self):
        path = self._baseline_path()
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertIn("tools", document)
        self.assertIn("hmac", document)
        self.assertEqual(document["tools"]["tool1"], self.detector._fingerprint_tool(self.tools[0]))

    def test_tampered_fingerprint_is_detected_and_not_trusted(self):
        path = self._baseline_path()
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        # Attacker edits the fingerprint directly without re-signing, to
        # hide that the real tool changed.
        document["tools"]["tool1"] = "0" * 64
        Path(path).write_text(json.dumps(document), encoding="utf-8")

        findings = self.detector.check(self.server_url, self.tools)
        rules = {f.rule for f in findings}
        self.assertIn("RUGPULL_BASELINE_TAMPERED", rules)
        # Refuses to reason about "changes" against an untrusted baseline.
        self.assertNotIn("RUGPULL_FINGERPRINT_MISMATCH", rules)
        self.assertNotIn("RUGPULL_NEW_TOOL", rules)

    def test_stripped_signature_is_detected(self):
        path = self._baseline_path()
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        del document["hmac"]
        Path(path).write_text(json.dumps(document), encoding="utf-8")

        findings = self.detector.check(self.server_url, self.tools)
        self.assertTrue(any(f.rule == "RUGPULL_BASELINE_TAMPERED" for f in findings))

    def test_legacy_unsigned_baseline_still_works_with_upgrade_hint(self):
        path = self._baseline_path()
        # Simulate a baseline written by a pre-signing version: flat
        # {name: fingerprint}, no "tools"/"hmac" wrapper.
        legacy = {"tool1": self.detector._fingerprint_tool(self.tools[0])}
        Path(path).write_text(json.dumps(legacy), encoding="utf-8")

        findings = self.detector.check(self.server_url, self.tools)
        rules = {f.rule for f in findings}
        self.assertIn("RUGPULL_BASELINE_UNSIGNED", rules)
        # Still functions as a valid comparison baseline.
        self.assertNotIn("RUGPULL_FINGERPRINT_MISMATCH", rules)
        self.assertNotIn("RUGPULL_NEW_TOOL", rules)

    def test_env_var_key_overrides_local_key_file(self):
        import os

        os.environ["MCP_TOOL_AUDITOR_BASELINE_KEY"] = "ci-secret-key"
        try:
            path = self._baseline_path()
            # A detector without the env key set can't forge a matching
            # signature for a tampered file even with write access to the dir.
            del os.environ["MCP_TOOL_AUDITOR_BASELINE_KEY"]
            other_detector = RugPullDetector(fingerprint_dir=self.tmpdir)
            document = json.loads(Path(path).read_text(encoding="utf-8"))
            document["tools"]["tool1"] = "0" * 64
            document["hmac"] = other_detector._sign(document["tools"])
            Path(path).write_text(json.dumps(document), encoding="utf-8")

            os.environ["MCP_TOOL_AUDITOR_BASELINE_KEY"] = "ci-secret-key"
            findings = self.detector.check(self.server_url, self.tools)
            self.assertTrue(any(f.rule == "RUGPULL_BASELINE_TAMPERED" for f in findings))
        finally:
            os.environ.pop("MCP_TOOL_AUDITOR_BASELINE_KEY", None)


if __name__ == "__main__":
    unittest.main()
