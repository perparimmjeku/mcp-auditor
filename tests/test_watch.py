"""Tests for the watch-mode daemon: dedup behavior and webhook alerting.

WatchDaemon.run() installs signal handlers and sleeps in a real loop, so
these tests exercise it with max_iterations (a testing seam) and a near-zero
interval rather than running it unbounded.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mcp_tool_auditor.auditor.models import Finding, ScanResult, Severity
from mcp_tool_auditor.watch import WatchDaemon


def _finding(rule="ST_IGNORE_PREVIOUS", tool_name="t1", message="poisoned"):
    return Finding(
        severity=Severity.HIGH, rule=rule, message=message, owasp_id="MCP03", tool_name=tool_name
    )


def test_process_only_alerts_new_findings_once():
    daemon = WatchDaemon(webhook_url=None)
    result = ScanResult(tools_scanned=1, findings=[_finding()])

    first = daemon._process({"server-a": result})
    assert len(first) == 1

    # Same finding again -- already seen, shouldn't re-alert.
    second = daemon._process({"server-a": result})
    assert second == []

    # A genuinely new finding on the same server does alert.
    result2 = ScanResult(tools_scanned=1, findings=[_finding(rule="ST_BYPASS", message="new one")])
    third = daemon._process({"server-a": result2})
    assert len(third) == 1


def test_run_honors_max_iterations_and_calls_scan_once_each_time():
    daemon = WatchDaemon(webhook_url=None, interval=0)
    calls = []

    def scan_once():
        calls.append(1)
        return {"server-a": ScanResult(tools_scanned=0, findings=[])}

    daemon.run(scan_once, max_iterations=3)
    assert len(calls) == 3


def test_run_stops_early_on_request_stop():
    daemon = WatchDaemon(webhook_url=None, interval=0)
    calls = []

    def scan_once():
        calls.append(1)
        if len(calls) == 2:
            daemon.request_stop()
        return {"server-a": ScanResult(tools_scanned=0, findings=[])}

    daemon.run(scan_once, max_iterations=10)
    assert len(calls) == 2


def test_iteration_exception_does_not_crash_the_loop():
    daemon = WatchDaemon(webhook_url=None, interval=0)
    calls = []

    def scan_once():
        calls.append(1)
        raise RuntimeError("server unreachable")

    daemon.run(scan_once, max_iterations=2)
    assert len(calls) == 2


class _WebhookHandler(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        _WebhookHandler.received.append(body)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def webhook_server():
    _WebhookHandler.received = []
    httpd = HTTPServer(("127.0.0.1", 0), _WebhookHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_new_finding_posts_to_webhook(webhook_server):
    daemon = WatchDaemon(webhook_url=webhook_server)
    result = ScanResult(tools_scanned=1, findings=[_finding()])
    daemon._process({"server-a": result})

    assert len(_WebhookHandler.received) == 1
    payload = _WebhookHandler.received[0]
    assert payload["source"] == "mcp-tool-auditor"
    assert payload["count"] == 1
    assert payload["findings"][0]["server"] == "server-a"
    assert payload["findings"][0]["rule"] == "ST_IGNORE_PREVIOUS"
