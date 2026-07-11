"""Continuous MCP server monitoring with webhook alerting.

`scan`/`check` are point-in-time; production monitoring wants something that
keeps watching and pages someone when a server's tools start looking
poisoned. WatchDaemon re-runs a scan on an interval and POSTs newly-observed
findings to a webhook (Slack/Discord/PagerDuty/anything with a webhook
endpoint) — no vendor-specific integration code, just a JSON POST.

Dedup is in-memory and per-process: each finding is alerted once, the first
time it's observed, so a standing issue doesn't repeat-alert every interval.
This does not persist across restarts — acceptable for a monitoring loop
that's expected to run continuously, not a durable alert ledger.
"""

from __future__ import annotations

import hashlib
import logging
import signal
import time
from collections.abc import Callable
from typing import Any

from .auditor.models import Finding, ScanResult

logger = logging.getLogger(__name__)

ScanOnce = Callable[[], dict[str, ScanResult]]


class WatchDaemon:
    """Re-runs a scan on an interval and alerts a webhook on new findings."""

    def __init__(self, webhook_url: str | None = None, interval: int = 300):
        self.webhook_url = webhook_url
        self.interval = interval
        self._seen: set[str] = set()
        self._stop = False

    def request_stop(self, *_args: Any) -> None:
        self._stop = True

    def run(self, scan_once: ScanOnce, max_iterations: int | None = None) -> None:
        """Loop forever (or `max_iterations` times, for tests) calling `scan_once`.

        Installs SIGINT/SIGTERM handlers for graceful shutdown; only safe to
        call from the main thread of the process.
        """
        signal.signal(signal.SIGINT, self.request_stop)
        signal.signal(signal.SIGTERM, self.request_stop)

        iterations = 0
        while not self._stop:
            try:
                results = scan_once()
                self._process(results)
            except Exception as exc:
                logger.error("Watch iteration failed: %s", exc)

            iterations += 1
            if max_iterations is not None and iterations >= max_iterations:
                break

            for _ in range(self.interval):
                if self._stop:
                    break
                time.sleep(1)

    def _process(self, results: dict[str, ScanResult]) -> list[tuple[str, Finding]]:
        new_findings: list[tuple[str, Finding]] = []
        for server_name, result in results.items():
            for finding in result.findings:
                sig = self._signature(server_name, finding)
                if sig not in self._seen:
                    self._seen.add(sig)
                    new_findings.append((server_name, finding))

        if new_findings:
            logger.warning("Watch: %d new finding(s) detected", len(new_findings))
            if self.webhook_url:
                self._alert(new_findings)
        return new_findings

    @staticmethod
    def _signature(server_name: str, finding: Finding) -> str:
        raw = f"{server_name}|{finding.rule}|{finding.tool_name}|{finding.message}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _alert(self, new_findings: list[tuple[str, Finding]]) -> None:
        import requests

        assert self.webhook_url is not None  # only called when set, see _process

        payload = {
            "source": "mcp-tool-auditor",
            "event": "new_findings",
            "count": len(new_findings),
            "findings": [
                {"server": server_name, **finding.to_dict()}
                for server_name, finding in new_findings
            ],
        }
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            resp.raise_for_status()
        except Exception as exc:
            logger.error("Webhook delivery to %s failed: %s", self.webhook_url, exc)
