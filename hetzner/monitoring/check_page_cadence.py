#!/usr/bin/env python3
"""Proves, against a real Alertmanager, how soon a further page reaches the
phone. What it checks and why `amtool` cannot is in `check_page_cadence.md`.

    python3 hetzner/monitoring/check_page_cadence.py CONFIG IMAGE

CONFIG is the rendered `alertmanager.yml` (placeholders filled, as CI renders
it); IMAGE is the pinned Alertmanager image. Needs a local Docker daemon and
takes about two minutes. Exit 0 when the cadence holds, 1 when it does not.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# How long after it is raised a further estate-wide page may take to reach the
# receiver. The group interval is 1m; the rest is slack for a slow runner. A
# group interval of 1h, the root's, fails this by a factor of forty.
FURTHER_PAGE_BOUND_SECONDS = 90.0

# The first page of a group waits `group_wait` (30s) before it is sent.
FIRST_PAGE_BOUND_SECONDS = 90.0

# After the estate-wide further page arrives, how long to keep watching for a
# tenant-scoped further page that must not: it shares the tick, so a tenant
# group that had been given the short interval would have arrived by now.
TENANT_QUIET_SECONDS = 5.0

PAGE_RECEIVER_URL = re.compile(r"url: 'http://ntfy:80/[^']*'")


@dataclass(frozen=True)
class Seen:
    """One alert as the page receiver was handed it."""

    at: float
    alertname: str
    reason: str


@dataclass
class Receiver:
    """What the stand-in for ntfy has been sent, oldest first."""

    seen: list[Seen] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, body: bytes) -> None:
        payload = json.loads(body)
        now = time.monotonic()
        with self.lock:
            for alert in payload.get("alerts", []):
                labels = alert.get("labels", {})
                self.seen.append(
                    Seen(now, str(labels.get("alertname", "")), str(labels.get("reason", "")))
                )

    def has(self, alertname: str, reason: str) -> bool:
        with self.lock:
            return any(s.alertname == alertname and s.reason == reason for s in self.seen)


def retarget_pager(config_text: str, webhook_url: str) -> str:
    """The rendered config with the ntfy receiver pointed at `webhook_url`.

    Refuses a config that does not name the ntfy URL exactly once: a test that
    quietly left the real receiver in place would prove nothing."""
    found = PAGE_RECEIVER_URL.findall(config_text)
    if len(found) != 1:
        raise ValueError(f"expected exactly one ntfy receiver url, found {len(found)}")
    return PAGE_RECEIVER_URL.sub(lambda _m: f"url: '{webhook_url}'", config_text)


def judge(
    first_pages_seen: bool,
    further_estate_page_delay: float | None,
    further_tenant_page_seen: bool,
    further_bound: float = FURTHER_PAGE_BOUND_SECONDS,
) -> list[str]:
    """The problems with what was observed; empty when the cadence holds."""
    problems: list[str] = []
    if not first_pages_seen:
        problems.append("a first page never reached the receiver")
    if further_estate_page_delay is None:
        problems.append(
            f"a second estate-wide page did not reach the receiver within {further_bound:.0f}s"
        )
    elif further_estate_page_delay > further_bound:
        problems.append(
            f"a second estate-wide page took {further_estate_page_delay:.0f}s, "
            f"over the {further_bound:.0f}s bound"
        )
    if further_tenant_page_seen:
        problems.append(
            "a second tenant-scoped page arrived inside the window: "
            "tenant pages must keep the root group interval"
        )
    return problems


def _handler(receiver: Receiver) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            receiver.record(self.rfile.read(length))
            self.send_response(200)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    return Handler


def _post_alerts(base: str, alerts: list[dict[str, str]]) -> None:
    now = datetime.now(timezone.utc)
    body = json.dumps(
        [
            {
                "labels": labels,
                "startsAt": now.isoformat(),
                "endsAt": (now + timedelta(minutes=30)).isoformat(),
            }
            for labels in alerts
        ]
    ).encode()
    request = urllib.request.Request(
        f"{base}/api/v2/alerts",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


def _wait_for(condition: Callable[[], bool], seconds: float) -> float | None:
    """Seconds until `condition` held, polling twice a second; None on timeout."""
    start = time.monotonic()
    while time.monotonic() - start < seconds:
        if condition():
            return time.monotonic() - start
        time.sleep(0.5)
    return None


def _seconds(value: float | None) -> str:
    return "never (timed out)" if value is None else f"{value:.1f}s"


def _docker(*args: str) -> str:
    return subprocess.run(
        ["docker", *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def run(config_path: pathlib.Path, image: str) -> list[str]:
    receiver = Receiver()
    server = ThreadingHTTPServer(("0.0.0.0", 0), _handler(receiver))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    webhook = f"http://host.docker.internal:{server.server_address[1]}/pages"
    name = f"page-cadence-{uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory() as scratch:
        config = pathlib.Path(scratch) / "alertmanager.yml"
        config.write_text(retarget_pager(config_path.read_text(), webhook))
        config.chmod(0o644)
        try:
            _docker(
                "run", "-d", "--name", name,
                "--add-host", "host.docker.internal:host-gateway",
                "-p", "127.0.0.1:0:9093",
                "-v", f"{config}:/etc/alertmanager/alertmanager.yml:ro",
                image,
                "--config.file=/etc/alertmanager/alertmanager.yml",
                "--storage.path=/tmp/alertmanager",
            )  # fmt: skip
            port = _docker("port", name, "9093/tcp").splitlines()[0].rsplit(":", 1)[1]
            base = f"http://127.0.0.1:{port}"

            def ready() -> bool:
                try:
                    with urllib.request.urlopen(f"{base}/-/ready", timeout=2) as r:
                        return bool(r.status == 200)
                except OSError:
                    return False

            if _wait_for(ready, 30) is None:
                return ["Alertmanager did not become ready: " + _docker("logs", name)]

            ban = {"alertname": "EdgeBanIssued", "severity": "page"}
            tenant = {"alertname": "TenantFailedUnsafe", "severity": "page", "tenant": "acme"}
            _post_alerts(
                base,
                [
                    {**ban, "reason": "first"},
                    {**tenant, "reason": "first"},
                ],
            )
            first = _wait_for(
                lambda: receiver.has("EdgeBanIssued", "first")
                and receiver.has("TenantFailedUnsafe", "first"),
                FIRST_PAGE_BOUND_SECONDS,
            )
            print(f"first pages reached the receiver after {_seconds(first)}")
            if first is None:
                return judge(False, None, False)

            # Both groups have now notified once. Raise a further alert in
            # each: the estate-wide one must page soon, the tenant one not.
            _post_alerts(
                base,
                [
                    {**ban, "reason": "second"},
                    {**tenant, "alertname": "ReadersCannotRead", "reason": "second"},
                ],
            )
            delay = _wait_for(
                lambda: receiver.has("EdgeBanIssued", "second"), FURTHER_PAGE_BOUND_SECONDS
            )
            print(f"second estate-wide page reached the receiver after {_seconds(delay)}")
            time.sleep(TENANT_QUIET_SECONDS)
            tenant_seen = receiver.has("ReadersCannotRead", "second")
            return judge(first is not None, delay, tenant_seen)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
            server.shutdown()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=pathlib.Path)
    parser.add_argument("image")
    args = parser.parse_args(argv)
    problems = run(args.config, args.image)
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if not problems:
        print("OK: a further estate-wide page is prompt and tenant pages keep the root interval")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
