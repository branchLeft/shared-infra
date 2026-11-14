"""Replays Ghost admin traffic and admin probes against the edge's own CrowdSec.

What it proves: a person using our own Ghost admin is not banned, and a probe
still is. It starts the `crowdsec` service of `stack/compose.yml` exactly as the
host runs it (same image, same environment, same mounted files), with two
changes an isolated runner needs: no port bound to edge1's private address, and
Caddy's log volume replaced by a directory this test writes. It then plays two
kinds of traffic:

- AppSec: the requests Caddy's bouncer forwards to the AppSec listener, header
  for header, so the Core Rule Set sees what it sees on the host.
- The access log: Caddy JSON access-log lines, which the log scenarios read.

Every case has its own source address, so a ban names the case that caused it.

It needs a Docker engine that can start containers, which a workstation here
does not have, so it is skipped unless `BRANCHLEFT_CROWDSEC_REPLAY=1`; CI's
`edge-config-validate` job sets it (the owner ruled "skip-locally").
"""

from __future__ import annotations

import dataclasses
import http.client
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import tempfile
import time
import unittest
from collections.abc import Mapping, Sequence
from typing import NoReturn

EDGE = pathlib.Path(__file__).resolve().parent
COMPOSE_FILE = EDGE / "stack" / "compose.yml"

ENABLED = os.environ.get("BRANCHLEFT_CROWDSEC_REPLAY") == "1"


class ReplayError(AssertionError):
    """The replay could not be run, as opposed to a verdict that was wrong."""


def fail(message: str) -> NoReturn:
    raise ReplayError(message)


GHOST_HOST = "blog.branchleft.co.uk"
OTHER_HOST = "branchleft.co.uk"

# The out-of-band bucket's capacity is 5, so a sixth matching request bans. The
# owner's session raised eight WAF alerts; twelve leaves no doubt either way.
REPEATS = 12

# Long enough for a cold hub download of every collection compose.yml names.
START_TIMEOUT_S = 300
VERDICT_TIMEOUT_S = 120
# After the last expected ban lands, how much longer a ban that is not expected
# is given to appear before its absence counts.
SETTLE_S = 15

CHROME_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)

# Settings > Design. Ghost admin's theme preview (apps/admin-x-settings,
# theme-preview.tsx) POSTs to the site root with no body, Content-Type
# text/html and the unsaved design settings in this header, URLSearchParams-
# encoded. Values are Casper's defaults with an uploaded icon.
THEME_PREVIEW = (
    "c=%2315171A&d=Thoughts%2C+stories+and+ideas."
    "&icon=https%3A%2F%2Fblog.branchleft.co.uk%2Fcontent%2Fimages%2F2026%2F11%2Ficon.png"
    "&logo=&cover=https%3A%2F%2Fstatic.ghost.org%2Fv5.0.0%2Fimages%2Fpublication-cover.jpg"
    "&bf=&hf="
    "&custom=%7B%22navigation_layout%22%3A%22Logo+on+cover%22%2C"
    "%22site_background_color%22%3A%22%23ffffff%22%2C"
    "%22header_and_footer_color%22%3A%22Background+color%22%2C"
    "%22title_font%22%3A%22Modern+sans-serif%22%2C%22body_font%22%3A%22Elegant+serif%22%2C"
    "%22signup_heading%22%3A%22%22%2C%22signup_subheading%22%3A%22%22%2C"
    "%22header_style%22%3A%22Landing%22%2C%22header_text%22%3A%22%22%2C"
    "%22background_image%22%3Atrue%2C%22show_featured_posts%22%3Afalse%2C"
    "%22post_feed_style%22%3A%22List%22%2C%22show_images_in_feed%22%3Atrue%2C"
    "%22show_author%22%3Atrue%2C%22show_publish_date%22%3Atrue%2C"
    "%22show_publication_info_sidebar%22%3Afalse%2C%22show_post_metadata%22%3Atrue%2C"
    "%22enable_drop_caps_on_posts%22%3Afalse%2C%22show_related_articles%22%3Atrue%7D"
)

# Settings > Announcement bar: the same request shape (announcement-bar-preview.tsx).
ANNOUNCEMENT_PREVIEW = (
    "announcement_bg=accent&announcement=%3Cp%3ENew+issue+out+now%3C%2Fp%3E"
    "&announcement_vis=visitors%2Cfree_members"
)


def browser_headers(host: str, accept: str, dest: str) -> dict[str, str]:
    """What Chrome sends on a same-origin request, before Caddy sees it."""
    return {
        "Accept": accept,
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-GB,en;q=0.9",
        "Origin": f"https://{host}",
        "Referer": f"https://{host}/ghost/",
        "Sec-Ch-Ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Sec-Fetch-Dest": dest,
        "Sec-Fetch-Mode": "cors" if dest == "empty" else "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Priority": "u=1, i",
        "User-Agent": CHROME_UA,
    }


def preview_headers(host: str, preview: str | None) -> dict[str, str]:
    """A design or announcement preview fetch. The admin session cookie is scoped
    to /ghost, so a request to the site root carries none."""
    headers = browser_headers(host, "text/html", "empty")
    headers["Content-Type"] = "text/html;charset=utf-8"
    if preview is not None:
        headers["X-Ghost-Preview"] = preview
    return headers


def admin_shell_headers(host: str) -> dict[str, str]:
    """Loading the admin app itself: a navigation carrying the session cookie."""
    headers = browser_headers(host, "text/html,application/xhtml+xml,*/*;q=0.8", "document")
    headers["Cookie"] = "ghost-admin-api-session=s%3AqR3vN0bX2tY9.Zk1lZ2h0c2lnbmF0dXJl"
    return headers


@dataclasses.dataclass(frozen=True)
class AppsecRequest:
    """One request as Caddy received it, which the bouncer forwards to AppSec."""

    method: str
    host: str
    uri: str
    headers: Mapping[str, str]


@dataclasses.dataclass(frozen=True)
class LogLine:
    """One request as Caddy's access log records it."""

    host: str
    uri: str
    status: int
    method: str = "GET"


@dataclasses.dataclass(frozen=True)
class Case:
    """A source address, the traffic it sends, and whether it must be banned."""

    name: str
    ip: str
    banned: bool
    appsec: Sequence[AppsecRequest] = ()
    log: Sequence[LogLine] = ()


def preview_post(host: str, preview: str | None) -> AppsecRequest:
    return AppsecRequest("POST", host, "/?admin_toolbar=0", preview_headers(host, preview))


GHOST_ADMIN_API_PATHS = (
    "/ghost/api/admin/users/me/?include=roles",
    "/ghost/api/admin/settings/?group=site,theme,private,members,portal,newsletter,email,labs,slack,unsplash,views,firstpromoter,editor,comments,analytics,announcement,pintura,donations,recommendations,security,social_web",
    "/ghost/api/admin/custom_theme_settings/",
    "/ghost/api/admin/themes/",
    "/ghost/api/admin/site/",
    "/ghost/api/admin/images/upload/",
    "/ghost/api/admin/posts/6735a1c2e4b0f2001b3c4d5e/?formats=mobiledoc,lexical&include=tags,authors,authors.roles,email,tiers,newsletter,count.clicks,post_revisions,post_revisions.author",
)

CASES: tuple[Case, ...] = (
    # The owner's 00:48 session: Settings > Design, previewed and saved. Before
    # this change, the eight "anomaly: 8" WAF alerts and the out-of-band ban.
    Case(
        "owner: design and announcement previews, admin shell",
        "198.51.100.10",
        banned=False,
        appsec=(
            *[preview_post(GHOST_HOST, THEME_PREVIEW) for _ in range(REPEATS)],
            *[preview_post(GHOST_HOST, ANNOUNCEMENT_PREVIEW) for _ in range(REPEATS)],
            AppsecRequest("GET", GHOST_HOST, "/ghost/", admin_shell_headers(GHOST_HOST)),
        ),
    ),
    # The owner's admin API calls answered 403 and 404 (an expired session,
    # device verification, a deleted post, or a ban already in force, as at
    # 00:50:54Z). Before this change, an admin-interface-probing ban.
    Case(
        "owner: Ghost admin API calls answered 403 and 404",
        "198.51.100.11",
        banned=False,
        log=tuple(
            LogLine(GHOST_HOST, path, 403 if index % 2 == 0 else 404, method)
            for index, path in enumerate(GHOST_ADMIN_API_PATHS)
            for method in ("GET", "PUT")
        ),
    ),
    # Probes: each must still ban.
    Case(
        "probe: an SQL injection in the query string of a Ghost site",
        "203.0.113.20",
        banned=True,
        appsec=tuple(
            AppsecRequest(
                "GET",
                GHOST_HOST,
                f"/?id=1%27%20OR%20%271%27%3D%27{index}",
                browser_headers(GHOST_HOST, "*/*", "empty"),
            )
            for index in range(REPEATS)
        ),
    ),
    Case(
        "probe: the preview shape on a host that is not a Ghost site",
        "203.0.113.21",
        banned=True,
        appsec=tuple(preview_post(OTHER_HOST, THEME_PREVIEW) for _ in range(REPEATS)),
    ),
    Case(
        "probe: a bodiless text/html POST to a Ghost site without the preview header",
        "203.0.113.22",
        banned=True,
        appsec=tuple(preview_post(GHOST_HOST, None) for _ in range(REPEATS)),
    ),
    Case(
        "probe: generic admin interfaces on a Ghost site",
        "203.0.113.30",
        banned=True,
        log=(
            LogLine(GHOST_HOST, "/wp-admin/", 404),
            LogLine(GHOST_HOST, "/phpmyadmin/", 404),
            LogLine(GHOST_HOST, "/admin/", 404),
        ),
    ),
    Case(
        "probe: Ghost admin API paths on a host that is not a Ghost site",
        "203.0.113.31",
        banned=True,
        log=tuple(LogLine(OTHER_HOST, path, 404) for path in GHOST_ADMIN_API_PATHS[:3]),
    ),
    Case(
        "probe: a generic admin interface mixed into Ghost admin API paths",
        "203.0.113.32",
        banned=True,
        log=(
            LogLine(GHOST_HOST, "/wp-login.php", 404),
            LogLine(GHOST_HOST, GHOST_ADMIN_API_PATHS[0], 403),
            LogLine(GHOST_HOST, GHOST_ADMIN_API_PATHS[2], 403),
        ),
    ),
    Case(
        "probe: dot segments out of the Ghost admin API prefix",
        "203.0.113.33",
        banned=True,
        log=(
            LogLine(GHOST_HOST, "/ghost/api/admin/../../phpmyadmin/", 404),
            LogLine(GHOST_HOST, "/ghost/api/admin/%2e%2e/%2e%2e/wp-admin/", 404),
            LogLine(GHOST_HOST, "/ghost/api/admin/..%2f..%2fmanager/html", 404),
        ),
    ),
)


def caddy_log_line(ip: str, line: LogLine) -> str:
    """A line in the shape Caddy's JSON access log writes and crowdsecurity/caddy-logs reads."""
    now = time.time()
    record = {
        "level": "info",
        "ts": now,
        "logger": "http.log.access.log0",
        "msg": "handled request",
        "request": {
            "remote_ip": ip,
            "remote_port": "51234",
            "client_ip": ip,
            "proto": "HTTP/2.0",
            "method": line.method,
            "host": line.host,
            "uri": line.uri,
            "headers": {"User-Agent": [CHROME_UA], "Accept": ["*/*"]},
            "tls": {"resumed": False, "version": 772, "proto": "h2", "server_name": line.host},
        },
        "bytes_read": 0,
        "user_id": "",
        "duration": 0.004,
        "size": 0,
        "status": line.status,
        "resp_headers": {"Content-Type": ["application/json; charset=utf-8"]},
    }
    return json.dumps(record, separators=(",", ":"))


class Stack:
    """The `crowdsec` service of the edge Compose stack, run under a throwaway project."""

    def __init__(self, workdir: pathlib.Path) -> None:
        self.workdir = workdir
        self.logs = workdir / "caddy-logs"
        self.access_log = self.logs / "access.log"
        self.override = workdir / "override.yml"
        self.project = f"edge-replay-{secrets.token_hex(4)}"
        self.key = secrets.token_hex(24)
        self.appsec_port = 0

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "IMAGE": "ghcr.io/branchleft/edge-caddy@sha256:" + "0" * 64,
                "CROWDSEC_BOUNCER_KEY": self.key,
                "ACME_EMAIL": "replay@example.invalid",
            }
        )
        return env

    def compose(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = [
            "docker",
            "compose",
            "--project-name",
            self.project,
            "--file",
            str(COMPOSE_FILE),
            "--file",
            str(self.override),
            *args,
        ]
        return subprocess.run(  # noqa: S603 -- a fixed docker argv, no shell
            command,
            env=self._env(),
            check=check,
            capture_output=True,
            text=True,
            timeout=START_TIMEOUT_S,
        )

    def cscli_json(self, *args: str) -> object:
        ran = self.compose("exec", "-T", "crowdsec", "cscli", *args, "-o", "json")
        text = ran.stdout.strip()
        return json.loads(text) if text and text != "null" else []

    def start(self) -> None:
        self.logs.mkdir()
        self.access_log.touch()
        self.logs.chmod(0o755)
        self.access_log.chmod(0o644)
        # Compose merges a service's volumes by target, so this one entry
        # replaces only the Caddy log volume; every configuration mount stays as
        # compose.yml has it. Ports are replaced whole: edge1's private address
        # does not exist here, and only the AppSec listener is needed.
        self.override.write_text(
            "services:\n"
            "  crowdsec:\n"
            "    ports: !override\n"
            "      - '127.0.0.1::7422'\n"
            "    volumes:\n"
            "      - type: bind\n"
            f"        source: {self.logs}\n"
            "        target: /var/log/caddy\n"
            "        read_only: true\n",
            encoding="utf-8",
        )
        ran = self.compose("up", "--detach", "--wait", "crowdsec", check=False)
        if ran.returncode != 0:
            logs = self.compose("logs", "crowdsec", check=False)
            fail(f"crowdsec did not start:\n{ran.stderr}\n{logs.stdout[-8000:]}")
        port = self.compose("port", "crowdsec", "7422").stdout.strip()
        self.appsec_port = int(port.rsplit(":", 1)[1])
        deadline = time.monotonic() + START_TIMEOUT_S
        while True:
            try:
                status = self.forward(
                    "127.0.0.1",
                    AppsecRequest("GET", "readiness.invalid", "/", {"User-Agent": "replay"}),
                )
                if status == 200:
                    return
            except OSError:
                pass
            if time.monotonic() > deadline:
                fail("the AppSec listener never answered 200")
            time.sleep(2)

    def stop(self) -> None:
        if self.override.exists():
            self.compose("down", "--volumes", "--timeout", "5", check=False)

    def forward(self, ip: str, request: AppsecRequest) -> int:
        """Send `request` to AppSec the way caddy-crowdsec-bouncer v0.15.0 does.

        A request with no body goes as a GET with no Content-Length (the
        bouncer's own transport drops the client's), the original headers are
        copied, and the original method, URI, host, address and user agent ride
        in the X-Crowdsec-Appsec-* headers.
        """
        connection = http.client.HTTPConnection("127.0.0.1", self.appsec_port, timeout=10)
        try:
            connection.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "crowdsec:7422")
            for name, value in request.headers.items():
                if name != "User-Agent":
                    connection.putheader(name, value)
            connection.putheader("X-Crowdsec-Appsec-Ip", ip)
            connection.putheader("X-Crowdsec-Appsec-Uri", request.uri)
            connection.putheader("X-Crowdsec-Appsec-Host", request.host)
            connection.putheader("X-Crowdsec-Appsec-Verb", request.method)
            connection.putheader("X-Crowdsec-Appsec-Api-Key", self.key)
            connection.putheader(
                "X-Crowdsec-Appsec-User-Agent", request.headers.get("User-Agent", "")
            )
            connection.putheader("User-Agent", "caddy-crowdsec-bouncer")
            connection.endheaders()
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def write_log(self, lines: Sequence[str]) -> None:
        with self.access_log.open("a", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line + "\n")
                handle.flush()

    def banned(self) -> dict[str, list[str]]:
        """Each banned address, with the scenarios behind its decisions."""
        found: dict[str, list[str]] = {}
        alerts = self.cscli_json("decisions", "list", "--limit", "0")
        for alert in alerts if isinstance(alerts, list) else []:
            for decision in alert.get("decisions") or []:
                if decision.get("type") == "ban" and decision.get("scope") == "Ip":
                    found.setdefault(str(decision.get("value")), []).append(
                        str(decision.get("scenario"))
                    )
        return found

    def alerts_for(self, ip: str) -> list[str]:
        """Every alert raised against `ip`, with the rule each event names."""
        described: list[str] = []
        alerts = self.cscli_json("alerts", "list", "--ip", ip, "--limit", "0")
        for alert in alerts if isinstance(alerts, list) else []:
            detail = self.cscli_json("alerts", "inspect", "--details", str(alert.get("id")))
            events = detail.get("events") if isinstance(detail, dict) else None
            rules = sorted(
                {
                    f"{meta.get('key')}={str(meta.get('value'))[:160]}"
                    for event in events or []
                    for meta in event.get("meta") or []
                    if meta.get("key") not in ("source_ip", "target_fqdn", "service", "log_type")
                }
            )
            described.append(f"{alert.get('scenario')}: {alert.get('message')} {rules}")
        return described

    def every_alert(self) -> list[str]:
        """One line per alert of any kind: scenario, source and message, for a failure's evidence."""
        alerts = self.cscli_json("alerts", "list", "--limit", "0", "--all")
        return [
            f"{alert.get('scenario')} {(alert.get('source') or {}).get('value')} {alert.get('message')}"
            for alert in (alerts if isinstance(alerts, list) else [])
        ]


@unittest.skipUnless(
    ENABLED, "needs a Docker engine that can start containers; CI sets BRANCHLEFT_CROWDSEC_REPLAY=1"
)
class GhostAdminIsNotBannedAndProbesAre(unittest.TestCase):
    stack: Stack
    workdir: pathlib.Path
    bans: dict[str, list[str]]

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("docker") is None:
            fail("BRANCHLEFT_CROWDSEC_REPLAY=1 but there is no docker on PATH")
        cls.workdir = pathlib.Path(tempfile.mkdtemp(prefix="crowdsec-replay-"))
        cls.workdir.chmod(0o755)
        cls.stack = Stack(cls.workdir)
        try:
            cls.stack.start()
            for case in CASES:
                for request in case.appsec:
                    status = cls.stack.forward(case.ip, request)
                    if status not in (200, 403):
                        fail(f"{case.name}: AppSec answered {status}")
                cls.stack.write_log([caddy_log_line(case.ip, line) for line in case.log])
            cls.bans = cls._await_verdicts()
        except BaseException:
            cls.stack.stop()
            shutil.rmtree(cls.workdir, ignore_errors=True)
            raise

    @classmethod
    def _await_verdicts(cls) -> dict[str, list[str]]:
        expected = {case.ip for case in CASES if case.banned}
        deadline = time.monotonic() + VERDICT_TIMEOUT_S
        bans = cls.stack.banned()
        while not expected <= bans.keys() and time.monotonic() < deadline:
            time.sleep(3)
            bans = cls.stack.banned()
        time.sleep(SETTLE_S)
        return cls.stack.banned()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stack.stop()
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def _explain(self, case: Case) -> str:
        alerts = self.stack.alerts_for(case.ip)
        return (
            f"{case.name} ({case.ip}): bans {self.bans.get(case.ip, [])}; alerts:\n  "
            + "\n  ".join(alerts)
        )

    def test_the_owners_admin_use_raises_no_ban(self) -> None:
        for case in CASES:
            if case.banned:
                continue
            with self.subTest(case.name):
                explanation = self._explain(case)
                print(explanation)
                self.assertNotIn(case.ip, self.bans, explanation)

    def test_the_owners_previews_raise_no_waf_alert_at_all(self) -> None:
        case = CASES[0]
        every = "\n  ".join(self.stack.every_alert())
        self.assertEqual(
            self.stack.alerts_for(case.ip), [], f"{self._explain(case)}\nevery alert:\n  {every}"
        )

    def test_every_probe_is_still_banned(self) -> None:
        for case in CASES:
            if not case.banned:
                continue
            with self.subTest(case.name):
                explanation = self._explain(case)
                print(explanation)
                self.assertIn(case.ip, self.bans, explanation)


if __name__ == "__main__":
    unittest.main()
