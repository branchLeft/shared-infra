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
    body: bytes = b""


@dataclasses.dataclass(frozen=True)
class LogLine:
    """One request as Caddy's access log records it."""

    host: str
    uri: str
    status: int
    method: str = "GET"


@dataclasses.dataclass(frozen=True)
class Case:
    """A source address, the traffic it sends, and whether it must be banned.

    `watched` means the out-of-band Core Rule Set scenario must record an alert
    for the address while no bouncer is told to refuse it: the scenario is
    watch-only (posture.md, "Watch-only scenarios").
    """

    name: str
    ip: str
    banned: bool
    appsec: Sequence[AppsecRequest] = ()
    log: Sequence[LogLine] = ()
    watched: bool = False


# The out-of-band Core Rule Set scenario, which only watches.
OUT_OF_BAND_SCENARIO = "crowdsecurity/crowdsec-appsec-outofband"


def preview_post(host: str, preview: str | None) -> AppsecRequest:
    return AppsecRequest("POST", host, "/?admin_toolbar=0", preview_headers(host, preview))


def known_exploits(host: str) -> tuple[AppsecRequest, ...]:
    """Two requests the hub's in-band virtual patches refuse: a leaked .env and a
    leaked git config. Different rules, so the second inside a minute bans."""
    headers = {"User-Agent": "Mozilla/5.0 zgrab/0.x", "Accept": "*/*"}
    return (
        AppsecRequest("GET", host, "/.env", headers),
        AppsecRequest("GET", host, "/.git/config", headers),
    )


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
    # Probes the Core Rule Set alone sees: each is recorded, and none bans while
    # the out-of-band scenario only watches. Before that, each banned.
    Case(
        "probe: an SQL injection in the query string of a Ghost site",
        "203.0.113.20",
        banned=False,
        watched=True,
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
        banned=False,
        watched=True,
        appsec=tuple(preview_post(OTHER_HOST, THEME_PREVIEW) for _ in range(REPEATS)),
    ),
    Case(
        "probe: a bodiless text/html POST to a Ghost site without the preview header",
        "203.0.113.22",
        banned=False,
        watched=True,
        appsec=tuple(preview_post(GHOST_HOST, None) for _ in range(REPEATS)),
    ),
    # Known exploits: refused in-band, one request at a time, and two different
    # ones inside a minute ban. This half of the WAF stays enforcing.
    Case(
        "probe: two known exploits, refused in-band",
        "203.0.113.23",
        banned=True,
        appsec=known_exploits(OTHER_HOST),
    ),
    # Probes the access log shows: each must still ban.
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


def go_duration_minutes(text: str) -> float:
    """Minutes in a Go duration string as cscli prints one, such as `29m58.3s`."""
    units = {"h": 60.0, "m": 1.0, "s": 1 / 60}
    total = 0.0
    number = ""
    for char in text:
        if char.isdigit() or char in ".-":
            number += char
            continue
        if char not in units or not number:
            fail(f"not a duration: {text!r}")
        total += float(number) * units[char]
        number = ""
    if number or not text:
        fail(f"not a duration: {text!r}")
    return total


def run_cases(stack: "Stack", cases: Sequence[Case]) -> dict[str, list[int]]:
    """Play every case at the stack; returns the AppSec status of each request, by case."""
    statuses: dict[str, list[int]] = {}
    for case in cases:
        for request in case.appsec:
            status = stack.forward(case.ip, request)
            if status not in (200, 403):
                fail(f"{case.name}: AppSec answered {status}")
            statuses.setdefault(case.name, []).append(status)
        stack.write_log([caddy_log_line(case.ip, line) for line in case.log])
    return statuses


def await_verdicts(stack: "Stack", cases: Sequence[Case]) -> dict[str, list[str]]:
    """Wait until every expected ban and every expected watched alert has landed,
    then a little longer for anything not expected; returns the enforced bans."""
    expected = {case.ip for case in cases if case.banned}
    watched = [case.ip for case in cases if case.watched]
    deadline = time.monotonic() + VERDICT_TIMEOUT_S
    while time.monotonic() < deadline:
        bans = stack.banned()
        if expected <= bans.keys() and all(
            OUT_OF_BAND_SCENARIO in stack.alerted(ip) for ip in watched
        ):
            break
        time.sleep(3)
    time.sleep(SETTLE_S)
    return stack.banned()


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
        bouncer's own transport drops the client's); one with a body goes as a
        POST carrying it. The original headers are copied, and the original
        method, URI, host, address and user agent ride in the
        X-Crowdsec-Appsec-* headers.
        """
        connection = http.client.HTTPConnection("127.0.0.1", self.appsec_port, timeout=10)
        try:
            method = "POST" if request.body else "GET"
            connection.putrequest(method, "/", skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "crowdsec:7422")
            for name, value in request.headers.items():
                if name not in ("User-Agent", "Content-Length"):
                    connection.putheader(name, value)
            if request.body:
                connection.putheader("Content-Length", str(len(request.body)))
            connection.putheader("X-Crowdsec-Appsec-Ip", ip)
            connection.putheader("X-Crowdsec-Appsec-Uri", request.uri)
            connection.putheader("X-Crowdsec-Appsec-Host", request.host)
            connection.putheader("X-Crowdsec-Appsec-Verb", request.method)
            connection.putheader("X-Crowdsec-Appsec-Api-Key", self.key)
            connection.putheader(
                "X-Crowdsec-Appsec-User-Agent", request.headers.get("User-Agent", "")
            )
            connection.putheader("User-Agent", "caddy-crowdsec-bouncer")
            connection.endheaders(request.body or None)
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

    def decisions(self) -> list[dict[str, object]]:
        """Every IP ban decision CrowdSec holds, simulated or not."""
        found: list[dict[str, object]] = []
        alerts = self.cscli_json("decisions", "list", "--limit", "0")
        for alert in alerts if isinstance(alerts, list) else []:
            for decision in alert.get("decisions") or []:
                if decision.get("type") == "ban" and decision.get("scope") == "Ip":
                    found.append(decision)
        return found

    def banned(self) -> dict[str, list[str]]:
        """Each address a bouncer is told to refuse, with the scenarios behind
        its decisions. A simulated decision refuses nobody, so it is not here."""
        found: dict[str, list[str]] = {}
        for decision in self.decisions():
            if not decision.get("simulated"):
                found.setdefault(str(decision.get("value")), []).append(
                    str(decision.get("scenario"))
                )
        return found

    def ban_minutes(self, ip: str, scenario: str) -> list[float]:
        """How long each enforced decision `scenario` made against `ip` runs, in minutes."""
        return [
            go_duration_minutes(str(decision.get("duration")))
            for decision in self.decisions()
            if str(decision.get("value")) == ip
            and str(decision.get("scenario")) == scenario
            and not decision.get("simulated")
        ]

    def add_decision(self, ip: str) -> None:
        """A one-minute ban by hand, as an operator's `cscli decisions add` makes one."""
        self.compose(
            "exec", "-T", "crowdsec", "cscli", "decisions", "add",
            "--ip", ip, "--duration", "1m", "--reason", "replay: an earlier ban",
        )  # fmt: skip

    def alerted(self, ip: str) -> list[str]:
        """The scenario behind each alert raised against `ip`."""
        alerts = self.cscli_json("alerts", "list", "--ip", ip, "--limit", "0")
        return [
            str(alert.get("scenario")) for alert in (alerts if isinstance(alerts, list) else [])
        ]

    def metrics(self) -> str:
        """CrowdSec's own Prometheus exposition, as edge1's monitoring scrapes it."""
        ran = self.compose(
            "exec", "-T", "crowdsec", "wget", "-q", "-O", "-", "http://127.0.0.1:6060/metrics",
        )  # fmt: skip
        return ran.stdout

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
    statuses: dict[str, list[int]]

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("docker") is None:
            fail("BRANCHLEFT_CROWDSEC_REPLAY=1 but there is no docker on PATH")
        cls.workdir = pathlib.Path(tempfile.mkdtemp(prefix="crowdsec-replay-"))
        cls.workdir.chmod(0o755)
        cls.stack = Stack(cls.workdir)
        try:
            cls.stack.start()
            cls.statuses = run_cases(cls.stack, CASES)
            cls.bans = await_verdicts(cls.stack, CASES)
        except BaseException:
            cls.stack.stop()
            shutil.rmtree(cls.workdir, ignore_errors=True)
            raise

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

    def test_the_core_rule_set_records_its_probes_and_bans_none(self) -> None:
        for case in CASES:
            if not case.watched:
                continue
            with self.subTest(case.name):
                explanation = self._explain(case)
                print(explanation)
                self.assertIn(OUT_OF_BAND_SCENARIO, self.stack.alerted(case.ip), explanation)
                self.assertNotIn(case.ip, self.bans, explanation)

    def test_known_exploits_are_refused_in_band(self) -> None:
        case = next(entry for entry in CASES if entry.name.endswith("refused in-band"))
        self.assertEqual(self.statuses.get(case.name), [403, 403], self._explain(case))


# --- Failed Ghost admin sign-ins and admin API key failures (workspace#3754) ---

BRUTE_FORCE_SCENARIO = "branchleft/ghost-admin-login-bruteforce"
SESSION_PATH = "/ghost/api/admin/session/"
VERIFY_PATH = "/ghost/api/admin/session/verify/"
POSTS_PATH = "/ghost/api/admin/posts/?limit=15"

# The bucket holds nine: the tenth failure bans.
BUCKET_CAPACITY = 9


def attempts(
    count: int, status: int, path: str = SESSION_PATH, method: str = "POST", host: str = GHOST_HOST
) -> tuple[LogLine, ...]:
    return tuple(LogLine(host, path, status, method) for _ in range(count))


# Ghost answers a wrong password 422, an unknown email 404, no credentials or a
# locked account 401, its own lockout 429, a bad Admin API key 401, and a right
# password from a new device 403 (2FA_NEW_DEVICE_DETECTED), which is no failure.
BRUTE_FORCE_CASES: tuple[Case, ...] = (
    # --- Must ban, and by this scenario. ---
    Case(
        "burst: wrong passwords (422)",
        "203.0.113.40",
        banned=True,
        log=attempts(REPEATS, 422),
    ),
    Case(
        "burst: unknown email addresses (404)",
        "203.0.113.41",
        banned=True,
        log=attempts(REPEATS, 404),
    ),
    Case(
        "burst: a script that keeps going after Ghost's own lockout (429)",
        "203.0.113.42",
        banned=True,
        log=(*attempts(5, 422), *attempts(REPEATS, 429)),
    ),
    Case(
        "burst: wrong passwords on a versioned, differently cased session path",
        "203.0.113.43",
        banned=True,
        log=attempts(REPEATS, 422, "/GHOST/api/v5.0/admin/session/"),
    ),
    Case(
        "burst: Admin API key guessing (401 on admin API paths, which Ghost does not limit)",
        "203.0.113.44",
        banned=True,
        log=(
            *attempts(REPEATS // 2, 401, POSTS_PATH, "GET"),
            *attempts(REPEATS // 2, 401, "/ghost/api/admin/users/", "GET"),
        ),
    ),
    Case(
        "burst: sign-in failures and key failures together",
        "203.0.113.45",
        banned=True,
        log=(*attempts(5, 422), *attempts(5, 401, POSTS_PATH, "GET")),
    ),
    Case(
        "burst: exactly ten failed sign-ins, the tenth being the first to ban",
        "203.0.113.46",
        banned=True,
        log=attempts(BUCKET_CAPACITY + 1, 422),
    ),
    # --- Must not ban. ---
    Case(
        "owner: mistypes the password five times, then meets Ghost's lockout three times",
        "198.51.100.40",
        banned=False,
        log=(*attempts(5, 422), *attempts(3, 429)),
    ),
    Case(
        "owner: nine failed sign-ins, the most the bucket holds",
        "198.51.100.41",
        banned=False,
        log=attempts(BUCKET_CAPACITY, 422),
    ),
    Case(
        "owner: a typo, a new device, a mistyped code twice, then sign-in and a day of admin use",
        "198.51.100.42",
        banned=False,
        log=(
            *attempts(1, 422),
            *attempts(1, 403),
            *attempts(2, 401, VERIFY_PATH, "PUT"),
            *attempts(1, 200, VERIFY_PATH, "PUT"),
            *attempts(1, 201),
            *attempts(20, 200, POSTS_PATH, "GET"),
            *attempts(10, 200, "/ghost/api/admin/posts/6735a1c2e4b0f2001b3c4d5e/", "PUT"),
            *attempts(10, 201, "/ghost/api/admin/images/upload/", "POST"),
        ),
    ),
    Case(
        "owner: an expired session, admin calls answered 403, and a sign-in that needs a code",
        "198.51.100.43",
        banned=False,
        log=(*attempts(4, 403, POSTS_PATH, "GET"), *attempts(2, 403)),
    ),
    Case(
        "not a Ghost site: the same burst of 422s on a host that is not a Ghost hostname",
        "198.51.100.44",
        banned=False,
        log=attempts(REPEATS, 422, host=OTHER_HOST),
    ),
)


@unittest.skipUnless(
    ENABLED, "needs a Docker engine that can start containers; CI sets BRANCHLEFT_CROWDSEC_REPLAY=1"
)
class FailedGhostSignInsAreBannedAndTheOwnersAreNot(unittest.TestCase):
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
            for case in BRUTE_FORCE_CASES:
                cls.stack.write_log([caddy_log_line(case.ip, line) for line in case.log])
            cls.bans = cls._await_verdicts()
        except BaseException:
            cls.stack.stop()
            shutil.rmtree(cls.workdir, ignore_errors=True)
            raise

    @classmethod
    def _await_verdicts(cls) -> dict[str, list[str]]:
        expected = {case.ip for case in BRUTE_FORCE_CASES if case.banned}
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
        every = "\n  ".join(self.stack.every_alert())
        return (
            f"{case.name} ({case.ip}): bans {self.bans.get(case.ip, [])}; alerts:\n  "
            + "\n  ".join(alerts)
            + f"\nevery alert:\n  {every}"
        )

    def _alerted(self, ip: str) -> list[str]:
        """The scenario behind each alert raised against `ip`."""
        alerts = self.stack.cscli_json("alerts", "list", "--ip", ip, "--limit", "0")
        return [
            str(alert.get("scenario")) for alert in (alerts if isinstance(alerts, list) else [])
        ]

    def test_a_burst_of_failed_sign_ins_or_key_failures_is_banned_by_the_scenario(self) -> None:
        for case in BRUTE_FORCE_CASES:
            if not case.banned:
                continue
            with self.subTest(case.name):
                explanation = self._explain(case)
                print(explanation)
                self.assertIn(case.ip, self.bans, explanation)
                # By alert, not by decision: a hub scenario can ban the same
                # address first, and CrowdSec keeps one decision per address.
                self.assertIn(BRUTE_FORCE_SCENARIO, self._alerted(case.ip), explanation)

    def test_the_owners_sign_in_and_admin_use_is_not_banned(self) -> None:
        for case in BRUTE_FORCE_CASES:
            if case.banned:
                continue
            with self.subTest(case.name):
                explanation = self._explain(case)
                print(explanation)
                self.assertNotIn(case.ip, self.bans, explanation)


# --- The lockouts of 14 and 15 Nov, replayed, and what must still ban ---
#
# The owner was banned from every site twice on 15 Nov while on a Nextcloud
# Talk video call, and on 14 Nov while editing the blog (the classes above
# replay the blog). Which rule fired on 15 Nov was not read off the host, so
# this replays the traffic a signed-in Talk call and the desktop sync client
# make, both to AppSec and to the access log, and requires no ban.

NEXTCLOUD_HOST = "cloud.branchleft.co.uk"
TALK_ROOM = "k7v3qz9p"
NC_USER = "owner"
OWN_HOST_IP = "10.20.1.50"  # ops1, on the never-ban list
FIRST_RUNG_MINUTES = 10
SECOND_RUNG_MINUTES = 30
ADMIN_PROBING = "crowdsecurity/http-admin-interface-probing"

NC_COOKIE = (
    "oc_sessionPassphrase=Zk1lZ2h0c2lnbmF0dXJlcGFzc3BocmFzZQ%3D%3D; "
    "nc_session_id=3c9b2f0e8a1d4f6b9e7c5a3d1f0b8e6a; "
    "ocx7a1b2c3d4e5=k2v9q8w7e6r5t4y3u2i1o0p9; "
    "__Host-nc_sameSiteCookielax=true; __Host-nc_sameSiteCookiestrict=true"
)

# One WebRTC offer and one ICE candidate, as Talk's own signalling sends them
# through Nextcloud when there is no separate signalling server.
SDP_OFFER = (
    "v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
    "a=group:BUNDLE 0 1\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS 3f2a9c\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126\r\nc=IN IP4 0.0.0.0\r\n"
    "a=rtcp:9 IN IP4 0.0.0.0\r\na=ice-ufrag:Hk3p\r\na=ice-pwd:9vYlq0dS8m2PbXk1fJb0yZ7A\r\n"
    "a=ice-options:trickle\r\na=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:26:12:B7:3A:"
    "5A:7E:8C:9A:8F:5E:3D:2C:1B:0A:99:88:77:66:55:44:33:22:11:00\r\n"
    "a=setup:actpass\r\na=mid:0\r\na=sendrecv\r\na=rtcp-mux\r\na=rtpmap:111 opus/48000/2\r\n"
    "a=rtcp-fb:111 transport-cc\r\na=fmtp:111 minptime=10;useinbandfec=1\r\n"
    "m=video 9 UDP/TLS/RTP/SAVPF 96 97 102\r\nc=IN IP4 0.0.0.0\r\na=mid:1\r\na=sendrecv\r\n"
    "a=rtpmap:96 VP8/90000\r\na=rtcp-fb:96 goog-remb\r\na=rtcp-fb:96 nack pli\r\n"
)
ICE_CANDIDATE = (
    "candidate:842163049 1 udp 1677729535 198.51.100.60 54400 typ srflx raddr 0.0.0.0 "
    "rport 0 generation 0 ufrag Hk3p network-cost 999"
)


def nextcloud_headers(content_type: str | None = None, ocs: bool = True) -> dict[str, str]:
    """What the Nextcloud web app sends on a signed-in API call."""
    headers = browser_headers(NEXTCLOUD_HOST, "application/json, text/plain, */*", "empty")
    headers["Referer"] = f"https://{NEXTCLOUD_HOST}/call/{TALK_ROOM}"
    headers["Cookie"] = NC_COOKIE
    headers["requesttoken"] = "Yk9vT2x3N2s5c0J4c1hYb1dWZ0E9OjFEdkVhV2JKc2c="
    if ocs:
        headers["OCS-APIRequest"] = "true"
    if content_type is not None:
        headers["Content-Type"] = content_type
    return headers


def signalling_message(kind: str, payload: Mapping[str, object]) -> bytes:
    """One internal-signalling POST body: a JSON list of messages, each a JSON string."""
    inner = json.dumps(
        {
            "to": "b7d1e9c2a4f6",
            "sid": "1731700000123",
            "roomType": "video",
            "type": kind,
            "payload": payload,
        }
    )
    messages = json.dumps([{"ev": "message", "fn": inner, "sessionId": "a3c5e7f9b1d2"}])
    return json.dumps({"messages": messages}).encode()


def talk_call() -> tuple[AppsecRequest, ...]:
    """One round of a signed-in Talk video call, repeated as a call repeats it."""
    ocs = "/ocs/v2.php/apps/spreed/api"
    as_json = nextcloud_headers("application/json")
    plain = nextcloud_headers()
    one_round = (
        AppsecRequest("POST", NEXTCLOUD_HOST, f"{ocs}/v4/room/{TALK_ROOM}/participants/active",
                      as_json, b'{"force":true}'),
        AppsecRequest("POST", NEXTCLOUD_HOST, f"{ocs}/v4/call/{TALK_ROOM}", as_json,
                      b'{"flags":7,"silent":false,"recordingConsent":false}'),
        AppsecRequest("POST", NEXTCLOUD_HOST, f"{ocs}/v3/signaling/{TALK_ROOM}", as_json,
                      signalling_message("offer", {"type": "offer", "sdp": SDP_OFFER})),
        AppsecRequest("POST", NEXTCLOUD_HOST, f"{ocs}/v3/signaling/{TALK_ROOM}", as_json,
                      signalling_message("candidate", {"candidate": {
                          "candidate": ICE_CANDIDATE, "sdpMid": "0", "sdpMLineIndex": 0}})),
        AppsecRequest("GET", NEXTCLOUD_HOST, f"{ocs}/v3/signaling/{TALK_ROOM}", plain),
        AppsecRequest("GET", NEXTCLOUD_HOST,
                      f"{ocs}/v4/room/{TALK_ROOM}/participants?includeStatus=true", plain),
        AppsecRequest("GET", NEXTCLOUD_HOST,
                      f"{ocs}/v1/chat/{TALK_ROOM}?lookIntoFuture=1&limit=100&timeout=30"
                      "&lastKnownMessageId=4211&markNotificationsAsRead=0&includeLastKnown=0",
                      plain),
        AppsecRequest("POST", NEXTCLOUD_HOST, f"{ocs}/v1/chat/{TALK_ROOM}", as_json,
                      json.dumps({"message": "Can you hear me? I'm on -- my mic's muted; "
                                  "one sec & I'll share the 'Q4' doc.",
                                  "actorDisplayName": "", "replyTo": 0, "silent": False,
                                  "referenceId": "9f86d081884c7d659a2feaa0c55ad015"}).encode()),
        AppsecRequest("GET", NEXTCLOUD_HOST, "/ocs/v2.php/apps/notifications/api/v2/notifications",
                      plain),
        AppsecRequest("GET", NEXTCLOUD_HOST, f"/index.php/avatar/{NC_USER}/64/dark",
                      nextcloud_headers(ocs=False)),
    )  # fmt: skip
    return tuple(request for _ in range(REPEATS) for request in one_round)


def talk_call_log() -> tuple[LogLine, ...]:
    """The access log of the same call, with the answers Talk gives mid-call."""
    ocs = "/ocs/v2.php/apps/spreed/api"
    one_round = (
        LogLine(NEXTCLOUD_HOST, f"{ocs}/v4/room/{TALK_ROOM}/participants/active", 200, "POST"),
        LogLine(NEXTCLOUD_HOST, f"{ocs}/v4/call/{TALK_ROOM}", 200, "POST"),
        LogLine(NEXTCLOUD_HOST, f"{ocs}/v3/signaling/{TALK_ROOM}", 200, "POST"),
        LogLine(NEXTCLOUD_HOST, f"{ocs}/v3/signaling/{TALK_ROOM}", 404),
        LogLine(NEXTCLOUD_HOST, f"{ocs}/v4/room/{TALK_ROOM}/participants?includeStatus=true", 200),
        LogLine(NEXTCLOUD_HOST, f"{ocs}/v1/chat/{TALK_ROOM}?lookIntoFuture=1&limit=100", 304),
        LogLine(NEXTCLOUD_HOST, f"{ocs}/v4/call/{TALK_ROOM}", 412, "PUT"),
        LogLine(NEXTCLOUD_HOST, f"/index.php/avatar/{NC_USER}/64/dark", 304),
    )
    guests = tuple(
        LogLine(NEXTCLOUD_HOST, f"/index.php/avatar/guest-{index}/64", 404) for index in range(12)
    )
    return (*[line for _ in range(REPEATS) for line in one_round], *guests)


PROPFIND_BODY = (
    b'<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" '
    b'xmlns:nc="http://nextcloud.org/ns"><d:prop><d:getlastmodified/><d:getcontentlength/>'
    b"<d:resourcetype/><d:getetag/><oc:fileid/><oc:permissions/><nc:has-preview/></d:prop>"
    b"</d:propfind>"
)
SYNC_CLIENT_UA = (
    "Mozilla/5.0 (Macintosh) mirall/3.14.3 (Nextcloud, osx-23.3.0 ClientArchitecture: arm64 "
    "OsArchitecture: arm64)"
)


def sync_and_files() -> tuple[AppsecRequest, ...]:
    """The desktop client checking a folder, and the web app listing one."""
    dav = f"/remote.php/dav/files/{NC_USER}/Documents/"
    client = {
        "User-Agent": SYNC_CLIENT_UA,
        "Authorization": "Basic b3duZXI6YXBwLXBhc3N3b3JkLW5vdC1yZWFs",
        "Content-Type": "application/xml; charset=utf-8",
        "Depth": "1",
        "Accept": "*/*",
    }
    web = nextcloud_headers("application/xml; charset=utf-8", ocs=False)
    web["Depth"] = "1"
    return tuple(
        request
        for _ in range(REPEATS)
        for request in (
            AppsecRequest("PROPFIND", NEXTCLOUD_HOST, dav, client, PROPFIND_BODY),
            AppsecRequest("PROPFIND", NEXTCLOUD_HOST, dav, web, PROPFIND_BODY),
        )
    )


def sync_and_files_log() -> tuple[LogLine, ...]:
    """Sync and browsing as the access log shows them: a 404 before each new upload,
    and a 404 for each file that has no preview yet."""
    dav = f"/remote.php/dav/files/{NC_USER}"
    return (
        *[LogLine(NEXTCLOUD_HOST, f"{dav}/Documents/", 207, "PROPFIND") for _ in range(20)],
        *[
            line
            for index in range(15)
            for line in (
                LogLine(NEXTCLOUD_HOST, f"{dav}/Documents/minutes-{index}.odt", 404, "PROPFIND"),
                LogLine(NEXTCLOUD_HOST, f"{dav}/Documents/minutes-{index}.odt", 201, "PUT"),
            )
        ],
        LogLine(NEXTCLOUD_HOST, f"{dav}/Photos/2026-11/", 201, "MKCOL"),
        LogLine(NEXTCLOUD_HOST, f"{dav}/Photos/2026-11/", 405, "MKCOL"),
        *[
            LogLine(
                NEXTCLOUD_HOST, f"/index.php/core/preview?fileId={9000 + index}&x=250&y=250", 404
            )
            for index in range(15)
        ],
        *[
            LogLine(
                NEXTCLOUD_HOST, f"/apps/files/api/v1/thumbnail/256/256/Photos/{index}.heic", 404
            )
            for index in range(15)
        ],
    )


LOCKOUT_CASES: tuple[Case, ...] = (
    # --- The owner's own use: must not ban. ---
    Case(
        "owner: a signed-in Nextcloud Talk video call",
        "198.51.100.60",
        banned=False,
        appsec=talk_call(),
        log=talk_call_log(),
    ),
    Case(
        "owner: Nextcloud desktop sync and the Files app",
        "198.51.100.61",
        banned=False,
        appsec=sync_and_files(),
        log=sync_and_files_log(),
    ),
    Case(
        "own host: ops1, whatever it sends",
        OWN_HOST_IP,
        banned=False,
        appsec=(
            *[preview_post(OTHER_HOST, None) for _ in range(REPEATS)],
            *known_exploits(NEXTCLOUD_HOST),
        ),
        log=(
            LogLine(NEXTCLOUD_HOST, "/wp-admin/", 404),
            LogLine(NEXTCLOUD_HOST, "/phpmyadmin/", 404),
            LogLine(NEXTCLOUD_HOST, "/admin/", 404),
            LogLine(GHOST_HOST, "/wp-login.php", 404),
        ),
    ),
    # --- Attacks on the Nextcloud hostname: must still ban. ---
    Case(
        "probe: generic admin interfaces on the Nextcloud hostname",
        "203.0.113.60",
        banned=True,
        log=(
            LogLine(NEXTCLOUD_HOST, "/wp-admin/", 404),
            LogLine(NEXTCLOUD_HOST, "/phpmyadmin/", 404),
            LogLine(NEXTCLOUD_HOST, "/admin/", 404),
        ),
    ),
    Case(
        "probe: dot segments out of the WebDAV prefix",
        "203.0.113.61",
        banned=True,
        log=(
            LogLine(NEXTCLOUD_HOST, "/remote.php/dav/../../wp-admin/", 404),
            LogLine(NEXTCLOUD_HOST, "/remote.php/webdav/%2e%2e/%2e%2e/phpmyadmin/", 404),
            LogLine(NEXTCLOUD_HOST, "/remote.php/dav/..%2f..%2fadmin/", 404),
        ),
    ),
    Case(
        "probe: two known exploits on the Nextcloud hostname, refused in-band",
        "203.0.113.62",
        banned=True,
        appsec=known_exploits(NEXTCLOUD_HOST),
    ),
    # --- The ban ladder. ---
    Case(
        "ladder: a first ban is the first rung",
        "203.0.113.70",
        banned=True,
        log=(
            LogLine(OTHER_HOST, "/wp-admin/", 404),
            LogLine(OTHER_HOST, "/phpmyadmin/", 404),
            LogLine(OTHER_HOST, "/admin/", 404),
        ),
    ),
    Case(
        "ladder: a ban after an earlier one climbs a rung",
        "203.0.113.71",
        banned=True,
        log=(
            LogLine(OTHER_HOST, "/wp-admin/", 404),
            LogLine(OTHER_HOST, "/phpmyadmin/", 404),
            LogLine(OTHER_HOST, "/admin/", 404),
        ),
    ),
)


def case_named(prefix: str) -> Case:
    return next(case for case in LOCKOUT_CASES if case.name.startswith(prefix))


@unittest.skipUnless(
    ENABLED, "needs a Docker engine that can start containers; CI sets BRANCHLEFT_CROWDSEC_REPLAY=1"
)
class TheLockoutsDoNotRecurAndAttacksStillBan(unittest.TestCase):
    stack: Stack
    workdir: pathlib.Path
    bans: dict[str, list[str]]
    statuses: dict[str, list[int]]
    metrics: str

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("docker") is None:
            fail("BRANCHLEFT_CROWDSEC_REPLAY=1 but there is no docker on PATH")
        cls.workdir = pathlib.Path(tempfile.mkdtemp(prefix="crowdsec-replay-"))
        cls.workdir.chmod(0o755)
        cls.stack = Stack(cls.workdir)
        try:
            cls.stack.start()
            # The second ladder case has had a ban today already.
            cls.stack.add_decision(case_named("ladder: a ban after").ip)
            cls.statuses = run_cases(cls.stack, LOCKOUT_CASES)
            cls.bans = await_verdicts(cls.stack, LOCKOUT_CASES)
            cls.metrics = cls.stack.metrics()
        except BaseException:
            cls.stack.stop()
            shutil.rmtree(cls.workdir, ignore_errors=True)
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stack.stop()
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def _explain(self, case: Case) -> str:
        alerts = self.stack.alerts_for(case.ip)
        return (
            f"{case.name} ({case.ip}): bans {self.bans.get(case.ip, [])}; statuses "
            f"{self.statuses.get(case.name, [])}; alerts:\n  " + "\n  ".join(alerts)
        )

    def test_the_owners_talk_call_and_sync_are_not_banned(self) -> None:
        for prefix in ("owner: a signed-in Nextcloud Talk", "owner: Nextcloud desktop sync"):
            case = case_named(prefix)
            with self.subTest(case.name):
                explanation = self._explain(case)
                print(explanation)
                self.assertNotIn(case.ip, self.bans, explanation)

    def test_nextclouds_own_traffic_raises_no_log_scenario_alert(self) -> None:
        for prefix in ("owner: a signed-in Nextcloud Talk", "owner: Nextcloud desktop sync"):
            case = case_named(prefix)
            with self.subTest(case.name):
                others = [s for s in self.stack.alerted(case.ip) if s != OUT_OF_BAND_SCENARIO]
                self.assertEqual(others, [], self._explain(case))

    def test_our_own_host_is_never_banned_and_raises_no_alert(self) -> None:
        case = case_named("own host")
        explanation = self._explain(case)
        print(explanation)
        self.assertNotIn(case.ip, self.bans, explanation)
        self.assertEqual(self.stack.alerted(case.ip), [], explanation)

    def test_attacks_on_the_nextcloud_hostname_still_ban(self) -> None:
        for case in LOCKOUT_CASES:
            if case.banned:
                with self.subTest(case.name):
                    explanation = self._explain(case)
                    print(explanation)
                    self.assertIn(case.ip, self.bans, explanation)
        exploits = case_named("probe: two known exploits")
        self.assertEqual(self.statuses.get(exploits.name), [403, 403], self._explain(exploits))

    def test_a_first_ban_lasts_the_first_rung(self) -> None:
        case = case_named("ladder: a first ban")
        minutes = self.stack.ban_minutes(case.ip, ADMIN_PROBING)
        self.assertTrue(minutes, self._explain(case))
        self.assertTrue(
            all(FIRST_RUNG_MINUTES - 2 < value <= FIRST_RUNG_MINUTES for value in minutes),
            f"{minutes}\n{self._explain(case)}",
        )

    def test_a_ban_after_an_earlier_one_lasts_the_second_rung(self) -> None:
        case = case_named("ladder: a ban after")
        minutes = self.stack.ban_minutes(case.ip, ADMIN_PROBING)
        self.assertTrue(minutes, self._explain(case))
        self.assertTrue(
            all(SECOND_RUNG_MINUTES - 2 < value <= SECOND_RUNG_MINUTES for value in minutes),
            f"{minutes}\n{self._explain(case)}",
        )

    def test_the_paging_metric_counts_real_bans_and_not_watched_ones(self) -> None:
        # The page rule reads cs_active_decisions{action="ban"} by reason
        # (hetzner/monitoring/render.ts, EdgeBanIssued).
        series = [
            line
            for line in self.metrics.splitlines()
            if line.startswith("cs_active_decisions{") and 'action="ban"' in line
        ]
        probing = [line for line in series if f'reason="{ADMIN_PROBING}"' in line]
        self.assertTrue(probing, "\n".join(series) or self.metrics[-4000:])
        self.assertGreaterEqual(float(probing[0].rsplit(" ", 1)[1]), 1, "\n".join(series))
        watched = [
            line
            for line in series
            if f'reason="{OUT_OF_BAND_SCENARIO}"' in line and float(line.rsplit(" ", 1)[1]) > 0
        ]
        self.assertEqual(watched, [], "\n".join(series))


if __name__ == "__main__":
    unittest.main()
