"""A verified Ghost staff session is never refused by a CrowdSec ban or AppSec.

What it proves, against the edge's real Caddy (the image CI builds from
`Dockerfile`, bouncer and AppSec modules included) and the edge's real CrowdSec
(the `crowdsec` service of `stack/compose.yml`, its mounted files included):

- an address CrowdSec has banned still reaches Ghost with a valid staff session;
- the same address is refused with a forged, expired or wrong-origin cookie, and
  with every other answer from Ghost that is not a 2xx JSON one;
- traffic that would ban an address bans nobody when its session is verified,
  because its access-log lines never reach a bucket; and a forged
  `edge_trusted` header or query parameter changes nothing.

Caddy loads `validation/Caddyfile.trusted-session`, which `render.test.ts`
renders with this renderer: two Ghost tenants with `trustedSession` set. The one
changes made to it here are the certificate source (`local_certs`, so Caddy
issues from its own test CA instead of asking Let's Encrypt) and the upstream
address, which becomes the address of Ghost on the test network. Ghost is
`fixtures/ghost_session_stub.py`.
Each case's requests come from `fixtures/edge_client.py` in its own container,
at its own public test address, so a ban names the case that caused it.

Why the edge does this: `render.md`, "Verified sessions". It needs a Docker
engine that can start containers, so like `test_crowdsec_replay.py` it is
skipped unless `BRANCHLEFT_CROWDSEC_REPLAY=1`, which CI's
`edge-config-validate` job sets after building the edge image.
"""

from __future__ import annotations

import dataclasses
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
CADDYFILE = EDGE / "validation" / "Caddyfile.trusted-session"
FIXTURES = EDGE / "fixtures"

ENABLED = os.environ.get("BRANCHLEFT_CROWDSEC_REPLAY") == "1"
# The tag CI's edge-config-validate job builds from hetzner/edge/Dockerfile.
CADDY_IMAGE = os.environ.get("BRANCHLEFT_EDGE_CADDY_IMAGE", "edge-caddy-ci:validate")
# Already pinned for this repository's Molecule scenarios.
PYTHON_IMAGE = (
    "python:3.12-slim@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217"
)

TENANT_ONE = "tenant-one.test"  # AppSec skips /ghost/api/*, as on the blog
TENANT_TWO = "tenant-two.test"  # AppSec on every path, as on the portal
# The rendered upstreams name `app1`, 10.20.1.100. The test network uses a
# subnet of its own, so a workstation network already on edge1's plan does not
# stop it, and the upstream address is the second and last change to the file.
RENDERED_GHOST_ADDRESS = "10.20.1.100:"
PRIVATE_SUBNET = "10.199.36.0/24"
GHOST_ADDRESS = "10.199.36.100"
# A public documentation range for clients, so no private-range whitelist the
# hub ships can be what spares an address.
PUBLIC_SUBNET = "198.51.100.0/24"
EDGE_PUBLIC_ADDRESS = "198.51.100.10"

NEUTRAL = "198.51.100.40"
BANNED = "198.51.100.51"
TRUSTED_PROBER = "198.51.100.60"
CONTROL_PROBER = "198.51.100.61"
FORGED_FLAG = "198.51.100.62"
APPSEC_CONTROL = "198.51.100.63"

UPLOAD_BYTES = 64 * 1024 * 1024  # the blog's requestBodyMaxSize
PROBE_PATHS = tuple(f"/ghost/api/admin/missing-{index}/" for index in range(15))

START_TIMEOUT_S = 300
BAN_ARMED_TIMEOUT_S = 120
VERDICT_TIMEOUT_S = 120
SETTLE_S = 15


class ReplayError(AssertionError):
    """The replay could not be run, as opposed to a verdict that was wrong."""


def fail(message: str) -> NoReturn:
    raise ReplayError(message)


def browser(host: str, session: str | None, **extra: str) -> dict[str, str]:
    """What Chrome sends on a same-origin Ghost admin API call."""
    headers = {
        "Accept": "application/json",
        "Origin": f"https://{host}",
        "Referer": f"https://{host}/ghost/",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/142.0.0.0",
    }
    if session is not None:
        headers["Cookie"] = f"ghost-admin-api-session={session}"
    headers.update(extra)
    return headers


@dataclasses.dataclass(frozen=True)
class Request:
    name: str
    host: str
    path: str
    headers: Mapping[str, str]
    method: str = "GET"
    body_bytes: int = 0

    def spec(self) -> dict[str, object]:
        return {
            "host": self.host,
            "path": self.path,
            "method": self.method,
            "headers": dict(self.headers),
            "body_bytes": self.body_bytes,
        }


VALID_ONE = f"staff-{TENANT_ONE}"
VALID_TWO = f"staff-{TENANT_TWO}"
API = "/ghost/api/admin/posts/?formats=lexical&include=tags,authors"

# From the banned address. Each must reach Ghost.
ADMITTED = (
    Request(
        "a valid staff session on the admin API", TENANT_ONE, API, browser(TENANT_ONE, VALID_ONE)
    ),
    Request(
        "a valid staff session on the admin app",
        TENANT_ONE,
        "/ghost/",
        browser(TENANT_ONE, VALID_ONE),
    ),
    Request(
        "a valid staff session on a site that inspects every path",
        TENANT_TWO,
        "/ghost/api/admin/site/",
        browser(TENANT_TWO, VALID_TWO),
    ),
    Request(
        "a valid staff session among other cookies",
        TENANT_ONE,
        API,
        browser(
            TENANT_ONE,
            None,
            Cookie=f"ghost-members-ssr=m; ghost-admin-api-session={VALID_ONE}; x=1",
        ),
    ),
)
UPLOAD = Request(
    "a 64 MiB upload with a valid staff session",
    TENANT_ONE,
    "/ghost/api/admin/media/upload/",
    browser(TENANT_ONE, VALID_ONE, **{"Content-Type": "application/octet-stream"}),
    method="POST",
    body_bytes=UPLOAD_BYTES,
)
# From the banned address. Each must be refused by the ban.
REFUSED = (
    Request("no session at all", TENANT_ONE, API, browser(TENANT_ONE, None)),
    Request("a forged cookie", TENANT_ONE, API, browser(TENANT_ONE, "s%3Aforged.c2lnbmF0dXJl")),
    Request("an expired session", TENANT_ONE, API, browser(TENANT_ONE, "expired-session")),
    Request(
        "a valid cookie from another origin",
        TENANT_ONE,
        API,
        browser(
            TENANT_ONE, VALID_ONE, Origin="https://attacker.test", Referer="https://attacker.test/"
        ),
    ),
    Request(
        "a valid cookie with no Origin or Referer",
        TENANT_ONE,
        API,
        {"Cookie": f"ghost-admin-api-session={VALID_ONE}"},
    ),
    Request(
        "another tenant's valid session",
        TENANT_TWO,
        "/ghost/api/admin/site/",
        browser(TENANT_TWO, VALID_ONE),
    ),
    Request("a 2xx answer that is not JSON", TENANT_ONE, API, browser(TENANT_ONE, "staff-html")),
    Request("a verifier that errors", TENANT_ONE, API, browser(TENANT_ONE, "ghost-error")),
    Request(
        "an Admin API key beside a forged cookie",
        TENANT_ONE,
        API,
        browser(TENANT_ONE, "forged", Authorization="Ghost eyJhbGciOiJIUzI1NiJ9.e30.c2ln"),
    ),
    Request(
        "a members session in the staff cookie's place",
        TENANT_ONE,
        API,
        browser(TENANT_ONE, None, Cookie=f"ghost-members-ssr={VALID_ONE}"),
    ),
    Request("a valid staff session off /ghost/", TENANT_ONE, "/", browser(TENANT_ONE, VALID_ONE)),
    Request(
        "a forged trust flag in a header and the query",
        TENANT_ONE,
        API + "&edge_trusted=1",
        browser(TENANT_ONE, None, **{"edge_trusted": "1", "Edge-Trusted": "1"}),
    ),
)


def probes(host: str, session: str | None, **extra: str) -> list[Request]:
    """Fifteen distinct 404s on the admin API: what http-probing bans for."""
    return [
        Request(f"probe {path}", host, path, browser(host, session, **extra))
        for path in PROBE_PATHS
    ]


# The in-band AppSec rule set refuses a request for a `.env` file.
APPSEC_PROBE = "/ghost/.env"


class Edge:
    """Caddy, CrowdSec and the Ghost stand-in, as one throwaway Compose project."""

    def __init__(self, workdir: pathlib.Path) -> None:
        self.workdir = workdir
        self.logs = workdir / "caddy-logs"
        self.access_log = self.logs / "access.log"
        self.caddy_dir = workdir / "caddy"
        self.records = workdir / "records"
        self.specs = workdir / "specs"
        self.override = workdir / "override.yml"
        self.project = f"edge-trusted-{secrets.token_hex(4)}"
        self.key = secrets.token_hex(24)

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "IMAGE": CADDY_IMAGE,
                "CROWDSEC_BOUNCER_KEY": self.key,
                "ACME_EMAIL": "replay@example.invalid",
            }
        )
        return env

    def run(self, command: Sequence[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 -- a fixed docker argv, no shell
            list(command),
            env=self._env(),
            check=check,
            capture_output=True,
            text=True,
            timeout=START_TIMEOUT_S,
        )

    def compose(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self.run(
            [
                "docker",
                "compose",
                "--project-name",
                self.project,
                "--file",
                str(COMPOSE_FILE),
                "--file",
                str(self.override),
                *args,
            ],
            check=check,
        )

    def cscli_json(self, *args: str) -> object:
        ran = self.compose("exec", "-T", "crowdsec", "cscli", *args, "-o", "json")
        text = ran.stdout.strip()
        return json.loads(text) if text and text != "null" else []

    def _write_caddyfile(self) -> None:
        rendered = CADDYFILE.read_text(encoding="utf-8")
        marker = "\n{\n"
        if marker not in rendered:
            fail(f"{CADDYFILE} has no global options block to add local_certs to")
        # Every proxy to Ghost: each tenant's upstream and its verification call.
        if rendered.count(RENDERED_GHOST_ADDRESS) < 2:
            fail(f"{CADDYFILE} does not proxy both tenants to {RENDERED_GHOST_ADDRESS}")
        rendered = rendered.replace(RENDERED_GHOST_ADDRESS, f"{GHOST_ADDRESS}:")
        self.caddy_dir.mkdir()
        (self.caddy_dir / "Caddyfile").write_text(
            rendered.replace(marker, "\n{\n\tlocal_certs\n\tskip_install_trust\n", 1),
            encoding="utf-8",
        )

    def _write_override(self) -> None:
        # Compose merges a service's volumes by target, so each entry replaces
        # only the mount at that target. Ports are reset whole: edge1's
        # addresses do not exist here, and the clients reach Caddy on the
        # public test network.
        self.override.write_text(
            f"""networks:
  default:
    ipam:
      config:
        - subnet: {PRIVATE_SUBNET}
  public:
    ipam:
      config:
        - subnet: {PUBLIC_SUBNET}
services:
  caddy:
    ports: !reset []
    networks:
      default: {{}}
      public:
        ipv4_address: {EDGE_PUBLIC_ADDRESS}
    volumes:
      - type: bind
        source: {self.caddy_dir}
        target: /etc/caddy
        read_only: true
      - type: bind
        source: {self.logs}
        target: /var/log/caddy
  crowdsec:
    ports: !reset []
    volumes:
      - type: bind
        source: {self.logs}
        target: /var/log/caddy
        read_only: true
  ghost:
    image: {PYTHON_IMAGE}
    command: ['python3', '-I', '/fixtures/ghost_session_stub.py']
    networks:
      default:
        ipv4_address: {GHOST_ADDRESS}
    volumes:
      - type: bind
        source: {FIXTURES}
        target: /fixtures
        read_only: true
      - type: bind
        source: {self.records}
        target: /records
""",
            encoding="utf-8",
        )

    def start(self) -> None:
        for directory in (self.logs, self.records, self.specs):
            directory.mkdir()
            directory.chmod(0o777)
        self.access_log.touch()
        self.access_log.chmod(0o666)
        self._write_caddyfile()
        self._write_override()
        if self.run(["docker", "image", "inspect", CADDY_IMAGE], check=False).returncode != 0:
            fail(f"no {CADDY_IMAGE} image: build it from hetzner/edge/Dockerfile first, as CI does")
        ran = self.compose("up", "--detach", "--wait", "crowdsec", "caddy", "ghost", check=False)
        if ran.returncode != 0:
            logs = self.compose("logs", check=False)
            fail(f"the edge did not start:\n{ran.stderr}\n{logs.stdout[-8000:]}")
        deadline = time.monotonic() + START_TIMEOUT_S
        ready = Request("readiness", TENANT_ONE, "/", browser(TENANT_ONE, None))
        while self.send(NEUTRAL, [ready])[0]["status"] != 200:
            if time.monotonic() > deadline:
                logs = self.compose("logs", "caddy", check=False)
                fail(f"Caddy never served {TENANT_ONE}:\n{logs.stdout[-8000:]}")
            time.sleep(2)

    def stop(self) -> None:
        if self.override.exists():
            self.compose("down", "--volumes", "--timeout", "5", check=False)

    def send(self, ip: str, requests: Sequence[Request]) -> list[dict[str, object]]:
        """Send `requests` in order from `ip`, in one client container."""
        spec = self.specs / f"{secrets.token_hex(4)}.json"
        spec.write_text(json.dumps([request.spec() for request in requests]), encoding="utf-8")
        spec.chmod(0o644)
        ran = self.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                f"{self.project}_public",
                "--ip",
                ip,
                "--volume",
                f"{FIXTURES}:/fixtures:ro",
                "--volume",
                f"{self.specs}:/specs:ro",
                PYTHON_IMAGE,
                "python3",
                "-I",
                "/fixtures/edge_client.py",
                f"/specs/{spec.name}",
                EDGE_PUBLIC_ADDRESS,
            ],
            check=False,
        )
        if ran.returncode != 0:
            fail(f"the client at {ip} failed:\n{ran.stderr[-4000:]}")
        results = json.loads(ran.stdout)
        if not isinstance(results, list):
            fail(f"the client at {ip} printed {ran.stdout[:200]}")
        return results

    def ban(self, ip: str) -> None:
        self.compose(
            "exec", "-T", "crowdsec", "cscli", "decisions", "add",
            "--ip", ip, "--duration", "2h", "--reason", "trusted-session replay",
        )  # fmt: skip

    def banned(self) -> dict[str, list[str]]:
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
        alerts = self.cscli_json("alerts", "list", "--ip", ip, "--limit", "0")
        return [
            f"{alert.get('scenario')}: {alert.get('message')}"
            for alert in (alerts if isinstance(alerts, list) else [])
        ]

    def log_lines(self) -> list[dict[str, object]]:
        lines = []
        for raw in self.access_log.read_text(encoding="utf-8").splitlines():
            if raw.strip():
                lines.append(json.loads(raw))
        return lines

    def verifications(self) -> list[dict[str, object]]:
        text = (self.records / "verifications.jsonl").read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def client_ip(line: Mapping[str, object]) -> str:
    request = line.get("request")
    return str(request.get("remote_ip")) if isinstance(request, dict) else ""


@unittest.skipUnless(
    ENABLED, "needs a Docker engine that can start containers; CI sets BRANCHLEFT_CROWDSEC_REPLAY=1"
)
class VerifiedSessionsAreNeverRefused(unittest.TestCase):
    edge: Edge
    workdir: pathlib.Path
    armed: list[dict[str, object]]
    admitted: list[dict[str, object]]
    upload: dict[str, object]
    refused: list[dict[str, object]]
    appsec_trusted: dict[str, object]
    appsec_control: dict[str, object]
    bans: dict[str, list[str]]

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("docker") is None:
            fail("BRANCHLEFT_CROWDSEC_REPLAY=1 but there is no docker on PATH")
        cls.workdir = pathlib.Path(tempfile.mkdtemp(prefix="trusted-session-"))
        cls.workdir.chmod(0o755)
        cls.edge = Edge(cls.workdir)
        try:
            cls.edge.start()
            cls._run()
        except BaseException:
            cls.edge.stop()
            shutil.rmtree(cls.workdir, ignore_errors=True)
            raise

    @classmethod
    def _run(cls) -> None:
        edge = cls.edge
        edge.ban(BANNED)
        # The bouncer pulls decisions every 15 seconds: wait until the ban is
        # what answers an address with no session.
        control = Request("ban armed", TENANT_ONE, API, browser(TENANT_ONE, None))
        deadline = time.monotonic() + BAN_ARMED_TIMEOUT_S
        cls.armed = edge.send(BANNED, [control])
        while cls.armed[0]["status"] != 403 and time.monotonic() < deadline:
            time.sleep(3)
            cls.armed = edge.send(BANNED, [control])

        cls.admitted = edge.send(BANNED, ADMITTED)
        cls.upload = edge.send(BANNED, [UPLOAD])[0]
        cls.refused = edge.send(BANNED, REFUSED)

        cls.appsec_trusted = edge.send(
            TRUSTED_PROBER,
            [
                Request(
                    "AppSec probe, verified",
                    TENANT_TWO,
                    APPSEC_PROBE,
                    browser(TENANT_TWO, VALID_TWO),
                )
            ],
        )[0]
        cls.appsec_control = edge.send(
            APPSEC_CONTROL,
            [
                Request(
                    "AppSec probe, no session", TENANT_TWO, APPSEC_PROBE, browser(TENANT_TWO, None)
                )
            ],
        )[0]
        edge.send(TRUSTED_PROBER, probes(TENANT_ONE, VALID_ONE))
        edge.send(CONTROL_PROBER, probes(TENANT_ONE, "forged"))
        edge.send(FORGED_FLAG, probes(TENANT_ONE, "forged", edge_trusted="1"))
        edge.send(
            FORGED_FLAG,
            [
                Request(
                    f"probe {path}?edge_trusted=1",
                    TENANT_ONE,
                    f"{path}?edge_trusted=1",
                    browser(TENANT_ONE, None),
                )
                for path in PROBE_PATHS
            ],
        )

        expected = {CONTROL_PROBER, FORGED_FLAG}
        deadline = time.monotonic() + VERDICT_TIMEOUT_S
        bans = edge.banned()
        while not expected <= bans.keys() and time.monotonic() < deadline:
            time.sleep(3)
            bans = edge.banned()
        time.sleep(SETTLE_S)
        cls.bans = edge.banned()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.edge.stop()
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def _evidence(self, ip: str) -> str:
        return f"{ip}: bans {self.bans.get(ip, [])}; alerts {self.edge.alerts_for(ip)}"

    def test_the_ban_is_in_force_for_an_address_with_no_session(self) -> None:
        self.assertEqual(self.armed[0]["status"], 403, self.armed)

    def test_a_banned_address_with_a_valid_staff_session_gets_through(self) -> None:
        for request, result in zip(ADMITTED, self.admitted, strict=True):
            with self.subTest(request.name):
                self.assertEqual(result["status"], 200, result)
                self.assertIn('"received": 0', str(result["body"]), result)

    def test_a_64_mib_upload_with_a_valid_staff_session_arrives_whole(self) -> None:
        self.assertEqual(self.upload["status"], 200, self.upload)
        self.assertIn(f'"received": {UPLOAD_BYTES}', str(self.upload["body"]), self.upload)

    def test_a_banned_address_with_a_forged_or_expired_cookie_is_refused(self) -> None:
        for request, result in zip(REFUSED, self.refused, strict=True):
            with self.subTest(request.name):
                self.assertEqual(result["status"], 403, result)
                self.assertNotIn('"received"', str(result["body"]), result)

    def test_appsec_does_not_refuse_a_verified_session(self) -> None:
        self.assertEqual(self.appsec_control["status"], 403, self.appsec_control)
        self.assertEqual(self.appsec_trusted["status"], 200, self.appsec_trusted)

    def test_verified_traffic_adds_nothing_to_a_ban_bucket(self) -> None:
        # The same traffic with a forged cookie bans, so it is traffic that would.
        self.assertIn(CONTROL_PROBER, self.bans, self._evidence(CONTROL_PROBER))
        self.assertNotIn(TRUSTED_PROBER, self.bans, self._evidence(TRUSTED_PROBER))
        self.assertEqual(self.edge.alerts_for(TRUSTED_PROBER), [], self._evidence(TRUSTED_PROBER))

    def test_a_forged_trust_flag_still_counts_towards_a_ban(self) -> None:
        self.assertIn(FORGED_FLAG, self.bans, self._evidence(FORGED_FLAG))
        flags = {
            str(line.get("edge_trusted"))
            for line in self.edge.log_lines()
            if client_ip(line) == FORGED_FLAG
        }
        self.assertEqual(flags, {"0"})

    def test_the_access_log_marks_only_verified_requests(self) -> None:
        marks: dict[str, set[str]] = {}
        for line in self.edge.log_lines():
            marks.setdefault(client_ip(line), set()).add(str(line.get("edge_trusted")))
        self.assertEqual(marks.get(TRUSTED_PROBER), {"1"}, marks)
        self.assertEqual(marks.get(CONTROL_PROBER), {"0"}, marks)
        self.assertEqual(marks.get(BANNED), {"0", "1"}, marks)

    def test_the_verification_call_carries_no_body_query_or_api_key(self) -> None:
        calls = self.edge.verifications()
        self.assertTrue(calls)
        for call in calls:
            with self.subTest(call):
                self.assertEqual(call["method"], "GET")
                self.assertEqual(call["query"], "")
                self.assertIs(call["authorization"], False)
                self.assertEqual(call["body_bytes"], 0)

    def test_only_a_staff_cookie_on_ghost_paths_costs_a_verification(self) -> None:
        sessions = {call["session"] for call in self.edge.verifications()}
        self.assertNotIn(None, sessions)


if __name__ == "__main__":
    unittest.main()
