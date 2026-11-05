"""Tests of the judge of the demo edge's candidate, against real Caddy.

The role does not read the candidate Caddyfile. It has Caddy adapt it and judges the JSON
Caddy prints (files/judge_caddy_config.py). Caddy ignores indentation and line breaks, so
the cases here are the spellings a text check would miss: an indented second site, a site
opened on the closing brace of the wildcard site, a plain-HTTP site, an internal issuer in
the global block or in the site, and the global options that change how certificates are
made.

Two layers. FixtureTests judge adapted JSON that was recorded from real Caddy, with no
Docker. RealCaddyTests build the demo edge's Caddy (2.11.4 with the Hetzner DNS module, the
pins of ghost-platform's services/demo-edge/Dockerfile), render the candidate with the real
vendored renderer, adapt every case with the role's own `docker run` argument list, require
the result to equal the recorded fixture and judge it. A runner with no Docker fails the
class: a proof that cannot run is not a pass. The Molecule scenarios replay the same
recorded files through a stand-in for Docker, so these tests are what ties them to real
Caddy.

Set DEMO1_BUILD_RECORD=1 to rewrite the fixtures from real Caddy instead of comparing.
Set DEMO1_BUILD_TEST_CADDY_IMAGE to an image ID to skip the build.
"""

from __future__ import annotations

# Every subprocess call here runs a fixed argument list built from this test's own paths and
# the role's own argument list, with no shell.
# ruff: noqa: S603
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

import jinja2
import yaml

ROLE = Path(__file__).resolve().parents[2]
FILES = ROLE / "files"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
RENDERER = FILES / "ghost-platform" / "demo-host" / "provision" / "render_demo_site.py"
JUDGE = FILES / "judge_caddy_config.py"
VARS = ROLE / "vars" / "main.yml"

sys.path.insert(0, str(FILES))
import judge_caddy_config  # noqa: E402

BASE = "site-fixture.invalid"
# A path the config names, not a credential: the role never has the token's value.
TOKEN = "/etc/branchleft/secrets/demo-dns-caddy-demo1-wildcard"  # noqa: S105
DNS = "dns hetzner {file." + TOKEN + "}"
ENV = "DEMO1_BUILD_ADAPTED_CONFIG"
EDGE = {
    "admittedHostname": None,
    "gate": {"kind": "passphrase"},
    "requestBodyMaxSize": "10MiB",
    "contentSecurityPolicy": "default-src 'self'",
    "contentSecurityPolicyMode": "enforcing",
}

# The pins of ghost-platform's services/demo-edge/Dockerfile. Its home is there; this copy is
# the test's own and carries the same versions, so the test adapts with the module the host runs.
BUILDER = (
    "caddy:2.11.4-builder-alpine@"
    "sha256:0aa610043dab5da82ad0a0268e46bb852785e6f5160f12f1c6fe3f42903d7e1b"
)
RUNTIME = (
    "caddy:2.11.4-alpine@sha256:6aeddd44c3078b0f9a35206472a11420648a79c184603ef95957d0a20044cb2b"
)
DOCKERFILE = f"""FROM {BUILDER} AS builder
RUN xcaddy build v2.11.4 --with github.com/caddy-dns/hetzner/v2@v2.0.1 --output /usr/bin/caddy

FROM {RUNTIME}
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
RUN caddy list-modules | grep -qx 'dns.providers.hetzner'
"""


def close_last_brace(text: str, replacement: str) -> str:
    end = text.rstrip().rfind("}")
    return text[:end] + replacement + text[end + 1 :]


def in_global(option: str) -> Callable[[str], str]:
    return lambda good: good.replace("\tadmin off\n", "\tadmin off\n\t" + option + "\n", 1)


# Each case is a way to change the renderer's own output, with the code the judge must
# refuse it for. None is the control: the unchanged output is accepted.
CASES: dict[str, tuple[Callable[[str], str], str | None]] = {
    "good": (lambda good: good, None),
    # The three spellings the column-0 check missed.
    "indented_http_site": (
        lambda good: good + '\n\thttp://demo-0.site-fixture.invalid {\n\trespond "x"\n}\n',
        "servers",
    ),
    "indented_slot_site": (
        lambda good: (
            good + "\n  demo-0.site-fixture.invalid {\n\treverse_proxy 127.0.0.1:9300\n}\n"
        ),
        "policies",
    ),
    "closing_brace_site": (
        lambda good: close_last_brace(
            good, '} http://demo-1.site-fixture.invalid {\n\trespond "x"\n}'
        ),
        "servers",
    ),
    # The plain spelling, which the old check did catch, stays caught.
    "http_only_site": (
        lambda good: good + '\nhttp://demo-0.site-fixture.invalid {\n\trespond "x"\n}\n',
        "servers",
    ),
    # Interim certificate modes, in the global block and in the site.
    "global_cert_issuer_internal": (in_global("cert_issuer internal"), "internal-issuer"),
    "global_local_certs": (in_global("local_certs"), "internal-issuer"),
    "site_tls_block_internal_issuer": (
        lambda good: good.replace("\t\t" + DNS + "\n", "\t\tissuer internal\n"),
        "internal-issuer",
    ),
    "site_tls_internal": (
        lambda good: good.replace("\ttls {\n\t\t" + DNS + "\n\t}\n", "\ttls internal\n"),
        "internal-issuer",
    ),
    "site_tls_internal_indented": (
        lambda good: good.replace("\ttls {\n\t\t" + DNS + "\n\t}\n", "      tls    internal\n"),
        "internal-issuer",
    ),
    # Options that do not name an issuer and still change how Caddy serves or trusts.
    "global_skip_install_trust": (in_global("skip_install_trust"), "apps"),
    "global_auto_https_off": (in_global("auto_https off"), "server-keys"),
    "global_auto_https_disable_redirects": (
        in_global("auto_https disable_redirects"),
        "server-keys",
    ),
    "global_acme_ca": (in_global("acme_ca https://acme.invalid/directory"), "policies"),
    "site_certificate_files": (
        lambda good: good.replace(
            "\ttls {\n\t\t" + DNS + "\n\t}\n", "\ttls /etc/a.pem /etc/a.key\n"
        ),
        "tls-shape",
    ),
    "token_from_the_environment": (
        lambda good: good.replace("{file." + TOKEN + "}", "{env.TOKEN}"),
        "issuer-challenges",
    ),
}


def render_good() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        flags: list[str] = []
        for slot in ("0", "1"):
            path = Path(tmp) / f"demo-{slot}.edge.json"
            path.write_text(json.dumps({"displayHostname": f"demo-{slot}.{BASE}", **EDGE}))
            flags += ["--site", f"{slot}={path}"]
        done = subprocess.run(
            [
                sys.executable,
                "-E",
                "-s",
                "-B",
                str(RENDERER),
                "--base",
                BASE,
                *flags,
                "--dns-directive",
                DNS,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    return done.stdout


def fixture_path(name: str) -> Path:
    return FIXTURES / f"adapted-{name}.json"


def judge_recorded(name: str) -> str | None:
    return judge_caddy_config.judge(json.loads(fixture_path(name).read_text()), BASE, TOKEN)


class FixtureTests(unittest.TestCase):
    def test_every_recorded_case_is_judged_as_expected(self) -> None:
        for name, (_, expected) in CASES.items():
            with self.subTest(case=name):
                self.assertEqual(judge_recorded(name), expected)

    def test_a_refused_case_prints_one_line_and_no_hostname(self) -> None:
        for name, (_, expected) in CASES.items():
            if expected is None:
                continue
            with self.subTest(case=name):
                done = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(JUDGE),
                        "--env",
                        ENV,
                        "--base",
                        BASE,
                        "--token-file",
                        TOKEN,
                    ],
                    env={ENV: fixture_path(name).read_text()},
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(done.returncode, 1)
                self.assertRegex(done.stdout, rf"^REFUSED {expected}: .+\n$")
                self.assertNotIn("site-fixture", done.stdout + done.stderr)

    def test_the_good_case_is_accepted_through_the_program(self) -> None:
        done = subprocess.run(
            [sys.executable, "-I", str(JUDGE), "--env", ENV, "--base", BASE, "--token-file", TOKEN],
            env={ENV: fixture_path("good").read_text()},
            capture_output=True,
            text=True,
        )
        self.assertEqual((done.returncode, done.stdout), (0, "OK\n"))

    def test_text_that_is_not_json_is_refused(self) -> None:
        for text in ("", "not json", "[]", "null", '"{}"'):
            with self.subTest(text=text):
                done = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(JUDGE),
                        "--env",
                        ENV,
                        "--base",
                        BASE,
                        "--token-file",
                        TOKEN,
                    ],
                    env={ENV: text},
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(done.returncode, 1)
                self.assertTrue(done.stdout.startswith("REFUSED not-json:"))

    def test_a_config_for_another_base_or_token_file_is_refused(self) -> None:
        good = json.loads(fixture_path("good").read_text())
        self.assertEqual(judge_caddy_config.judge(good, "other.invalid", TOKEN), "policy-subjects")
        self.assertEqual(
            judge_caddy_config.judge(good, BASE, "/etc/branchleft/secrets/other"),
            "issuer-challenges",
        )

    def test_a_second_route_or_a_second_server_is_refused(self) -> None:
        good = json.loads(fixture_path("good").read_text())
        server = good["apps"]["http"]["servers"]["srv0"]
        server["routes"].append(dict(server["routes"][0]))
        self.assertEqual(judge_caddy_config.judge(good, BASE, TOKEN), "routes")
        del server["routes"][1]
        good["apps"]["http"]["servers"]["srv1"] = dict(server)
        self.assertEqual(judge_caddy_config.judge(good, BASE, TOKEN), "servers")

    def test_an_internal_issuer_is_found_wherever_it_sits(self) -> None:
        good = json.loads(fixture_path("good").read_text())
        good["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["x"] = [
            {"module": "internal"}
        ]
        self.assertEqual(judge_caddy_config.judge(good, BASE, TOKEN), "internal-issuer")

    def test_the_old_per_slot_names_are_what_the_role_removes(self) -> None:
        pattern = yaml.safe_load(VARS.read_text())["demo1_build_superseded_candidate_pattern"]
        for name in ("site-0.caddy", "site-6.caddy", "site-12.caddy"):
            self.assertTrue(re.search(pattern, name), name)
        for name in (
            "Caddyfile",
            "edge-upstreams.caddy",
            "site-x.caddy",
            "site-0.caddy.bak",
            "xsite-0.caddy",
        ):
            self.assertFalse(re.search(pattern, name), name)


def docker_binary() -> str:
    found = shutil.which("docker")
    if found is None:
        message = "docker is not on the PATH, so the real-Caddy proof cannot run (it fails)"
        raise AssertionError(message)
    return found


def role_adapt_argv(docker: str, image: str) -> list[str]:
    """Return the argument list the role runs, rendered from its own vars/main.yml.

    Raises:
        TypeError: The template did not render to a list of strings.
    """
    role_vars = yaml.safe_load(VARS.read_text())
    # The template renders an argument list for a command, not markup: nothing is escaped.
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)  # noqa: S701
    context: dict[str, str] = {"demo1_build_docker": docker, "demo1_build_caddy_image": image}
    rendered = env.from_string(role_vars["demo1_build_caddy_adapt_argv"]).render(**context)
    argv = ast.literal_eval(rendered)
    if not (isinstance(argv, list) and all(isinstance(a, str) for a in argv)):
        message = "the role's adapt argument list did not render to a list of strings"
        raise TypeError(message)
    return [str(a) for a in argv]


class RealCaddyTests(unittest.TestCase):
    image = ""
    docker = ""
    good = ""

    @classmethod
    def setUpClass(cls) -> None:
        cls.docker = docker_binary()
        subprocess.run([cls.docker, "info"], capture_output=True, check=True)
        given = os.environ.get("DEMO1_BUILD_TEST_CADDY_IMAGE", "")
        if given:
            cls.image = given
        else:
            tag = "demo1-build-test-caddy:" + hashlib.sha256(DOCKERFILE.encode()).hexdigest()[:16]
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "Dockerfile").write_text(DOCKERFILE)
                subprocess.run(
                    [cls.docker, "build", "--quiet", "-t", tag, tmp],
                    check=True,
                    capture_output=True,
                )
            cls.image = subprocess.run(
                [cls.docker, "image", "inspect", "--format", "{{.Id}}", tag],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        cls.good = render_good()

    def adapt(self, text: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            role_adapt_argv(self.docker, self.image), input=text, capture_output=True, text=True
        )

    def test_the_image_holds_the_hetzner_dns_provider(self) -> None:
        done = subprocess.run(
            [self.docker, "run", "--rm", self.image, "caddy", "list-modules"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("dns.providers.hetzner", done.stdout.split())

    def test_the_role_argv_names_no_pull_no_network_and_a_read_only_root(self) -> None:
        argv = role_adapt_argv("docker", self.image)
        for flag, value in (("--pull", "never"), ("--network", "none")):
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn("--read-only", argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")

    def test_every_case_adapts_to_its_recorded_fixture_and_is_judged_as_expected(self) -> None:
        record = os.environ.get("DEMO1_BUILD_RECORD") == "1"
        for name, (change, expected) in CASES.items():
            with self.subTest(case=name):
                text = change(self.good)
                if name != "good":
                    self.assertNotEqual(
                        text, self.good, "the change did not alter the renderer's output"
                    )
                done = self.adapt(text)
                self.assertEqual(done.returncode, 0, done.stderr[:300])
                if record:
                    FIXTURES.mkdir(exist_ok=True)
                    fixture_path(name).write_text(done.stdout)
                else:
                    self.assertEqual(
                        json.loads(done.stdout), json.loads(fixture_path(name).read_text())
                    )
                self.assertEqual(
                    judge_caddy_config.judge(json.loads(done.stdout), BASE, TOKEN), expected
                )

    def test_the_program_accepts_the_real_good_config_and_refuses_the_real_bypasses(self) -> None:
        for name, (change, expected) in CASES.items():
            with self.subTest(case=name):
                done = self.adapt(change(self.good))
                verdict = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(JUDGE),
                        "--env",
                        ENV,
                        "--base",
                        BASE,
                        "--token-file",
                        TOKEN,
                    ],
                    env={ENV: done.stdout},
                    capture_output=True,
                    text=True,
                )
                if expected is None:
                    self.assertEqual((verdict.returncode, verdict.stdout), (0, "OK\n"))
                else:
                    self.assertEqual(verdict.returncode, 1)
                    self.assertTrue(
                        verdict.stdout.startswith(f"REFUSED {expected}:"), verdict.stdout
                    )


if __name__ == "__main__":
    unittest.main()
