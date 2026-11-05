"""Tests of the judge of the demo edge's candidate, against real Caddy.

The role has Caddy adapt the candidate and judges the JSON Caddy prints
(files/judge_caddy_config.py). The cases here are the spellings a text check would miss:
an indented second site, a site opened on the closing brace, a plain-HTTP site, an
internal issuer, and the global options that change how certificates are made.

Two layers. FixtureTests judge adapted JSON that was recorded from real Caddy, with no
Docker. RealCaddyTests build the demo edge's Caddy (2.11.4 with the Hetzner DNS module, the
pins of ghost-platform's services/demo-edge/Dockerfile), render the candidate with the real
vendored renderer, adapt every case with the role's own `docker run` argument list, require
the result to equal the recorded fixture and judge it. A runner with no Docker fails the
class: a proof that cannot run is not a pass. The Molecule scenarios replay the same
recorded files through a stand-in for Docker, so these tests are what ties them to real
Caddy.

A third layer runs the role's image check (docker image inspect and the RepoDigests test)
against a real Docker on the classic and the containerd image store, in throwaway
Docker-in-Docker daemons with no network, beside the molecule stand-in for docker.

Set DEMO1_BUILD_RECORD=1 to rewrite the fixtures from real Caddy instead of comparing.
Set DEMO1_BUILD_TEST_CADDY_IMAGE to an image ID to skip the build.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import uuid
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


def last_handle(body: str) -> Callable[[str], str]:
    """Return a change that replaces the wildcard site's closing `handle { abort }`."""
    return lambda good: good.replace(
        "\thandle {\n\t\tabort\n\t}\n", "\thandle {\n" + body + "\t}\n", 1
    )


TOKEN_DIR = str(Path(TOKEN).parent)
TOKEN_NAME = Path(TOKEN).name
# Handler bodies that read a file off the disk. Each is a body for the wildcard site's last
# handle, and the same text is served by real Caddy in the danger test.
FILE_SERVER_SECRETS_DIR = f"\t\troot * {TOKEN_DIR}\n\t\tfile_server browse\n"
FILE_SERVER_ANCESTOR_ROOT = "\t\troot * /etc\n\t\tfile_server\n"
FILE_SERVER_RELATIVE_ROOT = "\t\troot * secrets\n\t\tfile_server\n"
FILE_SERVER_NESTED_ROUTE = "\t\troute {\n\t\t\troot * /etc\n\t\t\tfile_server\n\t\t}\n"
# A backtick string, so the template's own double quotes need no escape.
TEMPLATES_INCLUDE = (
    f'\t\theader Content-Type text/plain\n\t\ttemplates\n\t\trespond `{{{{include "{TOKEN}"}}}}`\n'
)

# A CEL expression matcher reads a placeholder whose name it builds at run time, so neither a
# literal {file. nor {env. in the text, nor the one placeholder the JSON may hold, shows it:
# "fi" + "le.<path>" is two strings in the config. startsWith answers yes or no, which leaks the
# file a byte at a time. The danger test serves it from real Caddy against a fake token.
def expression_file_oracle(prefix: str) -> str:
    return (
        f'\t\t@leak expression ph(req, "fi" + "le.{TOKEN}").startsWith("{prefix}")\n'
        '\t\trespond @leak "match"\n\t\trespond "nomatch"\n'
    )


EXPRESSION_FILE_ORACLE = expression_file_oracle("A")
EXPRESSION_ENV_ORACLE = (
    '\t\t@leak expression ph(req, "en" + "v.R2_SECRET").startsWith("A")\n\t\trespond @leak "1"\n'
)
# Not a reader, only an expression: refused for being the one matcher that can compute a name.
EXPRESSION_PLAIN = "\t\t@m expression {path} == '/x'\n\t\trespond @m \"x\"\n"
EXPRESSION_BLOCK = '\t\t@m {\n\t\t\texpression {path} == "/x"\n\t\t}\n\t\trespond @m "x"\n'
EXPRESSION_IN_ROUTE = (
    "\t\troute {\n"
    f'\t\t\t@leak expression ph(req, "fi" + "le.{TOKEN}").startsWith("A")\n'
    '\t\t\trespond @leak "match"\n\t\t}\n'
)

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
    # A handler that reads a file or the environment when the edge runs. Adapting does not
    # resolve a placeholder, so each adapts, and the JSON holds the placeholder twice.
    "handler_respond_token": (last_handle('\t\trespond "{file.' + TOKEN + '}"\n'), "placeholder"),
    "handler_header_token": (
        last_handle('\t\theader X-Any "{file.' + TOKEN + '}"\n\t\trespond "x"\n'),
        "placeholder",
    ),
    "handler_respond_env": (last_handle('\t\trespond "{env.R2_SECRET}"\n'), "placeholder"),
    # A handler that serves or includes a file, so it can reach the token wherever the token
    # sits. Each adapts, and none holds a placeholder, so only the handler itself is refused.
    "handler_file_server_secrets_dir": (
        last_handle(FILE_SERVER_SECRETS_DIR),
        "handler-file-server",
    ),
    "handler_file_server_ancestor_root": (
        last_handle(FILE_SERVER_ANCESTOR_ROOT),
        "handler-file-server",
    ),
    "handler_file_server_relative_root": (
        last_handle(FILE_SERVER_RELATIVE_ROOT),
        "handler-file-server",
    ),
    "handler_file_server_nested_route": (
        last_handle(FILE_SERVER_NESTED_ROUTE),
        "handler-file-server",
    ),
    "handler_templates_include": (last_handle(TEMPLATES_INCLUDE), "handler-templates"),
    "handler_templates_alone": (
        last_handle('\t\ttemplates\n\t\trespond "x"\n'),
        "handler-templates",
    ),
    "handler_root_alone": (last_handle('\t\troot * /etc\n\t\trespond "x"\n'), "handler-root"),
    # A CEL expression matcher: the placeholder it reads is built at run time, so the JSON holds
    # the token's path once (the issuer's) and no second placeholder. Only the matcher shows it.
    "handler_expression_file_oracle": (last_handle(EXPRESSION_FILE_ORACLE), "matcher-expression"),
    "handler_expression_env_oracle": (last_handle(EXPRESSION_ENV_ORACLE), "matcher-expression"),
    "handler_expression_plain": (last_handle(EXPRESSION_PLAIN), "matcher-expression"),
    "handler_expression_in_route": (last_handle(EXPRESSION_IN_ROUTE), "matcher-expression"),
}

# Changes to the raw candidate that are refused before Caddy adapts it, with the code. Adapting
# runs with an empty environment and an empty filesystem, so the JSON of the first, fifth and
# sixth is a config the judge would accept; DANGERS shows each of those adding a site when the
# environment or the filesystem is the edge's. The rest also change the JSON and are refused
# there too (CASES), or Caddy cannot adapt them at all.
EXTRA_SITE = ':8081 {\n\trespond "extra"\n}\n'
TEXT_CASES: dict[str, tuple[Callable[[str], str], str]] = {
    "env_var_site": (lambda good: good + "\n{$R2_SITE}\n", "text-env-var"),
    "env_var_default": (lambda good: good + "\n{$R2_SITE:}\n", "text-env-var"),
    "env_var_in_handler": (last_handle('\t\trespond "{$R2_SECRET}"\n'), "text-env-var"),
    "env_placeholder": (last_handle('\t\trespond "{env.R2_SECRET}"\n'), "text-env-placeholder"),
    "second_file_placeholder_respond": (
        last_handle('\t\trespond "{file.' + TOKEN + '}"\n'),
        "text-file-placeholder",
    ),
    "second_file_placeholder_header": (
        last_handle('\t\theader X-Any "{file.' + TOKEN + '}"\n\t\trespond "x"\n'),
        "text-file-placeholder",
    ),
    "other_file_placeholder": (
        last_handle('\t\trespond "{file./etc/passwd}"\n'),
        "text-file-placeholder",
    ),
    "import_glob": (lambda good: good + "\nimport /srv/extra/*.caddy\n", "text-import"),
    "import_glob_spaced": (
        lambda good: good + "\n\t\t  import   /srv/extra/*.caddy  \n",
        "text-import",
    ),
    "import_quoted": (lambda good: good + '\n"import" /srv/extra/*.caddy\n', "text-import"),
    "import_name_no_snippet_defines": (lambda good: good + "\nimport extra\n", "text-import"),
    "import_snippet_with_a_path_argument": (
        lambda good: good + "\nimport slot0-upstream /srv/extra/x\n",
        "text-import",
    ),
    # The directives that read a file off the disk, in the spellings of the adapted cases, and
    # the spellings of the text alone: quoted, and indented to any depth.
    "file_server_secrets_dir": (last_handle(FILE_SERVER_SECRETS_DIR), "text-file-server"),
    "file_server_ancestor_root": (
        last_handle(FILE_SERVER_ANCESTOR_ROOT),
        "text-file-server",
    ),
    "file_server_relative_root": (
        last_handle(FILE_SERVER_RELATIVE_ROOT),
        "text-file-server",
    ),
    "file_server_nested_route": (
        last_handle(FILE_SERVER_NESTED_ROUTE),
        "text-file-server",
    ),
    "file_server_indented": (
        lambda good: good + "\n\t\t\t\t   file_server\n",
        "text-file-server",
    ),
    "file_server_quoted": (lambda good: good + '\n"file_server"\n', "text-file-server"),
    "templates_include": (last_handle(TEMPLATES_INCLUDE), "text-templates"),
    "templates_alone": (last_handle('\t\ttemplates\n\t\trespond "x"\n'), "text-templates"),
    "templates_quoted": (
        last_handle('\t\t"templates"\n\t\trespond "x"\n'),
        "text-templates",
    ),
    "root_alone": (last_handle('\t\troot * /etc\n\t\trespond "x"\n'), "text-root"),
    "root_in_a_snippet": (
        lambda good: good + "\n(extra) {\n\troot * /etc\n}\n",
        "text-root",
    ),
    # The expression matcher, and the CEL function that reads a placeholder by a built name.
    "expression_file_oracle": (last_handle(EXPRESSION_FILE_ORACLE), "text-expression"),
    "expression_env_oracle": (last_handle(EXPRESSION_ENV_ORACLE), "text-expression"),
    "expression_plain": (last_handle(EXPRESSION_PLAIN), "text-expression"),
    "expression_block": (last_handle(EXPRESSION_BLOCK), "text-expression"),
    "expression_in_route": (last_handle(EXPRESSION_IN_ROUTE), "text-expression"),
    "expression_quoted": (
        last_handle('\t\t@m "expression" {path} == "/x"\n\t\trespond @m "x"\n'),
        "text-expression",
    ),
    "ph_call_in_a_backtick_matcher": (
        last_handle('\t\t@m `ph(req, "fi" + "le.' + TOKEN + '") == "x"`\n\t\trespond @m "x"\n'),
        "text-expression",
    ),
    "ph_call_spaced": (
        last_handle('\t\t@m `ph  (req, "x") == "x"`\n\t\trespond @m "x"\n'),
        "text-expression",
    ),
}

# Spellings that hold the words as part of a host name, and are not the directives: they must
# stay accepted, or the judge would refuse a customer's own host name.
TEXT_ACCEPTED: dict[str, Callable[[str], str]] = {
    "host_labels_are_not_directives": lambda good: good.replace(
        "\thandle {\n\t\tabort",
        "\t@r host root.site-fixture.invalid templates.site-fixture.invalid"
        " file_server.site-fixture.invalid root-a.site-fixture.invalid"
        " expression.site-fixture.invalid\n\thandle {\n\t\tabort",
        1,
    ),
    "placeholder_path_is_not_a_directive": last_handle('\t\trespond "{http.vars.root}"\n'),
}

# The text cases that are a config the judge accepts when Caddy adapts them in the judging
# container, with what the edge's environment or filesystem adds: a docker run option list
# (put before the image) and the files to put in /srv/extra.
DANGERS: dict[str, tuple[list[str], dict[str, str]]] = {
    "env_var_site": (["-e", "R2_SITE=" + EXTRA_SITE], {}),
    "import_glob": (["-v", "@EXTRA@:/srv/extra:ro"], {"extra.caddy": EXTRA_SITE}),
    "import_name_no_snippet_defines": (
        ["-v", "@EXTRA@:/srv/extra:ro", "-w", "/srv/extra"],
        {"extra": EXTRA_SITE},
    ),
}


# The handler bodies that serve a file, each with what real Caddy needs to serve the fake token
# in a container: the working directory (the relative root) and the path to fetch. The names
# are the CASES keys without "handler_" and the TEXT_CASES keys. A root alone reads nothing, so
# it is not here; the judge refuses it for being the setting a file handler reads from.
FETCH = "http://127.0.0.1:8080"
DANGEROUS_HANDLERS: dict[str, tuple[str, str, str]] = {
    "file_server_secrets_dir": (FILE_SERVER_SECRETS_DIR, "/", "/" + TOKEN_NAME),
    "file_server_ancestor_root": (
        FILE_SERVER_ANCESTOR_ROOT,
        "/",
        "/branchleft/secrets/" + TOKEN_NAME,
    ),
    "file_server_relative_root": (FILE_SERVER_RELATIVE_ROOT, "/etc/branchleft", "/" + TOKEN_NAME),
    "file_server_nested_route": (
        FILE_SERVER_NESTED_ROUTE,
        "/",
        "/branchleft/secrets/" + TOKEN_NAME,
    ),
    "templates_include": (TEMPLATES_INCLUDE, "/", "/"),
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

    def test_the_unchanged_candidate_passes_the_text_judge(self) -> None:
        self.assertIsNone(judge_caddy_config.judge_text(render_good(), TOKEN))

    def test_every_text_case_is_refused_for_its_code(self) -> None:
        good = render_good()
        for name, (change, expected) in TEXT_CASES.items():
            with self.subTest(case=name):
                text = change(good)
                self.assertNotEqual(text, good, "the change did not alter the renderer's output")
                self.assertEqual(judge_caddy_config.judge_text(text, TOKEN), expected)

    def test_a_refused_text_prints_one_line_and_no_hostname_through_the_program(self) -> None:
        good = render_good()
        for name, (change, expected) in TEXT_CASES.items():
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
                        "--what",
                        "candidate",
                    ],
                    env={ENV: change(good)},
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(done.returncode, 1)
                self.assertRegex(done.stdout, rf"^REFUSED {expected}: .+\n$")
                self.assertNotIn("site-fixture", done.stdout + done.stderr)

    def test_a_host_name_that_holds_the_words_is_not_a_directive(self) -> None:
        good = render_good()
        for name, change in TEXT_ACCEPTED.items():
            with self.subTest(case=name):
                text = change(good)
                self.assertNotEqual(text, good, "the change did not alter the renderer's output")
                self.assertIsNone(judge_caddy_config.judge_text(text, TOKEN))

    def test_a_file_reader_is_found_at_any_depth_in_the_config(self) -> None:
        for where, reader in (
            ("file_server", {"handler": "file_server"}),
            ("templates", {"handler": "templates"}),
            ("root", {"root": "/etc"}),
            ("root_in_a_matcher", {"match": [{"file": {"root": "/etc"}}]}),
        ):
            with self.subTest(where=where):
                good = json.loads(fixture_path("good").read_text())
                route = good["apps"]["http"]["servers"]["srv0"]["routes"][0]
                route["handle"][0]["routes"].append(
                    {"handle": [{"handler": "subroute", "routes": [{"handle": [reader]}]}]}
                )
                code = {
                    "file_server": "handler-file-server",
                    "templates": "handler-templates",
                }.get(where, "handler-root")
                self.assertEqual(judge_caddy_config.judge(good, BASE, TOKEN), code)

    def test_the_first_of_two_file_readers_named_is_the_file_server(self) -> None:
        good = json.loads(fixture_path("good").read_text())
        route = good["apps"]["http"]["servers"]["srv0"]["routes"][0]
        route["handle"] += [{"handler": "vars", "root": "/etc"}, {"handler": "templates"}]
        route["handle"].append({"handler": "file_server"})
        self.assertEqual(judge_caddy_config.judge(good, BASE, TOKEN), "handler-file-server")

    def test_an_expression_matcher_is_found_at_any_depth_in_the_config(self) -> None:
        for where, matcher in (
            ("in_a_match_set", {"match": [{"expression": {"expr": "true"}}]}),
            ("as_a_bare_string", {"match": [{"expression": "true"}]}),
            ("under_not", {"match": [{"not": [{"expression": "true"}]}]}),
            ("a_key_beside_other_keys", {"handler": "static_response", "expression": "x"}),
        ):
            with self.subTest(where=where):
                good = json.loads(fixture_path("good").read_text())
                route = good["apps"]["http"]["servers"]["srv0"]["routes"][0]
                route["handle"][0]["routes"].append(
                    {"handle": [{"handler": "subroute", "routes": [matcher]}]}
                )
                self.assertEqual(judge_caddy_config.judge(good, BASE, TOKEN), "matcher-expression")

    def test_the_word_expression_as_a_value_is_not_the_matcher(self) -> None:
        # Only the key is the matcher. A header value that says the word is a string.
        good = json.loads(fixture_path("good").read_text())
        route = good["apps"]["http"]["servers"]["srv0"]["routes"][0]
        route["handle"][0]["routes"][0]["handle"][0]["x"] = "expression"
        self.assertNotEqual(judge_caddy_config.judge(good, BASE, TOKEN), "matcher-expression")

    def test_the_unchanged_text_is_accepted_through_the_program(self) -> None:
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
                "--what",
                "candidate",
            ],
            env={ENV: render_good()},
            capture_output=True,
            text=True,
        )
        self.assertEqual((done.returncode, done.stdout), (0, "OK\n"))

    def test_the_text_judge_counts_the_token_reference_not_a_longer_path(self) -> None:
        good = render_good()
        longer = good.replace("{file." + TOKEN + "}", "{file." + TOKEN + "-other}")
        self.assertEqual(judge_caddy_config.judge_text(longer, TOKEN), "text-file-placeholder")
        twice = good.replace(
            "\thandle {\n\t\tabort", "\t# {file." + TOKEN + "}\n\thandle {\n\t\tabort"
        )
        self.assertNotEqual(twice, good)
        self.assertEqual(judge_caddy_config.judge_text(twice, TOKEN), "text-file-placeholder")
        # No reference at all is the config check's to refuse (the issuer names no token file).
        none = good.replace("{file." + TOKEN + "}", "x")
        self.assertIsNone(judge_caddy_config.judge_text(none, TOKEN))

    def test_a_placeholder_is_found_in_a_key_a_value_and_a_list(self) -> None:
        for where in ("key", "value", "list"):
            with self.subTest(where=where):
                good = json.loads(fixture_path("good").read_text())
                handle = good["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]
                if where == "key":
                    handle["{env.X}"] = 1
                elif where == "value":
                    handle["x"] = "a {file.y} b"
                else:
                    handle["x"] = [["{env.X}"]]
                self.assertEqual(judge_caddy_config.judge(good, BASE, TOKEN), "placeholder")

    def test_the_role_names_an_image_only_by_name_and_digest(self) -> None:
        pattern = yaml.safe_load(VARS.read_text())["demo1_build_caddy_image_pattern"]
        digest = "sha256:" + "0123456789abcdef" * 4
        for image in (f"name@{digest}", f"ghcr.io/org/edge@{digest}", f"a.b/c_d-e@{digest}"):
            self.assertTrue(re.match(pattern, image), image)
        for image in (
            digest,
            f"name:tag@{digest}",
            f"Name@{digest}",
            f"-name@{digest}",
            f"@{digest}",
            "name@sha256:" + "0" * 63,
            "name@sha256:" + "0" * 65,
            "name@sha256:" + "G" * 64,
            f"name@{digest}\n",
            f"name@{digest} ",
            "name",
            "name:tag",
        ):
            self.assertFalse(re.match(pattern, image), image)

    def test_only_one_image_whose_repo_digests_hold_the_pinned_digest_is_verified(self) -> None:
        digest = "sha256:" + "0123456789abcdef" * 4
        other = "sha256:" + "fedcba9876543210" * 4
        image = f"name@{digest}"
        one = {"Id": "sha256:" + "1" * 64, "RepoDigests": [f"name@{digest}"]}
        self.assertTrue(role_image_verified(image, [one]))
        self.assertTrue(
            role_image_verified(image, [{**one, "RepoDigests": [f"x/y@{other}", f"z@{digest}"]}])
        )
        for label, listed, unreadable in (
            ("none", [], False),
            ("two", [one, one], False),
            ("no digests", [{**one, "RepoDigests": []}], False),
            ("digests absent", [{"Id": one["Id"]}], False),
            ("digests null", [{**one, "RepoDigests": None}], False),
            ("digests a string", [{**one, "RepoDigests": f"name@{digest}"}], False),
            ("another digest", [{**one, "RepoDigests": [f"name@{other}"]}], False),
            ("digest as a prefix", [{**one, "RepoDigests": [f"name@{digest}0"]}], False),
            ("digest with no name", [{**one, "RepoDigests": [digest]}], False),
            ("a mapping", one, False),
            ("a string", "[]", False),
            ("an item that is not a mapping", ["x"], False),
            ("not JSON", [], True),
        ):
            with self.subTest(case=label):
                self.assertFalse(role_image_verified(image, listed, unreadable))

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


def role_template(name: str, **context: object) -> str:
    """Render one of the role's own templates from vars/main.yml with the given variables."""
    role_vars = yaml.safe_load(VARS.read_text())
    # The templates render an argument list or a boolean, not markup: nothing is escaped.
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)  # noqa: S701
    # Ansible's `match` test anchors at the start of the string, as re.match does.
    env.tests["match"] = lambda value, pattern: re.match(pattern, str(value)) is not None
    return env.from_string(role_vars[name]).render(**context)


def role_argv(name: str, docker: str, image: str) -> list[str]:
    """Return the argument list the role runs, rendered from its own vars/main.yml.

    Raises:
        TypeError: The template did not render to a list of strings.
    """
    rendered = role_template(name, demo1_build_docker=docker, demo1_build_caddy_image=image)
    argv = ast.literal_eval(rendered)
    if not (isinstance(argv, list) and all(isinstance(a, str) for a in argv)):
        message = f"the role's {name} did not render to a list of strings"
        raise TypeError(message)
    return [str(a) for a in argv]


def role_adapt_argv(docker: str, image: str) -> list[str]:
    return role_argv("demo1_build_caddy_adapt_argv", docker, image)


def role_inspect_argv(docker: str, image: str) -> list[str]:
    return role_argv("demo1_build_caddy_image_inspect_argv", docker, image)


def role_image_verified(image: str, listed: object, unreadable: bool = False) -> bool:
    """Return the role's own answer to: is the image docker listed the pinned one?"""
    rendered = role_template(
        "demo1_build_caddy_image_verified_template",
        demo1_build_caddy_image=image,
        demo1_build_caddy_image_listed=listed,
        demo1_build_caddy_image_unreadable=unreadable,
    )
    return rendered.strip() == "True"


def servers(adapted: str) -> int:
    return len(json.loads(adapted)["apps"]["http"]["servers"])


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

    def adapt(
        self, text: str, before_image: list[str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Run the role's adapt argument list, with options the edge would add before the image."""
        argv = role_adapt_argv(self.docker, self.image)
        if before_image:
            at = argv.index(self.image)
            argv = [*argv[:at], *before_image, *argv[at:]]
        return subprocess.run(argv, input=text, capture_output=True, text=True)

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

    def test_the_raw_text_bypasses_are_real_and_adapting_alone_would_accept_them(self) -> None:
        for name, (options, files) in DANGERS.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                # The container drops every capability, so root in it reads only what others can.
                Path(tmp).chmod(0o755)
                for file_name, content in files.items():
                    (Path(tmp) / file_name).write_text(content)
                    (Path(tmp) / file_name).chmod(0o644)
                text = TEXT_CASES[name][0](self.good)
                # What the role's adapt sees: no environment value, no file. Either Caddy
                # cannot adapt it, or the config it prints is one the judge accepts.
                alone = self.adapt(text)
                if alone.returncode == 0:
                    self.assertIsNone(
                        judge_caddy_config.judge(json.loads(alone.stdout), BASE, TOKEN)
                    )
                    self.assertEqual(servers(alone.stdout), 1)
                # What the edge would run it with: a second server, the site the environment
                # or the file added.
                edge = self.adapt(text, [o.replace("@EXTRA@", tmp) for o in options])
                self.assertEqual(edge.returncode, 0, edge.stderr[:300])
                self.assertEqual(servers(edge.stdout), 2)
                self.assertEqual(
                    judge_caddy_config.judge(json.loads(edge.stdout), BASE, TOKEN), "servers"
                )
                # The raw text is refused before either.
                self.assertEqual(judge_caddy_config.judge_text(text, TOKEN), TEXT_CASES[name][1])

    def test_a_handler_that_serves_the_token_is_adapted_by_caddy_and_refused_by_the_judge(
        self,
    ) -> None:
        # Real Caddy keeps the placeholders and resolves them when the edge runs. The token
        # path is in the issuer and in the handler: twice in the JSON.
        for name in ("handler_respond_token", "handler_header_token"):
            with self.subTest(case=name):
                done = self.adapt(CASES[name][0](self.good))
                self.assertEqual(done.returncode, 0, done.stderr[:300])
                self.assertEqual(done.stdout.count(TOKEN), 2)
                self.assertEqual(
                    judge_caddy_config.judge(json.loads(done.stdout), BASE, TOKEN), "placeholder"
                )

    def test_a_file_reader_adapts_and_is_refused_for_the_handler_not_a_placeholder(self) -> None:
        # Real Caddy adapts each of these, and the JSON holds the token's path once, in the
        # issuer: no placeholder reaches the file, so only the handler itself shows the danger.
        for name in DANGEROUS_HANDLERS:
            with self.subTest(case=name):
                change, expected = CASES["handler_" + name]
                done = self.adapt(change(self.good))
                self.assertEqual(done.returncode, 0, done.stderr[:300])
                self.assertEqual(
                    judge_caddy_config.judge(json.loads(done.stdout), BASE, TOKEN), expected
                )
                self.assertEqual(done.stdout.count("{file."), 1)

    def serve_and_fetch(self, body: str, workdir: str, path: str, fake: str) -> str:
        """Serve one handler body from real Caddy and return what the container's wget gets.

        The container has no network but its own loopback, and holds a fake token at the
        token's path (a random string made here, mounted read-only), never a real secret.
        """
        with tempfile.TemporaryDirectory() as tmp:
            # The container drops every capability, so root in it reads only what others can.
            Path(tmp).chmod(0o755)
            (Path(tmp) / TOKEN_NAME).write_text(fake)
            (Path(tmp) / TOKEN_NAME).chmod(0o644)
            config = "{\n\tadmin off\n\tauto_https off\n}\n:8080 {\n" + body + "}\n"
            (Path(tmp) / "Caddyfile").write_text(config)
            (Path(tmp) / "Caddyfile").chmod(0o644)
            name = f"demo1-build-test-serve-{os.getpid()}-{uuid.uuid4().hex[:8]}"
            self.addCleanup(subprocess.run, [self.docker, "rm", "-f", name], capture_output=True)
            subprocess.run(
                [
                    *[self.docker, "run", "-d", "--rm", "--network", "none", "--cap-drop", "ALL"],
                    # The caddy binary carries a file capability for binding a port.
                    *["--cap-add", "NET_BIND_SERVICE"],
                    *["--name", name, "-w", workdir, "-v", f"{tmp}:{TOKEN_DIR}:ro", self.image],
                    *[
                        "caddy",
                        "run",
                        "--adapter",
                        "caddyfile",
                        "--config",
                        TOKEN_DIR + "/Caddyfile",
                    ],
                ],
                capture_output=True,
                check=True,
            )
            got = ""
            for _ in range(40):
                done = subprocess.run(
                    [self.docker, "exec", name, "wget", "-qO-", "-T", "2", FETCH + path],
                    capture_output=True,
                    text=True,
                )
                got = done.stdout
                if done.returncode == 0:
                    break
                time.sleep(0.5)
            return got

    def test_every_file_reader_the_judge_refuses_serves_the_token_from_real_caddy(self) -> None:
        # The refusals are not a theory: each handler body is served by real Caddy beside a
        # fake token at the token's own path, and a plain fetch returns the fake token. The
        # judge before this change printed OK for every one of them.
        for name, (body, workdir, path) in DANGEROUS_HANDLERS.items():
            with self.subTest(case=name):
                fake = "FAKE-TOKEN-" + uuid.uuid4().hex
                self.assertIn(fake, self.serve_and_fetch(body, workdir, path, fake))

    def test_a_site_that_serves_no_file_does_not_return_the_fake_token(self) -> None:
        # The control: the same fetch against a handler that reads no file gets no token, so the
        # test above can fail.
        fake = "FAKE-TOKEN-" + uuid.uuid4().hex
        served = self.serve_and_fetch(
            '\t\trespond "x"\n', "/etc", "/branchleft/secrets/" + TOKEN_NAME, fake
        )
        # Caddy answered (the server was up), and what it said is not the file.
        self.assertEqual(served, "x")

    def test_an_expression_matcher_adapts_with_the_token_path_once_and_is_refused_for_the_matcher(
        self,
    ) -> None:
        # The path is built at run time from two strings, so the JSON holds one {file.: the
        # issuer's. The placeholder count and the literal text check both pass it; the
        # matcher is the only thing that shows it.
        for name in ("file_oracle", "env_oracle", "plain", "in_route"):
            with self.subTest(case=name):
                text = CASES["handler_expression_" + name][0](self.good)
                done = self.adapt(text)
                self.assertEqual(done.returncode, 0, done.stderr[:300])
                self.assertEqual(done.stdout.count("{file."), 1)
                self.assertEqual(done.stdout.count("{env."), 0)
                self.assertIn('"expression"', done.stdout)
                self.assertEqual(
                    judge_caddy_config.judge(json.loads(done.stdout), BASE, TOKEN),
                    "matcher-expression",
                )

    def test_an_expression_matcher_leaks_the_token_a_prefix_at_a_time_from_real_caddy(self) -> None:
        # The danger is real: a plain fetch tells a right guess of the token's start from a
        # wrong one, on a Caddy that serves no file and holds no {file. but the issuer's. The
        # judge before this change printed OK for this text, in both layers.
        fake = "A-FAKE-TOKEN-" + uuid.uuid4().hex
        right = self.serve_and_fetch(expression_file_oracle("A-FAKE"), "/", "/", fake)
        wrong = self.serve_and_fetch(expression_file_oracle("Z-FAKE"), "/", "/", fake)
        self.assertEqual((right, wrong), ("match", "nomatch"))
        self.assertNotIn(fake, right + wrong)

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


# The Docker-in-Docker image the throwaway daemons run, pinned by its digest. The containers
# have no network, so nothing is pulled into them and nothing leaves them.
DIND = "docker:27-dind@sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce"
STANDIN = ROLE / "molecule" / "default" / "files" / "standin-docker.sh"


class Daemon:
    """A throwaway Docker daemon in a privileged container, on one image store."""

    def __init__(self, docker: str, store: str) -> None:
        self.docker = docker
        self.store = store
        self.name = f"demo1-build-test-{store}-{os.getpid()}-{uuid.uuid4().hex[:8]}"

    def start(self) -> None:
        features = ["--feature", "containerd-snapshotter"] if self.store == "containerd" else []
        subprocess.run(
            [
                self.docker,
                "run",
                "-d",
                "--rm",
                "--privileged",
                "--network",
                "none",
                "-e",
                "DOCKER_TLS_CERTDIR=",
                "--name",
                self.name,
                DIND,
                *features,
            ],
            capture_output=True,
            check=True,
        )

    def wait(self) -> None:
        for _ in range(180):
            if self.run(["docker", "info"]).returncode == 0:
                return
            time.sleep(1)
        message = f"the {self.store} daemon did not start"
        raise AssertionError(message)

    def run(self, argv: list[str], data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [self.docker, "exec", "-i", self.name, *argv], input=data, capture_output=True
        )

    def stop(self) -> None:
        subprocess.run([self.docker, "rm", "-f", self.name], capture_output=True)


def marker_tar() -> bytes:
    """Return a tar holding one file, the filesystem of the test image."""
    data = b"demo1_build test image\n"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("marker")
        info.size = len(data)
        archive.addfile(info, fileobj=io.BytesIO(data))
    return buffer.getvalue()


def require_ok(done: subprocess.CompletedProcess[bytes]) -> None:
    if done.returncode != 0:
        raise AssertionError(done.stderr.decode()[:300])


class ImageStoreTests(unittest.TestCase):
    """The role's image check against a real Docker on each image store.

    The owner carries the image with `docker save` from a workstation into `docker load` on
    the host. Each daemon below is a host: one on the classic image store, one on the
    containerd image store. The image is made in the containerd daemon, saved by its tag,
    removed there and loaded back, and loaded into the classic daemon, which is the carry.
    """

    classic = Daemon("", "classic")
    containerd = Daemon("", "containerd")
    ref = ""
    tag = "edge-test:pinned"

    @classmethod
    def setUpClass(cls) -> None:
        docker = docker_binary()
        subprocess.run([docker, "info"], capture_output=True, check=True)
        cls.classic = Daemon(docker, "classic")
        cls.containerd = Daemon(docker, "containerd")
        for daemon in (cls.classic, cls.containerd):
            cls.addClassCleanup(daemon.stop)
            daemon.start()
        for daemon in (cls.classic, cls.containerd):
            daemon.wait()
        require_ok(cls.containerd.run(["docker", "import", "-", cls.tag], marker_tar()))
        image_id = cls.containerd.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", cls.tag]
        ).stdout.decode()
        cls.ref = "edge-test@" + image_id.strip()
        saved = cls.containerd.run(["docker", "save", cls.tag]).stdout
        cls.containerd.run(["docker", "rmi", "-f", cls.tag])
        for daemon in (cls.containerd, cls.classic):
            require_ok(daemon.run(["docker", "load"], saved))

    def listed(self, daemon: Daemon, ref: str) -> tuple[int, object]:
        """Run the role's own inspect argument list on the daemon: its status and its listing."""
        done = daemon.run(role_inspect_argv("docker", ref))
        return done.returncode, json.loads(done.stdout) if done.stdout.strip() else None

    def test_the_containerd_store_lists_the_loaded_image_by_digest_and_the_role_verifies_it(
        self,
    ) -> None:
        status, listed = self.listed(self.containerd, self.ref)
        self.assertEqual(status, 0)
        self.assertTrue(role_image_verified(self.ref, listed), listed)

    def test_the_classic_store_does_not_find_the_loaded_image_by_digest(self) -> None:
        status, listed = self.listed(self.classic, self.ref)
        self.assertNotEqual(status, 0)
        self.assertEqual(listed, [])

    def test_the_classic_store_lists_the_loaded_image_by_tag_with_no_digests(self) -> None:
        # Why the role must read RepoDigests and not trust that docker found something.
        status, listed = self.listed(self.classic, self.tag)
        self.assertEqual(status, 0)
        self.assertFalse(role_image_verified(self.ref, listed), listed)

    def test_a_wrong_digest_under_the_right_name_is_not_found_on_either_store(self) -> None:
        wrong = "edge-test@sha256:" + "0" * 64
        for daemon in (self.classic, self.containerd):
            with self.subTest(store=daemon.store):
                status, listed = self.listed(daemon, wrong)
                self.assertNotEqual(status, 0)
                self.assertEqual(listed, [])

    def test_the_old_listing_call_finds_nothing_on_either_store(self) -> None:
        # `docker images --quiet REF` took the reference for a repository filter, so the role
        # that used it never found an image that was there, by either form it accepted: the
        # name and digest, or the image ID. (A tag it would find, and the role never takes one.)
        for daemon in (self.classic, self.containerd):
            for ref in (self.ref, self.ref.replace("edge-test@", "")):
                with self.subTest(store=daemon.store, ref=ref):
                    done = daemon.run(["docker", "images", "--quiet", ref])
                    self.assertEqual((done.returncode, done.stdout.strip()), (0, b""))

    def test_the_molecule_stand_in_answers_as_a_real_docker_does(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / "images").write_text(self.ref + "\n")

            def standin(*args: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["/bin/sh", str(STANDIN), *args],
                    env={"STANDIN_DOCKER_STATE": tmp, "PATH": os.environ["PATH"]},
                    capture_output=True,
                    text=True,
                )

            # The listing call: nothing, with status 0, for the reference the role holds.
            real = self.containerd.run(["docker", "images", "--quiet", self.ref])
            fake = standin("images", "--quiet", self.ref)
            self.assertEqual((real.returncode, real.stdout.strip()), (0, b""))
            self.assertEqual((fake.returncode, fake.stdout.strip()), (0, ""))
            # The inspect call on an image that is there: the role's argument list, one image
            # with its RepoDigests, the loaded reference in them as the containerd store lists.
            argv = role_inspect_argv("docker", self.ref)[1:]
            real = self.containerd.run(["docker", *argv])
            fake = standin(*argv)
            self.assertEqual((real.returncode, fake.returncode), (0, 0))
            for listing in (json.loads(real.stdout), json.loads(fake.stdout)):
                self.assertEqual(len(listing), 1)
                self.assertTrue({"Id", "RepoDigests", "RepoTags"} <= set(listing[0]), listing)
                self.assertIn(self.ref, listing[0]["RepoDigests"])
                self.assertTrue(role_image_verified(self.ref, listing))
            # The same call on an image that is not there: status 1, an empty list.
            gone = role_inspect_argv("docker", "edge-test@sha256:" + "0" * 64)[1:]
            real = self.containerd.run(["docker", *gone])
            fake = standin(*gone)
            self.assertEqual((real.returncode, fake.returncode), (1, 1))
            self.assertEqual(
                (real.stdout.strip(), fake.stdout.strip()),
                (b"[]", "[]"),
                (real.stderr, fake.stderr),
            )
            # What a loaded image lists on the classic store, no digests, which the stand-in
            # can be made to report and which the role must not accept.
            (state / "image-digests").write_text("")
            fake = standin(*argv)
            self.assertEqual(json.loads(fake.stdout)[0]["RepoDigests"], [])
            real = self.classic.run(["docker", "image", "inspect", self.tag])
            self.assertEqual(json.loads(real.stdout)[0]["RepoDigests"], [])
            self.assertFalse(role_image_verified(self.ref, json.loads(fake.stdout)))


if __name__ == "__main__":
    unittest.main()
