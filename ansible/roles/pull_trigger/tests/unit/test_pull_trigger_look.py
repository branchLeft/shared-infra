"""Unit tests for the look: a declared, read-only set of host facts printed by a check run.

Three things are proved. A declared fact prints one fixed line. An entry that is not one of the
closed kinds, that carries a field the kind does not name, or whose value is command-like or
outside its allowed place is refused by name and nothing is run for it. And the look never
changes what a run is: the verdict and the exit status are those of the same run without it,
and an apply or a step prints no look.
"""

import contextlib
import hashlib
import http.client
import http.server
import io
import json
import os
import re
import shutil
import socket
import stat
import sys
import tempfile
import threading
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest import mock

import pull_trigger as trigger
from test_pull_trigger import (
    GIT,
    GPG,
    GPGCONF,
    SSH_KEYGEN,
    Remote,
    Run,
    Scene,
    SshKey,
    fake_ansible,
    make_ssh_key,
    playbook_text,
    valid_config_data,
)

ROLE = Path(__file__).resolve().parents[2]
ANSIBLE = ROLE.parents[1]
README = ROLE / "README.md"
PLAY = "ansible/playbooks/host.yml"
OTHER_PLAY = "ansible/playbooks/other.yml"
UNIT_FACT = {
    "issue": 7,
    "name": "demo-unit",
    "playbook": PLAY,
    "kind": "unit_active",
    "unit": "demo.service",
}
FILE_FACT = {
    "issue": 7,
    "name": "demo-file",
    "playbook": PLAY,
    "kind": "file_sha256",
    "path": "/usr/local/bin/demo",
}
HTTP_FACT = {
    "issue": 7,
    "name": "demo-http",
    "playbook": PLAY,
    "kind": "http_status",
    "port": 8080,
    "url_path": "/health",
}
# The credential-assignment pattern of the plan job's secret scan, held here as the scan holds it
# (github-workflows, host_output_scan.py). A line of the look that matched it would fail the plan
# of every host, so no line may.
SCAN_ASSIGNMENT = re.compile(
    r"(passw(or)?d|passphrase|secret|token|api[_-]?key|private[_-]?key|credential)"
    r'[A-Za-z0-9_.-]*"?\s*[:=]\s*"?[^\s"]{4,}',
    re.IGNORECASE,
)


def declaration(*facts: Mapping[str, object]) -> str:
    """Return the text of a look file holding these entries."""
    return json.dumps({"facts": list(facts)})


def with_fact(base: Mapping[str, object], **changes: object) -> dict[str, object]:
    """Return a copy of a fact with fields changed; a value of None removes the field."""
    fact = dict(base)
    for key, value in changes.items():
        if value is None:
            fact.pop(key, None)
        else:
            fact[key] = value
    return fact


def refusals_of(text: str, roots: Sequence[str] = trigger.LOOK_FILE_ROOTS) -> list[str]:
    """Return the reasons the entries of a look file were refused, in order."""
    return [item.why.value for item in trigger.parse_look(text, roots).refusals]


def declare_http(test: unittest.TestCase, *ports: int) -> None:
    """Declare the loopback ports the test's http facts may GET, until the test ends."""
    for name in ("demo-http", "demo-miss"):
        patcher = mock.patch.dict(trigger.LOOK_HTTP_PORTS, {name: frozenset(ports)})
        patcher.start()
        test.addCleanup(patcher.stop)


class ParseTests(unittest.TestCase):
    """What the file may hold: one closed list of kinds, each with exactly its own fields."""

    def setUp(self) -> None:
        """Declare the port the shared http fact names, so only the tests below vary it."""
        declare_http(self, 8080)

    def test_an_http_fact_whose_service_is_not_declared_is_refused(self) -> None:
        with mock.patch.dict(trigger.LOOK_HTTP_PORTS, {}, clear=True):
            self.assertEqual(["service-not-declared"], refusals_of(declaration(HTTP_FACT)))

    def test_an_http_fact_naming_a_port_its_service_does_not_declare_is_refused(self) -> None:
        self.assertEqual(
            ["port-not-allowed"], refusals_of(declaration(with_fact(HTTP_FACT, port=8081)))
        )
        self.assertEqual([], refusals_of(declaration(HTTP_FACT)))

    def test_each_kind_with_its_own_fields_is_accepted(self) -> None:
        parsed = trigger.parse_look(declaration(UNIT_FACT, FILE_FACT, HTTP_FACT))
        self.assertEqual("ok", parsed.file)
        self.assertEqual([], list(parsed.refusals))
        self.assertEqual(
            ["unit_active", "file_sha256", "http_status"],
            [fact.kind.value for fact in parsed.facts],
        )

    def test_the_optional_host_name_of_an_http_fact_is_accepted(self) -> None:
        text = declaration(with_fact(HTTP_FACT, host="app.example.test"))
        self.assertEqual([], refusals_of(text))

    def test_a_command_like_entry_is_refused_by_name_whatever_shape_it_takes(self) -> None:
        cases = {
            "a kind that is a command": (
                with_fact(UNIT_FACT, kind="command", run="id"),
                "unknown-kind",
            ),
            "a shell kind": ({"kind": "shell", "cmd": "id"}, "unknown-kind"),
            "an exec kind": (with_fact(UNIT_FACT, kind="exec"), "unknown-kind"),
            "no kind at all": (with_fact(UNIT_FACT, kind=None), "unknown-kind"),
            "a kind that is a list": (with_fact(UNIT_FACT, kind=["unit_active"]), "unknown-kind"),
            "a run field on a unit fact": (with_fact(UNIT_FACT, run="id"), "unknown-field"),
            "a command field on a file fact": (
                with_fact(FILE_FACT, command="cat /etc/shadow"),
                "unknown-field",
            ),
            "an args field on an http fact": (with_fact(HTTP_FACT, args=["-v"]), "unknown-field"),
            "a unit field on a file fact": (
                with_fact(FILE_FACT, unit="x.service"),
                "unknown-field",
            ),
            "a path field on a unit fact": (
                with_fact(UNIT_FACT, path="/usr/local/bin/x"),
                "unknown-field",
            ),
            "a missing path": (with_fact(FILE_FACT, path=None), "missing-field"),
            "a missing unit": (with_fact(UNIT_FACT, unit=None), "missing-field"),
            "a missing port": (with_fact(HTTP_FACT, port=None), "missing-field"),
            "an entry that is a string": ("id", "entry-shape"),
            "an entry that is a list": (["unit_active"], "entry-shape"),
        }
        for label, (entry, reason) in cases.items():
            with self.subTest(label):
                self.assertEqual([reason], refusals_of(json.dumps({"facts": [entry]})))

    def test_a_unit_that_is_not_a_plain_unit_name_is_refused(self) -> None:
        hostile = [
            "demo.service; id",
            "demo.service && id",
            "demo.service id",
            "$(id).service",
            "`id`.service",
            "-demo.service",
            "--help.service",
            "demo.service\n",
            "demo.service\nid",
            " demo.service",
            "demo",
            "demo.sh",
            "../demo.service",
            "/etc/demo.service",
            "demo\x00.service",
            "",
            "a" * 200 + ".service",
            7,
            ["demo.service"],
        ]
        for unit in hostile:
            with self.subTest(unit=unit):
                self.assertEqual(
                    ["bad-unit"], refusals_of(declaration(with_fact(UNIT_FACT, unit=unit)))
                )

    def test_a_file_outside_the_four_directories_or_not_plain_is_refused(self) -> None:
        hostile = [
            "/etc/shadow",
            "/etc/branchleft/host-inputs.json",
            "/etc/pull-trigger/config.json",
            "/root/.ssh/authorized_keys",
            "/var/lib/pull-trigger/last-applied",
            "/usr/local/bin/../../../etc/shadow",
            "/usr/local/bin/./demo",
            "/usr/local/bin//demo",
            "/usr/local/bin/demo/",
            "/usr/local/bin/",
            "/usr/local/bin",
            "/usr/local/binx/demo",
            "/usr/local/bin/demo\n",
            "/usr/local/bin/de mo",
            "/usr/local/bin/$(id)",
            "/usr/local/bin/demo;id",
            "usr/local/bin/demo",
            "demo",
            "/usr/local/bin/.hidden",
            "/usr/local/bin/" + "a" * 250,
            "/usr/local/bin/demo\x00",
            "",
            7,
            ["/usr/local/bin/demo"],
        ]
        for path in hostile:
            with self.subTest(path=path):
                self.assertEqual(
                    ["path-not-allowed"], refusals_of(declaration(with_fact(FILE_FACT, path=path)))
                )

    def test_a_file_in_each_allowed_directory_is_accepted(self) -> None:
        for path in (
            "/etc/systemd/system/demo@.service",
            "/usr/local/bin/demo",
            "/usr/local/lib/demo/helper.py",
            "/usr/local/sbin/pull-trigger",
        ):
            with self.subTest(path=path):
                self.assertEqual([], refusals_of(declaration(with_fact(FILE_FACT, path=path))))

    def test_a_port_or_path_or_host_that_is_not_loopback_http_is_refused(self) -> None:
        cases = [
            ("port", 0, "bad-port"),
            ("port", 65536, "bad-port"),
            ("port", -1, "bad-port"),
            ("port", True, "bad-port"),
            ("port", "8080", "bad-port"),
            ("port", 80.5, "bad-port"),
            ("url_path", "health", "bad-url-path"),
            ("url_path", "/health?x=1", "bad-url-path"),
            ("url_path", "/health#top", "bad-url-path"),
            ("url_path", "/../etc", "bad-url-path"),
            ("url_path", "/a/./b", "bad-url-path"),
            ("url_path", "//evil.example/x", "bad-url-path"),
            ("url_path", "/a b", "bad-url-path"),
            ("url_path", "/health\r\nX: 1", "bad-url-path"),
            ("url_path", "http://example.test/", "bad-url-path"),
            ("url_path", "/" + "a" * 200, "bad-url-path"),
            ("host", "Example.test", "bad-host-name"),
            ("host", "a b", "bad-host-name"),
            ("host", "a\r\nX: 1", "bad-host-name"),
            ("host", "-bad.test", "bad-host-name"),
            ("host", "", "bad-host-name"),
            ("host", 7, "bad-host-name"),
        ]
        for field, value, reason in cases:
            with self.subTest(field=field, value=value):
                text = declaration(with_fact(HTTP_FACT, **{field: value}))
                self.assertEqual([reason], refusals_of(text))

    def test_an_http_fact_has_no_field_that_could_name_another_address(self) -> None:
        for field in ("address", "url", "ip", "scheme", "method", "headers", "body"):
            with self.subTest(field=field):
                self.assertEqual(
                    ["unknown-field"],
                    refusals_of(declaration(with_fact(HTTP_FACT, **{field: "127.0.0.1"}))),
                )

    def test_the_issue_the_name_and_the_playbook_are_checked(self) -> None:
        cases = [
            ("issue", 0, "bad-issue"),
            ("issue", -3, "bad-issue"),
            ("issue", True, "bad-issue"),
            ("issue", "7", "bad-issue"),
            ("issue", 7.5, "bad-issue"),
            ("issue", 10**9, "bad-issue"),
            ("name", "Demo", "bad-name"),
            ("name", "demo unit", "bad-name"),
            ("name", "demo_unit", "bad-name"),
            ("name", "1demo", "bad-name"),
            ("name", "demo\n", "bad-name"),
            ("name", "", "bad-name"),
            ("name", "a" * 49, "bad-name"),
            ("name", 7, "bad-name"),
            ("playbook", "ansible/playbooks/../x.yml", "bad-playbook"),
            ("playbook", "/ansible/playbooks/x.yml", "bad-playbook"),
            ("playbook", "ansible/roles/x.yml", "bad-playbook"),
            ("playbook", "ansible/playbooks/x.sh", "bad-playbook"),
            ("playbook", 7, "bad-playbook"),
        ]
        for field, value, reason in cases:
            with self.subTest(field=field, value=value):
                self.assertEqual(
                    [reason], refusals_of(declaration(with_fact(UNIT_FACT, **{field: value})))
                )

    def test_a_name_with_a_word_the_plan_scan_reads_is_refused(self) -> None:
        for word in ("secret", "token", "password", "passwd", "passphrase", "credential", "apikey"):
            with self.subTest(word=word):
                self.assertEqual(
                    ["bad-name"],
                    refusals_of(declaration(with_fact(UNIT_FACT, name=f"my-{word}-unit"))),
                )
        for word in ("api-key", "private-key"):
            with self.subTest(word=word):
                self.assertEqual(
                    ["bad-name"],
                    refusals_of(declaration(with_fact(UNIT_FACT, name=f"my-{word}"))),
                )

    def test_a_name_used_twice_refuses_the_second(self) -> None:
        text = declaration(UNIT_FACT, with_fact(FILE_FACT, name="demo-unit"))
        parsed = trigger.parse_look(text)
        self.assertEqual(1, len(parsed.facts))
        self.assertEqual(["duplicate-name"], [item.why.value for item in parsed.refusals])
        self.assertEqual(2, parsed.refusals[0].entry)

    def test_one_bad_entry_does_not_hide_the_others(self) -> None:
        text = declaration(
            UNIT_FACT, with_fact(FILE_FACT, name="demo-bad", path="/etc/shadow"), HTTP_FACT
        )
        parsed = trigger.parse_look(text)
        self.assertEqual(["demo-unit", "demo-http"], [fact.name for fact in parsed.facts])
        self.assertEqual(
            [(2, "path-not-allowed")], [(r.entry, r.why.value) for r in parsed.refusals]
        )
        self.assertEqual(3, parsed.declared)

    def test_a_file_that_is_not_the_one_shape_is_refused_whole(self) -> None:
        good = declaration(UNIT_FACT)
        cases = {
            "not json": ("{", "file-not-json"),
            "empty": ("", "file-not-json"),
            "not a document": ("facts", "file-not-json"),
            "a repeated key": ('{"facts": [], "facts": []}', "file-not-json"),
            "a repeated key inside an entry": (
                '{"facts": [{"kind": "unit_active", "kind": "file_sha256"}]}',
                "file-not-json",
            ),
            "not a number": ('{"facts": [{"issue": NaN}]}', "file-not-json"),
            "a list": ("[]", "file-shape"),
            "no facts key": ("{}", "file-shape"),
            "another key": (good[:-1] + ', "run": "id"}', "file-shape"),
            "facts is an object": ('{"facts": {}}', "file-shape"),
            "too large": (good + " " * trigger.MAX_LOOK_BYTES, "file-too-large"),
            "too many": (
                declaration(*[with_fact(UNIT_FACT, name=f"n{i}") for i in range(65)]),
                "file-too-many",
            ),
            "too deep": ("[" * 30_000, "file-not-json"),
        }
        for label, (text, reason) in cases.items():
            with self.subTest(label):
                parsed = trigger.parse_look(text)
                self.assertEqual(reason, parsed.file)
                self.assertEqual((), parsed.facts)

    def test_the_declared_file_of_the_repository_has_no_refusal(self) -> None:
        """CI fails a declaration that any host would refuse, so a merged file has none."""
        path = ANSIBLE / "tools" / "look" / "facts.json"
        self.assertTrue(path.is_file(), "the repository's look file must exist")
        parsed = trigger.parse_look(path.read_text(encoding="utf-8"))
        self.assertEqual("ok", parsed.file)
        self.assertEqual([], [(r.entry, r.why.value) for r in parsed.refusals])
        self.assertGreater(len(parsed.facts), 0)

    def test_every_declared_playbook_exists_and_is_never_the_mail_host(self) -> None:
        path = ANSIBLE / "tools" / "look" / "facts.json"
        for fact in trigger.parse_look(path.read_text(encoding="utf-8")).facts:
            with self.subTest(name=fact.name):
                self.assertTrue((ANSIBLE.parent / fact.playbook).is_file(), fact.playbook)
                self.assertNotIn("mx1", fact.playbook)

    def test_the_readme_names_every_kind_and_every_reason(self) -> None:
        text = README.read_text(encoding="utf-8")
        for kind in trigger.LookKind:
            with self.subTest(kind=kind.value):
                self.assertIn(f"`{kind.value}`", text)
        for why in trigger.LookWhy:
            with self.subTest(why=why.value):
                self.assertIn(f"`{why.value}`", text)

    def test_no_word_the_look_can_print_is_one_the_plan_scan_reads(self) -> None:
        words = [why.value for why in trigger.LookWhy] + [kind.value for kind in trigger.LookKind]
        words += sorted(trigger.LOOK_UNIT_STATES) + ["absent", "unknown", "skipped-time"]
        for word in words:
            with self.subTest(word=word):
                for field in ("reason", "result", "file", "kind"):
                    self.assertIsNone(SCAN_ASSIGNMENT.search(f"look {field}={word}"))


def fake_systemctl(directory: Path, word: str, code: int = 0) -> Path:
    """Write a stand-in for systemctl that records how it was called and prints ``word``."""
    script = directory / "systemctl"
    calls = directory / "systemctl-calls.txt"
    script.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"with open({str(calls)!r}, 'a', encoding='utf-8') as handle:\n"
        "    handle.write(' '.join(sys.argv[1:]) + '\\n')\n"
        f"print({word!r})\n"
        f"sys.exit({code})\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def systemctl_calls(directory: Path) -> list[str]:
    """Return what the stand-in systemctl was asked, one line a call."""
    calls = directory / "systemctl-calls.txt"
    return calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []


class QuietHandler(http.server.BaseHTTPRequestHandler):
    """A loopback server whose answers carry a body no result may repeat."""

    def do_GET(self) -> None:  # noqa: N802 - the name http.server calls
        """Answer by path: 200, 404, or a redirect that must not be followed."""
        paths = {"/health": 200, "/missing": 404, "/moved": 302, "/broken": 503}
        status = paths.get(self.path, 404)
        body = b"BODY-THE-LOOK-MUST-NOT-REPEAT"
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Seen-Host", self.headers.get("Host", ""))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - the base's name
        """Print nothing."""


class LookerTests(unittest.TestCase):
    """What each kind reads, and that nothing but its fixed words and digests comes back."""

    def setUp(self) -> None:
        """Make a directory that stands for the allowed root, and the stand-in programs."""
        self.root = Path(tempfile.mkdtemp(prefix="look")).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.allowed = self.root / "allowed"
        self.allowed.mkdir()
        self.roots = (f"{self.allowed}/",)

    def looker(self, systemctl: Path | None = None, total: float = 60.0) -> trigger.Looker:
        """Return a looker that reads the stand-in root and runs the stand-in systemctl."""
        tools = trigger.Tools(systemctl=systemctl or fake_systemctl(self.bin, "active"))
        return trigger.Looker(tools, threading.Event(), self.roots, total)

    def facts(self, *entries: Mapping[str, object]) -> trigger.LookDeclaration:
        """Parse entries against the stand-in root."""
        return trigger.parse_look(declaration(*entries), self.roots)

    def test_a_declared_file_prints_its_digest_and_no_content(self) -> None:
        target = self.allowed / "demo"
        target.write_text("PRIVATE-CONTENT-THE-LOOK-MUST-NOT-REPEAT\n", encoding="utf-8")
        parsed = self.facts(with_fact(FILE_FACT, path=str(target)))
        lines = self.looker().lines(parsed, PLAY)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        self.assertEqual(
            [
                f"look issue=7 name=demo-file kind=file_sha256 result={digest}",
                "look-summary declared=1 here=1 refused=0 file=ok",
            ],
            lines,
        )
        self.assertNotIn("PRIVATE", "".join(lines))

    def test_a_file_that_cannot_be_hashed_gives_a_word_and_never_the_error(self) -> None:
        directory = self.allowed / "adir"
        directory.mkdir()
        outside = self.root / "outside"
        outside.write_text("x", encoding="utf-8")
        link = self.allowed / "link"
        link.symlink_to(outside)
        inside = self.allowed / "inside"
        inside.write_text("x", encoding="utf-8")
        inner = self.allowed / "inner-link"
        inner.symlink_to(inside)
        unreadable = self.allowed / "locked"
        unreadable.write_text("x", encoding="utf-8")
        unreadable.chmod(0)
        self.addCleanup(unreadable.chmod, stat.S_IRUSR | stat.S_IWUSR)
        cases = {
            "absent": (self.allowed / "nothing", "absent"),
            "a directory": (directory, "not-regular"),
            "a link out of the root": (link, "outside-root"),
            "a link inside the root": (inner, hashlib.sha256(b"x").hexdigest()),
        }
        if os.geteuid() != 0:
            cases["a file that cannot be read"] = (unreadable, "unreadable")
        for label, (path, expected) in cases.items():
            with self.subTest(label):
                parsed = self.facts(with_fact(FILE_FACT, path=str(path)))
                self.assertEqual(expected, self.looker().result(parsed.facts[0]))

    def test_a_file_over_the_size_limit_is_not_read(self) -> None:
        target = self.allowed / "big"
        target.write_bytes(b"x" * 100)
        parsed = self.facts(with_fact(FILE_FACT, path=str(target)))
        with mock.patch.object(trigger, "LOOK_MAX_FILE_BYTES", 10):
            self.assertEqual("too-large", self.looker().result(parsed.facts[0]))

    def test_a_unit_is_asked_by_one_fixed_argument_list_and_answers_a_closed_word(self) -> None:
        parsed = self.facts(UNIT_FACT)
        for word in sorted(trigger.LOOK_UNIT_STATES):
            with self.subTest(word=word):
                looker = self.looker(fake_systemctl(self.bin, word, 0 if word == "active" else 3))
                self.assertEqual(word, looker.result(parsed.facts[0]))
        self.assertEqual("--no-pager", systemctl_calls(self.bin)[0].split()[1])
        self.assertEqual("is-active --no-pager -- demo.service", systemctl_calls(self.bin)[0])

    def test_a_unit_answer_that_is_not_a_known_word_is_not_repeated(self) -> None:
        parsed = self.facts(UNIT_FACT)
        looker = self.looker(fake_systemctl(self.bin, "ERROR-text-from-the-host token=abc12345"))
        self.assertEqual("unknown", looker.result(parsed.facts[0]))

    def test_a_systemctl_that_is_missing_or_hangs_gives_unknown(self) -> None:
        parsed = self.facts(UNIT_FACT)
        missing = trigger.Looker(
            trigger.Tools(systemctl=self.bin / "absent"), threading.Event(), self.roots
        )
        self.assertEqual("unknown", missing.result(parsed.facts[0]))
        slow = self.bin / "slow"
        slow.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\n", encoding="utf-8")
        slow.chmod(0o755)
        with mock.patch.object(trigger, "LOOK_UNIT_SECONDS", 0.3):
            self.assertEqual("unknown", self.looker(slow).result(parsed.facts[0]))

    def serve(self) -> int:
        """Start the loopback server and return its port."""
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = int(server.server_address[1])
        declare_http(self, port)
        return port

    def test_an_http_fact_prints_only_the_status_of_one_get_to_loopback(self) -> None:
        port = self.serve()
        cases = {"/health": "200", "/missing": "404", "/moved": "302", "/broken": "503"}
        for url_path, expected in cases.items():
            with self.subTest(url_path):
                parsed = self.facts(with_fact(HTTP_FACT, port=port, url_path=url_path))
                lines = self.looker().lines(parsed, PLAY)
                self.assertEqual(
                    f"look issue=7 name=demo-http kind=http_status result={expected}", lines[0]
                )
                self.assertNotIn("BODY", "".join(lines))

    def test_the_host_header_is_the_declared_name_but_the_connection_is_loopback(self) -> None:
        port = self.serve()
        seen: list[str] = []
        original = QuietHandler.do_GET

        def record(handler: QuietHandler) -> None:
            seen.append(handler.headers.get("Host", ""))
            original(handler)

        with mock.patch.object(QuietHandler, "do_GET", record):
            parsed = self.facts(with_fact(HTTP_FACT, port=port, host="app.example.test"))
            self.looker().result(parsed.facts[0])
            parsed = self.facts(with_fact(HTTP_FACT, port=port))
            self.looker().result(parsed.facts[0])
        self.assertEqual(["app.example.test", "localhost"], seen)

    def test_an_http_fact_that_cannot_be_reached_or_times_out_gives_a_word(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = int(probe.getsockname()[1])
        declare_http(self, closed)
        parsed = self.facts(with_fact(HTTP_FACT, port=closed))
        self.assertEqual("unreachable", self.looker().result(parsed.facts[0]))
        with socket.socket() as silent:
            silent.bind(("127.0.0.1", 0))
            silent.listen(1)
            declare_http(self, int(silent.getsockname()[1]))
            parsed = self.facts(with_fact(HTTP_FACT, port=int(silent.getsockname()[1])))
            with mock.patch.object(trigger, "LOOK_HTTP_SECONDS", 0.3):
                self.assertEqual("timeout", self.looker().result(parsed.facts[0]))

    def test_a_port_the_service_does_not_declare_is_never_connected_to(self) -> None:
        port = self.serve()
        fact = trigger.LookFact(
            issue=7,
            name="demo-http",
            playbook=PLAY,
            kind=trigger.LookKind.HTTP_STATUS,
            port=port,
            url_path="/health",
        )
        with mock.patch.dict(trigger.LOOK_HTTP_PORTS, {"demo-http": frozenset()}):
            with mock.patch.object(http.client, "HTTPConnection") as connection:
                self.assertEqual("port-not-allowed", trigger.Looker._http_status(fact))
        connection.assert_not_called()

    def test_a_refused_entry_runs_nothing_and_is_named(self) -> None:
        marker = self.root / "marker"
        entries = [
            with_fact(UNIT_FACT, name="one", run=f"touch {marker}"),
            with_fact(UNIT_FACT, name="two", unit=f"x.service; touch {marker}"),
            with_fact(FILE_FACT, name="three", path="/etc/shadow"),
            with_fact(UNIT_FACT, name="four", kind="command"),
        ]
        parsed = self.facts(*entries)
        lines = self.looker().lines(parsed, PLAY)
        self.assertEqual(
            [
                "look-refused entry=1 reason=unknown-field",
                "look-refused entry=2 reason=bad-unit",
                "look-refused entry=3 reason=path-not-allowed",
                "look-refused entry=4 reason=unknown-kind",
                "look-summary declared=4 here=0 refused=4 file=ok",
            ],
            lines,
        )
        self.assertFalse(marker.exists())
        self.assertEqual([], systemctl_calls(self.bin))

    def test_a_fact_for_another_playbook_is_checked_but_not_looked_at(self) -> None:
        parsed = self.facts(UNIT_FACT, with_fact(UNIT_FACT, name="elsewhere", playbook=OTHER_PLAY))
        lines = self.looker().lines(parsed, OTHER_PLAY)
        self.assertEqual(
            [
                "look issue=7 name=elsewhere kind=unit_active result=active",
                "look-summary declared=2 here=1 refused=0 file=ok",
            ],
            lines,
        )
        self.assertEqual(1, len(systemctl_calls(self.bin)))

    def test_a_refused_file_prints_one_summary_and_looks_at_nothing(self) -> None:
        parsed = trigger.refused_look_file(trigger.LookWhy.FILE_NOT_REGULAR)
        self.assertEqual(
            ["look-summary declared=0 here=0 refused=0 file=file-not-regular"],
            self.looker().lines(parsed, PLAY),
        )

    def test_a_look_past_its_time_or_after_a_stop_reads_nothing_more(self) -> None:
        parsed = self.facts(UNIT_FACT)
        late = self.looker(total=-1.0).lines(parsed, PLAY)
        self.assertEqual(
            "look issue=7 name=demo-unit kind=unit_active result=skipped-time", late[0]
        )
        stopped = threading.Event()
        stopped.set()
        tools = trigger.Tools(systemctl=fake_systemctl(self.bin, "active"))
        lines = trigger.Looker(tools, stopped, self.roots).lines(parsed, PLAY)
        self.assertEqual(
            "look issue=7 name=demo-unit kind=unit_active result=skipped-time", lines[0]
        )
        self.assertEqual([], systemctl_calls(self.bin))

    def test_every_line_has_the_one_shape_and_none_matches_the_plan_scan(self) -> None:
        port = self.serve()
        target = self.allowed / "demo"
        target.write_text("x", encoding="utf-8")
        parsed = self.facts(
            UNIT_FACT,
            with_fact(FILE_FACT, path=str(target)),
            with_fact(FILE_FACT, name="gone", path=str(self.allowed / "gone")),
            with_fact(HTTP_FACT, port=port),
            with_fact(HTTP_FACT, name="demo-miss", port=port, url_path="/missing"),
        )
        lines = self.looker().lines(parsed, PLAY)
        for line in lines[:-1]:
            with self.subTest(line=line):
                self.assertIsNotNone(trigger.LOOK_LINE.fullmatch(line))
                self.assertIsNone(SCAN_ASSIGNMENT.search(line))
        self.assertIsNone(SCAN_ASSIGNMENT.search(lines[-1]))
        self.assertTrue(lines[-1].startswith("look-summary "))

    def test_a_line_that_is_not_of_the_one_shape_is_not_printed(self) -> None:
        fact = trigger.LookFact(
            7, "demo-unit", PLAY, trigger.LookKind.UNIT_ACTIVE, unit="x.service"
        )
        looker = self.looker()
        with mock.patch.object(looker, "result", return_value="free text with spaces"):
            self.assertEqual(
                "look-refused entry=0 reason=line-shape",
                looker._line(fact),  # noqa: SLF001
            )


class LookEndToEndTests(unittest.TestCase):
    """The whole program on real repositories: the look follows a check and nothing else."""

    keys: dict[str, SshKey]
    root: Path
    remote: Remote
    commits: dict[str, str]
    web_port: int

    @classmethod
    def setUpClass(cls) -> None:
        """Make a key and a signed history with each kind of look file."""
        cls.root = Path(tempfile.mkdtemp(prefix="pt-look-"))
        keys_dir = cls.root / "keys"
        keys_dir.mkdir()
        cls.keys = {"a": make_ssh_key(keys_dir, "signer-a")}
        cls.remote = Remote.create(cls.root)
        a = cls.keys["a"]
        look = "ansible/tools/look/facts.json"
        commits: dict[str, str] = {}
        commits["plain"] = cls.remote.commit({PLAY: playbook_text("plain")}, "plain", None, a)
        good = declaration(UNIT_FACT, FILE_FACT)
        commits["declared"] = cls.remote.commit({look: good}, "declared", commits["plain"], a)
        hostile = declaration(
            with_fact(UNIT_FACT, name="hostile-a", run="touch HOSTILE-MARKER"),
            with_fact(UNIT_FACT, name="hostile-b", unit="x.service; touch HOSTILE-MARKER"),
            with_fact(FILE_FACT, name="hostile-c", path="/etc/shadow"),
            UNIT_FACT,
        )
        commits["hostile"] = cls.remote.commit({look: hostile}, "hostile", commits["declared"], a)
        commits["broken"] = cls.remote.commit({look: "{"}, "broken", commits["hostile"], a)
        commits["linked"] = cls.remote.commit(
            {look: "->../../../etc/hostname"}, "linked", commits["broken"], a
        )
        commits["big"] = cls.remote.commit(
            {look: " " * (trigger.MAX_LOOK_BYTES + 1)}, "big", commits["linked"], a
        )
        cls.remote.set_ref("main", commits["big"])
        cls.commits = commits

    @classmethod
    def tearDownClass(cls) -> None:
        """Remove the fixture."""
        shutil.rmtree(cls.root, ignore_errors=True)

    def make_scene(self, word: str = "active") -> Scene:
        """Make a host with its own copy of the remote and a stand-in systemctl."""
        root = Path(tempfile.mkdtemp(prefix="pt", dir="/tmp")).resolve()  # noqa: S108
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        root.chmod(0o700)
        bare = root / "remote.git"
        shutil.copytree(self.remote.bare, bare)
        config_dir = root / "etc"
        config_dir.mkdir(mode=0o755)
        helper = root / "bin"
        helper.mkdir()
        ansible = fake_ansible(helper)
        fake_systemctl(helper, word)
        data = valid_config_data(
            remote_url=f"file://{bare}",
            signers=[{"format": "ssh", "key": self.keys["a"].public_line}],
            ansible_playbook=str(ansible),
            state_dir=str(root / "state"),
            log_dir=str(root / "logs"),
            timeout_seconds=60,
        )
        config_path = config_dir / "config.json"
        config_path.write_text(json.dumps(data), encoding="utf-8")
        config_path.chmod(0o644)
        return Scene(
            root,
            Remote(bare, self.remote.work),
            config_path,
            root / "state",
            root / "logs",
            ansible,
            helper / "calls.txt",
        )

    def request(self, scene: Scene, commit: str, mode: str = "check") -> Run:
        """Call the program as the forced command would."""
        out, relayed, errors = io.StringIO(), io.BytesIO(), io.StringIO()
        argv = ["--mode", mode, "--config", str(scene.config_path)]
        tools = trigger.Tools(
            git=GIT,
            gpg=Path(GPG or "/usr/bin/gpg"),
            gpgconf=Path(GPGCONF or "/usr/bin/gpgconf"),
            ssh_keygen=SSH_KEYGEN,
            systemctl=scene.root / "bin" / "systemctl",
        )
        with contextlib.redirect_stderr(errors):
            code = trigger.main(
                argv, {"SSH_ORIGINAL_COMMAND": commit}, threading.Event(), tools, out, relayed
            )
        return Run(code, out.getvalue().strip(), errors.getvalue(), relayed.getvalue().decode())

    @staticmethod
    def look_lines(run: Run) -> list[str]:
        """Return the lines of the relayed output that belong to the look."""
        return [line for line in run.relayed.splitlines() if line.startswith("look")]

    @staticmethod
    def without_commit(summary: str) -> str:
        """Return a summary line with its commit removed, so two commits' lines compare."""
        return re.sub(r"commit=[0-9a-f]{40}", "commit=-", summary)

    def test_a_declared_fact_prints_after_the_playbook_output(self) -> None:
        scene = self.make_scene("active")
        result = self.request(scene, self.commits["declared"])
        self.assertEqual(11, result.code, result.summary + result.errors)
        lines = result.relayed.splitlines()
        self.assertIn("PLAY RECAP", result.relayed)
        self.assertEqual(
            [
                "look issue=7 name=demo-unit kind=unit_active result=active",
                "look issue=7 name=demo-file kind=file_sha256 result=absent",
                "look-summary declared=2 here=2 refused=0 file=ok",
            ],
            lines[-3:],
        )
        self.assertEqual(
            ["is-active --no-pager -- demo.service"], systemctl_calls(scene.root / "bin")
        )

    def test_the_look_changes_neither_the_verdict_nor_the_exit_status(self) -> None:
        plain = self.request(self.make_scene(), self.commits["plain"])
        for name in ("declared", "hostile", "broken", "linked", "big"):
            with self.subTest(name):
                looked = self.request(self.make_scene(), self.commits[name])
                self.assertEqual(plain.code, looked.code)
                self.assertEqual(
                    self.without_commit(plain.summary), self.without_commit(looked.summary)
                )
                self.assertEqual(1, len(looked.summary.splitlines()))

    def test_a_commit_with_no_look_file_prints_no_look(self) -> None:
        result = self.request(self.make_scene(), self.commits["plain"])
        self.assertEqual([], self.look_lines(result))

    def test_an_apply_and_a_failed_playbook_print_no_look(self) -> None:
        scene = self.make_scene()
        applied = self.request(scene, self.commits["declared"], mode="apply")
        self.assertEqual(10, applied.code, applied.summary + applied.errors)
        self.assertEqual([], self.look_lines(applied))
        self.assertEqual([], systemctl_calls(scene.root / "bin"))
        scene = self.make_scene()
        scene.ansible.write_text(
            scene.ansible.read_text(encoding="utf-8").replace("sys.exit(0)", "sys.exit(2)"),
            encoding="utf-8",
        )
        failed = self.request(scene, self.commits["declared"])
        self.assertEqual(30, failed.code, failed.summary + failed.errors)
        # A playbook that failed still ended by itself, so the look follows it.
        self.assertEqual(3, len(self.look_lines(failed)))

    def test_a_command_like_entry_is_refused_and_runs_nothing(self) -> None:
        scene = self.make_scene()
        result = self.request(scene, self.commits["hostile"])
        self.assertEqual(11, result.code, result.summary + result.errors)
        self.assertEqual(
            [
                "look-refused entry=1 reason=unknown-field",
                "look-refused entry=2 reason=bad-unit",
                "look-refused entry=3 reason=path-not-allowed",
                "look issue=7 name=demo-unit kind=unit_active result=active",
                "look-summary declared=4 here=1 refused=3 file=ok",
            ],
            self.look_lines(result),
        )
        self.assertEqual(
            ["is-active --no-pager -- demo.service"], systemctl_calls(scene.root / "bin")
        )
        self.assertFalse(list(scene.root.rglob("HOSTILE-MARKER")))
        self.assertNotIn("HOSTILE", result.relayed)
        self.assertNotIn("shadow", result.relayed)

    def test_a_look_file_that_is_broken_linked_or_too_large_is_refused_whole(self) -> None:
        for name, reason in (
            ("broken", "file-not-json"),
            ("linked", "file-not-regular"),
            ("big", "file-too-large"),
        ):
            with self.subTest(name):
                scene = self.make_scene()
                result = self.request(scene, self.commits[name])
                self.assertEqual(11, result.code, result.summary + result.errors)
                self.assertEqual(
                    [f"look-summary declared=0 here=0 refused=0 file={reason}"],
                    self.look_lines(result),
                )
                self.assertEqual([], systemctl_calls(scene.root / "bin"))

    def test_the_output_of_a_unit_that_is_not_a_known_word_is_never_relayed(self) -> None:
        scene = self.make_scene("HOST-TEXT secret=hunter2hunter2")
        result = self.request(scene, self.commits["declared"])
        self.assertIn("result=unknown", result.relayed)
        self.assertNotIn("hunter2", result.relayed + result.errors)

    def test_a_fault_in_the_look_never_changes_the_verdict(self) -> None:
        plain = self.request(self.make_scene(), self.commits["plain"])
        with mock.patch.object(trigger.Looker, "lines", side_effect=RuntimeError("TEXT-OF-FAULT")):
            result = self.request(self.make_scene(), self.commits["declared"])
        self.assertEqual(plain.code, result.code)
        self.assertEqual(self.without_commit(plain.summary), self.without_commit(result.summary))
        self.assertEqual(["look-refused entry=0 reason=look-fault"], self.look_lines(result))
        self.assertNotIn("TEXT-OF-FAULT", result.relayed + result.errors)
        with mock.patch.object(trigger, "parse_look", side_effect=RuntimeError("TEXT-OF-FAULT")):
            result = self.request(self.make_scene(), self.commits["declared"])
        self.assertEqual(plain.code, result.code)
        self.assertEqual(
            ["look-summary declared=0 here=0 refused=0 file=look-fault"], self.look_lines(result)
        )

    def test_a_caller_that_has_gone_does_not_change_the_verdict(self) -> None:
        scene = self.make_scene()

        class Gone(io.RawIOBase):
            def writable(self) -> bool:
                return True

            def write(self, _data: object) -> int:
                raise BrokenPipeError

        out, errors = io.StringIO(), io.StringIO()
        tools = trigger.Tools(
            git=GIT,
            gpg=Path(GPG or "/usr/bin/gpg"),
            gpgconf=Path(GPGCONF or "/usr/bin/gpgconf"),
            ssh_keygen=SSH_KEYGEN,
            systemctl=scene.root / "bin" / "systemctl",
        )
        argv = ["--mode", "check", "--config", str(scene.config_path)]
        gone = io.BufferedWriter(Gone())
        with contextlib.redirect_stderr(errors):
            code = trigger.main(
                argv,
                {"SSH_ORIGINAL_COMMAND": self.commits["declared"]},
                threading.Event(),
                tools,
                out,
                gone,
            )
        self.assertEqual(11, code, out.getvalue() + errors.getvalue())


if __name__ == "__main__":
    unittest.main()
