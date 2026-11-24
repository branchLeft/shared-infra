"""Unit tests for the app host's tenant entry point.

The host is a temporary directory and every downstream program is a fake that records its
arguments, so a refusal is proved by what did not run and what was not written. The cases a
controller key must never get through are each named for the guard they hold: break the guard
and the case beside it fails. Placeholders only; no value here is a real name, key or secret.
"""

import base64
import dataclasses
import errno
import fcntl
import inspect
import io
import json
import os
import re
import shutil
import signal
import stat
import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest import mock

import branchleft_tenant_entry as entry
from ruamel.yaml import YAML

ROLE = Path(__file__).resolve().parents[2]
ROLES = ROLE.parent
JUDGE = ROLE / "files" / "tenant_compose_check.py"

SLUG = "example-tenant"
OTHER = "example-other"
CANARY = "EXAMPLE_SECRET_CANARY_7f3a"
OWNER_EMAIL = "owner@example.invalid"
TEMPLATE = "GHOST_DB_PASSWORD=\nGHOST_OWNER_EMAIL=\n"
VALUES = {"GHOST_DB_PASSWORD": CANARY, "GHOST_OWNER_EMAIL": OWNER_EMAIL}
CONTAINER_ID = "a" * 64
IMAGE_DIGEST = "sha256:" + "b" * 64
PIN = f"IMAGE=ghcr.io/branchleft/ghost-tenant@{IMAGE_DIGEST}\n"
BIND = "10.20.2.30"
# Every key of a Ghost service the host's template writes, with mail on. A parameter adds none.
FIXED_SERVICE_KEYS = {
    "image", "restart", "stop_grace_period", "user", "init", "read_only", "tmpfs", "cap_drop",
    "security_opt", "pids_limit", "mem_limit", "memswap_limit", "cpus", "cpu_shares", "ulimits",
    "logging", "ports", "environment", "networks", "volumes", "healthcheck",
}  # fmt: skip


def jget(document: object, *path: str) -> object:
    """Walk a parsed JSON document by keys.

    Raises:
        TypeError: at the first step that is not an object.
    """
    for key in path:
        if not isinstance(document, dict):
            raise TypeError(path)
        document = document[key]
    return document


def jmap(document: object, *path: str) -> dict[str, object]:
    """Like jget, for a step that must be an object.

    Raises:
        TypeError: when it is not.
    """
    value = jget(document, *path)
    if not isinstance(value, dict):
        raise TypeError(path)
    return value


def stack_parameters(**changes: object) -> dict[str, object]:
    """The parameters of a plain `stack` request: a size, mail on, and a small environment."""
    parameters: dict[str, object] = {
        "size": "standard",
        "mail": True,
        "environment": {
            "url": "https://blog.example.invalid",
            "database__client": "mysql",
            "database__connection__password": {"secret": "GHOST_DB_PASSWORD"},
            "mail__options__port": 587,
            "privacy__useGravatar": False,
        },
    }
    parameters.update(changes)
    return parameters


def make_key(number: int) -> str:
    """A well-formed ed25519 public key, `number` apart from the others."""
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes([number]) * 32
    return f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')}"


KEY = make_key(1)


def tenant_compose_text(slug: str = SLUG, uid: int = 30000, **service: object) -> str:
    """A placeholder stack with the shape the renderer produces, which the judge accepts.

    JSON is YAML, so the text is the JSON of the document. Keyword arguments are set on the
    service, or removed from it when the value is None, to make the stack break one rule.
    """
    app: dict[str, object] = {
        "image": "${IMAGE}",
        "user": f"{uid}:{uid}",
        "ports": ["10.20.2.30:40000:2368"],
        "environment": {
            "db": "${GHOST_DB_PASSWORD:?set GHOST_DB_PASSWORD in the env file}",
            "owner": "${GHOST_OWNER_EMAIL:?set GHOST_OWNER_EMAIL in the env file}",
        },
        "volumes": [f"ghost-{slug}-content:/var/lib/ghost/content"],
    }
    for key, value in service.items():
        if value is None:
            del app[key]
        else:
            app[key] = value
    document: dict[str, object] = {
        "name": slug,
        "services": {"app": app},
        "volumes": {f"ghost-{slug}-content": {"external": True}},
    }
    return json.dumps(document)


@dataclasses.dataclass
class Call:
    """One program run the fakes saw."""

    argv: list[str]
    stdin: bytes | None
    template_text: str | None = None


class FakeHost:
    """A temporary app host: its directories, its downstream programs and a record of both."""

    def __init__(self, case: unittest.TestCase, root: Path) -> None:
        self.case = case
        self.root = root
        self.etc = root / "etc"
        self.opt = root / "opt"
        self.entry = self.etc / "tenant-entry"
        self.paths = entry.Paths(
            etc_dir=str(self.etc),
            opt_dir=str(self.opt),
            entry_dir=str(self.entry),
            volume_program="/fake/volume",
            secrets_program="/fake/secrets",
            owner_program="/fake/owner.mjs",
            slot_program="/fake/slot",
            judge_module=str(JUDGE),
            systemctl="/fake/systemctl",
            docker="/fake/docker",
            node="/fake/node",
            root_uid=os.geteuid(),
        )
        self.entry.mkdir(parents=True)
        os.chmod(self.entry, 0o700)
        self.opt.mkdir()
        (self.etc / "deploy-slots").mkdir()
        address = self.entry / entry.BIND_ADDRESS_FILE
        address.write_text(BIND + "\n", encoding="ascii")
        os.chmod(address, 0o600)
        self.calls: list[Call] = []
        self.claims: dict[str, int] = {}
        self.enabled: set[str] = set()
        self.volume_returncode = 0
        self.secrets_stderr = ""
        self.secrets_returncode = 0
        self.slot_returncode = 0
        self.containers = CONTAINER_ID
        self.owner_returncode = 0
        self.log: list[str] = []

    def runner(self, argv: Sequence[str], stdin: bytes | None) -> entry.Outcome:
        """Answer as each downstream program would, and record the call."""
        call = Call(list(argv), stdin)
        self.calls.append(call)
        program, args = argv[0], list(argv[1:])
        if program == "/fake/volume":
            return self.volume(args)
        if program == "/fake/secrets":
            return self.secrets(args, call, stdin)
        if program == "/fake/systemctl":
            return self.systemctl(args)
        if program == "/fake/slot":
            return self.slot(args, stdin)
        if program == "/fake/docker":
            return entry.Outcome(0, self.containers + "\n" if self.containers else "", "")
        if program == "/fake/node":
            return entry.Outcome(self.owner_returncode, '{"created":true}\n', "")
        self.case.fail(f"an unexpected program ran: {program}")

    def volume(self, args: list[str]) -> entry.Outcome:
        if args == ["--list-claims"]:
            return entry.Outcome(0, "".join(f"{s}={u}\n" for s, u in self.claims.items()), "")
        self.case.assertEqual(args[0], "--uid")
        if self.volume_returncode == 0:
            self.claims[args[2]] = int(args[1])
        return entry.Outcome(self.volume_returncode, "", "EXAMPLE volume refusal")

    def secrets(self, args: list[str], call: Call, stdin: bytes | None) -> entry.Outcome:
        template_file = args[1].removeprefix("--template-file=")
        call.template_text = Path(template_file).read_text(encoding="utf-8")
        if self.secrets_returncode != 0:
            return entry.Outcome(self.secrets_returncode, "", self.secrets_stderr)
        slug = args[0].removeprefix("--slug=")
        target = self.etc / f"{slug}.env"
        values: dict[str, str] = json.loads(stdin or b"{}")
        target.write_text(
            "".join(f"{name}={value}\n" for name, value in values.items()), encoding="utf-8"
        )
        os.chmod(target, 0o600)
        return entry.Outcome(0, "written\nkey GHOST_DB_PASSWORD\n", "")

    def systemctl(self, args: list[str]) -> entry.Outcome:
        unit = args[1]
        if args[0] == "enable":
            self.enabled.add(unit)
            return entry.Outcome(0, "", "")
        self.case.assertEqual(args[0], "is-enabled")
        if unit in self.enabled:
            return entry.Outcome(0, "enabled\n", "")
        return entry.Outcome(1, "disabled\n", "")

    def slot(self, args: list[str], stdin: bytes | None) -> entry.Outcome:
        self.case.assertIsNotNone(stdin)
        if self.slot_returncode != 0:
            return entry.Outcome(self.slot_returncode, "", "EXAMPLE slot refusal " + KEY)
        slug = args[-1]
        (self.etc / "deploy-slots" / f"{slug}.pub").write_text("x", encoding="utf-8")
        return entry.Outcome(0, "granted\n", "")

    def request(
        self, command: str | None, payload: object = None, raw: bytes | None = None
    ) -> tuple[int, str, str]:
        """Run one request the way sshd and sudo hand it over, and return code, stdout, stderr."""
        data = (
            raw if raw is not None else (b"" if payload is None else json.dumps(payload).encode())
        )
        environ = {} if command is None else {"SSH_ORIGINAL_COMMAND": command}
        out, err = io.StringIO(), io.StringIO()
        code = entry.main(
            [entry.SERVE_FLAG],
            environ,
            io.BytesIO(data),
            out,
            err,
            paths=self.paths,
            runner=self.runner,
            log=self.log.append,
            geteuid=os.geteuid,
        )
        return code, out.getvalue(), err.getvalue()

    def files(self) -> list[str]:
        """Every path under the host, so a case can show nothing was written."""
        return sorted(
            str(p.relative_to(self.root)) for p in self.root.rglob("*") if p.name != ".lock"
        )

    def claim(self, slug: str = SLUG) -> None:
        code, _out, err = self.request(f"claim {slug}")
        self.case.assertEqual(code, 0, err)

    def get_to(self, stage: str, slug: str = SLUG) -> None:
        """Take a slug through the steps, in order, up to and including `stage`."""
        order = ["claim", "secrets", "enable", "key"]
        for step in order[: order.index(stage) + 1]:
            if step == "claim":
                if not (self.entry / f"{slug}.json").exists():
                    self.claim(slug)
            elif step == "secrets":
                code, _o, err = self.request(
                    f"secrets {slug}", {"template": TEMPLATE, "values": VALUES}
                )
                self.case.assertEqual(code, 0, err)
            elif step == "enable":
                self.case.assertEqual(self.request(f"enable {slug}")[0], 0)
            else:
                self.case.assertEqual(self.request(f"key {slug}", {"public_key": KEY})[0], 0)

    def stack(self, slug: str = SLUG, /, **parameters: object) -> tuple[int, str, str]:
        """Ask for a slug's compose file as the controller does: parameters, and nothing else.

        With no keyword arguments the request is a plain one; with some, it carries exactly those.
        """
        body = parameters if parameters else stack_parameters()
        return self.request(f"stack {slug}", body)

    def hand_made_tenant(self, slug: str = OTHER) -> None:
        """A tenant set up by hand: a claim, a secrets file, a stack directory and a slot."""
        self.claims[slug] = 30500
        (self.etc / f"{slug}.env").write_text("HAND=1\n", encoding="utf-8")
        os.chmod(self.etc / f"{slug}.env", 0o600)
        (self.opt / slug).mkdir()
        (self.etc / "deploy-slots" / f"{slug}.pub").write_text("x", encoding="utf-8")


class EntryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.host = FakeHost(self, Path(self._tmp.name))

    def assert_refused(
        self, result: tuple[int, str, str], reason: str, *, code: int = entry.EXIT_REFUSED
    ) -> None:
        self.assertEqual(result[0], code, result)
        self.assertEqual(result[1], "")
        self.assertEqual(result[2], f"refused: {reason}\n")


class RequestShapeTests(EntryTestCase):
    """The request text is two checked words. Nothing else reaches a program or a path."""

    def test_hostile_request_text_is_refused_before_anything_runs(self) -> None:
        hostile = [
            None,
            "",
            "claim",
            "claim ",
            "claim example-tenant extra",
            "claim example-tenant;id",
            "claim example-tenant && id",
            "claim $(id)",
            "claim `id`",
            "claim example-tenant\n",
            "claim example-tenant\nclaim example-other",
            "claim ../example-other",
            "claim /etc/passwd",
            "claim Example",
            "claim example_tenant",
            "claim " + "a" * 27,
            "claim -example",
            "claim example-",
            "claim 1example",
            "claim example\x00",
            "claim exämple",
            "bash",
            "sh -c id",
            "scp -t /tmp",
            "x" * 200,
        ]
        before = self.host.files()
        for text in hostile:
            with self.subTest(text=text):
                code, out, err = self.host.request(text)
                self.assertEqual((code, out), (entry.EXIT_REFUSED, ""))
                self.assertRegex(err, r"\Arefused: (request-shape|slug-shape)\n\Z")
                self.assertNotIn("example", err)
        self.assertEqual(self.host.calls, [])
        self.assertEqual(self.host.files(), before)

    def test_unknown_verbs_are_refused_by_word(self) -> None:
        for verb in ("revoke", "delete", "shell", "rotate", "list"):
            with self.subTest(verb=verb):
                self.assert_refused(self.host.request(f"{verb} {SLUG}"), "unknown-verb")
        self.assertEqual(self.host.calls, [])

    def test_a_slug_at_the_length_limit_is_accepted_and_one_past_it_is_not(self) -> None:
        self.assertEqual(self.host.request("status " + "a" * 26)[0], entry.EXIT_DONE)
        self.assertEqual(self.host.request("status " + "a" * 27)[0], entry.EXIT_REFUSED)

    def test_only_the_serve_flag_is_accepted_and_only_as_root(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        for argv in ([], ["--other"], [entry.SERVE_FLAG, "extra"], ["claim", SLUG]):
            with self.subTest(argv=argv):
                code = entry.main(argv, {}, io.BytesIO(), out, err, paths=self.host.paths)
                self.assertEqual(code, entry.EXIT_USAGE)
        code = entry.main(
            [entry.SERVE_FLAG],
            {"SSH_ORIGINAL_COMMAND": f"claim {SLUG}"},
            io.BytesIO(),
            out,
            err,
            paths=dataclasses.replace(self.host.paths, root_uid=os.geteuid() + 1),
            geteuid=os.geteuid,
        )
        self.assertEqual(code, entry.EXIT_REFUSED)
        self.assertEqual(self.host.calls, [])


class ClaimTests(EntryTestCase):
    def test_claim_takes_the_first_free_uid_and_ports_and_makes_the_volumes(self) -> None:
        code, out, err = self.host.request(f"claim {SLUG}")
        self.assertEqual((code, err), (entry.EXIT_DONE, ""))
        self.assertEqual(out, "claimed uid=30000 port_a=40000 port_b=40001 port_health=40002\n")
        self.assertEqual(self.host.claims, {SLUG: 30000})
        self.assertEqual(
            self.host.calls[-1].argv, ["/fake/volume", "--uid", "30000", SLUG], self.host.calls
        )
        marker = self.host.entry / f"{SLUG}.json"
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)

    def test_a_second_claim_skips_every_taken_uid_and_port(self) -> None:
        self.host.claims["example-hand"] = 30000
        self.host.claim()
        self.host.claims["example-hand2"] = 30002
        code, out, _err = self.host.request(f"claim {OTHER}")
        self.assertEqual(code, entry.EXIT_DONE)
        self.assertEqual(out, "claimed uid=30003 port_a=40004 port_b=40005 port_health=40006\n")

    def test_a_slug_that_exists_anywhere_is_refused_and_nothing_is_written(self) -> None:
        # Guard: slug_in_use and the claim check. A tenant set up by hand is never touched.
        for existing in ("claim", "env", "stack", "slot", "marker"):
            with self.subTest(existing=existing):
                self.setUp()
                if existing == "claim":
                    self.host.claims[SLUG] = 30001
                elif existing == "env":
                    (self.host.etc / f"{SLUG}.env").write_text("HAND=1\n", encoding="utf-8")
                elif existing == "stack":
                    (self.host.opt / SLUG).mkdir()
                elif existing == "slot":
                    (self.host.etc / "deploy-slots" / f"{SLUG}.pub").write_text("x")
                else:
                    (self.host.entry / f"{SLUG}.json").write_text("{}")
                before = self.host.files()
                self.assert_refused(self.host.request(f"claim {SLUG}"), "slug-in-use")
                self.assertEqual(self.host.files(), before)
                self.assertEqual([c.argv[1:2] for c in self.host.calls if "--uid" in c.argv], [])

    def test_a_second_claim_of_the_same_slug_is_refused(self) -> None:
        self.host.claim()
        self.assert_refused(self.host.request(f"claim {SLUG}"), "slug-in-use")

    def test_a_failed_volume_step_frees_the_slug_when_no_claim_was_made(self) -> None:
        self.host.volume_returncode = 1
        code, _out, err = self.host.request(f"claim {SLUG}")
        self.assertEqual(code, entry.EXIT_FAILED)
        self.assertIn("failed: volumes\n", err)
        self.assertFalse((self.host.entry / f"{SLUG}.json").exists())

    def test_a_failed_volume_step_keeps_the_marker_when_a_claim_exists(self) -> None:
        original = self.host.volume

        def claim_then_fail(args: list[str]) -> entry.Outcome:
            if args[0] == "--uid":
                self.host.claims[args[2]] = int(args[1])
                return entry.Outcome(1, "", "EXAMPLE partial")
            return original(args)

        self.host.volume = claim_then_fail  # type: ignore[method-assign]
        self.assertEqual(self.host.request(f"claim {SLUG}")[0], entry.EXIT_FAILED)
        self.assertTrue((self.host.entry / f"{SLUG}.json").exists())

    def test_a_timed_out_volume_step_frees_the_slug_and_a_retry_succeeds(self) -> None:
        original = self.host.volume

        def timeout_on_claim(args: list[str]) -> entry.Outcome:
            if args[0] == "--uid":
                raise entry.FailedError("timeout")
            return original(args)

        self.host.volume = timeout_on_claim  # type: ignore[method-assign]
        code, _out, err = self.host.request(f"claim {SLUG}")
        self.assertEqual(code, entry.EXIT_FAILED)
        self.assertIn("failed: timeout\n", err)
        self.assertFalse((self.host.entry / f"{SLUG}.json").exists())
        self.host.volume = original  # type: ignore[method-assign]
        self.host.claim()
        self.assertEqual(self.host.claims, {SLUG: 30000})

    def test_a_missing_volume_program_frees_the_slug_and_a_retry_succeeds(self) -> None:
        original = self.host.volume

        # The listing at the start of the claim works; the program is gone when the claim runs.
        def missing_on_claim(args: list[str]) -> entry.Outcome:
            if args[0] == "--uid":
                raise entry.FailedError("program-missing")
            return original(args)

        self.host.volume = missing_on_claim  # type: ignore[method-assign]
        code, _out, err = self.host.request(f"claim {SLUG}")
        self.assertEqual(code, entry.EXIT_FAILED)
        self.assertIn("failed: program-missing\n", err)
        self.assertFalse((self.host.entry / f"{SLUG}.json").exists())
        self.host.volume = original  # type: ignore[method-assign]
        self.host.claim()
        self.assertEqual(self.host.claims, {SLUG: 30000})

    def test_a_timeout_with_an_unreadable_listing_keeps_the_marker_and_a_retry_claims_cleanly(
        self,
    ) -> None:
        # Guard: release_unclaimed_marker keeps the marker when the listing fails, because the
        # claim may stand. The retry settles the marker with a working listing and claims again.
        original = self.host.volume
        listings: list[str] = []

        def timeout_then_no_listing(args: list[str]) -> entry.Outcome:
            if args == ["--list-claims"]:
                listings.append("listed")
                if len(listings) > 1:
                    raise entry.FailedError("timeout")
                return original(args)
            raise entry.FailedError("timeout")

        self.host.volume = timeout_then_no_listing  # type: ignore[method-assign]
        code, _out, err = self.host.request(f"claim {SLUG}")
        self.assertEqual(code, entry.EXIT_FAILED)
        self.assertIn("failed: timeout\n", err)
        self.assertTrue((self.host.entry / f"{SLUG}.json").exists())
        self.host.volume = original  # type: ignore[method-assign]
        self.host.claim()
        self.assertEqual(self.host.claims, {SLUG: 30000})

    def test_a_timeout_after_the_claim_with_a_failed_listing_keeps_the_claim_and_the_steps_go_on(
        self,
    ) -> None:
        # Guard: a claim that stands keeps its marker, so a retry is refused as in use and does
        # not take a second uid, and the later steps still reach the claimed slug.
        original = self.host.volume
        listings: list[str] = []

        def claim_then_timeout(args: list[str]) -> entry.Outcome:
            if args == ["--list-claims"]:
                listings.append("listed")
                if len(listings) > 1:
                    raise entry.FailedError("timeout")
                return original(args)
            self.host.claims[args[2]] = int(args[1])
            raise entry.FailedError("timeout")

        self.host.volume = claim_then_timeout  # type: ignore[method-assign]
        code, _out, err = self.host.request(f"claim {SLUG}")
        self.assertEqual(code, entry.EXIT_FAILED)
        self.assertIn("failed: timeout\n", err)
        self.assertEqual(self.host.claims, {SLUG: 30000})
        self.host.volume = original  # type: ignore[method-assign]
        self.assert_refused(self.host.request(f"claim {SLUG}"), "slug-in-use")
        self.assertIn("volumes=yes", self.host.request(f"status {SLUG}")[1])
        self.assertEqual(
            self.host.request(f"secrets {SLUG}", {"template": TEMPLATE, "values": VALUES})[0],
            entry.EXIT_DONE,
        )

    def test_a_marker_that_cannot_be_written_leaves_no_marker_and_a_retry_claims(self) -> None:
        # Guard: write_marker writes a temporary file, syncs it and links it. A full disk must not
        # leave a half marker, which would refuse every later claim for every slug.
        with mock.patch("os.fsync", side_effect=OSError(errno.ENOSPC, "full")):
            code, out, err = self.host.request(f"claim {SLUG}")
        self.assertEqual((code, out), (entry.EXIT_FAILED, ""))
        self.assertIn("failed: marker\n", err)
        self.assertEqual([c.argv for c in self.host.calls if "--uid" in c.argv], [])
        self.assertEqual(
            list(self.host.entry.iterdir()),
            [self.host.entry / ".lock", self.host.entry / entry.BIND_ADDRESS_FILE],
        )
        self.host.claim()
        self.assertEqual(self.host.claims, {SLUG: 30000})

    def test_a_termination_during_the_volume_step_frees_the_slug_and_a_retry_succeeds(self) -> None:
        # Guard: on_termination raises Terminated inside the claim, so the claim's cleanup runs.
        # The handler is restored afterwards.
        original = self.host.volume
        for number in entry.TERMINATION_SIGNALS:
            with self.subTest(signal=number.name):

                def terminated_on_claim(args: list[str], sent: int = number) -> entry.Outcome:
                    if args[0] == "--uid":
                        os.kill(os.getpid(), sent)
                    return original(args)

                self.host.volume = terminated_on_claim  # type: ignore[method-assign]
                code, out, err = self.host.request(f"claim {SLUG}")
                self.assertEqual((code, out, err), (entry.EXIT_FAILED, "", "failed: terminated\n"))
                self.assertEqual(
                    list(self.host.entry.iterdir()),
                    [self.host.entry / ".lock", self.host.entry / entry.BIND_ADDRESS_FILE],
                )
                self.assertIsNot(signal.getsignal(number), entry.on_termination)
        self.host.volume = original  # type: ignore[method-assign]
        self.host.claim()
        self.assertEqual(self.host.claims, {SLUG: 30000})

    def test_a_termination_after_the_claim_keeps_the_claim_and_a_retry_is_refused_in_use(
        self,
    ) -> None:
        # Guard: the listing after a termination still sees a claim that stands; its marker stays.
        original = self.host.volume

        def claim_then_terminated(args: list[str]) -> entry.Outcome:
            if args[0] == "--uid":
                self.host.claims[args[2]] = int(args[1])
                os.kill(os.getpid(), signal.SIGTERM)
            return original(args)

        self.host.volume = claim_then_terminated  # type: ignore[method-assign]
        code, _out, err = self.host.request(f"claim {SLUG}")
        self.assertEqual((code, err), (entry.EXIT_FAILED, "failed: terminated\n"))
        self.host.volume = original  # type: ignore[method-assign]
        self.assert_refused(self.host.request(f"claim {SLUG}"), "slug-in-use")
        self.assertIn("volumes=yes", self.host.request(f"status {SLUG}")[1])

    def test_an_unreadable_claim_list_stops_the_request(self) -> None:
        original = self.host.volume

        def broken(args: list[str]) -> entry.Outcome:
            if args == ["--list-claims"]:
                return entry.Outcome(0, "not a claim line\n", "")
            return original(args)

        self.host.volume = broken  # type: ignore[method-assign]
        code, _out, err = self.host.request(f"claim {SLUG}")
        self.assertEqual(code, entry.EXIT_FAILED)
        self.assertIn("claims-unreadable", err)
        self.assertEqual(
            sorted(p.name for p in self.host.entry.iterdir()), [".lock", entry.BIND_ADDRESS_FILE]
        )

    def test_the_uid_range_can_run_out(self) -> None:
        self.host.claims = {f"example-{n}": n for n in range(entry.UID_MIN, entry.UID_MAX + 1)}
        self.assert_refused(self.host.request(f"claim {SLUG}"), "no-free-uid")


class OrderTests(EntryTestCase):
    """The secrets file comes before the service, and nothing runs for a slug never claimed."""

    def test_enable_before_the_secrets_file_is_refused_and_systemctl_never_runs(self) -> None:
        # Guard: require_secrets. This is the service-before-secrets case.
        self.host.claim()
        calls_before = len(self.host.calls)
        self.assert_refused(self.host.request(f"enable {SLUG}"), "secrets-first")
        self.assertEqual(self.host.enabled, set())
        self.assertNotIn("enable", [c.argv[1] for c in self.host.calls[calls_before:]])

    def test_key_and_owner_before_the_service_is_enabled_are_refused(self) -> None:
        self.host.get_to("secrets")
        self.assert_refused(self.host.request(f"key {SLUG}", {"public_key": KEY}), "enable-first")
        self.assert_refused(
            self.host.request(
                f"owner {SLUG}",
                {
                    "colour": "a",
                    "name": "N",
                    "site_url": "https://example.invalid",
                    "site_title": "T",
                },
            ),
            "enable-first",
        )
        self.assertFalse(any(c.argv[0] in ("/fake/slot", "/fake/node") for c in self.host.calls))

    def test_every_later_step_before_the_claim_is_refused(self) -> None:
        for verb in ("secrets", "enable", "key", "owner"):
            with self.subTest(verb=verb):
                self.assert_refused(
                    self.host.request(f"{verb} {SLUG}", {"template": "", "values": {}}),
                    "not-claimed-here",
                )
        self.assertEqual(self.host.calls, [])

    def test_a_hand_made_tenant_is_never_touched_by_any_verb(self) -> None:
        # Guard: the marker. The tenant has a claim, a secrets file and a slot, but no marker.
        self.host.hand_made_tenant()
        before = self.host.files()
        payloads: dict[str, object] = {
            "secrets": {"template": TEMPLATE, "values": VALUES},
            "key": {"public_key": KEY},
            "owner": {
                "colour": "a",
                "name": "N",
                "site_url": "https://e.invalid",
                "site_title": "T",
            },
        }
        for verb in ("claim", "secrets", "enable", "key", "owner"):
            with self.subTest(verb=verb):
                code, _out, err = self.host.request(f"{verb} {OTHER}", payloads.get(verb))
                self.assertEqual(code, entry.EXIT_REFUSED, err)
        self.assertEqual(self.host.files(), before)
        self.assertEqual(self.host.enabled, set())
        self.assertFalse(
            any(c.argv[0] in ("/fake/secrets", "/fake/slot", "/fake/node") for c in self.host.calls)
        )

    def test_a_tenant_claimed_here_cannot_reach_another_tenants_files(self) -> None:
        self.host.hand_made_tenant()
        self.host.get_to("secrets")
        secrets_call = [c for c in self.host.calls if c.argv[0] == "/fake/secrets"][-1]
        self.assertEqual(
            secrets_call.argv,
            [
                "/fake/secrets",
                f"--slug={SLUG}",
                secrets_call.argv[2],
                f"--etc-dir={self.host.etc}",
            ],
        )
        self.assertEqual((self.host.etc / f"{OTHER}.env").read_text(), "HAND=1\n")

    def test_a_claim_gone_from_the_volume_program_stops_the_later_steps(self) -> None:
        self.host.get_to("enable")
        del self.host.claims[SLUG]
        self.assert_refused(self.host.request(f"key {SLUG}", {"public_key": KEY}), "claim-missing")


class SecretsTests(EntryTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.host.claim()

    def secrets(self, payload: object = None, raw: bytes | None = None) -> tuple[int, str, str]:
        if payload is None and raw is None:
            payload = {"template": TEMPLATE, "values": VALUES}
        return self.host.request(f"secrets {SLUG}", payload, raw)

    def test_the_values_go_to_the_program_on_stdin_and_nowhere_else(self) -> None:
        code, out, err = self.secrets()
        self.assertEqual((code, err), (entry.EXIT_DONE, ""))
        self.assertIn("written", out)
        call = [c for c in self.host.calls if c.argv[0] == "/fake/secrets"][0]
        self.assertEqual(json.loads(call.stdin or b""), VALUES)
        self.assertEqual(call.template_text, TEMPLATE)
        for text in (*call.argv, out, err, *self.host.log):
            self.assertNotIn(CANARY, text)
            self.assertNotIn(OWNER_EMAIL, text)
        # The template file the program read is gone, and the secrets file is closed.
        self.assertEqual(
            sorted(p.name for p in self.host.entry.iterdir()),
            [".lock", "bind-address", f"{SLUG}.json"],
        )
        self.assertEqual(stat.S_IMODE((self.host.etc / f"{SLUG}.env").stat().st_mode), 0o600)

    def test_a_refusal_that_repeats_a_value_is_withheld(self) -> None:
        # Guard: detail_of's hidden values. The program is trusted, and this is the second lock.
        self.host.secrets_returncode = 1
        self.host.secrets_stderr = f"refused: bad value {CANARY}"
        code, out, err = self.secrets()
        self.assertEqual((code, out), (entry.EXIT_FAILED, ""))
        self.assertNotIn(CANARY, err)
        self.assertIn("withheld", err)

    def test_a_message_that_repeats_a_value_past_the_cut_or_escaped_is_withheld(self) -> None:
        # Guard: detail_of checks the whole message, in each escaped form, before it is cut. A
        # value the 1000-character cut would split, or a JSON-escaped one, is still withheld.
        self.host.secrets_returncode = 1
        self.host.secrets_stderr = "x" * 990 + CANARY
        code, out, err = self.secrets()
        self.assertEqual((code, out), (entry.EXIT_FAILED, ""))
        self.assertEqual(err, "failed: secrets\nwithheld: the message held a secret value\n")
        quoted = 'EXAMPLE"quoted_CANARY'
        self.host.secrets_stderr = "refused: value " + json.dumps(quoted)[1:-1]
        code, _out, err = self.secrets(
            {
                "template": TEMPLATE,
                "values": {"GHOST_DB_PASSWORD": quoted, "GHOST_OWNER_EMAIL": OWNER_EMAIL},
            }
        )
        self.assertEqual(code, entry.EXIT_FAILED)
        self.assertNotIn("quoted_CANARY", err)
        self.assertIn("withheld", err)

    def test_a_refusal_that_names_only_keys_is_passed_on(self) -> None:
        self.host.secrets_returncode = 1
        self.host.secrets_stderr = "refused: missing key GHOST_DB_PASSWORD"
        code, _out, err = self.secrets()
        self.assertEqual(code, entry.EXIT_FAILED)
        self.assertIn("missing key GHOST_DB_PASSWORD", err)

    def test_payload_shapes_that_are_refused(self) -> None:
        cases: dict[str, tuple[object, bytes | None, str]] = {
            "not json": (None, b"{nope", "payload-not-json"),
            "a list": (None, b"[]", "payload-not-object"),
            "duplicate key": (
                None,
                b'{"template": "", "template": "", "values": {"A": "b"}}',
                "payload-not-json",
            ),
            "missing values": ({"template": TEMPLATE}, None, "payload-keys"),
            "extra key": (
                {"template": TEMPLATE, "values": VALUES, "etc_dir": "/elsewhere"},
                None,
                "payload-keys",
            ),
            "empty object": ({}, None, "payload-keys"),
            "too large": (None, b" " * (entry.MAX_PAYLOAD + 1), "payload-too-large"),
            "invalid utf-8": (None, b"\xff\xfe", "payload-not-json"),
            "template not text": ({"template": 1, "values": VALUES}, None, "field-template"),
            "template with NUL": ({"template": "A=\x00", "values": VALUES}, None, "field-template"),
            "template too long": (
                {"template": "A" * (entry.MAX_TEMPLATE + 1), "values": VALUES},
                None,
                "field-template",
            ),
            "no values": ({"template": TEMPLATE, "values": {}}, None, "field-values"),
            "values not an object": ({"template": TEMPLATE, "values": []}, None, "field-values"),
            "lower-case key": (
                {"template": TEMPLATE, "values": {"ghost_db": "x"}},
                None,
                "field-values",
            ),
            "key with a path": (
                {"template": TEMPLATE, "values": {"A/../B": "x"}},
                None,
                "field-values",
            ),
            "empty value": ({"template": TEMPLATE, "values": {"A": ""}}, None, "field-values"),
            "value not text": ({"template": TEMPLATE, "values": {"A": 1}}, None, "field-values"),
            "value too long": (
                {"template": TEMPLATE, "values": {"A": "x" * 4097}},
                None,
                "field-values",
            ),
            "too many keys": (
                {"template": TEMPLATE, "values": {f"K{n}": "x" for n in range(33)}},
                None,
                "field-values",
            ),
        }
        for name, (payload, raw, reason) in cases.items():
            with self.subTest(name=name):
                self.assert_refused(self.secrets(payload, raw), reason)
        self.assertFalse(any(c.argv[0] == "/fake/secrets" for c in self.host.calls))
        self.assertFalse((self.host.etc / f"{SLUG}.env").exists())

    def test_a_secrets_file_that_is_not_closed_after_the_program_is_a_failure(self) -> None:
        original = self.host.secrets

        def loose(args: list[str], call: Call, stdin: bytes | None) -> entry.Outcome:
            result = original(args, call, stdin)
            os.chmod(self.host.etc / f"{SLUG}.env", 0o644)
            return result

        self.host.secrets = loose  # type: ignore[method-assign]
        code, _out, err = self.secrets()
        self.assertEqual(code, entry.EXIT_FAILED)
        self.assertIn("secrets-file", err)


class EnableTests(EntryTestCase):
    def test_the_unit_is_enabled_and_never_started(self) -> None:
        # Guard: the enable argument list. A start would fail: the unit has no image pin yet.
        self.host.get_to("secrets")
        code, out, _err = self.host.request(f"enable {SLUG}")
        self.assertEqual((code, out), (entry.EXIT_DONE, "enabled\n"))
        argv = [c.argv for c in self.host.calls if "enable" in c.argv][0]
        self.assertEqual(argv, ["/fake/systemctl", "enable", f"branchleft-compose@{SLUG}.service"])
        for call in self.host.calls:
            for word in ("--now", "start", "restart", "daemon-reload"):
                self.assertNotIn(word, call.argv)

    def test_a_secrets_file_that_is_too_open_stops_the_service_step(self) -> None:
        self.host.get_to("secrets")
        os.chmod(self.host.etc / f"{SLUG}.env", 0o644)
        self.assert_refused(self.host.request(f"enable {SLUG}"), "secrets-first")

    def test_a_secrets_file_that_is_a_link_stops_the_service_step(self) -> None:
        self.host.claim()
        target = self.host.root / "elsewhere"
        target.write_text("EXAMPLE=1\n")
        os.chmod(target, 0o600)
        (self.host.etc / f"{SLUG}.env").symlink_to(target)
        self.assert_refused(self.host.request(f"enable {SLUG}"), "secrets-first")


class KeyTests(EntryTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.host.get_to("enable")

    def key(self, public_key: object) -> tuple[int, str, str]:
        return self.host.request(f"key {SLUG}", {"public_key": public_key})

    def test_the_key_goes_to_the_slot_program_on_stdin_for_this_slug_only(self) -> None:
        code, out, err = self.key(KEY)
        self.assertEqual((code, out, err), (entry.EXIT_DONE, "slot granted\n", ""))
        call = [c for c in self.host.calls if c.argv[0] == "/fake/slot"][0]
        self.assertEqual(call.argv, ["/fake/slot", "--public-key-file", "/dev/stdin", SLUG])
        self.assertEqual(call.stdin, (KEY + "\n").encode())
        self.assertNotIn(KEY, " ".join(call.argv))

    def test_a_stack_directory_of_the_slug_is_adopted_and_no_other_is(self) -> None:
        (self.host.opt / SLUG).mkdir()
        self.assertEqual(self.key(KEY)[0], entry.EXIT_DONE)
        call = [c for c in self.host.calls if c.argv[0] == "/fake/slot"][0]
        self.assertEqual(
            call.argv,
            ["/fake/slot", "--public-key-file", "/dev/stdin", "--adopt-existing-stack", SLUG],
        )

    def test_keys_that_are_not_one_plain_ed25519_key_are_refused(self) -> None:
        body = KEY.split(" ")[1]
        cases = [
            "",
            1,
            None,
            "ssh-rsa " + body,
            "ssh-ed25518 " + body,
            body,
            f'command="/bin/x" {KEY}',
            f"{KEY}\n{make_key(2)}",
            f"{KEY}\n",
            f"{KEY} comment\nssh-ed25519 {body}",
            KEY + " " + "c" * 101,
            "ssh-ed25519 " + body[:40],
            f"{KEY} café",
        ]
        for case in cases:
            with self.subTest(case=repr(case)[:40]):
                self.assert_refused(self.key(case), "field-public_key")
        self.assertFalse(any(c.argv[0] == "/fake/slot" for c in self.host.calls))

    def test_a_slot_that_already_exists_is_not_replaced(self) -> None:
        self.assertEqual(self.key(KEY)[0], entry.EXIT_DONE)
        self.assert_refused(self.key(make_key(2)), "slot-exists")
        self.assertEqual(len([c for c in self.host.calls if c.argv[0] == "/fake/slot"]), 1)

    def test_a_slot_program_refusal_that_repeats_the_key_is_withheld(self) -> None:
        self.host.slot_returncode = 1
        code, _out, err = self.key(KEY)
        self.assertEqual(code, entry.EXIT_FAILED)
        self.assertNotIn(KEY, err)

    def test_the_extra_and_missing_payload_keys_are_refused(self) -> None:
        self.assert_refused(self.host.request(f"key {SLUG}", {}), "payload-keys")
        self.assert_refused(
            self.host.request(f"key {SLUG}", {"public_key": KEY, "stack": OTHER}), "payload-keys"
        )


class OwnerTests(EntryTestCase):
    GOOD: dict[str, object] = {
        "colour": "a",
        "name": "Example Owner",
        "site_url": "https://example.invalid",
        "site_title": "Example Title",
    }

    def setUp(self) -> None:
        super().setUp()
        self.host.get_to("enable")

    def owner(self, **changes: object) -> tuple[int, str, str]:
        return self.host.request(f"owner {SLUG}", {**self.GOOD, **changes})

    def test_the_owner_script_is_run_with_the_secrets_file_and_no_address_in_argv(self) -> None:
        code, out, err = self.owner()
        self.assertEqual((code, err), (entry.EXIT_DONE, ""))
        self.assertEqual(out, '{"created":true}\n')
        docker = [c for c in self.host.calls if c.argv[0] == "/fake/docker"][0]
        self.assertIn(f"label=com.docker.compose.project={SLUG}", docker.argv)
        self.assertIn("label=com.docker.compose.service=ghost-a", docker.argv)
        node = [c for c in self.host.calls if c.argv[0] == "/fake/node"][0]
        self.assertEqual(
            node.argv,
            [
                "/fake/node",
                "/fake/owner.mjs",
                "--container",
                CONTAINER_ID,
                "--secrets-file",
                str(self.host.etc / f"{SLUG}.env"),
                "--name",
                "Example Owner",
                "--site-url",
                "https://example.invalid",
                "--site-title",
                "Example Title",
            ],
        )
        self.assertNotIn(OWNER_EMAIL, " ".join(node.argv))

    def test_payload_values_that_are_refused(self) -> None:
        cases: dict[str, dict[str, object]] = {
            "colour c": {"colour": "c"},
            "colour list": {"colour": ["a"]},
            "http url": {"site_url": "http://example.invalid"},
            "url with a path": {"site_url": "https://example.invalid/ghost"},
            "url with userinfo": {"site_url": "https://user@example.invalid"},
            "url with a query": {"site_url": "https://example.invalid?x=1"},
            "url in capitals": {"site_url": "https://EXAMPLE.invalid"},
            "name with a line break": {"name": "A\nB"},
            "empty name": {"name": ""},
            "name too long": {"name": "n" * 65},
            "title too long": {"site_title": "t" * 121},
            "title not text": {"site_title": 1},
            "name starting with a dash": {"name": "-x"},
            "name that is an option": {"name": "--help"},
            "title starting with a dash": {"site_title": "-o"},
            "title that is a long option": {"site_title": "--container=x"},
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                code, _out, err = self.owner(**change)
                self.assertEqual(code, entry.EXIT_REFUSED, err)
        self.assertFalse(any(c.argv[0] in ("/fake/docker", "/fake/node") for c in self.host.calls))

    def test_no_running_container_or_two_of_them_is_refused(self) -> None:
        for found in ("", CONTAINER_ID + "\n" + "b" * 64, "not-an-id"):
            with self.subTest(found=found[:12]):
                self.host.containers = found
                self.assert_refused(self.owner(), "container-not-running")
        self.assertFalse(any(c.argv[0] == "/fake/node" for c in self.host.calls))

    def test_a_failed_owner_script_is_reported(self) -> None:
        self.host.owner_returncode = 1
        code, _out, err = self.owner()
        self.assertEqual(code, entry.EXIT_FAILED)
        self.assertIn("failed: owner\n", err)


class StackTests(EntryTestCase):
    """The compose file is built here and written once, after the judge, for a claimed slug only."""

    def setUp(self) -> None:
        super().setUp()
        self.host.get_to("secrets")
        self.compose = self.host.opt / SLUG / "compose.yml"
        self.pin = self.host.etc / f"{SLUG}.image.env"

    def document(self, path: Path | None = None) -> object:
        loaded: object = json.loads((path or self.compose).read_text())
        return loaded

    def assert_nothing_written(self) -> None:
        self.assertFalse((self.host.opt / SLUG).exists())
        self.assertFalse(self.pin.exists() or self.pin.is_symlink())
        self.assertEqual([p for p in self.host.etc.iterdir() if p.name.startswith(".stack")], [])

    def use_judge(self, judge: Path) -> None:
        self.host.paths = dataclasses.replace(self.host.paths, judge_module=str(judge))

    def fake_judge(self, *, raises: str = "", refusal: str = "", claim_state: str = "same") -> Path:
        """A stand-in judge file, the test user's and closed, with a canned answer."""
        path = self.host.root / f"judge-{len(list(self.host.root.glob('judge-*')))}.py"
        error = raises or "Unused"
        path.write_text(
            "from dataclasses import dataclass\n"
            f"class {error}(Exception):\n    pass\n"
            "@dataclass(frozen=True)\n"
            "class Verdict:\n"
            "    refusals: tuple[str, ...]\n"
            "    claim_state: str\n"
            "    image_env: str\n"
            "def params_from_mapping(values):\n    return values\n"
            "def judge(params):\n"
            f"    if {bool(raises)!r}:\n        raise {error}()\n"
            f"    return Verdict(({refusal!r},) if {bool(refusal)!r} else (), {claim_state!r},"
            " params['image_env_text'])\n",
            encoding="utf-8",
        )
        os.chmod(path, 0o644)
        return path

    def test_a_stack_is_built_from_the_claim_and_written_with_the_modes_tenant_compose_uses(
        self,
    ) -> None:
        code, out, err = self.host.stack()
        self.assertEqual((code, out, err), (entry.EXIT_DONE, "compose.yml written\n", ""))
        self.assertEqual(stat.S_IMODE(self.compose.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.compose.parent.stat().st_mode), 0o755)
        # No temporary file is left behind, and no image pin is written by this verb.
        self.assertEqual([p.name for p in self.compose.parent.iterdir()], ["compose.yml"])
        self.assertEqual([p.name for p in self.host.etc.iterdir() if p.name.startswith(".")], [])
        self.assertFalse(self.pin.exists())
        document = self.document()
        self.assertEqual(jget(document, "name"), SLUG)
        a = ("services", "ghost-a")
        # The claim's uid and ports, and the host's own address: nothing from the request.
        self.assertEqual(jget(document, *a, "user"), "30000:30000")
        self.assertEqual(jget(document, *a, "ports"), [f"{BIND}:40000:2368"])
        self.assertEqual(jget(document, "services", "ghost-b", "ports"), [f"{BIND}:40001:2368"])
        self.assertEqual(jget(document, *a, "image"), "${IMAGE}")
        self.assertEqual(jget(document, *a, "networks"), ["default", "branchleft-mail-30000"])
        self.assertEqual(
            jget(document, *a, "environment", "database__connection__password"),
            "${GHOST_DB_PASSWORD:?set GHOST_DB_PASSWORD in the env file}",
        )
        self.assertEqual(jget(document, *a, "environment", "url"), "https://blog.example.invalid")
        self.assertEqual(jget(document, *a, "environment", "mail__options__port"), "587")
        self.assertEqual(jget(document, *a, "environment", "privacy__useGravatar"), "false")
        self.assertEqual(jget(document, *a, "cpus"), "1.0")
        volumes = jmap(document, "volumes")
        self.assertEqual(
            sorted(volumes),
            [f"ghost-{SLUG}-{name}" for name in ("adapters", "content", "metrics")],
        )
        self.assertNotIn(CANARY, self.compose.read_text())

    def test_the_second_tenant_gets_its_own_claim_and_the_stack_follows_it(self) -> None:
        self.host.get_to("secrets", OTHER)
        result = self.host.stack(OTHER, **stack_parameters(size="small", mail=False))
        self.assertEqual(result[0], entry.EXIT_DONE)
        document = self.document(self.host.opt / OTHER / "compose.yml")
        self.assertEqual(jget(document, "services", "ghost-a", "user"), "30001:30001")
        self.assertEqual(jget(document, "services", "ghost-a", "ports"), [f"{BIND}:40004:2368"])
        self.assertEqual(jget(document, "services", "ghost-b", "ports"), [f"{BIND}:40005:2368"])
        self.assertEqual(jget(document, "services", "ghost-a", "cpus"), "0.5")
        self.assertNotIn("networks", jmap(document, "services", "ghost-a"))
        self.assertIn("port_a=40004\n", self.host.request(f"status {OTHER}")[1])

    def test_hostile_values_that_pass_the_schema_cannot_change_the_stacks_shape(self) -> None:
        # Guard: build_stack encodes every value; it adds no key from a parameter.
        hostile = {
            "mount": "/:/host:rw",
            "root": "0:0",
            "quote": 'a", "user": "0:0", "volumes": ["/:/host',
            "braces": "}}, 'privileged': true, {",
            "yaml": "x\\n  privileged: true",
            "colon": "key: value # comment",
            "image": "ghcr.io/example/evil@sha256:" + "c" * 64,
        }
        code, _out, err = self.host.stack(**stack_parameters(environment=hostile))
        self.assertEqual(code, entry.EXIT_DONE, err)
        document = self.document()
        self.assertEqual(sorted(jmap(document)), ["name", "networks", "services", "volumes"])
        for name in ("ghost-a", "ghost-b"):
            service = jmap(document, "services", name)
            self.assertEqual(set(service), FIXED_SERVICE_KEYS)
            self.assertEqual(service["user"], "30000:30000")
            self.assertEqual(service["image"], "${IMAGE}")
            self.assertEqual(service["environment"], dict(sorted(hostile.items())))
            self.assertEqual(
                service["volumes"],
                [
                    f"ghost-{SLUG}-content:/var/lib/ghost/content",
                    f"ghost-{SLUG}-adapters:/var/lib/ghost/content/adapters:ro",
                    f"ghost-{SLUG}-metrics:/var/lib/ghost/metrics",
                ],
            )
            self.assertEqual(service["security_opt"], ["no-new-privileges:true"])
            self.assertEqual(service["cap_drop"], ["ALL"])

    def test_a_parameter_that_tries_to_inject_a_mount_a_user_or_a_key_is_refused_by_name(
        self,
    ) -> None:
        # Guard: read_stack_parameters. Each case is one way to reach beyond the schema.
        base = stack_parameters()
        extra: dict[str, dict[str, object]] = {
            "a mount": {"volumes": ["/:/host:rw"]},
            "a user": {"user": "0:0"},
            "an entrypoint": {"entrypoint": ["/bin/sh"]},
            "a port": {"ports": ["0.0.0.0:22:22"]},
            "a uid": {"uid": 0},
            "a slug": {"slug": OTHER},
            "a bind address": {"bind": "0.0.0.0"},  # noqa: S104  # a key the request must not carry.
            "a service key": {"privileged": True},
            "host pid": {"pid": "host"},
            "another document": {"services": {"x": {}}},
        }
        for case, more in extra.items():
            with self.subTest(case=case):
                self.assert_refused(self.host.stack(**{**base, **more}), "payload-keys")
                self.assert_nothing_written()
        for case, missing in {"size": "size", "mail": "mail", "environment": "environment"}.items():
            with self.subTest(missing=case):
                self.assert_refused(
                    self.host.stack(**{k: v for k, v in base.items() if k != missing}),
                    "payload-keys",
                )
        self.assert_nothing_written()

    def test_parameters_outside_the_schema_are_refused_by_the_field_name(self) -> None:
        secret = {"secret": "GHOST_DB_PASSWORD"}
        cases: list[tuple[str, dict[str, object]]] = [
            ("field-size", {"size": "huge"}),
            ("field-size", {"size": 1}),
            ("field-size", {"size": None}),
            ("field-mail", {"mail": "yes"}),
            ("field-mail", {"mail": 1}),
            ("field-environment", {"environment": {}}),
            ("field-environment", {"environment": []}),
            ("field-environment", {"environment": {f"k{n}": "v" for n in range(65)}}),
            ("field-environment", {"environment": {"user: 0": "v"}}),
            ("field-environment", {"environment": {"a b": "v"}}),
            ("field-environment", {"environment": {"a-b": "v"}}),
            ("field-environment", {"environment": {"1a": "v"}}),
            ("field-environment", {"environment": {"": "v"}}),
            ("field-environment", {"environment": {"a\nvolumes": "v"}}),
            ("field-environment", {"environment": {"k": "${IMAGE}"}}),
            ("field-environment", {"environment": {"k": "$$"}}),
            ("field-environment", {"environment": {"k": "a\nb"}}),
            ("field-environment", {"environment": {"k": "a\x00b"}}),
            ("field-environment", {"environment": {"k": "é"}}),
            ("field-environment", {"environment": {"k": "x" * 501}}),
            ("field-environment", {"environment": {"k": None}}),
            ("field-environment", {"environment": {"k": 1.5}}),
            ("field-environment", {"environment": {"k": -1}}),
            ("field-environment", {"environment": {"k": 2**40}}),
            ("field-environment", {"environment": {"k": ["a"]}}),
            ("field-environment", {"environment": {"k": {"volumes": ["/:/host"]}}}),
            ("field-environment", {"environment": {"k": {}}}),
            ("field-environment", {"environment": {"k": {**secret, "extra": 1}}}),
            ("field-environment", {"environment": {"k": {"secret": "ghost_db"}}}),
            ("field-environment", {"environment": {"k": {"secret": "OTHER_KEY"}}}),
            ("field-environment", {"environment": {"k": {"secret": "GHOST_" + "A" * 57}}}),
            ("field-environment", {"environment": {"k": {"secret": 1}}}),
            ("field-environment", {"environment": {"k": {"secret": "GHOST_X:-/etc/shadow"}}}),
        ]
        for reason, change in cases:
            with self.subTest(reason=reason, change=str(change)[:60]):
                params = {**stack_parameters(), **change}
                code, out, err = self.host.stack(**params)
                self.assertEqual((code, out, err), (entry.EXIT_REFUSED, "", f"refused: {reason}\n"))
                self.assert_nothing_written()

    def test_a_stack_call_that_carries_a_pin_is_refused_by_name_and_no_pin_is_ever_written(
        self,
    ) -> None:
        # Guard: PIN_KEYS. The first pin is branchleft-deploy's, after its attestation check.
        for key in ("image_env_text", "image_env", "image", "pin"):
            with self.subTest(key=key):
                self.assert_refused(
                    self.host.stack(**{**stack_parameters(), key: PIN}), "pin-not-accepted"
                )
                self.assert_nothing_written()
        # The renderer's old payload, a compose text with its first pin, is refused for the pin.
        self.assert_refused(
            self.host.stack(compose_text="name: x\n", image_env_text=PIN), "pin-not-accepted"
        )
        self.assert_nothing_written()
        # A successful stack, and the enable after it, leave no pin: the unit cannot start.
        self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
        self.assertEqual(self.host.request(f"enable {SLUG}")[0], entry.EXIT_DONE)
        self.assertFalse(self.pin.exists() or self.pin.is_symlink())
        self.assertEqual(
            sorted(p.name for p in self.host.etc.iterdir() if "image" in p.name), [], "a pin"
        )

    def test_a_request_that_carries_a_compose_text_is_refused_by_name(self) -> None:
        # Guard: COMPOSE_KEYS. The stack is the host's own; a caller never sends one.
        for key in ("compose_text", "compose"):
            with self.subTest(key=key):
                self.assert_refused(
                    self.host.stack(**{**stack_parameters(), key: tenant_compose_text()}),
                    "compose-not-accepted",
                )
                self.assert_nothing_written()

    def test_the_stack_is_never_enabled_or_started_by_the_verb(self) -> None:
        self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
        self.assertEqual(self.host.enabled, set())
        self.assertFalse(any(c.argv[0] == "/fake/systemctl" for c in self.host.calls))

    def test_status_reports_the_stack_step_from_the_compose_file_alone(self) -> None:
        self.assertIn("stack=no\n", self.host.request(f"status {SLUG}")[1])
        self.host.stack()
        self.assertIn("stack=yes\n", self.host.request(f"status {SLUG}")[1])
        self.compose.chmod(0o666)
        self.assertIn("stack=no\n", self.host.request(f"status {SLUG}")[1])
        self.compose.chmod(0o644)
        self.compose.unlink()
        self.assertIn("stack=no\n", self.host.request(f"status {SLUG}")[1])

    def test_a_stack_the_judge_refuses_is_refused_by_name_and_nothing_is_written(self) -> None:
        # Guard: the judge's verdict, on the text built here. A secret the stack needs and the
        # secrets file lacks, and a uid another slug already holds, are both the judge's.
        broken = {
            "a secret nobody supplies": (
                {"environment": {"x": {"secret": "GHOST_NOT_IN_THE_SECRETS_FILE"}}},
                "secrets file has no key GHOST_NOT_IN_THE_SECRETS_FILE",
            ),
        }
        for case, (change, sentence) in broken.items():
            with self.subTest(case=case):
                code, out, err = self.host.stack(**{**stack_parameters(), **change})
                self.assertEqual((code, out), (entry.EXIT_REFUSED, ""))
                self.assertTrue(err.startswith("refused: judge-refused\n"), err)
                self.assertIn(sentence, err)
                self.assertNotIn(CANARY, err)
                self.assertNotIn(OWNER_EMAIL, err)
                self.assert_nothing_written()
        self.host.claims["example-hand"] = 30000
        code, _out, err = self.host.stack()
        self.assertEqual(code, entry.EXIT_REFUSED, err)
        self.assertTrue(err.startswith("refused: judge-refused\n"), err)
        self.assertIn("uid 30000 is already claimed by example-hand", err)
        self.assert_nothing_written()
        self.assertEqual(
            self.host.log[-1], f"verb=stack slug={SLUG} result=refused reason=judge-refused"
        )

    def test_a_judge_refusal_stops_the_write_whatever_the_text(self) -> None:
        # Guard: `if verdict.refusals`. The stand-in judge refuses a stack the real one passes.
        self.use_judge(self.fake_judge(refusal="EXAMPLE rule"))
        code, out, err = self.host.stack()
        self.assertEqual((code, out), (entry.EXIT_REFUSED, ""))
        self.assertEqual(err, "refused: judge-refused\nEXAMPLE rule\n")
        self.assert_nothing_written()

    def test_the_judge_is_given_the_built_text_the_claims_and_the_secrets_file(self) -> None:
        seen: dict[str, object] = {}
        real = entry.load_judge

        def spy(host: entry.Host) -> entry.Judge:
            judge = real(host)

            def params(values: Mapping[str, object]) -> object:
                seen.update(values)
                return judge.params_from_mapping(values)

            return entry.Judge(params, judge.judge)

        with mock.patch.object(entry, "load_judge", spy):
            self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
        self.assertEqual(seen["slug"], SLUG)
        self.assertEqual(seen["profile"], "tenant")
        self.assertEqual(seen["uid"], 30000)
        self.assertEqual(seen["compose_text"], self.compose.read_text())
        self.assertEqual(seen["claims_text"], f"{SLUG}=30000\n")
        self.assertIn(CANARY, str(seen["secrets_env_text"]))
        self.assertEqual(seen["image_env_text"], entry.JUDGE_PLACEHOLDER_PIN)

    def test_a_slug_never_claimed_here_is_refused_before_the_payload_is_read(self) -> None:
        # Guard: the marker. A tenant set up by hand has a claim and a secrets file, and no marker.
        self.host.hand_made_tenant()
        before = self.host.files()
        calls = len(self.host.calls)
        self.assert_refused(self.host.stack(OTHER), "not-claimed-here")
        self.assert_refused(self.host.stack("example-nobody"), "not-claimed-here")
        self.assertEqual(self.host.files(), before)
        self.assertEqual(len(self.host.calls), calls)

    def test_a_claimed_slug_without_its_secrets_file_is_refused(self) -> None:
        # Guard: require_secrets. The marker exists, the secrets step is not done.
        self.host.claim(OTHER)
        self.assert_refused(self.host.stack(OTHER), "secrets-first")
        self.assertFalse((self.host.opt / OTHER).exists())
        os.chmod(self.host.etc / f"{SLUG}.env", 0o644)
        self.assert_refused(self.host.stack(), "secrets-first")
        self.assert_nothing_written()

    def test_a_claim_gone_from_the_volume_program_is_refused(self) -> None:
        del self.host.claims[SLUG]
        self.assert_refused(self.host.stack(), "claim-missing")
        self.assert_nothing_written()

    def test_the_same_parameters_again_succeed_and_change_nothing(self) -> None:
        # Retries: a request whose reply was lost is sent again and finds its file.
        self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
        first = self.compose.stat()
        before = self.host.files()
        code, out, err = self.host.stack()
        self.assertEqual((code, out, err), (entry.EXIT_DONE, "compose.yml already in place\n", ""))
        self.assertEqual(self.host.files(), before)
        self.assertEqual(self.compose.stat().st_ino, first.st_ino)
        self.assertEqual(self.compose.stat().st_mtime_ns, first.st_mtime_ns)

    def test_different_parameters_over_an_existing_file_are_stack_exists(self) -> None:
        # Guard: compose_matches and the no-replace link. Whatever differs, nothing is replaced.
        self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
        held = self.compose.read_text()
        before = self.host.files()
        different: dict[str, dict[str, object]] = {
            "size": {"size": "large"},
            "mail": {"mail": False},
            "environment": {"environment": {"url": "https://other.example.invalid"}},
        }
        for case, change in different.items():
            with self.subTest(case=case):
                self.assert_refused(
                    self.host.stack(**{**stack_parameters(), **change}), "stack-exists"
                )
                self.assertEqual(self.compose.read_text(), held)
                self.assertEqual(self.host.files(), before)

    def test_an_existing_file_that_this_verb_did_not_write_is_never_overwritten(self) -> None:
        # Guard: the existence check and the no-replace link. Each starting state is refused.
        for state in ("foreign", "empty", "same-but-open", "same-but-link", "dangling-link"):
            with self.subTest(state=state):
                self.setUp()
                self.compose.parent.mkdir()
                if state == "foreign":
                    self.compose.write_text("HELD COMPOSE\n")
                elif state == "empty":
                    self.compose.write_text("")
                elif state == "same-but-open":
                    self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
                    self.compose.chmod(0o666)
                elif state == "same-but-link":
                    self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
                    held = self.compose.read_text()
                    self.compose.unlink()
                    (self.host.root / "copy").write_text(held)
                    self.compose.symlink_to(self.host.root / "copy")
                else:
                    self.compose.symlink_to(self.host.root / "nowhere")
                before = self.host.files()
                held_text = self.compose.read_text() if self.compose.is_file() else ""
                self.assert_refused(self.host.stack(), "stack-exists")
                self.assertEqual(self.host.files(), before)
                if self.compose.is_file():
                    self.assertEqual(self.compose.read_text(), held_text)
                self.assertEqual([p for p in self.compose.parent.iterdir() if p.name[0] == "."], [])

    def test_an_existing_empty_stack_directory_is_used(self) -> None:
        (self.host.opt / SLUG).mkdir()
        self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
        self.assertTrue(self.compose.is_file())

    def test_a_file_that_appears_after_the_check_is_not_replaced(self) -> None:
        # Guard: place_file. The file shows up between the check and the link.
        real_link = os.link

        def link(src: str, dst: str) -> None:
            Path(dst).write_text("RACED\n")
            real_link(src, dst)

        with mock.patch("os.link", side_effect=link):
            self.assert_refused(self.host.stack(), "stack-exists")
        self.assertEqual(self.compose.read_text(), "RACED\n")
        self.assertEqual([p.name for p in self.compose.parent.iterdir()], ["compose.yml"])

    def test_a_directory_that_appears_after_the_check_is_refused_by_name(self) -> None:
        real_mkdir = os.mkdir

        def mkdir(path: str, mode: int = 0o777) -> None:
            real_mkdir(path, mode)
            raise FileExistsError

        with mock.patch("os.mkdir", side_effect=mkdir):
            self.assert_refused(self.host.stack(), "stack-exists")
        self.assertFalse(self.compose.exists())

    def test_a_write_that_fails_leaves_no_temporary_file_and_no_stack(self) -> None:
        with mock.patch("os.fsync", side_effect=OSError("EXAMPLE disk full")):
            code, out, err = self.host.stack()
        self.assertEqual((code, out, err), (entry.EXIT_FAILED, "", "failed: write\n"))
        self.assertFalse(self.compose.exists())
        self.assertEqual([p.name for p in self.compose.parent.iterdir()], [])

    def test_nothing_is_written_outside_the_slot(self) -> None:
        # Guard: check_slot_targets. The slug's stack directory is a link or not a directory.
        elsewhere = self.host.root / "elsewhere"
        elsewhere.mkdir()
        (self.host.opt / SLUG).symlink_to(elsewhere)
        self.assert_refused(self.host.stack(), "path-outside-slot")
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assertFalse(self.pin.exists())
        (self.host.opt / SLUG).unlink()
        (self.host.opt / SLUG).write_text("a file, not a directory")
        self.assert_refused(self.host.stack(), "path-outside-slot")
        self.assertFalse(self.pin.exists())

    def test_a_stack_root_that_is_missing_or_open_to_writes_is_refused(self) -> None:
        # Guard: check_slot_targets. A root another user can write is not a place to write.
        self.host.opt.chmod(0o777)
        self.assert_refused(self.host.stack(), "path-outside-slot")
        self.host.opt.chmod(0o775)
        self.assert_refused(self.host.stack(), "path-outside-slot")
        self.host.opt.chmod(0o755)
        self.host.opt.rmdir()
        self.assert_refused(self.host.stack(), "path-outside-slot")
        self.assertFalse(self.pin.exists())

    def test_the_hosts_address_must_be_one_private_address_in_a_closed_file(self) -> None:
        address = self.host.entry / entry.BIND_ADDRESS_FILE
        for text in (
            "8.8.8.8\n",
            "127.0.0.1\n",
            "0.0.0.0\n",
            "10.0.0.1 x\n",
            "",
            "10.20.2\n",
            "10.20.2.300\n",
            "172.32.0.1\n",
            "192.169.0.1\n",
            "::1\n",
        ):
            with self.subTest(text=text):
                address.write_text(text)
                code, out, err = self.host.stack()
                self.assertEqual(
                    (code, out, err), (entry.EXIT_FAILED, "", "failed: bind-address\n")
                )
                self.assert_nothing_written()
        address.write_text(BIND + "\n")
        address.chmod(0o644)
        self.assertEqual(self.host.stack()[2], "failed: bind-address\n")
        address.chmod(0o600)
        address.unlink()
        self.assertEqual(self.host.stack()[2], "failed: bind-address\n")
        self.assert_nothing_written()

    def test_the_line_the_role_writes_is_a_line_the_program_reads(self) -> None:
        # The role's own `content:` line, as YAML reads it and with the variable filled, is the
        # file's text. A single-quoted scalar keeps a backslash and an n where a newline belongs,
        # and the program refuses that file: so this feeds the real line to the real reader.
        tasks: list[dict[str, object]] = YAML(typ="safe").load(
            (ROLE / "tasks" / "_program.yml").read_text(encoding="utf-8")
        )
        writers = [
            task
            for task in tasks
            if isinstance(task.get("ansible.builtin.copy"), dict)
            and "tenant_entry_bind_address_file" in str(task["ansible.builtin.copy"])
        ]
        self.assertEqual(len(writers), 1)
        copy = writers[0]["ansible.builtin.copy"]
        self.assertIsInstance(copy, dict)
        content = str(copy["content"]) if isinstance(copy, dict) else ""
        self.assertEqual(content.count("{{ tenant_entry_bind_address }}"), 1)
        text = content.replace("{{ tenant_entry_bind_address }}", BIND)
        self.assertEqual(text, BIND + "\n")
        (self.host.entry / entry.BIND_ADDRESS_FILE).write_text(text, encoding="ascii")
        self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
        self.assertIn(f'"{BIND}:40000:2368"', self.compose.read_text())

    def test_a_private_address_in_each_private_range_is_accepted(self) -> None:
        address = self.host.entry / entry.BIND_ADDRESS_FILE
        for text in ("10.0.0.1", "172.16.5.9", "172.31.255.255", "192.168.1.1"):
            with self.subTest(text=text):
                self.setUp()
                (self.host.entry / entry.BIND_ADDRESS_FILE).write_text(text + "\n")
                self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
                self.assertIn(f'"{text}:40000:2368"', self.compose.read_text())
        self.assertTrue(address.exists())

    def test_the_payload_shapes_that_are_not_a_json_object_within_the_cap_are_refused(self) -> None:
        cases: list[tuple[object, bytes | None, str]] = [
            ([1, 2], None, "payload-not-object"),
            ("text", None, "payload-not-object"),
            (None, b"{nope", "payload-not-json"),
            (None, b"", "payload-not-json"),
            (None, b'{"size": "standard", "size": "large"}', "payload-not-json"),
            (None, b"[" * 60000, "payload-not-json"),
            (None, b" " * (entry.MAX_PAYLOAD + 1), "payload-too-large"),
        ]
        for payload, raw, reason in cases:
            with self.subTest(reason=reason, raw=(raw or b"")[:8]):
                self.assert_refused(self.host.request(f"stack {SLUG}", payload, raw), reason)
                self.assert_nothing_written()

    def test_a_judge_that_is_missing_or_not_roots_stops_the_request(self) -> None:
        # Guard: load_judge. The judge is code that runs as root.
        judge = self.host.root / "judge.py"
        judge.write_text(JUDGE.read_text())
        self.use_judge(judge)
        for mode in (0o666, 0o664, 0o646):
            judge.chmod(mode)
            self.assert_refused(self.host.stack(), "judge-unsafe")
        judge.unlink()
        judge.symlink_to(JUDGE)
        self.assert_refused(self.host.stack(), "judge-unsafe")
        judge.unlink()
        code, out, err = self.host.stack()
        self.assertEqual((code, out, err), (entry.EXIT_FAILED, "", "failed: judge-missing\n"))
        judge.write_text("raise RuntimeError('EXAMPLE')\n")
        judge.chmod(0o644)
        code, out, err = self.host.stack()
        self.assertEqual((code, out, err), (entry.EXIT_FAILED, "", "failed: judge-missing\n"))
        self.assert_nothing_written()

    def test_a_judge_that_cannot_read_yaml_fails_by_name(self) -> None:
        self.use_judge(self.fake_judge(raises="YamlMissingError"))
        code, out, err = self.host.stack()
        self.assertEqual((code, out, err), (entry.EXIT_FAILED, "", "failed: judge-yaml-missing\n"))
        self.use_judge(self.fake_judge(raises="RuntimeError"))
        code, out, err = self.host.stack()
        self.assertEqual((code, out, err), (entry.EXIT_FAILED, "", "failed: judge\n"))
        self.assert_nothing_written()

    def test_a_judge_message_that_repeats_a_secret_is_withheld(self) -> None:
        # Guard: the hidden values. The judge promises no value, and this is the second lock.
        self.use_judge(self.fake_judge(refusal=f"EXAMPLE rule about {CANARY}"))
        code, _out, err = self.host.stack()
        self.assertEqual(code, entry.EXIT_REFUSED)
        self.assertEqual(err, "refused: judge-refused\nwithheld: the message held a secret value\n")
        self.assertNotIn(CANARY, "".join(self.host.log))
        self.assert_nothing_written()

    def test_a_claim_the_judge_does_not_call_the_same_is_refused(self) -> None:
        self.use_judge(self.fake_judge(claim_state="unclaimed"))
        self.assert_refused(self.host.stack(), "claim-mismatch")
        self.assert_nothing_written()

    def test_the_secrets_values_reach_nothing_the_verb_prints_or_logs(self) -> None:
        code, out, err = self.host.stack()
        self.assertEqual(code, entry.EXIT_DONE, err)
        for text in (out, err, *self.host.log):
            self.assertNotIn(CANARY, text)
            self.assertNotIn(OWNER_EMAIL, text)
        for call in self.host.calls:
            self.assertNotIn(CANARY, " ".join(call.argv))


class StatusTests(EntryTestCase):
    def test_status_says_only_that_for_a_slug_this_entry_point_never_claimed(self) -> None:
        self.host.hand_made_tenant()
        code, out, _err = self.host.request(f"status {OTHER}")
        self.assertEqual((code, out), (entry.EXIT_DONE, "claimed-here=no\n"))

    def test_status_follows_a_slug_through_the_steps(self) -> None:
        self.host.claim()
        self.assertEqual(
            self.host.request(f"status {SLUG}")[1],
            "claimed-here=yes\nuid=30000\nport_a=40000\nport_b=40001\nport_health=40002\n"
            "volumes=yes\nsecrets=no\nstack=no\nenabled=no\nslot=no\n",
        )
        self.host.get_to("key")
        self.assertEqual(
            self.host.request(f"status {SLUG}")[1],
            "claimed-here=yes\nuid=30000\nport_a=40000\nport_b=40001\nport_health=40002\n"
            "volumes=yes\nsecrets=yes\nstack=no\nenabled=yes\nslot=yes\n",
        )


class RegisterTests(EntryTestCase):
    def test_a_register_directory_that_is_not_closed_stops_every_verb(self) -> None:
        for mode in (0o755, 0o770, 0o500):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.host.entry, mode)
                for verb in ("status", "claim", "secrets", "enable", "key", "owner"):
                    self.assert_refused(self.host.request(f"{verb} {SLUG}"), "register-unsafe")
        os.chmod(self.host.entry, 0o700)
        self.assertEqual(self.host.calls, [])

    def test_a_register_directory_that_is_a_link_or_absent_is_refused(self) -> None:
        elsewhere = self.host.root / "elsewhere"
        elsewhere.mkdir()
        os.chmod(elsewhere, 0o700)
        shutil.rmtree(self.host.entry)
        self.assert_refused(self.host.request(f"status {SLUG}"), "register-unsafe")
        self.host.entry.symlink_to(elsewhere)
        self.assert_refused(self.host.request(f"status {SLUG}"), "register-unsafe")

    def test_a_marker_that_is_loose_a_link_or_unreadable_stops_the_request(self) -> None:
        self.host.claim()
        marker = self.host.entry / f"{SLUG}.json"
        os.chmod(marker, 0o644)
        self.assert_refused(self.host.request(f"enable {SLUG}"), "register-unsafe")
        os.chmod(marker, 0o600)
        marker.write_text("not json")
        self.assert_refused(self.host.request(f"enable {SLUG}"), "register-unsafe")
        marker.write_text('{"uid": "x", "port": 1}')
        self.assert_refused(self.host.request(f"enable {SLUG}"), "register-unsafe")
        marker.write_text("[]")
        self.assert_refused(self.host.request(f"enable {SLUG}"), "register-unsafe")
        marker.unlink()
        target = self.host.root / "target"
        target.write_text('{"uid": 30000, "port": 40000}')
        os.chmod(target, 0o600)
        marker.symlink_to(target)
        self.assert_refused(self.host.request(f"enable {SLUG}"), "register-unsafe")

    def test_an_unreadable_marker_of_another_slug_stops_a_claim(self) -> None:
        (self.host.entry / f"{OTHER}.json").write_text("{}")
        os.chmod(self.host.entry / f"{OTHER}.json", 0o644)
        self.assert_refused(self.host.request(f"claim {SLUG}"), "register-unsafe")

    def test_a_request_while_another_runs_is_busy_and_changes_nothing(self) -> None:
        fd = os.open(self.host.entry / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        code, out, err = self.host.request(f"claim {SLUG}")
        self.assertEqual((code, out, err), (entry.EXIT_BUSY, "", "busy\n"))
        self.assertEqual(self.host.calls, [])


class LogTests(EntryTestCase):
    def test_every_request_leaves_one_log_line_with_no_payload(self) -> None:
        self.host.claim()
        self.host.request(f"secrets {SLUG}", {"template": TEMPLATE, "values": VALUES})
        self.host.request("bash -c id")
        self.host.request(f"enable {OTHER}")
        self.assertEqual(
            self.host.log[0:1] + self.host.log[-2:],
            [
                f"verb=claim slug={SLUG} result=done",
                "verb=- slug=- result=refused reason=request-shape",
                f"verb=enable slug={OTHER} result=refused reason=not-claimed-here",
            ],
        )
        for line in self.host.log:
            self.assertNotIn(CANARY, line)


class RealRunnerTests(unittest.TestCase):
    """The real runner, against small programs on disk: a clean environment, stdin, no shell."""

    def test_the_child_gets_the_given_stdin_and_a_clean_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "child.py"
            script.write_text(
                f"#!{sys.executable}\n"
                "import os, sys\n"
                "print(sorted(os.environ))\n"
                "print(sys.stdin.read())\n"
                "sys.exit(3)\n",
                encoding="utf-8",
            )
            os.chmod(script, 0o700)
            os.environ["SSH_ORIGINAL_COMMAND"] = "EXAMPLE"
            self.addCleanup(os.environ.pop, "SSH_ORIGINAL_COMMAND", None)
            outcome = entry.run_command([str(script)], b"EXAMPLE_STDIN")
            self.assertEqual(outcome.returncode, 3)
            self.assertEqual(outcome.stdout.splitlines()[1], "EXAMPLE_STDIN")
            self.assertNotIn("SSH_ORIGINAL_COMMAND", outcome.stdout.splitlines()[0])
            self.assertIn("PATH", outcome.stdout.splitlines()[0])
            empty = entry.run_command([str(script)], None)
            self.assertEqual(empty.stdout.splitlines()[1], "")

    def test_a_missing_program_fails_closed_by_name(self) -> None:
        with self.assertRaises(entry.FailedError) as caught:
            entry.run_command(["/nonexistent/example"], None)
        self.assertEqual(caught.exception.step, "program-missing")


class RoleContractTests(unittest.TestCase):
    """The program's constants are held equal to the role's variables and to the other roles'."""

    @staticmethod
    def variables(role: str) -> dict[str, object]:
        loaded: dict[str, object] = YAML(typ="safe").load(
            (ROLES / role / "vars" / "main.yml").read_text(encoding="utf-8")
        )
        return loaded

    def test_the_serve_flag_is_the_one_the_role_grants_and_forces(self) -> None:
        own = self.variables("tenant_entry")
        self.assertEqual(own["tenant_entry_serve_flag"], entry.SERVE_FLAG)
        self.assertEqual(own["tenant_entry_program"], "/usr/local/sbin/branchleft-tenant-entry")

    def test_the_default_paths_are_the_ones_other_roles_install_at(self) -> None:
        paths = entry.Paths()
        own = self.variables("tenant_entry")
        self.assertEqual(paths.secrets_program, own["tenant_entry_secrets_program"])
        self.assertEqual(paths.entry_dir, own["tenant_entry_register_dir"])
        onboarding = self.variables("tenant_onboarding")
        program_dir = onboarding["tenant_onboarding_program_dir"]
        self.assertEqual(os.path.dirname(paths.secrets_program), program_dir)
        self.assertEqual(os.path.dirname(paths.volume_program), program_dir)
        self.assertEqual(
            onboarding["tenant_onboarding_program"],
            "{{ tenant_onboarding_program_dir }}/provision_tenant_volume.py",
        )
        self.assertEqual(os.path.basename(paths.volume_program), "provision_tenant_volume.py")
        slots = self.variables("deploy_slot_keys")
        self.assertEqual(paths.slot_program, slots["deploy_slot_keys_program_path"])

    def test_the_judge_is_a_byte_identical_copy_of_the_one_tenant_compose_runs(self) -> None:
        # ANS-12: no role imports another, so the copy is held to its original here.
        original = ROLES / "tenant_compose" / "library" / "tenant_compose_check.py"
        self.assertEqual(JUDGE.read_bytes(), original.read_bytes())

    def test_the_judge_path_and_the_python_are_the_ones_the_role_installs(self) -> None:
        own = self.variables("tenant_entry")
        self.assertEqual(
            own["tenant_entry_judge"], "{{ tenant_entry_judge_dir }}/tenant_compose_check.py"
        )
        self.assertEqual(
            os.path.join(str(own["tenant_entry_judge_dir"]), "tenant_compose_check.py"),
            entry.Paths().judge_module,
        )
        program = (ROLE / "files" / "branchleft_tenant_entry.py").read_text(encoding="utf-8")
        self.assertEqual(program.splitlines()[0], f"#!{own['tenant_entry_python']} -I")

    def test_the_owner_script_and_node_are_where_the_role_installs_them(self) -> None:
        own = self.variables("tenant_entry")
        paths = entry.Paths()
        self.assertEqual(own["tenant_entry_owner_program"], paths.owner_program)
        self.assertEqual(
            os.path.dirname(paths.owner_program),
            self.variables("tenant_onboarding")["tenant_onboarding_program_dir"],
        )
        self.assertEqual(own["tenant_entry_node"], "{{ tenant_entry_node_dir }}/bin/node")
        self.assertEqual(own["tenant_entry_node_dir"], "{{ tenant_entry_judge_dir }}/node")
        self.assertEqual(
            os.path.join(str(own["tenant_entry_judge_dir"]), "node", "bin", "node"), paths.node
        )

    def test_the_owner_script_is_pinned_to_a_commit_and_a_digest(self) -> None:
        own = self.variables("tenant_entry")
        self.assertRegex(str(own["tenant_entry_owner_ghost_commit"]), r"\A[0-9a-f]{40}\Z")
        self.assertRegex(str(own["tenant_entry_owner_program_sha256"]), r"\A[0-9a-f]{64}\Z")
        url = str(own["tenant_entry_owner_program_url"])
        self.assertTrue(
            url.startswith(
                "https://raw.githubusercontent.com/branchLeft/ghost-platform/"
                "{{ tenant_entry_owner_ghost_commit }}/"
            )
        )
        self.assertTrue(url.endswith("/adapters/sso/scripts/provision-owner.mjs"))
        self.assertEqual(
            os.path.basename(str(own["tenant_entry_owner_program"])),
            "provision-owner.mjs",
        )

    def test_node_is_the_pin_broker_deploy_holds(self) -> None:
        # ANS-12: no role imports another, so the version and both digests are copies, and
        # held to the original here. Every digest is a published sha256 and the fetch is https.
        own = self.variables("tenant_entry")
        broker: dict[str, object] = YAML(typ="safe").load(
            (ROLES / "broker_deploy" / "defaults" / "main.yml").read_text(encoding="utf-8")
        )
        self.assertEqual(own["tenant_entry_node_version"], broker["broker_deploy_node_version"])
        self.assertEqual(own["tenant_entry_node_checksums"], broker["broker_deploy_node_checksums"])
        self.assertEqual(own["tenant_entry_node_base_url"], broker["broker_deploy_node_base_url"])
        self.assertTrue(str(own["tenant_entry_node_base_url"]).startswith("https://"))
        checksums = own["tenant_entry_node_checksums"]
        self.assertIsInstance(checksums, dict)
        if not isinstance(checksums, dict):
            self.fail("tenant_entry_node_checksums is not a mapping")
        for arch, digest in checksums.items():
            self.assertRegex(str(digest), r"\Asha256:[0-9a-f]{64}\Z", arch)
        machines = own["tenant_entry_node_arch_by_machine"]
        self.assertIsInstance(machines, dict)
        if not isinstance(machines, dict):
            self.fail("tenant_entry_node_arch_by_machine is not a mapping")
        self.assertEqual(set(machines.values()), set(checksums))

    def test_the_sudoers_grant_and_the_forced_command_name_the_entry_program_only(self) -> None:
        # Installing node and the owner script must not give the account anything beyond the one
        # program: neither path appears in a sudoers line or in the key options.
        own = self.variables("tenant_entry")
        lines = [str(line) for line in own["tenant_entry_sudoers_lines"]]  # type: ignore[attr-defined]
        self.assertEqual(len(lines), 2)
        grants = [line for line in lines if "NOPASSWD" in line]
        self.assertEqual(
            grants,
            [
                "{{ tenant_entry_user }} ALL=(root) NOPASSWD: "
                "{{ tenant_entry_program }} {{ tenant_entry_serve_flag }}"
            ],
        )
        for needle in ("node", "provision-owner", "docker", "platform-provision"):
            for line in [*lines, str(own["tenant_entry_key_options"])]:
                self.assertNotIn(needle, line)

    def test_the_stack_paths_and_modes_are_the_ones_tenant_compose_writes(self) -> None:
        compose = self.variables("tenant_compose")
        paths = entry.Paths()
        self.assertEqual(paths.opt_dir, compose["tenant_compose_stack_root"])
        self.assertEqual(paths.etc_dir, compose["tenant_compose_config_root"])
        tasks = (ROLES / "tenant_compose" / "tasks" / "_stack.yml").read_text(encoding="utf-8")
        for text in ("dest: '{{ tenant_compose_project_dir }}/compose.yml'", "mode: '0644'"):
            self.assertIn(text, tasks)
        self.assertEqual((entry.COMPOSE_MODE, entry.STACK_DIR_MODE), (0o644, 0o755))

    def test_the_first_pin_is_never_this_programs_to_write(self) -> None:
        # The pin is branchleft-deploy's, written after it verifies the attestation. The stack
        # step does not name the pin file, and the program writes no IMAGE= line of its own.
        source = inspect.getsource(entry)
        for name in ("step_stack", "build_stack", "stage_file", "place_file"):
            for needle in ("image_env_path", ".image.env"):
                self.assertNotIn(needle, inspect.getsource(getattr(entry, name)), name)
        self.assertEqual(source.count("IMAGE="), 1)  # the judge's placeholder, never written.
        self.assertFalse(hasattr(entry, "IMAGE_ENV_MODE"))
        self.assertFalse(hasattr(entry, "TENANT_IMAGE_PATTERN"))

    def test_a_unit_with_no_pin_does_not_start(self) -> None:
        # The compose unit asserts the pin file exists, so a stack with a compose file and no pin
        # (what `stack` leaves, and what `enable` enables) stays inactive until branchleft-deploy
        # has verified an image and written one. No leading dash: the pin is mandatory.
        unit = ROLES.parent.parent / "hetzner" / "provision" / "branchleft-compose@.service"
        lines = unit.read_text(encoding="utf-8").splitlines()
        self.assertIn("AssertPathExists=/etc/branchleft/%i.image.env", lines)
        self.assertIn("EnvironmentFile=/etc/branchleft/%i.image.env", lines)
        self.assertFalse(any(line.startswith("AssertPathExists=-") for line in lines))
        self.assertFalse(any(line.rstrip() == "AssertPathExists=" for line in lines))

    def test_the_bind_address_file_and_pattern_are_the_ones_the_role_writes(self) -> None:
        own = self.variables("tenant_entry")
        self.assertEqual(
            os.path.join(str(own["tenant_entry_register_dir"]), entry.BIND_ADDRESS_FILE),
            "/etc/branchleft/tenant-entry/bind-address",
        )
        self.assertEqual(
            own["tenant_entry_bind_address_file"],
            "{{ tenant_entry_register_dir }}/bind-address",
        )
        octet = str(own["tenant_entry_octet"])
        role_pattern = re.compile(
            str(own["tenant_entry_private_address_pattern"]).replace(
                "{{ tenant_entry_octet }}", octet
            )
        )
        samples = [
            "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.0.1", "192.168.0.1",
            "172.15.0.1", "172.32.0.1", "192.169.0.1", "11.0.0.1", "127.0.0.1", "0.0.0.0",  # noqa: S104
            "8.8.8.8", "10.0.0", "10.0.0.256", "10.0.0.1.1", "", "::1", "10.0.0.1\n",
        ]  # fmt: skip
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(
                    role_pattern.match(sample) is not None,
                    entry.BIND_ADDRESS_PATTERN.match(sample) is not None
                    and not sample.endswith("\n"),
                )

    def test_the_port_and_uid_ranges_are_inside_what_the_stack_allows(self) -> None:
        self.assertGreaterEqual(entry.PORT_BASE, 1024)
        self.assertLessEqual(entry.PORT_BASE + entry.PORT_BLOCKS * entry.PORT_BLOCK_SIZE, 65536)
        self.assertEqual((entry.UID_MIN, entry.UID_MAX), (30000, 30999))

    def test_the_program_never_names_a_start_or_a_shell(self) -> None:
        source = (ROLE / "files" / "branchleft_tenant_entry.py").read_text(encoding="utf-8")
        for needle in ("shell=True", "os.system", "--now", '"start"', "eval(", "exec("):
            self.assertNotIn(needle, source)


if __name__ == "__main__":
    unittest.main()
