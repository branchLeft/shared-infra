"""Unit tests for the app host's tenant entry point.

The host is a temporary directory and every downstream program is a fake that records its
arguments, so a refusal is proved by what did not run and what was not written. The cases a
controller key must never get through are each named for the guard they hold: break the guard
and the case beside it fails. Placeholders only; no value here is a real name, key or secret.
"""

import base64
import dataclasses
import fcntl
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from collections.abc import Sequence
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

    def stack(
        self, slug: str = SLUG, compose_text: str | None = None, image_env_text: str = PIN
    ) -> tuple[int, str, str]:
        """Ask for the compose file and the first image pin of a slug, as the controller does."""
        text = compose_text if compose_text is not None else tenant_compose_text(slug)
        return self.request(
            f"stack {slug}", {"compose_text": text, "image_env_text": image_env_text}
        )

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

    def test_a_timeout_with_an_unreadable_listing_still_frees_the_slug(self) -> None:
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
        self.assertEqual(list(self.host.entry.iterdir()), [self.host.entry / ".lock"])

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
        self.assertEqual(list(self.host.entry.iterdir()), [self.host.entry / ".lock"])

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
            sorted(p.name for p in self.host.entry.iterdir()), [".lock", f"{SLUG}.json"]
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
    """The compose file and first pin are written once, after the judge, for a claimed slug only."""

    def setUp(self) -> None:
        super().setUp()
        self.host.get_to("secrets")
        self.compose = self.host.opt / SLUG / "compose.yml"
        self.pin = self.host.etc / f"{SLUG}.image.env"

    def assert_nothing_written(self) -> None:
        self.assertFalse((self.host.opt / SLUG).exists())
        self.assertFalse(self.pin.exists() or self.pin.is_symlink())

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

    def test_a_stack_the_judge_passes_is_written_with_the_modes_tenant_compose_uses(self) -> None:
        text = tenant_compose_text()
        code, out, err = self.host.stack(compose_text=text)
        self.assertEqual(
            (code, out, err), (entry.EXIT_DONE, "compose.yml and image.env written\n", "")
        )
        self.assertEqual(self.compose.read_text(), text)
        self.assertEqual(self.pin.read_text(), PIN)
        self.assertEqual(stat.S_IMODE(self.compose.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.pin.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.compose.parent.stat().st_mode), 0o755)
        # No temporary file is left behind in either directory.
        self.assertEqual([p.name for p in self.compose.parent.iterdir()], ["compose.yml"])
        self.assertEqual([p.name for p in self.host.etc.iterdir() if p.name.startswith(".")], [])

    def test_the_stack_is_never_enabled_or_started_by_the_verb(self) -> None:
        self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
        self.assertEqual(self.host.enabled, set())
        self.assertFalse(any(c.argv[0] == "/fake/systemctl" for c in self.host.calls))

    def test_status_reports_the_stack_step(self) -> None:
        self.assertIn("stack=no\n", self.host.request(f"status {SLUG}")[1])
        self.host.stack()
        self.assertIn("stack=yes\n", self.host.request(f"status {SLUG}")[1])
        self.pin.unlink()
        self.assertIn("stack=no\n", self.host.request(f"status {SLUG}")[1])

    def test_a_stack_the_judge_refuses_is_refused_by_name_and_nothing_is_written(self) -> None:
        # Guard: the judge's verdict. Each case breaks one rule the judge owns.
        broken = {
            "privileged": tenant_compose_text(privileged=True),
            "the docker socket": tenant_compose_text(volumes=["/var/run/docker.sock:/s"]),
            "another image": tenant_compose_text(image="example.invalid/app@" + IMAGE_DIGEST),
            "a wildcard port": tenant_compose_text(ports=["40000:2368"]),
            "a secret nobody supplies": tenant_compose_text(
                environment={"x": "${GHOST_NOT_IN_THE_SECRETS_FILE:?set it}"}
            ),
            "another tenant's verdict volume": tenant_compose_text(
                volumes=[f"ghost-{OTHER}-verdict:/verdict"]
            ),
            "not yaml": "name: [unclosed",
        }
        for case, text in broken.items():
            with self.subTest(case=case):
                code, out, err = self.host.stack(compose_text=text)
                self.assertEqual((code, out), (entry.EXIT_REFUSED, ""))
                self.assertTrue(err.startswith("refused: judge-refused\n"), err)
                self.assertIn(f"{SLUG}: ", err)
                self.assertNotIn(CANARY, err)
                self.assertNotIn(OWNER_EMAIL, err)
                self.assert_nothing_written()
        self.assertEqual(
            self.host.log[-1], f"verb=stack slug={SLUG} result=refused reason=judge-refused"
        )

    def test_the_judge_is_given_the_tenants_own_uid_claims_and_secrets_file(self) -> None:
        # The same inputs tenant_compose gives it: another slug holding this uid is refused.
        self.host.claims["example-hand"] = 30000
        code, _out, err = self.host.stack()
        self.assertEqual(code, entry.EXIT_REFUSED, err)
        self.assertTrue(err.startswith("refused: judge-refused\n"), err)
        self.assertIn("uid 30000 is already claimed by example-hand", err)
        self.assert_nothing_written()
        # A secret the compose file needs and the secrets file lacks is refused by its name.
        self.host.claims.pop("example-hand")
        code, _out, err = self.host.stack(
            compose_text=tenant_compose_text(environment={"x": "${GHOST_MISSING:?set it}"})
        )
        self.assertIn("secrets file has no key GHOST_MISSING", err)

    def test_an_image_pin_that_is_not_the_tenant_image_is_refused(self) -> None:
        # Guard: TENANT_IMAGE_PATTERN. The judge accepts any digest-pinned name.
        for pin in (
            f"IMAGE=example.invalid/app@{IMAGE_DIGEST}\n",
            f"IMAGE=ghcr.io/branchleft/ghost-tenant-evil@{IMAGE_DIGEST}\n",
            f"IMAGE=ghcr.io/branchleft/other@{IMAGE_DIGEST}\n",
        ):
            with self.subTest(pin=pin):
                self.assert_refused(self.host.stack(image_env_text=pin), "image-not-tenant")
                self.assert_nothing_written()
        # A pin the judge itself refuses is the judge's refusal.
        code, _out, err = self.host.stack(
            image_env_text="IMAGE=ghcr.io/branchleft/ghost-tenant:1\n"
        )
        self.assertEqual(code, entry.EXIT_REFUSED)
        self.assertTrue(err.startswith("refused: judge-refused\n"), err)

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

    def test_an_existing_file_is_never_overwritten(self) -> None:
        # Guard: the existence check and the no-replace link. Each starting state is refused.
        for state in ("compose", "pin", "both", "dangling-link", "again"):
            with self.subTest(state=state):
                self.setUp()
                held = {"compose": "HELD COMPOSE\n", "pin": "HELD PIN\n"}
                if state in ("compose", "both"):
                    self.compose.parent.mkdir()
                    self.compose.write_text(held["compose"])
                if state in ("pin", "both"):
                    self.pin.write_text(held["pin"])
                if state == "dangling-link":
                    self.compose.parent.mkdir()
                    self.compose.symlink_to(self.host.root / "nowhere")
                if state == "again":
                    self.assertEqual(self.host.stack()[0], entry.EXIT_DONE)
                    held = {"compose": self.compose.read_text(), "pin": self.pin.read_text()}
                before = self.host.files()
                self.assert_refused(self.host.stack(), "stack-exists")
                self.assertEqual(self.host.files(), before)
                if self.compose.is_file():
                    self.assertEqual(self.compose.read_text(), held["compose"])
                if self.pin.exists():
                    self.assertEqual(self.pin.read_text(), held["pin"])
                self.assertFalse(self.compose.is_symlink() and self.compose.exists())

    def test_a_file_that_appears_after_the_check_is_not_replaced_and_the_first_is_taken_back(
        self,
    ) -> None:
        # Guard: place_files. The pin shows up between the check and the second link.
        real_link = os.link

        def link(src: str, dst: str) -> None:
            if dst.endswith(".image.env"):
                self.pin.write_text("RACED\n")
            real_link(src, dst)

        with mock.patch("os.link", side_effect=link):
            self.assert_refused(self.host.stack(), "stack-exists")
        self.assertEqual(self.pin.read_text(), "RACED\n")
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

    def test_a_stack_root_that_is_not_a_directory_is_refused(self) -> None:
        # Guard: check_slot_targets. A root that is not a directory is not a place to write.
        self.host.opt.rmdir()
        self.assert_refused(self.host.stack(), "path-outside-slot")
        self.assertFalse(self.pin.exists())

    def test_the_payload_is_exactly_two_strings_within_the_cap(self) -> None:
        text = tenant_compose_text()
        cases: list[tuple[object, bytes | None, str]] = [
            ({"compose_text": text}, None, "payload-keys"),
            (
                {"compose_text": text, "image_env_text": PIN, "path": "/etc/passwd"},
                None,
                "payload-keys",
            ),
            ({"compose_text": text, "image_env_text": PIN, "slug": OTHER}, None, "payload-keys"),
            ({"compose_text": 1, "image_env_text": PIN}, None, "field-compose_text"),
            ({"compose_text": "", "image_env_text": PIN}, None, "field-compose_text"),
            ({"compose_text": "a\u0000b", "image_env_text": PIN}, None, "field-compose_text"),
            ({"compose_text": text, "image_env_text": None}, None, "field-image_env_text"),
            ({"compose_text": text, "image_env_text": ""}, None, "field-image_env_text"),
            ([text, PIN], None, "payload-not-object"),
            (None, b"{nope", "payload-not-json"),
            (
                None,
                b'{"compose_text": "a", "compose_text": "b", "image_env_text": "c"}',
                "payload-not-json",
            ),
            (None, b" " * (entry.MAX_PAYLOAD + 1), "payload-too-large"),
        ]
        for payload, raw, reason in cases:
            with self.subTest(reason=reason):
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
            "claimed-here=yes\nvolumes=yes\nsecrets=no\nstack=no\nenabled=no\nslot=no\n",
        )
        self.host.get_to("key")
        self.assertEqual(
            self.host.request(f"status {SLUG}")[1],
            "claimed-here=yes\nvolumes=yes\nsecrets=yes\nstack=no\nenabled=yes\nslot=yes\n",
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
        os.rmdir(self.host.entry)
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

    def test_the_stack_paths_and_modes_are_the_ones_tenant_compose_writes(self) -> None:
        compose = self.variables("tenant_compose")
        paths = entry.Paths()
        self.assertEqual(paths.opt_dir, compose["tenant_compose_stack_root"])
        self.assertEqual(paths.etc_dir, compose["tenant_compose_config_root"])
        self.assertEqual(
            entry.TENANT_IMAGE_PATTERN.pattern, compose["tenant_compose_tenant_image_pattern"]
        )
        tasks = (ROLES / "tenant_compose" / "tasks" / "_stack.yml").read_text(encoding="utf-8")
        for text in (
            "dest: '{{ tenant_compose_project_dir }}/compose.yml'",
            "mode: '0644'",
            "'{{ tenant_compose_config_root }}/{{ tenant_compose_stack.slug }}.image.env'",
            "mode: '0600'",
        ):
            self.assertIn(text, tasks)
        self.assertEqual(
            (entry.COMPOSE_MODE, entry.IMAGE_ENV_MODE, entry.STACK_DIR_MODE),
            (0o644, 0o600, 0o755),
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
