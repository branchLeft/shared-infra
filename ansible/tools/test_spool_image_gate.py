"""Tests for the gate that stops the demo1 bootstrap while the mail spool's image is not there.

The fixtures in fixtures/ are real output of `docker image inspect` (Docker 29, containerd image
store) for an image loaded from a file by its digest-form reference, and for an absent one. The
bad states are each refused with their own reason code, and the same states are run against a
stand-in that passes everything to show each would go red without the gate. The pattern and the
service are held to the demo1_egress_spool role, and the vendored Compose file must yield a ref.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import spool_image_gate as tool
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "demo1_egress_spool"
COMPOSE = ROLE / "files" / "ghost-platform" / "render-core" / "test" / "golden"
COMPOSE_FILE = COMPOSE / "mail-spool-compose.demo1.yml"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
TOOL = Path(tool.__file__).resolve()

LOADED = (FIXTURES / "docker-inspect-loaded-by-digest.json").read_text(encoding="utf-8")
ABSENT = (FIXTURES / "docker-inspect-absent.json").read_text(encoding="utf-8")
DIGEST = "sha256:72484c5512c27bc92e3ef3f63c7a882a1336c525d956cb82aa6c0f7fdb3e39b8"
REF = f"gatefixture/probe@{DIGEST}"
OTHER_DIGEST = "sha256:" + "a" * 64
SENTINEL = "SENTINELTEXTNOTTOBEPRINTED"

Judge = Callable[[str, str], str]


def with_digests(digests: list[str] | None) -> str:
    """The captured output with its RepoDigests replaced, or the key removed for None."""
    images = json.loads(LOADED)
    if digests is None:
        del images[0]["RepoDigests"]
    else:
        images[0]["RepoDigests"] = digests
    return json.dumps(images)


def with_null_digests() -> str:
    images = json.loads(LOADED)
    images[0]["RepoDigests"] = None
    return json.dumps(images)


def two_images() -> str:
    one = json.loads(LOADED)
    return json.dumps(one + copy.deepcopy(one))


def pass_everything(ref: str, stdin_text: str) -> str:
    """A stand-in for the gate with the mechanism removed."""
    return ""


# Each bad state: the ref asked for, what docker printed, and the reason the gate must give.
BAD: dict[str, tuple[str, str, str]] = {
    "ref with a tag only": ("gatefixture/probe:one", LOADED, "ref_not_digest_pinned"),
    "ref with a short digest": (
        f"gatefixture/probe@{DIGEST[:20]}",
        LOADED,
        "ref_not_digest_pinned",
    ),
    "ref with an upper-case name": (f"GateFixture/probe@{DIGEST}", LOADED, "ref_not_digest_pinned"),
    "image absent, the captured output": (REF, ABSENT, "image_absent"),
    "no output at all": (REF, "", "no_output"),
    "only a line break": (REF, "\n", "no_output"),
    "an image with another digest": (
        REF,
        with_digests([f"gatefixture/probe@{OTHER_DIGEST}"]),
        "digest_mismatch",
    ),
    "two images": (REF, two_images(), "several_images"),
    "text that is not json": (REF, "Error response from daemon: No such image", "unreadable"),
    "a json object, not a list": (REF, "{}", "unreadable"),
    "a list of strings": (REF, '["sha256:x"]', "unreadable"),
    "no RepoDigests key": (REF, with_digests(None), "no_repo_digest"),
    "an empty RepoDigests list": (REF, with_digests([]), "no_repo_digest"),
    "a null RepoDigests": (REF, with_null_digests(), "no_repo_digest"),
    "RepoDigests holding a number": (REF, with_digests([1]), "unreadable"),  # type: ignore[list-item]
}


PIN = f"IMAGE={REF}\n"
OTHER_REF = f"gatefixture/probe@{OTHER_DIGEST}"
# Each bad pin file: its text and the reason the gate must give.
BAD_PIN: dict[str, tuple[str, str]] = {
    "the older MAIL_SPOOL_IMAGE form": (f"MAIL_SPOOL_IMAGE={REF}\n", "pin_old_form"),
    "the older form with no line break": (f"MAIL_SPOOL_IMAGE={REF}", "pin_old_form"),
    "an empty file": ("", "pin_malformed"),
    "only a line break": ("\n", "pin_malformed"),
    "a bare ref": (f"{REF}\n", "pin_malformed"),
    "a tag only": ("IMAGE=gatefixture/probe:one\n", "pin_malformed"),
    "a short digest": (f"IMAGE=gatefixture/probe@{DIGEST[:20]}\n", "pin_malformed"),
    "two lines": (f"{PIN}{PIN}", "pin_malformed"),
    "a comment line after": (f"{PIN}# note\n", "pin_malformed"),
    "a comment line before": (f"# note\n{PIN}", "pin_malformed"),
    "a blank line after": (f"{PIN}\n", "pin_malformed"),
    "carriage return": (f"IMAGE={REF}\r\n", "pin_malformed"),
    "a trailing space": (f"IMAGE={REF} \n", "pin_malformed"),
    "a leading space": (f" IMAGE={REF}\n", "pin_malformed"),
    "a lower-case key": (f"image={REF}\n", "pin_malformed"),
    "an export prefix": (f"export IMAGE={REF}\n", "pin_malformed"),
    "quotes round the ref": (f'IMAGE="{REF}"\n', "pin_malformed"),
    "an upper-case name": (f"IMAGE=GateFixture/probe@{DIGEST}\n", "pin_malformed"),
}


def accept_any_pin(text: str) -> tuple[str, str]:
    """A stand-in for the pin check with the mechanism removed."""
    return text.removeprefix("IMAGE=").strip(), ""


class SpoolImageGate(unittest.TestCase):
    def assert_states_stop(self, judge: Judge) -> None:
        for name, (ref, text, reason) in BAD.items():
            with self.subTest(name):
                self.assertEqual(judge(ref, text), reason)

    def test_gate_stops_on_each_bad_state(self) -> None:
        self.assert_states_stop(tool.judge)
        self.assertEqual(tool.judge(REF, LOADED), "", "the captured output of the pinned image")
        other_name = with_digests([f"registry.example/other@{DIGEST}"])
        self.assertEqual(tool.judge(REF, other_name), "", "the same digest under another name")
        many = with_digests([f"x@{OTHER_DIGEST}", f"y@{DIGEST}"])
        self.assertEqual(tool.judge(REF, many), "", "the pinned digest among several")

    def test_corpus_has_teeth(self) -> None:
        for name, (ref, text, reason) in BAD.items():
            with self.subTest(name):
                self.assertEqual(pass_everything(ref, text), "")
                with self.assertRaises(AssertionError):
                    self.assertEqual(pass_everything(ref, text), reason)

    def test_pin_file_is_one_image_line_and_nothing_else(self) -> None:
        self.assertEqual(tool.pin_ref(PIN), (REF, ""))
        self.assertEqual(tool.pin_ref(PIN.rstrip("\n")), (REF, ""), "no final line break")
        for name, (text, reason) in BAD_PIN.items():
            with self.subTest(name):
                self.assertEqual(tool.pin_ref(text), ("", reason))

    def test_pin_corpus_has_teeth(self) -> None:
        for name, (text, reason) in BAD_PIN.items():
            with self.subTest(name):
                self.assertEqual(accept_any_pin(text)[1], "")
                with self.assertRaises(AssertionError):
                    self.assertEqual(accept_any_pin(text)[1], reason)

    def test_a_pin_digest_that_is_not_the_loaded_image_stops(self) -> None:
        pinned, reason = tool.pin_ref(f"IMAGE={OTHER_REF}\n")
        self.assertEqual((pinned, reason), (OTHER_REF, ""))
        self.assertEqual(tool.judge(pinned, LOADED), "digest_mismatch")
        self.assertEqual(tool.judge(tool.pin_ref(PIN)[0], LOADED), "")

    def test_the_vendored_compose_file_yields_a_ref_the_gate_accepts(self) -> None:
        text = COMPOSE_FILE.read_text(encoding="utf-8")
        ref, reason = tool.compose_ref(text)
        self.assertEqual(reason, "")
        document = yaml.safe_load(text)
        self.assertEqual(ref, document["services"][tool.SERVICE]["image"])
        digest = ref.rsplit("@", 1)[1]
        matching = json.dumps([{"RepoDigests": [ref], "Id": "sha256:x"}])
        self.assertEqual(tool.judge(ref, matching), "")
        stale = json.dumps([{"RepoDigests": [ref.replace(digest, OTHER_DIGEST)]}])
        self.assertEqual(tool.judge(ref, stale), "digest_mismatch")

    def test_compose_refs_that_are_not_pinned_are_refused(self) -> None:
        pinned = f"services:\n  mail-spool:\n    image: '{REF}'\n"
        corpus = {
            "a tag only": (pinned.replace(f"@{DIGEST}", ":latest"), "ref_not_digest_pinned"),
            "no image line": ("services:\n  mail-spool:\n    restart: always\n", "no_image"),
            "no services": ("name: mail-spool\n", "no_image"),
            "another service's image": (
                f"services:\n  other:\n    image: '{REF}'\n  mail-spool:\n    restart: no\n",
                "no_image",
            ),
            "two images": (pinned + f"    image: '{REF}'\n", "several_images"),
        }
        self.assertEqual(tool.compose_ref(pinned), (REF, ""))
        self.assertEqual(tool.compose_ref(pinned.replace("'", '"')), (REF, ""))
        self.assertEqual(tool.compose_ref(pinned.replace(f"'{REF}'", REF)), (REF, ""))
        for name, (text, reason) in corpus.items():
            with self.subTest(name):
                self.assertEqual(tool.compose_ref(text), ("", reason))

    def test_constants_equal_the_role(self) -> None:
        text = (ROLE / "vars" / "main.yml").read_text(encoding="utf-8")
        role = yaml.safe_load(text)
        self.assertEqual("^" + tool.IMAGE_PATTERN.pattern, role["demo1_egress_spool_image_pattern"])
        self.assertEqual(tool.SERVICE, role["demo1_egress_spool_service"])
        self.assertEqual(
            "^" + tool.PIN_PATTERN.pattern, role["demo1_egress_spool_image_env_pattern"]
        )
        self.assertEqual(
            role["demo1_egress_spool_image_env_path"], "/etc/branchleft/mail-spool.image.env"
        )
        self.assertTrue(
            COMPOSE_FILE.as_posix().endswith(role["demo1_egress_spool_compose_src"]),
            "the gate reads the file the role installs",
        )


class CommandLine(unittest.TestCase):
    """The invocations the runbook prints: the venv's python in isolated mode, then the tool."""

    def run_tool(self, *args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - this repository's own tool or ssh-keygen, run with fixed arguments
            [sys.executable, "-I", str(TOOL), *args],
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_the_runbook_invocations(self) -> None:
        got = self.run_tool("ref", "--compose", str(COMPOSE_FILE), "--no-pin")
        self.assertEqual((got.returncode, got.stderr), (0, ""))
        ref = got.stdout.rstrip("\n")
        self.assertRegex(ref, tool.IMAGE_PATTERN.pattern)
        digest = ref.rsplit("@", 1)[1]
        listing = json.dumps([{"RepoDigests": [ref]}])
        passed = self.run_tool("check", "--ref", ref, stdin=listing)
        self.assertEqual((passed.returncode, passed.stdout, passed.stderr), (0, "gate=pass\n", ""))
        stopped = self.run_tool("check", "--ref", ref, stdin=ABSENT)
        self.assertEqual(
            (stopped.returncode, stopped.stdout), (1, "gate=STOP reason=image_absent\n")
        )
        other = self.run_tool("check", "--ref", ref, stdin=listing.replace(digest, OTHER_DIGEST))
        self.assertEqual(
            (other.returncode, other.stdout), (1, "gate=STOP reason=digest_mismatch\n")
        )
        empty = self.run_tool("check", "--ref", ref)
        self.assertEqual((empty.returncode, empty.stdout), (1, "gate=STOP reason=no_output\n"))

    def test_the_pin_file_decides_the_ref_and_the_compose_file_only_where_there_is_none(
        self,
    ) -> None:
        golden = self.run_tool("ref", "--compose", str(COMPOSE_FILE), "--no-pin").stdout
        wanted = tool.compose_ref(COMPOSE_FILE.read_text(encoding="utf-8"))[0]
        self.assertEqual(golden, f"{wanted}\n", "no pin file: the vendored Compose digest")
        with tempfile.TemporaryDirectory() as folder:
            pin = Path(folder) / "mail-spool.image.env"
            absent = Path(folder) / "absent.env"
            compose = ["ref", "--compose", str(COMPOSE_FILE)]
            pin.write_text(PIN, "utf-8")
            matching = self.run_tool(*compose, "--pin-file", str(pin))
            self.assertEqual(
                (matching.returncode, matching.stdout, matching.stderr), (0, f"{REF}\n", "")
            )
            self.assertNotEqual(matching.stdout, golden, "the pin file wins over the Compose file")
            passed = self.run_tool("check", "--ref", REF, stdin=LOADED)
            self.assertEqual((passed.returncode, passed.stdout), (0, "gate=pass\n"))
            pin.write_text(f"IMAGE={OTHER_REF}\n", "utf-8")
            mismatched = self.run_tool(*compose, "--pin-file", str(pin))
            self.assertEqual(mismatched.stdout, f"{OTHER_REF}\n")
            stopped = self.run_tool("check", "--ref", OTHER_REF, stdin=LOADED)
            self.assertEqual(
                (stopped.returncode, stopped.stdout), (1, "gate=STOP reason=digest_mismatch\n")
            )
            for name, (text, reason) in BAD_PIN.items():
                with self.subTest(name):
                    pin.write_text(text, "utf-8", newline="")
                    done = self.run_tool(*compose, "--pin-file", str(pin))
                    self.assertEqual(
                        (done.returncode, done.stdout, done.stderr),
                        (1, "", f"ref=REFUSED reason={reason}\n"),
                    )
            unreadable = self.run_tool(*compose, "--pin-file", str(absent))
            self.assertEqual(unreadable.stderr, "ref=REFUSED reason=pin_unreadable\n")
            for extra in ([], ["--pin-file", str(pin), "--no-pin"]):
                with self.subTest(extra):
                    stray = self.run_tool(*compose, *extra)
                    self.assertEqual(stray.returncode, 2, "one of the two must be named")

    def test_a_ref_command_refuses_without_printing_a_ref(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            compose = Path(folder) / "compose.yml"
            compose.write_text("services:\n  mail-spool:\n    image: 'x:latest'\n", "utf-8")
            done = self.run_tool("ref", "--compose", str(compose), "--no-pin")
            self.assertEqual(
                (done.returncode, done.stdout, done.stderr),
                (1, "", "ref=REFUSED reason=ref_not_digest_pinned\n"),
            )
            missing = self.run_tool(
                "ref", "--compose", str(Path(folder) / "absent.yml"), "--no-pin"
            )
            self.assertEqual(missing.stderr, "ref=REFUSED reason=compose_unreadable\n")

    def test_the_gate_prints_nothing_of_what_it_was_given(self) -> None:
        planted = json.dumps([{"RepoDigests": [], "Env": [f"TOKEN={SENTINEL}"]}, SENTINEL])
        for text in (planted, f"Error {SENTINEL}", f'[{{"Id": "{SENTINEL}"}}, {{}}]'):
            with self.subTest(text[:12]):
                out, err = io.StringIO(), io.StringIO()
                stdin = io.TextIOWrapper(io.BytesIO(text.encode()))
                with (
                    contextlib.redirect_stdout(out),
                    contextlib.redirect_stderr(err),
                    mock.patch.object(sys, "stdin", stdin),
                ):
                    code = tool.main(["check", "--ref", REF])
                self.assertEqual(code, 1)
                self.assertRegex(out.getvalue(), r"^gate=STOP reason=[a-z_]+\n$")
                self.assertNotIn(SENTINEL, out.getvalue() + err.getvalue())


if __name__ == "__main__":
    unittest.main()
