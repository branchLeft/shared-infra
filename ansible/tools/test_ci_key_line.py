"""Tests for the builder and verifier of a CI account's two forced-command key lines.

The verifier is the guard: it must refuse each deviation from the two lines the builder makes,
including a key that is the stop-gap shared key of another host. The corpus of deviations is run
against a stand-in that accepts everything to show each case would go red without the guard.
Also here: the exact invocations the runbook prints, a leak test that plants a private key block
and an address, and the constants held to the ci_login and pull_trigger roles they are copied from.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import ci_key_line as tool
import yaml  # type: ignore[import-untyped]
from test_pubkey_only import PRIVATE_BLOCK, PRIVATE_SENTINEL, ed25519_line, rsa_line

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
TOOL = Path(tool.__file__).resolve()
SOURCE = "203.0.113.7"
OTHER_SOURCE = "203.0.113.8"
SENTINEL_ADDRESS = "198.51.100.77"
CHECK_PUB = ed25519_line(11, "demo1-check")
APPLY_PUB = ed25519_line(12, "demo1-apply")
SHARED_PUB = ed25519_line(13, "edge1-shared")


def body_of(line: str) -> str:
    return line.split(" ")[1]


def bare(line: str) -> str:
    """A public key line without its comment, which is what the builder writes."""
    return " ".join(line.split(" ")[:2])


def good_lines(source: str = SOURCE) -> tuple[str, str]:
    return (
        f"{tool.options_for('check', source)} {bare(CHECK_PUB)}",
        f"{tool.options_for('apply', source)} {bare(APPLY_PUB)}",
    )


@dataclass(frozen=True)
class Case:
    readback: str
    reason: str
    check_pub: str = CHECK_PUB
    apply_pub: str = APPLY_PUB
    not_keys: str | None = None


def deviations() -> dict[str, Case]:
    check, apply = good_lines()
    from_clause = f',from="{SOURCE}"'
    wide_clause = ',from="*"'
    shared_file = f'restrict,command="x" {SHARED_PUB}\nrestrict,command="y" {CHECK_PUB}\n'
    both = f"{check}\n{apply}\n"
    return {
        "swapped order": Case(f"{apply}\n{check}\n", "order_swapped"),
        "a third line": Case(f"{check}\n{apply}\n{check}\n", "line_count"),
        "one line only": Case(f"{check}\n", "line_count"),
        "empty read-back": Case("", "line_count"),
        "restrict dropped": Case(
            f"{check.removeprefix('restrict,')}\n{apply}\n", "restrict_missing"
        ),
        "mode changed in the command": Case(
            f"{check.replace('--mode check', '--mode apply')}\n{apply}\n", "command_mismatch"
        ),
        "source address dropped": Case(
            f"{check.replace(from_clause, '')}\n{apply}\n", "from_missing"
        ),
        "source address dropped from the apply line": Case(
            f"{check}\n{apply.replace(from_clause, '')}\n", "from_missing"
        ),
        "source address given twice": Case(
            f"{check.replace(from_clause, from_clause * 2)}\n{apply}\n", "several_from"
        ),
        "a second, wider source address": Case(
            f"{check}\n{apply.replace(from_clause, from_clause + wide_clause)}\n", "several_from"
        ),
        "source address changed": Case(
            f"{check.replace(SOURCE, OTHER_SOURCE)}\n{apply}\n", "from_mismatch"
        ),
        "extra option": Case(
            f"{check.replace('restrict,', 'restrict,port-forwarding,')}\n{apply}\n",
            "options_differ",
        ),
        "the apply key on the check line": Case(
            f"{check.replace(body_of(CHECK_PUB), body_of(APPLY_PUB))}\n{apply}\n", "key_mismatch"
        ),
        "no final line break": Case(f"{check}\n{apply}", "not_identical"),
        "carriage returns": Case(f"{check}\r\n{apply}\r\n", "not_identical"),
        "the same key for both modes": Case(both, "same_key_both_modes", apply_pub=CHECK_PUB),
        "a key held in the shared file": Case(both, "key_in_not_keys", not_keys=shared_file),
        "the apply key held in the shared file": Case(
            both, "key_in_not_keys", not_keys=f"restrict {APPLY_PUB}\n"
        ),
        "a check key that is not a key": Case(both, "check_pub_bad_shape", check_pub="not a key"),
        "an rsa apply key": Case(both, "apply_pub_wrong_type", apply_pub=rsa_line()),
        "a private key as the apply key": Case(
            both, "apply_pub_private_key", apply_pub=PRIVATE_BLOCK
        ),
    }


Verify = Callable[[Path, Path, Path, str, Path | None], str]


def accept_everything(
    readback: Path, check_pub: Path, apply_pub: Path, source: str, not_keys: Path | None
) -> str:
    """A stand-in for the guard with the mechanism removed."""
    return ""


class Files:
    """The files a verify reads, written to a temporary folder."""

    def __init__(self, folder: str) -> None:
        self.folder = Path(folder)

    def write(self, name: str, text: str) -> Path:
        path = self.folder / name
        path.write_text(text, encoding="utf-8")
        return path

    def run(self, case: Case, verify: Verify) -> str:
        not_keys = self.write("edge1", case.not_keys) if case.not_keys is not None else None
        return verify(
            self.write("readback", case.readback),
            self.write("check.pub", f"{case.check_pub}\n"),
            self.write("apply.pub", f"{case.apply_pub}\n"),
            SOURCE,
            not_keys,
        )


class Build(unittest.TestCase):
    def build(self, mode: str, pub: str, source: str = SOURCE) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as folder:
            return tool.build_line(mode, Files(folder).write("k.pub", f"{pub}\n"), source)

    def test_the_line_is_exactly_the_documented_shape(self) -> None:
        self.assertEqual(
            self.build("check", CHECK_PUB),
            (
                f'restrict,from="{SOURCE}",command="sudo /usr/local/sbin/pull-trigger '
                f'--mode check" ssh-ed25519 {body_of(CHECK_PUB)}',
                "",
            ),
        )
        self.assertEqual(
            self.build("apply", APPLY_PUB)[0],
            f'restrict,from="{SOURCE}",command="sudo /usr/local/sbin/pull-trigger --mode apply" '
            f"ssh-ed25519 {body_of(APPLY_PUB)}",
        )

    def test_the_comment_of_the_key_is_dropped(self) -> None:
        line, _ = self.build("check", ed25519_line(14, "x"))
        self.assertTrue(line.endswith(body_of(ed25519_line(14))), line)

    def test_refusals(self) -> None:
        corpus = {
            "an unknown mode": (self.build("both", CHECK_PUB), "bad_mode"),
            "a private key": (self.build("check", PRIVATE_BLOCK), "private_key"),
            "an rsa key": (self.build("check", rsa_line()), "wrong_type"),
            "a mask": (self.build("check", CHECK_PUB, f"{SOURCE}/32"), "bad_from"),
            "a list": (self.build("check", CHECK_PUB, f"{SOURCE},{SOURCE}"), "bad_from"),
            "a leading zero": (self.build("check", CHECK_PUB, "010.0.0.1"), "bad_from"),
            "an injected option": (
                self.build("check", CHECK_PUB, SOURCE + '",command="x'),
                "bad_from",
            ),
            "a host name": (self.build("check", CHECK_PUB, "edge1.example"), "bad_from"),
            "an empty address": (self.build("check", CHECK_PUB, ""), "bad_from"),
        }
        for name, (got, reason) in corpus.items():
            with self.subTest(name):
                self.assertEqual(got, ("", reason))


class Verifier(unittest.TestCase):
    def test_verify_refuses_each_deviation(self) -> None:
        check, apply = good_lines()
        with tempfile.TemporaryDirectory() as folder:
            files = Files(folder)
            good = Case(f"{check}\n{apply}\n", "")
            self.assertEqual(files.run(good, tool.verify_lines), "", "the built pair verifies")
            for name, case in deviations().items():
                with self.subTest(name):
                    self.assertEqual(files.run(case, tool.verify_lines), case.reason)

    def test_corpus_has_teeth(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            files = Files(folder)
            for name, case in deviations().items():
                with self.subTest(name):
                    self.assertEqual(files.run(case, accept_everything), "")
                    with self.assertRaises(AssertionError):
                        self.assertEqual(files.run(case, accept_everything), case.reason)

    def test_a_pair_built_by_build_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            files = Files(folder)
            check_pub = files.write("check.pub", f"{CHECK_PUB}\n")
            apply_pub = files.write("apply.pub", f"{APPLY_PUB}\n")
            lines = [
                tool.build_line("check", check_pub, SOURCE)[0],
                tool.build_line("apply", apply_pub, SOURCE)[0],
            ]
            readback = files.write("readback", "\n".join(lines) + "\n")
            edge1 = files.write("edge1", f"restrict {SHARED_PUB}\n")
            args = (readback, check_pub, apply_pub)
            self.assertEqual(tool.verify_lines(*args, SOURCE, edge1), "")
            self.assertEqual(tool.verify_lines(*args, OTHER_SOURCE, edge1), "from_mismatch")
            self.assertEqual(tool.verify_lines(*args, "", edge1), "bad_from")

    def test_files_that_cannot_be_read_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            files = Files(folder)
            check_pub = files.write("check.pub", f"{CHECK_PUB}\n")
            apply_pub = files.write("apply.pub", f"{APPLY_PUB}\n")
            readback = files.write("readback", "\n".join(good_lines()) + "\n")
            missing = Path(folder) / "absent"
            huge = files.write("huge", "x" * 70000)
            keys = (check_pub, apply_pub)
            self.assertEqual(tool.verify_lines(missing, *keys, SOURCE, None), "readback_unreadable")
            self.assertEqual(tool.verify_lines(huge, *keys, SOURCE, None), "readback_unreadable")
            self.assertEqual(
                tool.verify_lines(readback, *keys, SOURCE, missing), "not_keys_unreadable"
            )
            self.assertEqual(
                tool.verify_lines(readback, *keys, SOURCE, huge), "not_keys_unreadable"
            )
            self.assertEqual(tool.verify_lines(readback, *keys, "1.2.3", None), "bad_from")


class CommandLine(unittest.TestCase):
    """The invocations the runbook prints: the venv's python in isolated mode, then the tool."""

    def run_tool(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - this repository's own tool or ssh-keygen, run with fixed arguments
            [sys.executable, "-I", str(TOOL), *args], capture_output=True, text=True, check=False
        )

    def test_the_runbook_invocations(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            files = Files(folder)
            check_pub = files.write("check.pub", f"{CHECK_PUB}\n")
            apply_pub = files.write("apply.pub", f"{APPLY_PUB}\n")
            edge1 = files.write("edge1", f"restrict {SHARED_PUB}\n")
            built = [
                self.run_tool("build", "--mode", mode, "--pub", str(pub), "--from", SOURCE)
                for mode, pub in (("check", check_pub), ("apply", apply_pub))
            ]
            self.assertEqual([done.returncode for done in built], [0, 0])
            self.assertEqual(tuple(done.stdout.rstrip("\n") for done in built), good_lines())
            readback = files.write("authorized_keys", built[0].stdout + built[1].stdout)
            verify = ["verify", "--file", str(readback), "--check-pub", str(check_pub)]
            verify += ["--apply-pub", str(apply_pub), "--from", SOURCE, "--not-keys", str(edge1)]
            done = self.run_tool(*verify)
            self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "keylines=ok\n", ""))
            readback.write_text(built[1].stdout + built[0].stdout, encoding="utf-8")
            swapped = self.run_tool(*verify)
            self.assertEqual(
                (swapped.returncode, swapped.stdout),
                (1, "keylines=REFUSED reason=order_swapped\n"),
            )

    def test_from_is_required_in_build_and_in_verify(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            files = Files(folder)
            check_pub = files.write("check.pub", f"{CHECK_PUB}\n")
            apply_pub = files.write("apply.pub", f"{APPLY_PUB}\n")
            readback = files.write("rb", "\n".join(good_lines()) + "\n")
            build = self.run_tool("build", "--mode", "check", "--pub", str(check_pub))
            verify = self.run_tool(
                "verify",
                *("--file", str(readback), "--check-pub", str(check_pub)),
                *("--apply-pub", str(apply_pub)),
            )
            for name, done in (("build", build), ("verify", verify)):
                with self.subTest(name):
                    self.assertEqual(
                        (done.returncode, done.stdout, done.stderr), (2, "", "usage error\n")
                    )

    def test_a_refused_build_writes_nothing_to_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            private = Files(folder).write("id", PRIVATE_BLOCK)
            done = self.run_tool(
                "build", "--mode", "check", "--pub", str(private), "--from", SOURCE
            )
            self.assertEqual(
                (done.returncode, done.stdout, done.stderr),
                (1, "", "keyline=REFUSED reason=private_key\n"),
            )

    def test_no_output_carries_a_private_key_or_an_address_or_a_line(self) -> None:
        check, apply = good_lines(SENTINEL_ADDRESS)
        with tempfile.TemporaryDirectory() as folder:
            files = Files(folder)
            check_pub = files.write("check.pub", f"{CHECK_PUB}\n")
            apply_pub = files.write("apply.pub", f"{APPLY_PUB}\n")
            private = files.write("id", PRIVATE_BLOCK)
            for readback in (f"{check}\n{apply}\n", f"{apply}\n{check}\n", PRIVATE_BLOCK):
                path = files.write("rb", readback)
                for pub in (apply_pub, private):
                    out, err = io.StringIO(), io.StringIO()
                    argv = ["verify", "--file", str(path), "--check-pub", str(check_pub)]
                    argv += ["--apply-pub", str(pub), "--from", SENTINEL_ADDRESS]
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        tool.main(argv)
                    seen = out.getvalue() + err.getvalue()
                    for secret in (PRIVATE_SENTINEL, SENTINEL_ADDRESS, body_of(APPLY_PUB)):
                        self.assertNotIn(secret, seen)
            bad_source = self.run_tool(
                "build", "--mode", "check", "--pub", str(check_pub), "--from", PRIVATE_SENTINEL
            )
            self.assertNotIn(PRIVATE_SENTINEL, bad_source.stdout + bad_source.stderr)
            stray = self.run_tool("verify", "--bogus", PRIVATE_SENTINEL)
            self.assertEqual(
                (stray.returncode, stray.stdout, stray.stderr), (2, "", "usage error\n")
            )


class Authorities(unittest.TestCase):
    """The constants are copied from the roles because the tool runs without Ansible."""

    def role_vars(self, role: str) -> dict[str, object]:
        text = (ROLES / role / "vars" / "main.yml").read_text(encoding="utf-8")
        loaded: dict[str, object] = yaml.safe_load(text)
        return loaded

    def test_constants_equal_the_roles(self) -> None:
        login = self.role_vars("ci_login")
        self.assertEqual(tool.PROGRAM, login["ci_login_program"])
        self.assertEqual(tool.PROGRAM, self.role_vars("pull_trigger")["pull_trigger_program_path"])
        self.assertEqual(tool.OPTIONS, login["ci_login_key_options"])
        self.assertEqual(sorted(tool.MODES), sorted(login["ci_login_modes"]))  # type: ignore[call-overload]

    def test_the_line_has_the_role_template_shape(self) -> None:
        template = (ROLES / "ci_login" / "templates" / "authorized_keys.j2").read_text("utf-8")
        role_line = (
            '{{ ci_login_key_options }},command="sudo {{ ci_login_program }}'
            ' --mode {{ entry.mode }}" {{ entry.key }}'
        )
        self.assertIn(role_line, template)
        rendered = (
            role_line.replace("{{ ci_login_key_options }}", tool.OPTIONS)
            .replace("{{ ci_login_program }}", tool.PROGRAM)
            .replace("{{ entry.mode }}", "check")
            .replace("{{ entry.key }}", bare(CHECK_PUB))
        )
        self.assertEqual(rendered, good_lines()[0].replace(f',from="{SOURCE}"', ""))

    def test_each_command_is_one_the_sudoers_grants(self) -> None:
        sudoers = self.role_vars("ci_login")["ci_login_sudoers_lines"]
        self.assertIsInstance(sudoers, list)
        grant = str(sudoers[1]).replace("{{ ci_login_program }}", tool.PROGRAM)  # type: ignore[index]
        granted = grant.split("NOPASSWD: ")[1].split(", ")
        self.assertEqual(sorted(granted), sorted(f"{tool.PROGRAM} --mode {m}" for m in tool.MODES))


if __name__ == "__main__":
    unittest.main()
