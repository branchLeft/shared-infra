"""Unit tests for install_runtime: the checks, the order of the steps and what a failure leaves.

The runner is injected, so no test builds a real environment or reaches an index.
The role's container test does that with the repository's real lock.
"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest import mock

import install_runtime as program

HASH_A = "a" * 64
HASH_B = "b" * 64
WRONG_SHA_ONE = "0" * 64
WRONG_SHA_TWO = "f" * 64

LOCK_A = (
    "# comment line\n"
    f"alpha==1.0.0 \\\n    --hash=sha256:{HASH_A} \\\n    --hash=sha256:{HASH_B}\n"
    "    # via -r requirements.in\n"
    f"beta==2.0 ; python_version >= '3.12' \\\n    --hash=sha256:{HASH_A}\n"
).encode()
LOCK_B = LOCK_A + f"gamma==3.1 \\\n    --hash=sha256:{HASH_B}\n".encode()

# The bytes below have trailing blanks, a non-ASCII comment and several final newlines. Their
# fingerprint was recorded by running the expression the role used before this program existed,
# lookup('ansible.builtin.file', path) | ansible.builtin.hash('sha256') | truncate(16, True, ''),
# through ansible-core 2.21.5 from origin/main, and not by running this program.
GOLDEN_LOCK = (
    f"# café — “lock”\nalpha==1.0.0 \\\n    --hash=sha256:{HASH_A}  \n\n \t \n\n"
).encode()
GOLDEN_FINGERPRINT = "00885b2b10e79a23"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeRunner:
    """Records each command and plays the part of python -m venv and pip."""

    def __init__(
        self,
        *,
        pip_status: int = 0,
        venv_status: int = 0,
        make_engine: bool = True,
        half_made: bool = False,
    ) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.pip_status = pip_status
        self.venv_status = venv_status
        self.make_engine = make_engine
        # python -m venv puts bin/python down, then fails in ensurepip before bin/pip exists.
        self.half_made = half_made

    def __call__(self, argv: Sequence[str], env: Mapping[str, str]) -> int:
        self.calls.append((tuple(argv), dict(env)))
        if argv[1:3] == ["-m", "venv"]:
            target = Path(argv[-1])
            if "--clear" in argv and target.exists():
                shutil.rmtree(target)
            if self.venv_status == 0 or self.half_made:
                bin_dir = target / "bin"
                bin_dir.mkdir(parents=True, exist_ok=True)
                (bin_dir / "python").write_text("")
                if not self.half_made:
                    (bin_dir / "pip").write_text("")
                    (bin_dir / "pip").chmod(0o755)
            return self.venv_status
        if argv[1] == "install":
            if self.pip_status == 0 and self.make_engine:
                engine = Path(argv[0]).parent / "ansible-playbook"
                engine.write_text("#!/bin/sh\n")
                engine.chmod(0o755)
            return self.pip_status
        message = f"unexpected command {argv}"
        raise AssertionError(message)


class Case(unittest.TestCase):
    """A temporary directory with a lock, an environments directory and a link path."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "runtime"
        self.link = self.base / "ansible-playbook"
        self.lock_path = self.base / "lock.txt"

    def request(
        self,
        lock: bytes = LOCK_A,
        *,
        sha256: str | None = None,
        link: bool = False,
        expect: str | None = None,
        write: bool = True,
    ) -> program.Request:
        if write:
            self.lock_path.write_bytes(lock)
        return program.Request(
            lock=self.lock_path,
            lock_sha256=sha(lock) if sha256 is None else sha256,
            root=self.root,
            link=self.link if link else None,
            expect_fingerprint=expect,
            python="/usr/bin/python3",
        )

    def refused(self, request: program.Request, runner: FakeRunner, reason: program.Reason) -> None:
        with self.assertRaises(program.Refusal) as caught:
            program.install(request, runner)
        self.assertEqual(reason, caught.exception.reason)

    def nothing_made(self, runner: FakeRunner) -> None:
        self.assertEqual([], runner.calls)
        self.assertFalse(self.root.exists(), "the refusal must come before the directory is made")
        self.assertFalse(os.path.lexists(self.link))


class FingerprintTest(unittest.TestCase):
    def test_matches_the_value_the_role_computed_before_this_program(self) -> None:
        self.assertEqual(GOLDEN_FINGERPRINT, program.fingerprint(GOLDEN_LOCK))

    def test_trailing_whitespace_is_not_a_new_environment(self) -> None:
        self.assertEqual(program.fingerprint(LOCK_A), program.fingerprint(LOCK_A + b"  \n\n\t\n"))

    def test_a_different_lock_is_a_different_environment(self) -> None:
        self.assertNotEqual(program.fingerprint(LOCK_A), program.fingerprint(LOCK_B))

    def test_is_not_the_hash_of_the_file(self) -> None:
        self.assertNotEqual(sha(GOLDEN_LOCK)[:16], program.fingerprint(GOLDEN_LOCK))

    def test_text_that_is_not_utf8_is_refused(self) -> None:
        with self.assertRaises(program.Refusal) as caught:
            program.fingerprint(b"\xff\xfe")
        self.assertEqual(program.Reason.LOCK_NOT_TEXT, caught.exception.reason)


class LockChecksTest(Case):
    def test_a_matching_lock_installs_and_names_the_environment(self) -> None:
        runner = FakeRunner()
        outcome = program.install(self.request(), runner)
        name = program.fingerprint(LOCK_A)
        self.assertEqual(name, outcome.fingerprint)
        self.assertTrue(outcome.installed)
        self.assertTrue((self.root / f"venv-{name}" / "bin" / "ansible-playbook").is_file())
        self.assertEqual(
            f"{name}\n", (self.root / f"venv-{name}" / ".installed-from-lock").read_text()
        )
        self.assertEqual(LOCK_A, (self.root / f"requirements-{name}.txt").read_bytes())

    def test_two_different_wrong_hashes_are_refused_and_nothing_is_made(self) -> None:
        for wrong in (WRONG_SHA_ONE, WRONG_SHA_TWO):
            with self.subTest(wrong=wrong):
                runner = FakeRunner()
                self.refused(self.request(sha256=wrong), runner, program.Reason.LOCK_HASH)
                self.nothing_made(runner)

    def test_a_lock_changed_after_its_hash_was_recorded_is_refused(self) -> None:
        recorded = sha(LOCK_A)
        runner = FakeRunner()
        self.refused(self.request(LOCK_B, sha256=recorded), runner, program.Reason.LOCK_HASH)
        self.nothing_made(runner)

    def test_a_lock_with_no_hash_is_refused_before_anything_is_made(self) -> None:
        for text in (b"alpha==1.0.0\n", b"alpha==1.0.0\nbeta==2.0\n"):
            with self.subTest(text=text):
                runner = FakeRunner()
                self.refused(self.request(text), runner, program.Reason.LOCK_UNHASHED)
                self.nothing_made(runner)

    def test_a_lock_that_names_no_requirement_is_refused(self) -> None:
        for text in (b"# only a comment\n", b"", b"\n\n"):
            with self.subTest(text=text):
                runner = FakeRunner()
                self.refused(self.request(text), runner, program.Reason.LOCK_EMPTY)
                self.nothing_made(runner)

    def test_one_unhashed_requirement_among_hashed_ones_is_refused(self) -> None:
        lock = LOCK_A + b"delta==4.0\n"
        runner = FakeRunner()
        self.refused(self.request(lock), runner, program.Reason.LOCK_UNHASHED)
        self.nothing_made(runner)

    def test_a_line_that_is_not_a_pinned_hashed_requirement_is_refused(self) -> None:
        hashed = f"--hash=sha256:{HASH_A}"
        lines = {
            "an index option": "--index-url https://index.invalid/simple\n",
            "an extra index": "--extra-index-url https://index.invalid/simple\n",
            "another file": "-r other.txt\n",
            "an editable path": "-e ./local\n",
            "an unpinned version": f"alpha>=1.0 {hashed}\n",
            "a direct url": f"alpha @ https://example.invalid/alpha.whl {hashed}\n",
            "a path": f"./alpha.whl {hashed}\n",
            "a second option on the line": f"alpha==1.0 --no-binary :all: {hashed}\n",
            "an index option after a marker": (
                "alpha==1.0 ; python_version >= '3.13' "
                f"--index-url=https://index.invalid/simple {hashed}\n"
            ),
            "an index option with its value after a marker": (
                "alpha==1.0 ; python_version >= '3.13' "
                f"--index-url https://index.invalid/simple {hashed}\n"
            ),
            "a find-links option after a marker": (
                f"alpha==1.0 ; os_name == 'posix' -f https://index.invalid/ {hashed}\n"
            ),
            "an option in the marker with no space before it": (
                f"alpha==1.0 ;--extra-index-url=https://index.invalid/ {hashed}\n"
            ),
            "a short index option directly after the semicolon": (
                f"alpha==1.0;-i https://index.invalid/simple {hashed}\n"
            ),
            "a short find-links option directly after a spaced semicolon": (
                f"alpha==1.0 ;-f https://index.invalid/ {hashed}\n"
            ),
            "an option after a second semicolon": (
                f"alpha==1.0;x;-i https://index.invalid/simple {hashed}\n"
            ),
            "an option after a second semicolon and a space": (
                f"alpha==1.0; x;-i https://index.invalid/simple {hashed}\n"
            ),
            "an option after a comma": (f"alpha==1.0;a,-i https://index.invalid/simple {hashed}\n"),
            "a quoted option": f"alpha==1.0;'-i' https://index.invalid/simple {hashed}\n",
            "an option after a bracket": f"alpha==1.0;(-i https://index.invalid/simple {hashed}\n",
            "a hyphen in the marker": (f"alpha==1.0 ; sys_platform == 'linux-gnu' {hashed}\n"),
            "a second marker": f"alpha==1.0 ; os_name == 'posix' ; os_name == 'nt' {hashed}\n",
            "an option between the hashes": (
                f"alpha==1.0 ; os_name == 'posix' {hashed} --index-url=https://index.invalid/"
                f" {hashed}\n"
            ),
            "a short hash": "alpha==1.0 --hash=sha256:abc\n",
            "another hash algorithm": f"alpha==1.0 --hash=md5:{'a' * 32}\n",
        }
        for name, line in lines.items():
            with self.subTest(name=name):
                runner = FakeRunner()
                lock = LOCK_A + line.encode()
                self.refused(self.request(lock), runner, program.Reason.LOCK_UNHASHED)
                self.nothing_made(runner)

    def test_the_repositorys_own_lock_and_its_markers_are_accepted(self) -> None:
        # A control for the refusals above: a pattern that refused every marker would pass them.
        # In a checkout the lock is found from this file's place; the Molecule verify has no
        # checkout, so it copies the lock into the container and says where in REPOSITORY_LOCK.
        given = os.environ.get("REPOSITORY_LOCK")
        path = (
            Path(given)
            if given
            else Path(__file__).resolve().parents[5] / "ansible" / "requirements.txt"
        )
        lock = path.read_bytes()
        self.assertIn(b" ; ", lock)
        program.check_lock_is_hashed(lock)
        for marker in (
            "sys_platform == 'linux' or sys_platform == 'linux2'",
            "platform_python_implementation != 'PyPy'",
            "sys_platform == 'linux' and (python_version >= '3.8' or os_name != 'nt')",
        ):
            with self.subTest(marker=marker):
                program.check_lock_is_hashed(
                    f"alpha==1.0 ; {marker} \\\n    --hash=sha256:{HASH_A}\n".encode()
                )

    def test_a_lock_that_ends_in_a_continued_line_is_refused(self) -> None:
        runner = FakeRunner()
        self.refused(self.request(LOCK_A + b"zeta==1.0 \\\n"), runner, program.Reason.LOCK_UNHASHED)
        self.nothing_made(runner)

    def test_a_link_in_place_of_the_lock_is_refused(self) -> None:
        real = self.base / "real.txt"
        real.write_bytes(LOCK_A)
        self.lock_path.symlink_to(real)
        runner = FakeRunner()
        self.refused(self.request(write=False), runner, program.Reason.LOCK_NOT_REGULAR)
        self.nothing_made(runner)

    def test_a_fifo_or_a_directory_in_place_of_the_lock_is_refused(self) -> None:
        os.mkfifo(self.lock_path)
        runner = FakeRunner()
        self.refused(self.request(write=False), runner, program.Reason.LOCK_NOT_REGULAR)
        self.lock_path.unlink()
        self.lock_path.mkdir()
        self.refused(self.request(write=False), runner, program.Reason.LOCK_NOT_REGULAR)
        self.nothing_made(runner)

    def test_a_missing_lock_is_refused(self) -> None:
        runner = FakeRunner()
        self.refused(self.request(write=False), runner, program.Reason.LOCK_NOT_REGULAR)
        self.nothing_made(runner)

    def test_a_lock_over_the_limit_is_refused(self) -> None:
        self.lock_path.write_bytes(b"#" * 100)
        with mock.patch.object(program, "MAX_LOCK_BYTES", 50):
            runner = FakeRunner()
            self.refused(self.request(b"#" * 100, write=False), runner, program.Reason.LOCK_TOO_BIG)
        self.nothing_made(runner)

    def test_a_fingerprint_other_than_expected_is_refused(self) -> None:
        runner = FakeRunner()
        self.refused(self.request(expect="0" * 16), runner, program.Reason.FINGERPRINT)
        self.nothing_made(runner)

    def test_the_expected_fingerprint_is_accepted(self) -> None:
        outcome = program.install(self.request(expect=program.fingerprint(LOCK_A)), FakeRunner())
        self.assertTrue(outcome.installed)


class RootChecksTest(Case):
    def test_a_link_in_place_of_the_directory_is_refused(self) -> None:
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir(mode=0o755)
        self.root.symlink_to(elsewhere)
        runner = FakeRunner()
        self.refused(self.request(), runner, program.Reason.ROOT)
        self.assertEqual([], runner.calls)

    def test_a_directory_others_can_write_is_refused(self) -> None:
        for mode in (0o775, 0o757, 0o777):
            with self.subTest(mode=oct(mode)):
                self.root.mkdir(exist_ok=True)
                self.root.chmod(mode)
                runner = FakeRunner()
                self.refused(self.request(), runner, program.Reason.ROOT)
                self.assertEqual([], runner.calls)

    def test_a_directory_owned_by_another_account_is_refused(self) -> None:
        self.root.mkdir(mode=0o755)
        runner = FakeRunner()
        with mock.patch("os.geteuid", return_value=os.geteuid() + 1):
            self.refused(self.request(), runner, program.Reason.ROOT)
        self.assertEqual([], runner.calls)

    def test_a_relative_directory_is_refused(self) -> None:
        request = self.request()
        relative = program.Request(
            request.lock, request.lock_sha256, Path("relative"), None, None, request.python
        )
        self.refused(relative, FakeRunner(), program.Reason.ROOT)


class StepsTest(Case):
    def test_the_commands_and_the_environment_pip_runs_with(self) -> None:
        runner = FakeRunner()
        with mock.patch.dict(
            os.environ, {"PIP_INDEX_URL": "https://index.invalid", "PIP_REQUIRE_HASHES": "0"}
        ):
            program.install(self.request(), runner)
        name = program.fingerprint(LOCK_A)
        venv = self.root / f"venv-{name}"
        self.assertEqual(
            [
                ("/usr/bin/python3", "-m", "venv", str(venv)),
                (
                    str(venv / "bin" / "pip"),
                    "install",
                    "--require-virtualenv",
                    "--require-hashes",
                    "--no-input",
                    "--disable-pip-version-check",
                    "-r",
                    str(self.root / f"requirements-{name}.txt"),
                ),
            ],
            [call[0] for call in runner.calls],
        )
        for _, env in runner.calls:
            self.assertEqual({"PATH", "HOME", "LANG"}, set(env))

    def test_the_marker_is_written_last(self) -> None:
        runner = FakeRunner(pip_status=1)
        self.refused(self.request(), runner, program.Reason.PIP)
        name = program.fingerprint(LOCK_A)
        self.assertFalse((self.root / f"venv-{name}" / ".installed-from-lock").exists())

    def test_a_failing_pip_leaves_no_link_and_the_old_link_in_place(self) -> None:
        runner = FakeRunner()
        program.install(self.request(LOCK_A, link=True), runner)
        old_target = os.readlink(self.link)
        failing = FakeRunner(pip_status=1)
        self.refused(self.request(LOCK_B, link=True), failing, program.Reason.PIP)
        self.assertEqual(old_target, os.readlink(self.link))

    def test_a_failing_first_install_makes_no_link(self) -> None:
        self.refused(self.request(link=True), FakeRunner(pip_status=1), program.Reason.PIP)
        self.assertFalse(os.path.lexists(self.link))

    def test_a_failing_venv_makes_no_link_and_runs_no_pip(self) -> None:
        runner = FakeRunner(venv_status=1)
        self.refused(self.request(link=True), runner, program.Reason.VENV)
        self.assertEqual(1, len(runner.calls))
        self.assertFalse(os.path.lexists(self.link))

    def test_an_install_with_no_ansible_playbook_makes_no_marker_and_no_link(self) -> None:
        runner = FakeRunner(make_engine=False)
        self.refused(self.request(link=True), runner, program.Reason.NO_ENGINE)
        name = program.fingerprint(LOCK_A)
        self.assertFalse((self.root / f"venv-{name}" / ".installed-from-lock").exists())
        self.assertFalse(os.path.lexists(self.link))

    def test_a_finished_install_is_not_run_again(self) -> None:
        program.install(self.request(), FakeRunner())
        runner = FakeRunner()
        outcome = program.install(self.request(), runner)
        self.assertFalse(outcome.installed)
        self.assertEqual([], runner.calls)

    def test_an_install_that_died_before_its_marker_is_run_again(self) -> None:
        self.refused(self.request(), FakeRunner(pip_status=1), program.Reason.PIP)
        runner = FakeRunner()
        outcome = program.install(self.request(), runner)
        self.assertTrue(outcome.installed)
        self.assertEqual(1, len(runner.calls), "the environment exists, so only pip runs again")

    def test_a_venv_that_failed_after_bin_python_is_made_again_on_the_next_run(self) -> None:
        name = program.fingerprint(LOCK_A)
        venv = self.root / f"venv-{name}"
        self.refused(self.request(), FakeRunner(venv_status=1, half_made=True), program.Reason.VENV)
        self.assertTrue((venv / "bin" / "python").exists(), "the control: bin/python is left")
        self.assertFalse((venv / "bin" / "pip").exists())
        runner = FakeRunner()
        outcome = program.install(self.request(), runner)
        self.assertTrue(outcome.installed)
        self.assertEqual(
            ("/usr/bin/python3", "-m", "venv", "--clear", str(venv)),
            runner.calls[0][0],
            "the half-made directory is cleared, not reused",
        )
        self.assertTrue((venv / "bin" / "pip").exists())
        self.assertEqual(2, len(runner.calls))

    def test_a_link_where_the_venv_belongs_is_refused_and_nothing_behind_it_is_cleared(
        self,
    ) -> None:
        name = program.fingerprint(LOCK_A)
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "kept").write_text("kept")
        self.root.mkdir(mode=0o700)
        os.symlink(elsewhere, self.root / f"venv-{name}")
        runner = FakeRunner()
        self.refused(self.request(link=True), runner, program.Reason.VENV)
        self.assertEqual([], runner.calls)
        self.assertEqual("kept", (elsewhere / "kept").read_text())
        self.assertFalse(os.path.lexists(self.link))

    def test_a_first_venv_is_not_cleared_and_a_finished_one_is_not_made_again(self) -> None:
        first = FakeRunner(pip_status=1)
        self.refused(self.request(), first, program.Reason.PIP)
        self.assertNotIn("--clear", first.calls[0][0])
        again = FakeRunner()
        program.install(self.request(), again)
        self.assertEqual(1, len(again.calls), "pip is there, so only pip runs again")

    def test_a_marker_naming_another_lock_does_not_count(self) -> None:
        program.install(self.request(), FakeRunner())
        name = program.fingerprint(LOCK_A)
        (self.root / f"venv-{name}" / ".installed-from-lock").write_text("not-this-one\n")
        runner = FakeRunner()
        self.assertTrue(program.install(self.request(), runner).installed)

    def test_the_lock_copy_is_replaced_when_its_bytes_differ(self) -> None:
        name = program.fingerprint(LOCK_A)
        self.root.mkdir(mode=0o755)
        (self.root / f"requirements-{name}.txt").write_text("tampered\n")
        program.install(self.request(), FakeRunner())
        self.assertEqual(LOCK_A, (self.root / f"requirements-{name}.txt").read_bytes())


class LinkTest(Case):
    def target_of(self) -> str:
        return os.readlink(self.link)

    def test_a_lock_a_then_b_then_a_ends_on_a_without_installing_a_again(self) -> None:
        program.install(self.request(LOCK_A, link=True), FakeRunner())
        program.install(self.request(LOCK_B, link=True), FakeRunner())
        self.assertIn(program.fingerprint(LOCK_B), self.target_of())
        runner = FakeRunner()
        outcome = program.install(self.request(LOCK_A, link=True), runner)
        self.assertIn(program.fingerprint(LOCK_A), self.target_of())
        self.assertEqual((False, True), (outcome.installed, outcome.linked))
        self.assertEqual([], runner.calls)

    def test_a_deleted_link_is_made_again(self) -> None:
        program.install(self.request(link=True), FakeRunner())
        self.link.unlink()
        program.install(self.request(link=True), FakeRunner())
        self.assertIn(program.fingerprint(LOCK_A), self.target_of())

    def test_a_link_to_nowhere_is_replaced(self) -> None:
        self.link.symlink_to(self.base / "gone")
        program.install(self.request(link=True), FakeRunner())
        self.assertIn(program.fingerprint(LOCK_A), self.target_of())

    def test_no_link_is_made_unless_asked(self) -> None:
        outcome = program.install(self.request(link=False), FakeRunner())
        self.assertFalse(outcome.linked)
        self.assertFalse(os.path.lexists(self.link))

    def test_a_directory_at_the_link_path_is_refused(self) -> None:
        self.link.mkdir()
        self.refused(self.request(link=True), FakeRunner(), program.Reason.LINK)

    def test_a_relative_link_and_a_missing_directory_are_refused(self) -> None:
        base = self.request()
        for link in (Path("relative-link"), self.base / "nowhere" / "ansible-playbook"):
            with self.subTest(link=str(link)):
                request = program.Request(
                    base.lock, base.lock_sha256, base.root, link, None, base.python
                )
                self.refused(request, FakeRunner(), program.Reason.LINK)

    def test_no_temporary_link_is_left_behind(self) -> None:
        program.install(self.request(link=True), FakeRunner())
        self.assertEqual(
            ["ansible-playbook", "lock.txt", "runtime"],
            sorted(path.name for path in self.base.iterdir()),
        )


class ArgumentsTest(unittest.TestCase):
    BASE = ("--lock", "/x/lock", "--lock-sha256", HASH_A, "--root", "/x/root")

    def test_the_least_that_is_accepted(self) -> None:
        request = program.parse_request(self.BASE)
        self.assertIsNone(request.link)
        self.assertIsNone(request.expect_fingerprint)
        self.assertEqual(program.DEFAULT_PYTHON, request.python)

    def test_each_required_argument_is_required(self) -> None:
        for dropped in ("--lock", "--lock-sha256", "--root"):
            index = self.BASE.index(dropped)
            argv = self.BASE[:index] + self.BASE[index + 2 :]
            with self.subTest(dropped=dropped), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(program.Refusal) as caught:
                    program.parse_request(argv)
                self.assertEqual(program.Reason.USAGE, caught.exception.reason)

    def test_bad_values_are_refused(self) -> None:
        without_sha = ["--lock", "/x/lock", "--root", "/x/root"]
        bad = {
            "an uppercase sha": [*without_sha, "--lock-sha256", "A" * 64],
            "a short sha": [*without_sha, "--lock-sha256", "a" * 63],
            "a sha with a newline": [*without_sha, "--lock-sha256", "a" * 64 + "\n"],
            "a short fingerprint": [*self.BASE, "--expect-fingerprint", "a" * 15],
            "an unknown option": [*self.BASE, "--no-hashes"],
            "an abbreviated option": [*self.BASE, "--expect-fp", "a" * 16],
        }
        for name, argv in bad.items():
            with self.subTest(name=name), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(program.Refusal):
                    program.parse_request(argv)


class MainTest(Case):
    def argv(self, lock: bytes = LOCK_A, sha256: str | None = None) -> list[str]:
        self.lock_path.write_bytes(lock)
        return [
            "--lock", str(self.lock_path),
            "--lock-sha256", sha(lock) if sha256 is None else sha256,
            "--root", str(self.root),
            "--link", str(self.link),
        ]  # fmt: skip

    def test_success_prints_one_json_line_and_returns_zero(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = program.main(self.argv(), FakeRunner())
        self.assertEqual(0, status)
        printed = json.loads(out.getvalue())
        self.assertEqual(program.fingerprint(LOCK_A), printed["fingerprint"])
        self.assertTrue(printed["installed"] and printed["linked"])

    def test_a_refusal_returns_non_zero_and_prints_nothing_on_stdout(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = program.main(self.argv(sha256=WRONG_SHA_ONE), FakeRunner())
        self.assertEqual((1, ""), (status, out.getvalue()))
        self.assertIn("refused", err.getvalue())

    def test_an_unexpected_error_of_any_class_is_non_zero(self) -> None:
        for raised in (RuntimeError("boom"), OSError("disk"), KeyboardInterrupt(), SystemExit(0)):
            with self.subTest(raised=type(raised).__name__):
                err = io.StringIO()
                with (
                    mock.patch.object(program, "install", side_effect=raised),
                    contextlib.redirect_stderr(err),
                ):
                    status = program.main(self.argv(), FakeRunner())
                self.assertEqual(1, status)
                self.assertNotIn("boom", err.getvalue(), "an error's own text is not echoed")


class ProgramProcessTest(Case):
    """The program as a process, with a stand-in python and a pip that fails or works."""

    # The stand-in python makes the environment's bin/ with a stand-in pip. The pip prints a reason
    # and fails when the flag file named in it exists. The flag is a file, not a variable, because
    # the program gives pip no variable but PATH, HOME and LANG.
    PYTHON = (
        "#!/bin/sh\n"
        'dir="$3"\n'
        'mkdir -p "$dir/bin"\n'
        ': > "$dir/bin/python"\n'
        "cat > \"$dir/bin/pip\" <<'PIP'\n"
        "#!/bin/sh\n"
        'echo "pip said: the-reason" >&2\n'
        '[ -e "{flag}" ] && exit 1\n'
        'touch "$(dirname "$0")/ansible-playbook"\n'
        'chmod 755 "$(dirname "$0")/ansible-playbook"\n'
        "PIP\n"
        'chmod 755 "$dir/bin/pip"\n'
    )

    def run_program(
        self, *, pip_fails: bool, lock: bytes = LOCK_A
    ) -> subprocess.CompletedProcess[str]:
        flag = self.base / "pip-fails"
        if pip_fails:
            flag.write_text("")
        python = self.base / "fake-python"
        python.write_text(self.PYTHON.replace("{flag}", str(flag)))
        python.chmod(0o755)
        self.lock_path.write_bytes(lock)
        return subprocess.run(  # noqa: S603 - fixed argv built from this test's own paths
            [
                sys.executable,
                "-I",
                program.__file__,
                "--lock",
                str(self.lock_path),
                "--lock-sha256",
                sha(lock),
                "--root",
                str(self.root),
                "--link",
                str(self.link),
                "--python",
                str(python),
            ],
            env={"PATH": os.environ["PATH"]},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_success_installs_links_and_keeps_stdout_clean(self) -> None:
        done = self.run_program(pip_fails=False)
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertEqual(program.fingerprint(LOCK_A), json.loads(done.stdout)["fingerprint"])
        self.assertTrue(stat.S_ISLNK(os.lstat(self.link).st_mode))

    def test_a_failing_pip_is_non_zero_with_its_reason_on_stderr_and_no_link(self) -> None:
        done = self.run_program(pip_fails=True)
        self.assertNotEqual(0, done.returncode)
        self.assertIn("pip said: the-reason", done.stderr)
        self.assertEqual("", done.stdout)
        self.assertFalse(os.path.lexists(self.link))


if __name__ == "__main__":
    unittest.main()
