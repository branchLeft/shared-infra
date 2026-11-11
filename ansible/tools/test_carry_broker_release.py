"""Tests for the tool that carries a verified broker release into the broker_deploy role.

A release is built in memory as a gzip tarball. The bad ones (a link, a device, a path that is not
plain, a repeat, a missing entry point, a wrong digest) are each refused with their own reason
code and write nothing. A good one is carried into a scratch copy of the role and then judged by
the role's own pin check, run for real with ansible-playbook, so the tool and the role cannot
drift apart. A missing ansible-playbook is a failure, not a skip.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import carry_broker_release as tool
import yaml  # type: ignore[import-untyped]

ROLE = Path(tool.__file__).resolve().parents[1] / "roles" / "broker_deploy"
TOOL = Path(tool.__file__).resolve()
VERSION = "0.1.0"
SENTINEL = "SENTINELTEXTNOTTOBEPRINTED"
Member = tuple[str, bytes, bytes]  # name, type, content
GOOD: list[Member] = [
    ("broker.mjs", tarfile.REGTYPE, b"export const broker = 1;\n"),
    ("plugins", tarfile.DIRTYPE, b""),
    ("plugins/renderCorePlugin.mjs", tarfile.REGTYPE, b"export const render = 2;\n"),
    ("plugins/ghostAdminApi.mjs", tarfile.REGTYPE, b"export const admin = 3;\n"),
]


def build(members: list[Member], extra: Callable[[tarfile.TarFile], None] | None = None) -> bytes:
    """Return a gzip tarball of the members, with one member made per its type."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.GNU_FORMAT) as archive:
        for name, kind, content in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            else:
                info.linkname = "broker.mjs" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                archive.addfile(info)
        if extra is not None:
            extra(archive)
    return buffer.getvalue()


def digest(data: bytes) -> str:
    """Return the sha256 hex digest of some bytes."""
    return hashlib.sha256(data).hexdigest()


def ansible_playbook() -> Path:
    """Return the ansible-playbook beside the interpreter that runs the tests.

    Raises:
        AssertionError: the interpreter's environment has no ansible-playbook.
    """
    found = Path(sys.executable).parent / "ansible-playbook"
    if not found.exists():
        message = f"{found} is missing: run these tests with the pinned tool environment"
        raise AssertionError(message)
    return found


@dataclass
class Outcome:
    """What one run of ansible-playbook did."""

    code: int
    output: str


class Lab(unittest.TestCase):
    """A scratch role tree holding the real defaults and vars, and a scratch place for tarballs."""

    def setUp(self) -> None:
        """Copy the role's defaults and vars into a scratch role directory."""
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.role = self.root / "role"
        for name in ("defaults", "vars"):
            shutil.copytree(ROLE / name, self.role / name)
        self.defaults = self.role / "defaults" / "main.yml"
        self.before = self.defaults.read_text(encoding="utf-8")

    def tarball(self, members: list[Member] | None = None, name: str = "release.tar.gz") -> Path:
        """Write a release tarball and return its path."""
        path = self.root / name
        path.write_bytes(build(GOOD if members is None else members))
        return path

    def run_tool(
        self, tarball: Path, *, version: str = VERSION, sha: str | None = None, write: bool = False
    ) -> tuple[int, str]:
        """Run the tool's main in process and return its status and printed text."""
        args = [
            "--version",
            version,
            "--tarball",
            str(tarball),
            "--tarball-sha256",
            sha if sha is not None else digest(tarball.read_bytes()),
            "--role-dir",
            str(self.role),
        ]
        if write:
            args.append("--write")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = tool.main(args)
        return status, out.getvalue()

    def assert_untouched(self) -> None:
        """Assert that nothing was written under the scratch role."""
        self.assertFalse((self.role / "files").exists())
        self.assertEqual(self.before, self.defaults.read_text(encoding="utf-8"))


class Carrying(Lab):
    """A good release is checked, then carried, once."""

    def test_a_check_prints_the_pins_and_writes_nothing(self) -> None:
        """Without --write the pins are shown and the tree is untouched."""
        status, out = self.run_tool(self.tarball())
        self.assertEqual(0, status)
        self.assertIn("carry=CHECKED files=3", out)
        self.assertIn(f"'broker.mjs': '{digest(GOOD[0][2])}'", out)
        self.assert_untouched()

    def test_a_write_carries_the_files_and_the_pins(self) -> None:
        """--write puts each file in place and sets the version and the pins to match."""
        status, out = self.run_tool(self.tarball(), write=True)
        self.assertEqual(0, status)
        self.assertIn("carry=WRITTEN files=3", out)
        release = self.role / "files" / "releases" / VERSION
        loaded = yaml.safe_load(self.defaults.read_text(encoding="utf-8"))
        self.assertEqual(VERSION, loaded["broker_deploy_release_version"])
        expected = {
            name: digest(content) for name, kind, content in GOOD if kind == tarfile.REGTYPE
        }
        self.assertEqual({VERSION: expected}, loaded["broker_deploy_release_pins"])
        for name, content in ((n, c) for n, k, c in GOOD if k == tarfile.REGTYPE):
            self.assertEqual(content, (release / name).read_bytes())
            self.assertEqual(0o644, (release / name).stat().st_mode & 0o777)
        self.assertEqual(
            sorted(expected),
            sorted(str(p.relative_to(release)) for p in release.rglob("*") if p.is_file()),
        )

    def test_the_rest_of_the_defaults_is_left_as_it_was(self) -> None:
        """Only the version and the pins change in the defaults file."""
        self.run_tool(self.tarball(), write=True)
        after = self.defaults.read_text(encoding="utf-8").split("\n")
        removed = [line for line in self.before.split("\n") if line not in after]
        self.assertEqual([tool.VERSION_LINE, tool.PINS_LINE], removed)
        self.assertEqual(self.before.split("\n")[0], after[0], "the file's first line is not moved")

    def test_a_second_carry_of_the_same_version_is_refused(self) -> None:
        """A release is never replaced."""
        self.run_tool(self.tarball(), write=True)
        defaults = self.defaults.read_text(encoding="utf-8")
        status, out = self.run_tool(self.tarball(), write=True)
        self.assertEqual(1, status)
        self.assertIn("reason=defaults_not_placeholders", out)
        self.assertEqual(defaults, self.defaults.read_text(encoding="utf-8"))

    def test_a_version_already_in_the_tree_is_refused(self) -> None:
        """A release directory that exists is not written over, with the defaults unchanged."""
        (self.role / "files" / "releases" / VERSION).mkdir(parents=True)
        status, out = self.run_tool(self.tarball(), write=True)
        self.assertEqual((1, "carry=REFUSED reason=release_already_carried\n"), (status, out))
        self.assertEqual(self.before, self.defaults.read_text(encoding="utf-8"))

    def test_defaults_that_are_not_the_placeholders_are_refused(self) -> None:
        """A tree that already pins a release is changed by hand, not by this tool."""
        self.defaults.write_text(
            self.before.replace(tool.PINS_LINE, "broker_deploy_release_pins:\n  '0.0.9': {}\n"),
            encoding="utf-8",
        )
        before = self.defaults.read_text(encoding="utf-8")
        status, out = self.run_tool(self.tarball(), write=True)
        self.assertEqual((1, "carry=REFUSED reason=defaults_not_placeholders\n"), (status, out))
        self.assertEqual(before, self.defaults.read_text(encoding="utf-8"))
        self.assertFalse((self.role / "files").exists())

    def test_a_failed_defaults_write_removes_the_release(self) -> None:
        """If the defaults cannot be replaced, the files are taken away again."""
        with mock.patch.object(tool, "replace_file", side_effect=OSError("disk")):
            status, out = self.run_tool(self.tarball(), write=True)
        self.assertEqual((1, "carry=REFUSED reason=write_failed\n"), (status, out))
        self.assertFalse((self.role / "files" / "releases" / VERSION).exists())
        self.assertEqual(self.before, self.defaults.read_text(encoding="utf-8"))


class Refusals(Lab):
    """Each bad release has its own reason, and writes nothing."""

    def refused(self, members: list[Member], reason: str) -> None:
        """Assert a release of these members is refused with a reason, writing nothing."""
        status, out = self.run_tool(self.tarball(members), write=True)
        self.assertEqual((1, f"carry=REFUSED reason={reason}\n"), (status, out))
        self.assert_untouched()

    def test_the_corpus(self) -> None:
        """Every bad shape is refused with its own reason."""
        entry = GOOD[0]
        cases: dict[str, tuple[list[Member], str]] = {
            "symlink": (
                [entry, ("plugins/x.mjs", tarfile.SYMTYPE, b"")],
                "member_not_a_plain_file",
            ),
            "hardlink": (
                [entry, ("plugins/x.mjs", tarfile.LNKTYPE, b"")],
                "member_not_a_plain_file",
            ),
            "device": ([entry, ("dev", tarfile.CHRTYPE, b"")], "member_not_a_plain_file"),
            "fifo": ([entry, ("pipe", tarfile.FIFOTYPE, b"")], "member_not_a_plain_file"),
            "absolute": ([entry, ("/etc/x.mjs", tarfile.REGTYPE, b"x")], "path_not_plain"),
            "dot dot": ([entry, ("../x.mjs", tarfile.REGTYPE, b"x")], "path_not_plain"),
            "inner dot dot": (
                [entry, ("plugins/../x.mjs", tarfile.REGTYPE, b"x")],
                "path_not_plain",
            ),
            "dot prefix": ([("./broker.mjs", tarfile.REGTYPE, b"x")], "path_not_plain"),
            "space": ([entry, ("a b.mjs", tarfile.REGTYPE, b"x")], "path_not_plain"),
            "newline": ([entry, ("a\nb.mjs", tarfile.REGTYPE, b"x")], "path_not_plain"),
            "repeat": ([entry, entry], "repeated_path"),
            "file and directory": (
                [
                    entry,
                    ("plugins", tarfile.REGTYPE, b"x"),
                    ("plugins/a.mjs", tarfile.REGTYPE, b"x"),
                ],
                "file_is_also_a_directory",
            ),
            "no entry point": ([("plugins/a.mjs", tarfile.REGTYPE, b"x")], "no_entry_point"),
            "empty": ([], "no_entry_point"),
        }
        for label, (members, reason) in cases.items():
            with self.subTest(label):
                self.refused(members, reason)

    def test_the_writer_alone_refuses_a_path_outside_the_release(self) -> None:
        """If a name got past the plain check, the writer still writes nothing outside."""
        destination = self.role / "files" / "releases" / VERSION
        for name in ("../escape.mjs", "/etc/escape.mjs", "a/../../escape.mjs"):
            with self.subTest(name), self.assertRaises(tool.RefusedError) as caught:
                tool.write_release(destination, {"broker.mjs": b"x", name: b"x"})
            self.assertEqual("path_escapes_release", caught.exception.reason)
            self.assertFalse(destination.exists())
            self.assertFalse((self.role / "files" / "releases" / "escape.mjs").exists())
            self.assertFalse(Path("/etc/escape.mjs").exists())

    def test_the_size_limits(self) -> None:
        """A release over a limit is refused."""
        for limit, reason in (
            ("MAX_FILE", "release_too_large"),
            ("MAX_TOTAL", "release_too_large"),
        ):
            with self.subTest(limit), mock.patch.object(tool, limit, 20):
                self.refused(GOOD, reason)
        with mock.patch.object(tool, "MAX_MEMBERS", 2):
            self.refused(GOOD, "too_many_members")
        with mock.patch.object(tool, "MAX_TARBALL", 10):
            status, out = self.run_tool(self.tarball(), write=True)
            self.assertEqual((1, "carry=REFUSED reason=tarball_too_large\n"), (status, out))

    def test_a_digest_that_is_not_the_tarballs_is_refused(self) -> None:
        """One changed byte of the tarball, or any other digest, stops the carry."""
        path = self.tarball()
        status, out = self.run_tool(path, sha="a" * 64, write=True)
        self.assertEqual((1, "carry=REFUSED reason=tarball_digest_differs\n"), (status, out))
        self.assert_untouched()

    def test_input_of_the_wrong_shape_is_refused(self) -> None:
        """A version or digest of the wrong shape, and a tarball that is not a plain file."""
        path = self.tarball()
        for version in ("1.2", "v1.2.3", "1.2.3\n", "1.2.3-rc1", ""):
            with self.subTest(version=version):
                status, out = self.run_tool(path, version=version, write=True)
                self.assertEqual(
                    (1, "carry=REFUSED reason=version_not_major_minor_patch\n"), (status, out)
                )
        for sha in ("A" * 64, "a" * 63, "a" * 64 + "\n", ""):
            with self.subTest(sha=sha):
                status, out = self.run_tool(path, sha=sha, write=True)
                self.assertEqual(
                    (1, "carry=REFUSED reason=digest_not_64_lower_hex\n"), (status, out)
                )
        link = self.root / "link.tar.gz"
        link.symlink_to(path)
        status, out = self.run_tool(link, sha=digest(path.read_bytes()), write=True)
        self.assertEqual((1, "carry=REFUSED reason=tarball_not_a_plain_file\n"), (status, out))
        status, out = self.run_tool(self.root / "absent.tar.gz", sha="a" * 64, write=True)
        self.assertEqual((1, "carry=REFUSED reason=tarball_not_a_plain_file\n"), (status, out))
        self.assert_untouched()

    def test_a_file_that_is_not_a_gzip_tarball_is_refused(self) -> None:
        """Bytes that match their digest but are not a gzip tar stop the carry."""
        path = self.root / "junk.tar.gz"
        path.write_bytes(b"not a tarball at all")
        status, out = self.run_tool(path, write=True)
        self.assertEqual((1, "carry=REFUSED reason=not_a_gzip_tarball\n"), (status, out))
        self.assert_untouched()

    def test_nothing_from_the_tarball_is_printed_when_it_is_refused(self) -> None:
        """A bad member name and its content never reach the output."""
        members: list[Member] = [GOOD[0], (f"{SENTINEL} bad", tarfile.REGTYPE, SENTINEL.encode())]
        status, out = self.run_tool(self.tarball(members), write=True)
        self.assertEqual(1, status)
        self.assertNotIn(SENTINEL, out)


class Shape(unittest.TestCase):
    """The tool is held to the role it feeds."""

    def test_the_path_rule_is_the_pin_checks_own(self) -> None:
        """The tool's path pattern is the one the role's pin check applies."""
        task = (ROLE / "tasks" / "_release_pin.yml").read_text(encoding="utf-8")
        self.assertIn(f"is match('^{tool.PATH_PATTERN.pattern}')", task)
        self.assertIn(r"is not search('(^|/)\.\.(/|\Z)')", task)
        self.assertEqual(r"(^|/)\.\.(/|\Z)", tool.DOT_DOT.pattern)

    def test_the_placeholders_are_the_real_defaults(self) -> None:
        """The two lines the tool replaces are each in the role's defaults exactly once."""
        lines = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8").split("\n")
        self.assertEqual(1, lines.count(tool.VERSION_LINE))
        self.assertEqual(1, lines.count(tool.PINS_LINE))

    def test_the_entry_point_is_the_one_the_role_requires(self) -> None:
        """The role refuses a release with no entry point of this name."""
        task = (ROLE / "tasks" / "_release_pin.yml").read_text(encoding="utf-8")
        self.assertIn(f"'{tool.ENTRY_POINT}' in broker_deploy_release_pins", task)

    def test_pins_that_look_like_other_types_are_read_back_as_text(self) -> None:
        """A path or digest that YAML would read as a number, a boolean or a null stays text."""
        pins = {"true": "1" * 64, "123": "12" + "0" * 62, "null": "1" + "e" * 63, "a.mjs": "0" * 64}
        text = tool.new_defaults(
            "x: 1\n" + tool.VERSION_LINE + "\n" + tool.PINS_LINE + "\ny: 2\n", VERSION, pins
        )
        loaded = yaml.safe_load(text)
        self.assertEqual({VERSION: pins}, loaded["broker_deploy_release_pins"])
        self.assertEqual((1, 2), (loaded["x"], loaded["y"]))

    def test_the_command_line_as_the_runbook_prints_it(self) -> None:
        """In isolated mode, an unknown argument is refused without being shown."""
        with tempfile.TemporaryDirectory() as scratch:
            for arguments in (["--bogus", SENTINEL], [], ["--version", SENTINEL]):
                with self.subTest(arguments=arguments):
                    done = subprocess.run(  # noqa: S603
                        [sys.executable, "-I", str(TOOL), *arguments],
                        capture_output=True,
                        text=True,
                        check=False,
                        cwd=scratch,
                    )
                    self.assertEqual(2, done.returncode)
                    self.assertEqual("carry=REFUSED reason=usage_error\n", done.stdout)
                    self.assertEqual("", done.stderr)


class RoleAgrees(Lab):
    """What the tool writes is accepted, byte for byte, by the role's own pin check."""

    def play(self, directory: Path) -> Outcome:
        """Run the real pin check against the carried release with the written defaults."""
        play = self.root / "play.yml"
        play.write_text(
            "- hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  vars_files:\n"
            f"    - {self.defaults}\n"
            "  tasks:\n"
            f"    - ansible.builtin.include_tasks: {ROLE / 'tasks' / '_release_pin.yml'}\n",
            encoding="utf-8",
        )
        environment = {
            **os.environ,
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_HOME": str(self.root / "ansible-home"),
        }
        done = subprocess.run(  # noqa: S603
            [
                str(ansible_playbook()),
                "-i",
                "localhost,",
                "-e",
                f"broker_deploy_release_dir={directory}",
                "-e",
                f"ansible_python_interpreter={sys.executable}",
                str(play),
            ],
            capture_output=True,
            text=True,
            check=False,
            env=environment,
            timeout=180,
        )
        return Outcome(done.returncode, done.stdout + done.stderr)

    def test_the_role_accepts_what_the_tool_carried(self) -> None:
        """The pin check passes on the carried tree, and fails once one carried byte changes."""
        self.assertEqual(0, self.run_tool(self.tarball(), write=True)[0])
        directory = self.role / "files" / "releases"
        accepted = self.play(directory)
        self.assertEqual(0, accepted.code, accepted.output)
        (directory / VERSION / "broker.mjs").write_bytes(b"changed")
        refused = self.play(directory)
        self.assertNotEqual(0, refused.code)
        self.assertIn("does not have its pinned sha256", refused.output)

    def test_the_role_refuses_the_defaults_before_the_tool_ran(self) -> None:
        """Before a release is carried the role stops, which is the state the tool starts from."""
        refused = self.play(self.role / "files" / "releases")
        self.assertNotEqual(0, refused.code)
        self.assertIn("No release is carried in the role", refused.output)


if __name__ == "__main__":
    unittest.main()
