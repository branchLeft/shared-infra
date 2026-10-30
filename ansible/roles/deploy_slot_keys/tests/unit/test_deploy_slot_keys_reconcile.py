"""Unit tests for deploy_slot_keys_reconcile, run against the real slot program.

The program is loaded by path from hetzner/provision/, the way the module loads the
installed copy, and the host is a fake filesystem that records every write. The
privilege-boundary cases are here: a key may run only its own slot's command, so every
way a stack name or a key could carry a second command, a second slot or a second line
is refused before anything is written, and a program that renders another slot's command
is caught by the read-back. Placeholders only: no value here is a real name or key.
The README gives the command, with the library directory on PYTHONPATH.
"""

import base64
import copy
import dataclasses
import errno
import os
import stat
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import deploy_slot_keys_reconcile as slots
from ruamel.yaml import YAML

REPO = Path(__file__).resolve().parents[5]
PROGRAM_PATH = REPO / "hetzner" / "provision" / "provision_deploy_slot.py"
PROGRAM_SOURCE = PROGRAM_PATH.read_text(encoding="utf-8")

STACK_A = "example-stack-a"
STACK_B = "example-stack-b"
STACK_C = "example-stack-c"
DEPLOY_GID = 1001
HOST_LEVEL_COMMENT = "EXAMPLE_HOST_LEVEL_COMMENT"
NO_ACCOUNT = "no such account on this host"


def make_key(number: int) -> str:
    """Return a well-formed ed25519 public key made for the test, `number` apart from others."""
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes([number]) * 32
    return f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')}"


KEY_A = make_key(1)
KEY_B = make_key(2)
KEY_C = make_key(3)
KEY_A_ROTATED = make_key(4)
HOST_KEY = make_key(9)


def load_program(source: str = PROGRAM_SOURCE) -> slots.Program:
    """Load the program the way the module does, from source."""
    return slots.load_program(source, str(PROGRAM_PATH))


class FakeFs:
    """An in-memory host that answers as the program's real filesystem would."""

    def __init__(self, error: type[Exception]) -> None:
        self.error = error
        self.files: dict[str, tuple[str, int, int, int]] = {}
        self.dirs: dict[str, tuple[int, int, int]] = {}
        self.links: set[str] = set()
        self.gids = {"deploy": DEPLOY_GID}
        self.writes: list[str] = []
        self.fail_on_read: str | None = None

    def add_dir(self, path: str, owner: int, group: int, mode: int) -> None:
        self.dirs[path] = (owner, group, mode)

    def add_file(self, path: str, text: str, owner: int, group: int, mode: int) -> None:
        self.files[path] = (text, owner, group, mode)

    def exists(self, path: str) -> bool:
        return path in self.files or path in self.dirs or path in self.links

    def listdir(self, path: str) -> list[str]:
        names = {
            candidate.rsplit("/", 1)[1]
            for candidate in [*self.files, *self.dirs]
            if candidate.rsplit("/", 1)[0] == path
        }
        return sorted(names)

    def walk(self, path: str) -> list[str]:
        return sorted(
            candidate for candidate in [*self.files, *self.dirs] if candidate.startswith(path + "/")
        )

    def is_symlink(self, path: str) -> bool:
        return path in self.links

    def owner_mode(self, path: str) -> tuple[int, int, int]:
        if path in self.files:
            _text, owner, group, mode = self.files[path]
            return owner, group, mode
        if path in self.dirs:
            return self.dirs[path]
        raise FileNotFoundError(path)

    def account_gid(self, name: str) -> int:
        if name not in self.gids:
            raise self.error(NO_ACCOUNT)
        return self.gids[name]

    def read_text(self, path: str) -> str:
        if self.fail_on_read == path:
            raise OSError(errno.EACCES, "denied", path)
        return self.files[path][0] if path in self.files else ""

    def remove(self, path: str) -> None:
        self.writes.append(f"remove {path}")
        del self.files[path]

    def makedirs(self, path: str, mode: int) -> None:
        if path not in self.dirs:
            self.writes.append(f"makedirs {path}")
            self.dirs[path] = (0, 0, mode)

    def chown(self, path: str, uid: int, gid: int) -> None:
        self.writes.append(f"chown {path}")
        if path in self.files:
            text, _owner, _group, mode = self.files[path]
            self.files[path] = (text, uid, gid, mode)
        else:
            _owner, _group, mode = self.dirs[path]
            self.dirs[path] = (uid, gid, mode)

    def chmod(self, path: str, mode: int) -> None:
        self.writes.append(f"chmod {path}")
        if path in self.files:
            text, owner, group, _mode = self.files[path]
            self.files[path] = (text, owner, group, mode)
        else:
            owner, group, _mode = self.dirs[path]
            self.dirs[path] = (owner, group, mode)

    def replace_text(self, path: str, text: str, mode: int, uid: int, gid: int) -> None:
        self.writes.append(f"replace {path}")
        self.files[path] = (text, uid, gid, mode)

    def snapshot(self) -> tuple[object, object]:
        return copy.deepcopy(self.files), copy.deepcopy(self.dirs)


def cloud_init_host(program: slots.Program) -> FakeFs:
    """Return a host as first boot leaves it: the account, its key, the wrapper, one stack."""
    fs = FakeFs(program.ProvisionError)
    fs.add_dir("/home/deploy", DEPLOY_GID, DEPLOY_GID, 0o755)
    fs.add_dir("/home/deploy/.ssh", DEPLOY_GID, DEPLOY_GID, 0o700)
    fs.add_file(
        "/home/deploy/.ssh/authorized_keys",
        f"restrict {HOST_KEY} {HOST_LEVEL_COMMENT}\n",
        DEPLOY_GID,
        DEPLOY_GID,
        0o600,
    )
    fs.add_file("/home/deploy/.bashrc", "# EXAMPLE\n", DEPLOY_GID, DEPLOY_GID, 0o644)
    fs.add_file("/usr/local/sbin/branchleft-deploy", "#!/bin/sh\n", 0, 0, 0o755)
    fs.add_dir("/opt/branchleft", 0, 0, 0o755)
    fs.add_dir("/opt/branchleft/website", 0, 0, 0o755)
    fs.writes.clear()
    return fs


def entry(stack: str, key: str, *, adopt: bool = False) -> slots.Entry:
    return slots.Entry(stack, key, adopt)


class Host:
    """A program, a fake host and a way to converge it."""

    def __init__(self, source: str = PROGRAM_SOURCE) -> None:
        self.program = load_program(source)
        self.fs = cloud_init_host(self.program)

    def converge(self, entries: list[slots.Entry], *, check: bool = False) -> slots.Result:
        return slots.converge(self.program, self.fs, entries, check_mode=check)

    def authorized(self) -> str:
        return self.fs.files["/home/deploy/.ssh/authorized_keys"][0]


class HostCase(unittest.TestCase):
    """Base for the cases that need a fresh host."""

    def setUp(self) -> None:
        self.host = Host()

    def refusal(self, entries: list[slots.Entry], *, check: bool = False) -> str:
        """Converge, expect a refusal, and return its message."""
        with self.assertRaises(slots.SlotRefusalError) as caught:
            self.host.converge(entries, check=check)
        return str(caught.exception)

    def assert_nothing_written(self) -> None:
        self.assertEqual([], self.host.fs.writes)


class StackNameTests(HostCase):
    """A stack name that could carry a second command or a path is refused before a write."""

    def test_every_shape_that_is_not_a_plain_stack_name_is_refused_before_any_write(self) -> None:
        hostile = [
            "Example",
            "EXAMPLE",
            "a;id",
            "a b",
            "a$(id)",
            "a`id`",
            "../a",
            "a/b",
            "a\nb",
            "a\n",
            "a" * 33,
            "",
            "1a",
            "-a",
            "a&&id",
            "a|id",
            "a'b",
            'a"b',
        ]
        for name in hostile:
            with self.subTest(name=name):
                message = self.refusal([entry(name, KEY_A)])
                self.assertEqual("slot entry number 1: stack-name-invalid", message)
                self.assert_nothing_written()

    def test_a_valid_name_in_second_place_is_reported_by_its_place(self) -> None:
        message = self.refusal([entry(STACK_A, KEY_A), entry("a;id", KEY_B)])
        self.assertEqual("slot entry number 2: stack-name-invalid", message)
        self.assert_nothing_written()

    def test_the_longest_name_is_accepted(self) -> None:
        result = self.host.converge([entry("a" * 32, KEY_A)])
        self.assertEqual(1, result.granted)


class PublicKeyTests(HostCase):
    """A key can only add its own line, and its comment never reaches the file."""

    def test_a_comment_with_a_quote_or_a_shell_command_never_reaches_the_file(self) -> None:
        hostile = f'{KEY_A} x" ; touch /tmp/EXAMPLE_MARKER #'
        self.host.converge([entry(STACK_A, hostile)])
        text = self.host.authorized()
        self.assertNotIn("touch", text)
        self.assertNotIn("EXAMPLE_MARKER", text)
        line = [line for line in text.splitlines() if line.endswith(f"branchleft-slot:{STACK_A}")]
        self.assertEqual([slots.pinned_line(STACK_A, KEY_A)], line)

    def test_a_key_spanning_two_lines_is_refused_before_any_write(self) -> None:
        cases = [
            f"{KEY_A} comment\n{KEY_B}",
            f"{KEY_A}\nrestrict {KEY_B}",
            f"{KEY_A} comment\r{KEY_B}",
        ]
        for text in cases:
            with self.subTest(text=text):
                message = self.refusal([entry(STACK_A, text)])
                self.assertEqual("slot entry number 1: public-key-invalid", message)
                self.assert_nothing_written()

    def test_text_that_is_not_a_key_is_refused(self) -> None:
        for text in ["", "ssh-ed25519", "ssh-dss AAAA", 'command="id" ' + KEY_A, "AAAA"]:
            with self.subTest(text=text):
                message = self.refusal([entry(STACK_A, text)])
                self.assertEqual("slot entry number 1: public-key-invalid", message)
                self.assert_nothing_written()


class OneKeyOneSlotTests(HostCase):
    """No key may reach two slots, or a slot and the host-level key."""

    def test_one_key_declared_for_two_stacks_is_refused_before_any_write(self) -> None:
        message = self.refusal([entry(STACK_A, KEY_A), entry(STACK_B, KEY_A)])
        self.assertEqual("slot entry number 2: key-declared-twice", message)
        self.assert_nothing_written()

    def test_the_same_key_with_another_comment_is_the_same_key(self) -> None:
        message = self.refusal([entry(STACK_A, KEY_A + " one"), entry(STACK_B, KEY_A + " two")])
        self.assertEqual("slot entry number 2: key-declared-twice", message)

    def test_one_stack_declared_twice_is_refused_before_any_write(self) -> None:
        message = self.refusal([entry(STACK_A, KEY_A), entry(STACK_A, KEY_B)])
        self.assertEqual("slot entry number 2: stack-declared-twice", message)
        self.assert_nothing_written()

    def test_a_key_equal_to_the_host_level_key_is_refused_before_any_write(self) -> None:
        message = self.refusal([entry(STACK_A, HOST_KEY + " another comment")])
        self.assertEqual("slot entry number 1: key-already-installed", message)
        self.assert_nothing_written()

    def test_a_key_swapped_between_two_granted_slots_is_refused_before_any_write(self) -> None:
        self.host.converge([entry(STACK_A, KEY_A), entry(STACK_B, KEY_B)])
        self.host.fs.writes.clear()
        message = self.refusal([entry(STACK_A, KEY_B), entry(STACK_B, KEY_A)])
        self.assertEqual("slot entry number 1: key-already-installed", message)
        self.assert_nothing_written()


class GrantRevokeTests(HostCase):
    """The declared list is the exact set, and a second run changes nothing."""

    def test_a_first_run_grants_every_slot_in_the_pinned_shape(self) -> None:
        result = self.host.converge([entry(STACK_A, KEY_A), entry(STACK_B, KEY_B)])
        self.assertEqual(slots.Result(2, 0, 0, 0, changed=True), result)
        lines = self.host.authorized().splitlines()
        self.assertEqual(f"restrict {HOST_KEY} {HOST_LEVEL_COMMENT}", lines[0])
        self.assertEqual(
            [slots.pinned_line(STACK_A, KEY_A), slots.pinned_line(STACK_B, KEY_B)], lines[1:]
        )

    def test_the_pinned_line_is_the_forced_command_of_that_slot_alone(self) -> None:
        self.assertEqual(
            'restrict,command="/usr/bin/sudo -n /usr/local/sbin/branchleft-deploy --slot '
            f'{STACK_A}" {KEY_A} branchleft-slot:{STACK_A}',
            slots.pinned_line(STACK_A, KEY_A),
        )

    def test_a_second_run_changes_nothing_and_writes_nothing(self) -> None:
        declared = [entry(STACK_A, KEY_A), entry(STACK_B, KEY_B)]
        self.host.converge(declared)
        self.host.fs.writes.clear()
        result = self.host.converge(declared)
        self.assertEqual(slots.Result(0, 0, 0, 2, changed=False), result)
        self.assert_nothing_written()

    def test_a_changed_key_is_rotated_and_the_old_key_no_longer_appears(self) -> None:
        self.host.converge([entry(STACK_A, KEY_A)])
        result = self.host.converge([entry(STACK_A, KEY_A_ROTATED)])
        self.assertEqual(slots.Result(0, 1, 0, 0, changed=True), result)
        self.assertNotIn(KEY_A.split(" ")[1], self.host.authorized())
        self.assertIn(slots.pinned_line(STACK_A, KEY_A_ROTATED), self.host.authorized())

    def test_a_slot_left_out_is_revoked_and_the_host_level_line_is_untouched(self) -> None:
        self.host.converge([entry(STACK_A, KEY_A), entry(STACK_B, KEY_B)])
        result = self.host.converge([entry(STACK_A, KEY_A)])
        self.assertEqual(slots.Result(0, 0, 1, 1, changed=True), result)
        text = self.host.authorized()
        self.assertTrue(text.startswith(f"restrict {HOST_KEY} {HOST_LEVEL_COMMENT}\n"))
        self.assertNotIn(KEY_B.split(" ")[1], text)
        self.assertNotIn(f"/etc/branchleft/deploy-slots/{STACK_B}.pub", self.host.fs.files)

    def test_an_empty_list_is_not_declared_and_never_revokes_anything(self) -> None:
        self.host.converge([entry(STACK_A, KEY_A)])
        before = self.host.fs.snapshot()
        self.host.fs.writes.clear()
        result = self.host.converge([])
        self.assertEqual(slots.Result(0, 0, 0, 0, changed=False), result)
        self.assertEqual(before, self.host.fs.snapshot())
        self.assert_nothing_written()


class CheckModeTests(HostCase):
    """The plan reads the host and changes nothing."""

    def test_check_mode_reports_the_change_and_writes_nothing(self) -> None:
        before = self.host.fs.snapshot()
        result = self.host.converge([entry(STACK_A, KEY_A)], check=True)
        self.assertEqual(slots.Result(1, 0, 0, 0, changed=True), result)
        self.assertEqual(before, self.host.fs.snapshot())
        self.assert_nothing_written()

    def test_check_mode_on_a_converged_host_reports_no_change(self) -> None:
        declared = [entry(STACK_A, KEY_A)]
        self.host.converge(declared)
        self.assertFalse(self.host.converge(declared, check=True).changed)

    def test_check_mode_still_refuses_what_an_apply_would_refuse(self) -> None:
        message = self.refusal([entry(STACK_A, KEY_A), entry(STACK_B, KEY_A)], check=True)
        self.assertEqual("slot entry number 2: key-declared-twice", message)


class AdoptionTests(HostCase):
    """A stack the host already runs is granted only when the entry says so."""

    def test_a_stack_already_on_the_host_is_refused_unless_adopted(self) -> None:
        message = self.refusal([entry("website", KEY_A)])
        self.assertEqual("slot entry number 1: stack-already-on-host-not-adopted", message)
        self.assert_nothing_written()

    def test_an_adopted_stack_is_granted_and_then_unchanged(self) -> None:
        declared = [entry("website", KEY_A, adopt=True)]
        self.assertEqual(1, self.host.converge(declared).granted)
        self.assertEqual(slots.Result(0, 0, 0, 1, changed=False), self.host.converge(declared))

    def test_a_granted_slot_does_not_need_adoption_again(self) -> None:
        self.host.converge([entry("website", KEY_A, adopt=True)])
        result = self.host.converge([entry("website", KEY_A)])
        self.assertFalse(result.changed)


class HardeningTests(HostCase):
    """The deploy account must not be able to write anything in its own home."""

    def test_a_first_run_takes_the_whole_home_to_root(self) -> None:
        self.host.converge([entry(STACK_A, KEY_A)])
        self.assertEqual(
            (0, DEPLOY_GID, 0o640), self.host.fs.owner_mode("/home/deploy/.ssh/authorized_keys")
        )
        self.assertEqual((0, DEPLOY_GID, 0o750), self.host.fs.owner_mode("/home/deploy"))
        self.assertEqual(0, self.host.fs.owner_mode("/home/deploy/.bashrc")[0])
        self.assertEqual([], self.host.program.unhardened_paths(fs=self.host.fs))

    def test_a_dotfile_the_account_can_write_is_drift_and_is_repaired(self) -> None:
        declared = [entry(STACK_A, KEY_A)]
        self.host.converge(declared)
        self.host.fs.chown("/home/deploy/.bashrc", DEPLOY_GID, DEPLOY_GID)
        self.host.fs.chmod("/home/deploy/.bashrc", 0o666)
        self.host.fs.writes.clear()
        planned = self.host.converge(declared, check=True)
        self.assertEqual(slots.Result(0, 0, 0, 1, changed=True), planned)
        self.assert_nothing_written()
        self.assertEqual(slots.Result(0, 0, 0, 1, changed=True), self.host.converge(declared))
        self.assertEqual((0, DEPLOY_GID, 0o644), self.host.fs.owner_mode("/home/deploy/.bashrc"))
        self.assertFalse(self.host.converge(declared).changed)

    def test_a_new_file_the_account_owns_is_drift_and_is_repaired(self) -> None:
        declared = [entry(STACK_A, KEY_A)]
        self.host.converge(declared)
        self.host.fs.add_file("/home/deploy/.profile", "x\n", DEPLOY_GID, DEPLOY_GID, 0o644)
        self.assertTrue(self.host.converge(declared, check=True).changed)
        self.host.converge(declared)
        self.assertEqual(0, self.host.fs.owner_mode("/home/deploy/.profile")[0])

    def test_authorized_keys_with_the_wrong_mode_is_drift_and_is_repaired(self) -> None:
        declared = [entry(STACK_A, KEY_A)]
        self.host.converge(declared)
        self.host.fs.chmod("/home/deploy/.ssh/authorized_keys", 0o666)
        self.assertTrue(self.host.converge(declared, check=True).changed)
        self.host.converge(declared)
        self.assertEqual(0o640, self.host.fs.owner_mode("/home/deploy/.ssh/authorized_keys")[2])

    def test_a_register_file_with_the_wrong_mode_is_drift_and_is_repaired(self) -> None:
        declared = [entry(STACK_A, KEY_A), entry(STACK_B, KEY_B)]
        self.host.converge(declared)
        path = f"/etc/branchleft/deploy-slots/{STACK_B}.pub"
        self.host.fs.chmod(path, 0o644)
        self.assertTrue(self.host.converge(declared, check=True).changed)
        self.host.converge(declared)
        self.assertEqual((0, 0, 0o600), self.host.fs.owner_mode(path))

    def test_an_authorized_keys_line_that_is_missing_is_drift_and_is_repaired(self) -> None:
        declared = [entry(STACK_A, KEY_A)]
        self.host.converge(declared)
        self.host.fs.add_file(
            "/home/deploy/.ssh/authorized_keys",
            f"restrict {HOST_KEY} {HOST_LEVEL_COMMENT}\n",
            0,
            DEPLOY_GID,
            0o640,
        )
        self.assertTrue(self.host.converge(declared, check=True).changed)
        self.host.converge(declared)
        self.assertIn(slots.pinned_line(STACK_A, KEY_A), self.host.authorized())


class HostRefusalTests(HostCase):
    """The host must be the shape first boot leaves, and the register must be explained."""

    def test_a_hand_edited_managed_line_stops_the_run_with_nothing_written(self) -> None:
        self.host.converge([entry(STACK_A, KEY_A)])
        path = "/home/deploy/.ssh/authorized_keys"
        text, owner, group, mode = self.host.fs.files[path]
        edited = text.replace("--slot", "--slot x-")
        self.host.fs.add_file(path, edited, owner, group, mode)
        self.host.fs.writes.clear()
        self.assertEqual(
            "host: register-and-authorized-keys-disagree",
            self.refusal([entry(STACK_A, KEY_A)]),
        )
        self.assert_nothing_written()

    def test_a_marked_line_the_register_does_not_explain_stops_the_run(self) -> None:
        self.host.converge([entry(STACK_A, KEY_A)])
        path = "/home/deploy/.ssh/authorized_keys"
        text, owner, group, mode = self.host.fs.files[path]
        self.host.fs.add_file(
            path, text + f"restrict {KEY_C} branchleft-slot:{STACK_C}\n", owner, group, mode
        )
        self.host.fs.writes.clear()
        self.assertEqual(
            "host: register-and-authorized-keys-disagree",
            self.refusal([entry(STACK_A, KEY_A)]),
        )
        self.assert_nothing_written()

    def test_a_register_file_that_is_not_a_key_stops_the_run(self) -> None:
        self.host.fs.add_file(
            f"/etc/branchleft/deploy-slots/{STACK_A}.pub", "not a key\n", 0, 0, 0o600
        )
        self.assertEqual("host: register-unreadable", self.refusal([entry(STACK_B, KEY_B)]))
        self.assert_nothing_written()

    def test_a_host_with_no_wrapper_is_refused(self) -> None:
        del self.host.fs.files["/usr/local/sbin/branchleft-deploy"]
        self.assertEqual(
            "host: wrapper-missing-or-not-root-owned", self.refusal([entry(STACK_A, KEY_A)])
        )
        self.assert_nothing_written()

    def test_a_wrapper_the_deploy_account_could_replace_is_refused(self) -> None:
        wrapper = "/usr/local/sbin/branchleft-deploy"
        for owner, mode in [(DEPLOY_GID, 0o755), (0, 0o775), (0, 0o644)]:
            with self.subTest(owner=owner, mode=mode):
                self.host.fs.add_file(wrapper, "#!/bin/sh\n", owner, 0, mode)
                self.assertEqual(
                    "host: wrapper-missing-or-not-root-owned", self.refusal([entry(STACK_A, KEY_A)])
                )

    def test_a_wrapper_that_is_a_link_is_refused(self) -> None:
        self.host.fs.links.add("/usr/local/sbin/branchleft-deploy")
        self.assertEqual(
            "host: wrapper-missing-or-not-root-owned", self.refusal([entry(STACK_A, KEY_A)])
        )

    def test_a_host_with_no_deploy_account_is_refused_in_check_mode_too(self) -> None:
        self.host.fs.gids.clear()
        self.assertEqual(
            "host: deploy-account-or-home-missing",
            self.refusal([entry(STACK_A, KEY_A)], check=True),
        )

    def test_a_host_with_no_home_is_refused(self) -> None:
        del self.host.fs.dirs["/home/deploy/.ssh"]
        self.assertEqual(
            "host: deploy-account-or-home-missing", self.refusal([entry(STACK_A, KEY_A)])
        )
        self.assert_nothing_written()


class ProgramTests(unittest.TestCase):
    """The program is trusted only if it is the pinned program, and its output is checked."""

    def mutated(self, old: str, new: str) -> str:
        self.assertEqual(1, PROGRAM_SOURCE.count(old), "the mutation must hit exactly once")
        return PROGRAM_SOURCE.replace(old, new)

    def test_a_program_whose_constant_differs_from_the_pinned_one_is_refused(self) -> None:
        for old, new in [
            ('SUDO = "/usr/bin/sudo"', 'SUDO = "/usr/bin/doas"'),
            ('WRAPPER = "/usr/local/sbin/branchleft-deploy"', 'WRAPPER = "/usr/local/sbin/other"'),
            ('MANAGED_MARKER = "branchleft-slot:"', 'MANAGED_MARKER = "other-slot:"'),
            ("AUTHORIZED_KEYS_MODE = 0o640", "AUTHORIZED_KEYS_MODE = 0o644"),
        ]:
            with self.subTest(constant=old), self.assertRaises(slots.HostRefusalError) as caught:
                load_program(self.mutated(old, new))
            self.assertEqual("host: program-constants-differ-from-pinned", str(caught.exception))

    def test_a_source_that_does_not_load_is_refused(self) -> None:
        with self.assertRaises(slots.HostRefusalError) as caught:
            slots.load_program("def (:\n", "EXAMPLE")
        self.assertEqual("host: program-not-loadable", str(caught.exception))

    def test_a_program_that_renders_another_slots_command_fails_the_plan(self) -> None:
        host = Host(self.mutated("--slot {stack}", "--slot example-other"))
        with self.assertRaises(slots.HostRefusalError) as caught:
            host.converge([entry(STACK_A, KEY_A)])
        self.assertEqual("host: rendered-line-differs-from-pinned-shape", str(caught.exception))
        self.assertEqual([], host.fs.writes)

    def test_a_program_that_renders_another_slots_command_fails_the_readback(self) -> None:
        # The program renders correctly and writes something else, so only the read-back
        # of the file can see it. The bad line must not be left in place.
        old = "rendered = render_authorized_keys(fs.read_text(authorized_keys), slots)"
        host = Host(self.mutated(old, old + '.replace("--slot ", "--slot example-other-")'))
        original = host.authorized()
        with self.assertRaises(slots.HostRefusalError) as caught:
            host.converge([entry(STACK_A, KEY_A)])
        self.assertEqual("host: readback-line-differs-from-pinned-shape", str(caught.exception))
        self.assertEqual(original, host.authorized())

    def test_a_program_that_writes_a_second_line_for_a_key_fails_the_readback(self) -> None:
        old = "rendered = render_authorized_keys(fs.read_text(authorized_keys), slots)"
        extra = old + '\n    rendered += "restrict " + next(iter(slots.values())) + " x\\n"'
        host = Host(self.mutated(old, extra))
        with self.assertRaises(slots.HostRefusalError) as caught:
            host.converge([entry(STACK_A, KEY_A)])
        self.assertEqual("host: readback-line-differs-from-pinned-shape", str(caught.exception))

    def test_a_program_that_leaves_the_register_unwritten_fails_the_readback(self) -> None:
        old = 'fs.replace_text(entry, f"{public_key}\\n", SLOT_FILE_MODE, 0, 0)'
        host = Host(self.mutated(old, "pass"))
        with self.assertRaises(slots.HostRefusalError) as caught:
            host.converge([entry(STACK_A, KEY_A)])
        self.assertEqual("host: readback-register-differs-from-declared", str(caught.exception))


class OutputTests(HostCase):
    """The log of a plan is public: nothing that leaves the module names a stack or a key."""

    def test_a_result_holds_counts_and_a_flag_only(self) -> None:
        result = self.host.converge([entry(STACK_A, KEY_A)])
        for name, value in dataclasses.asdict(result).items():
            with self.subTest(field=name):
                self.assertIsInstance(value, int)

    def test_no_message_names_a_stack_a_key_or_a_fingerprint(self) -> None:
        program = self.host.program
        secrets = [STACK_A, STACK_B, STACK_C, "website"]
        for key in (KEY_A, KEY_B, KEY_C, HOST_KEY):
            secrets.extend([key, key.split(" ")[1], program.fingerprint(key)])
        messages: list[str] = []
        for declared in (
            [entry(STACK_A + ";", KEY_A)],
            [entry(STACK_A, "junk " + KEY_A)],
            [entry(STACK_A, KEY_A), entry(STACK_B, KEY_A)],
            [entry(STACK_A, KEY_A), entry(STACK_A, KEY_B)],
            [entry(STACK_A, HOST_KEY)],
            [entry("website", KEY_A)],
        ):
            messages.append(self.refusal(declared))
        self.host.converge([entry(STACK_A, KEY_A), entry(STACK_B, KEY_B)])
        messages.append(self.refusal([entry(STACK_A, KEY_B), entry(STACK_B, KEY_A)]))
        self.host.fs.add_file(f"/etc/branchleft/deploy-slots/{STACK_C}.pub", "x\n", 0, 0, 0o600)
        messages.append(self.refusal([entry(STACK_A, KEY_A)]))
        self.assertEqual(8, len(messages))
        for message in messages:
            for secret in secrets:
                with self.subTest(message=message):
                    self.assertNotIn(secret, message)

    def test_a_filesystem_error_is_reported_by_its_code_and_not_its_path(self) -> None:
        self.host.fs.fail_on_read = "/home/deploy/.ssh/authorized_keys"
        with self.assertRaises(slots.HostRefusalError) as caught:
            slots.converge_reporting(
                self.host.program, self.host.fs, [entry(STACK_A, KEY_A)], check_mode=False
            )
        self.assertEqual("host: filesystem-error-EACCES", str(caught.exception))
        self.assertNotIn("authorized_keys", str(caught.exception))

    def test_an_entry_dataclass_does_not_print_its_key(self) -> None:
        self.assertNotIn(KEY_A.split(" ")[1], repr(entry(STACK_A, KEY_A)))
        self.assertNotIn(KEY_A.split(" ")[1], repr(slots.Valid(STACK_A, KEY_A, False)))


PROGRAM_ON_HOST = "/usr/local/sbin/EXAMPLE_PROGRAM"
ROOT_DIRECTORY = (stat.S_IFDIR | 0o755, 0)
ROOT_PROGRAM = (stat.S_IFREG | 0o755, 0)


def fake_lstat(overrides: Mapping[str, tuple[int, int]]) -> Callable[[str], os.stat_result]:
    """Return an lstat of a host where every path is root's and closed, but for ``overrides``.

    An override is a path's type and mode, and its owner.
    """

    def lstat(path: str) -> os.stat_result:
        default = ROOT_PROGRAM if path == PROGRAM_ON_HOST else ROOT_DIRECTORY
        mode, owner = overrides.get(path, default)
        return os.stat_result((mode, 1, 1, 1, owner, 0, 0, 0, 0, 0))

    return lstat


class TrustedProgramTests(unittest.TestCase):
    """The program runs as root, so it and every directory above it must be root's alone."""

    def test_a_path_that_is_not_absolute_and_normal_is_refused(self) -> None:
        for path in ["program", "/usr/../usr/local/sbin/x", "/usr//local/x", "/usr/local/x/"]:
            with self.subTest(path=path), self.assertRaises(slots.HostRefusalError):
                slots.read_trusted_program(path)

    def test_a_missing_program_is_refused(self) -> None:
        with self.assertRaises(slots.HostRefusalError) as caught:
            slots.read_trusted_program("/nonexistent/EXAMPLE_PROGRAM")
        self.assertEqual("host: program-missing-or-not-root-owned", str(caught.exception))

    def test_a_clean_host_passes_the_checks_up_to_opening_the_file(self) -> None:
        # The control for the refusals below: with nothing overridden the metadata checks
        # pass, and the refusal is only that the file is not on this machine.
        with self.assertRaises(slots.HostRefusalError) as caught:
            slots.read_trusted_program(PROGRAM_ON_HOST, lstat=fake_lstat({}))
        self.assertEqual("host: program-missing-or-not-root-owned", str(caught.exception))
        self.assertTrue(slots.is_trusted(fake_lstat({})("/usr"), directory=True, owner_uid=0))
        self.assertTrue(
            slots.is_trusted(fake_lstat({})(PROGRAM_ON_HOST), directory=False, owner_uid=0)
        )

    def test_a_directory_above_the_program_that_others_can_write_is_refused(self) -> None:
        for bad in [stat.S_IFDIR | 0o775, stat.S_IFDIR | 0o757, stat.S_IFDIR | 0o1777]:
            with self.subTest(mode=oct(bad)):
                stat_of = fake_lstat({"/usr/local": (bad, 0)})
                self.assertFalse(
                    slots.is_trusted(stat_of("/usr/local"), directory=True, owner_uid=0)
                )
                with self.assertRaises(slots.HostRefusalError):
                    slots.read_trusted_program(PROGRAM_ON_HOST, lstat=stat_of)

    def test_a_directory_above_the_program_owned_by_another_account_is_refused(self) -> None:
        stat_of = fake_lstat({"/usr": (ROOT_DIRECTORY[0], 1000)})
        self.assertFalse(slots.is_trusted(stat_of("/usr"), directory=True, owner_uid=0))
        with self.assertRaises(slots.HostRefusalError):
            slots.read_trusted_program(PROGRAM_ON_HOST, lstat=stat_of)

    def test_a_link_in_the_path_is_refused(self) -> None:
        stat_of = fake_lstat({"/usr/local": (stat.S_IFLNK | 0o777, 0)})
        self.assertFalse(slots.is_trusted(stat_of("/usr/local"), directory=True, owner_uid=0))
        with self.assertRaises(slots.HostRefusalError):
            slots.read_trusted_program(PROGRAM_ON_HOST, lstat=stat_of)

    def test_a_program_that_is_a_link_or_is_writable_or_is_not_roots_is_refused(self) -> None:
        for mode, owner in [
            (stat.S_IFLNK | 0o777, 0),
            (stat.S_IFREG | 0o775, 0),
            (stat.S_IFREG | 0o757, 0),
            (stat.S_IFREG | 0o755, 1000),
            (stat.S_IFDIR | 0o755, 0),
        ]:
            with self.subTest(mode=oct(mode), owner=owner):
                stat_of = fake_lstat({PROGRAM_ON_HOST: (mode, owner)})
                self.assertFalse(
                    slots.is_trusted(stat_of(PROGRAM_ON_HOST), directory=False, owner_uid=0)
                )
                with self.assertRaises(slots.HostRefusalError):
                    slots.read_trusted_program(PROGRAM_ON_HOST, lstat=stat_of)

    def test_a_program_the_owner_alone_can_write_is_read(self) -> None:
        directory = stat.S_IFDIR | 0o755
        with tempfile.TemporaryDirectory() as work:
            program = Path(work) / "EXAMPLE_PROGRAM"
            program.write_text("EXAMPLE = 1\n", encoding="utf-8")
            program.chmod(0o755)
            real = os.lstat

            def lstat(path: str) -> os.stat_result:
                if path == str(program):
                    return real(path)
                return os.stat_result((directory, 1, 1, 1, os.getuid(), 0, 0, 0, 0, 0))

            text = slots.read_trusted_program(str(program), lstat=lstat, owner_uid=os.getuid())
        self.assertEqual("EXAMPLE = 1\n", text)


class ArgumentSpecTests(unittest.TestCase):
    """The argument_spec agrees with the documentation, and the key is a secret."""

    def test_the_documentation_states_the_argument_spec(self) -> None:
        document: Mapping[str, object] = YAML(typ="safe").load(slots.DOCUMENTATION)
        documented = cast("Mapping[str, Mapping[str, object]]", document["options"])
        self.assertEqual(set(documented), set(slots.ARGUMENT_SPEC))
        for name, option in slots.ARGUMENT_SPEC.items():
            with self.subTest(option=name):
                doc = documented[name]
                self.assertEqual(doc["type"], option["type"])
                self.assertEqual(doc.get("required", False), option.get("required", False))
        spec_options = cast(
            "Mapping[str, Mapping[str, object]]", slots.ARGUMENT_SPEC["slots"]["options"]
        )
        doc_options = cast("Mapping[str, Mapping[str, object]]", documented["slots"]["suboptions"])
        self.assertEqual(set(doc_options), set(spec_options))
        for name, sub in spec_options.items():
            with self.subTest(suboption=name):
                self.assertEqual(doc_options[name]["type"], sub["type"])
                self.assertEqual(doc_options[name].get("default"), sub.get("default"))

    def test_the_public_key_is_a_no_log_option_and_the_stack_is_not_a_default(self) -> None:
        options = cast(
            "Mapping[str, Mapping[str, object]]", slots.ARGUMENT_SPEC["slots"]["options"]
        )
        self.assertIs(True, options["public_key"]["no_log"])
        self.assertIs(True, slots.ARGUMENT_SPEC["slots"]["required"])
        self.assertNotIn("default", slots.ARGUMENT_SPEC["slots"])

    def test_entries_are_built_from_the_validated_list(self) -> None:
        built = slots.entries_from_params(
            [
                {"stack": STACK_A, "public_key": KEY_A, "adopt_existing": True},
                {"stack": STACK_B, "public_key": KEY_B},
            ]
        )
        self.assertEqual([entry(STACK_A, KEY_A, adopt=True), entry(STACK_B, KEY_B)], built)

    def test_a_value_of_the_wrong_type_is_refused(self) -> None:
        for bad in [
            "text",
            [1],
            [{"stack": 1, "public_key": KEY_A}],
            [{"stack": "a", "public_key": KEY_A, "adopt_existing": "yes"}],
        ]:
            with self.subTest(bad=bad), self.assertRaises(slots.WrongTypeError):
                slots.entries_from_params(bad)


class PinnedAgreementTests(unittest.TestCase):
    """The module's pins and the program's constants are the same values."""

    def test_every_pinned_constant_equals_the_program_constant(self) -> None:
        program = load_program()
        for name, pinned in slots.PINNED_PROGRAM_CONSTANTS.items():
            with self.subTest(constant=name):
                self.assertEqual(pinned, getattr(program, name))

    def test_the_program_forced_command_is_built_from_the_pinned_flag(self) -> None:
        program = load_program()
        line = program.render_authorized_keys("", {STACK_A: KEY_A})
        self.assertEqual(slots.pinned_line(STACK_A, KEY_A) + "\n", line)


if __name__ == "__main__":
    unittest.main()
