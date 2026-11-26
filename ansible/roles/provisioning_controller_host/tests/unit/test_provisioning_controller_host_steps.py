"""Unit tests for the controller steps program: the register check and the stack passphrase escrow.

Each control that a test names was run red on a sabotaged copy and green on the file as shipped
(the pull request records both). The passphrase is made in a temporary directory and is a throwaway.
"""

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import provisioning_controller_steps as program

ENTRY: dict[str, object] = {
    "tenantId": "demo-tenant",
    "mediaFolder": "demo-tenant",
    "stateFolder": "abc123",
    "mediaBucket": "bucket-a",
    "appHostSlot": "demo-tenant",
    "appHostPort": 8101,
    "appHostUid": 30001,
    "hostnames": [],
}
OTHER: dict[str, object] = {
    **ENTRY,
    "tenantId": "t2",
    "appHostSlot": "t2",
    "appHostPort": 8102,
    "appHostUid": 30002,
    "mediaBucket": "b2",
    "mediaFolder": "f2",
    "stateFolder": "s2",
}
INPUTS: dict[str, object] = {
    "slot": "demo-tenant",
    "port": 8101,
    "uid": 30001,
    "bucket": "bucket-a",
    "folder": "demo-tenant",
}
CONFIRM = "confirm-register-assignment"
ESCROW = "escrow-stack-passphrase"


class Case(unittest.TestCase):
    """A register and an escrow directory in a temporary place."""

    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name)
        self.register = self.root / "register.json"
        self.escrow = self.root / "escrow"
        self.escrow.mkdir()
        self.escrow.chmod(0o700)

    def write_register(self, *entries: dict[str, object], mode: int = 0o644) -> None:
        """Write a register of these entries."""
        self.register.write_text(json.dumps({"entries": list(entries)}), encoding="utf-8")
        self.register.chmod(mode)

    def step(self, step: str, inputs: dict[str, object]) -> int:
        """Run one step request and return the exit status."""
        request = {"key": "k", "id": step, "idempotencyKey": "i", "inputs": inputs}
        return program.run(request, str(self.register), str(self.escrow))


class ConfirmTests(Case):
    """The register check."""

    def test_the_delivered_entry_passes(self) -> None:
        self.write_register(ENTRY)
        self.assertEqual(self.step(CONFIRM, INPUTS), program.EXIT_OK)

    def test_each_number_that_differs_is_refused_for_good(self) -> None:
        self.write_register(ENTRY)
        for name in ("port", "uid", "bucket", "folder"):
            with self.subTest(name):
                other = "other" if isinstance(INPUTS[name], str) else 1
                self.assertEqual(self.step(CONFIRM, {**INPUTS, name: other}), program.EXIT_REFUSED)

    def test_a_slot_that_is_not_in_the_register_or_is_in_it_twice(self) -> None:
        self.write_register(ENTRY)
        self.assertEqual(self.step(CONFIRM, {**INPUTS, "slot": "x"}), program.EXIT_REFUSED)
        self.write_register(ENTRY, ENTRY)
        self.assertEqual(self.step(CONFIRM, INPUTS), program.EXIT_REFUSED)

    def test_a_value_another_entry_holds_is_refused(self) -> None:
        """The guard: two tenants may not share a port, uid, bucket, folder or state folder."""
        for field in ("appHostPort", "appHostUid", "mediaBucket", "mediaFolder", "stateFolder"):
            with self.subTest(field):
                self.write_register(ENTRY, {**OTHER, field: ENTRY[field]})
                self.assertEqual(self.step(CONFIRM, INPUTS), program.EXIT_REFUSED)

    def test_a_distinct_second_entry_is_fine(self) -> None:
        self.write_register(ENTRY, OTHER)
        self.assertEqual(self.step(CONFIRM, INPUTS), program.EXIT_OK)

    def test_a_register_others_can_write_or_that_is_not_one(self) -> None:
        self.write_register(ENTRY, mode=0o666)
        self.assertEqual(self.step(CONFIRM, INPUTS), program.EXIT_REFUSED)
        for text in ("nope", "[]", '{"entries": 1}', '{"entries": [1]}'):
            with self.subTest(text):
                self.register.write_text(text, encoding="utf-8")
                self.register.chmod(0o644)
                self.assertEqual(self.step(CONFIRM, INPUTS), program.EXIT_REFUSED)

    def test_a_missing_register_is_refused(self) -> None:
        self.assertEqual(self.step(CONFIRM, INPUTS), program.EXIT_REFUSED)


class EscrowTests(Case):
    """The stack passphrase escrow."""

    NAME = "STACK_PASSPHRASE_demo-tenant"

    def test_the_first_call_makes_one_private_file_and_the_second_leaves_it_alone(self) -> None:
        """The guard: a passphrase that exists is never made again."""
        inputs: dict[str, object] = {"secretName": self.NAME}
        self.assertEqual(self.step(ESCROW, inputs), program.EXIT_OK)
        path = self.escrow / self.NAME
        first = path.read_bytes()
        info = path.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_uid, os.geteuid())
        self.assertEqual(len(first), 43)
        self.assertEqual(self.step(ESCROW, inputs), program.EXIT_OK)
        self.assertEqual(path.read_bytes(), first)
        self.assertEqual(path.stat().st_ino, info.st_ino)

    def test_two_tenants_get_two_different_passphrases(self) -> None:
        for slot in ("a", "b"):
            self.step(ESCROW, {"secretName": f"STACK_PASSPHRASE_{slot}"})
        self.assertNotEqual(
            (self.escrow / "STACK_PASSPHRASE_a").read_bytes(),
            (self.escrow / "STACK_PASSPHRASE_b").read_bytes(),
        )

    def test_a_name_that_could_leave_the_directory_is_refused_and_makes_nothing(self) -> None:
        for bad in ("../x", "STACK_PASSPHRASE_/x", "STACK_PASSPHRASE_", "OTHER_x", "", 3, None):
            with self.subTest(str(bad)):
                self.assertEqual(self.step(ESCROW, {"secretName": bad}), program.EXIT_REFUSED)
        self.assertEqual(list(self.escrow.iterdir()), [])

    def test_a_file_that_is_not_fit_is_refused_and_not_replaced(self) -> None:
        path = self.escrow / self.NAME
        wide = self.escrow / "wide-source"
        wide.write_text("x", encoding="utf-8")
        wide.chmod(0o644)
        for label in ("wide mode", "empty", "link"):
            with self.subTest(label):
                if path.is_symlink() or path.exists():
                    path.unlink()
                if label == "wide mode":
                    path.write_text("x", encoding="utf-8")
                    path.chmod(0o644)
                elif label == "empty":
                    path.write_text("", encoding="utf-8")
                    path.chmod(0o600)
                else:
                    path.symlink_to(wide)
                before = os.lstat(path)
                self.assertEqual(self.step(ESCROW, {"secretName": self.NAME}), program.EXIT_REFUSED)
                self.assertEqual(os.lstat(path).st_ino, before.st_ino)

    def test_an_escrow_directory_others_can_reach_is_refused(self) -> None:
        self.escrow.chmod(0o755)
        self.assertEqual(self.step(ESCROW, {"secretName": self.NAME}), program.EXIT_REFUSED)
        self.assertEqual(list(self.escrow.iterdir()), [])

    def test_nothing_is_printed_by_the_program_run_as_a_command(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        request = json.dumps({"id": ESCROW, "inputs": {"secretName": self.NAME}})
        argv = ["--register", str(self.register), "--escrow-dir", str(self.escrow)]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = program.main(argv, request)
        self.assertEqual((code, out.getvalue(), err.getvalue()), (0, "", ""))


class DispatchTests(Case):
    """Steps this program does not serve, and requests that are not requests."""

    def test_every_other_step_is_refused_and_does_nothing(self) -> None:
        self.write_register(ENTRY)
        for step in ("enrol-backups", "create-owner-account", "register-host-keys", "", "x"):
            with self.subTest(step):
                self.assertEqual(self.step(step, INPUTS), program.EXIT_REFUSED)
        self.assertEqual(list(self.escrow.iterdir()), [])

    def test_a_request_that_is_not_an_object_with_inputs(self) -> None:
        requests: list[object] = [None, [], "x", {"id": 3, "inputs": {}}, {"id": CONFIRM}]
        for request in requests:
            with self.subTest(str(request)):
                code = program.run(request, str(self.register), str(self.escrow))
                self.assertEqual(code, program.EXIT_REFUSED)

    def test_input_that_is_not_json_or_paths_that_are_not_absolute(self) -> None:
        argv = ["--register", str(self.register), "--escrow-dir", str(self.escrow)]
        self.assertEqual(program.main(argv, "not json"), program.EXIT_REFUSED)
        relative = ["--register", "r", "--escrow-dir", str(self.escrow)]
        self.assertEqual(program.main(relative, "{}"), program.EXIT_REFUSED)


if __name__ == "__main__":
    unittest.main()
