"""Unit tests for restart_stamp: the read, the decision, the adoption and the record.

Run from a role's directory with library/ on PYTHONPATH, the way
``ansible/checks/run_role_unit_tests.py`` does, or from the pattern's own directory. Every role that
keeps a stamp links this file, so the module is proved in each of them. Every value here is a
throwaway: a fingerprint is the sha256 of a word made for the test.

Sabotage, the red and then green for the change that made them: in library/restart_stamp.py make
``decide`` return ``due`` for a closed gate, make ``write_stamps`` write in check mode for record,
drop the sha256 test in ``_fingerprint_to_write``, or make ``read_stamps`` return ``absent`` for an
unreadable stamp when it was told to fail. The test named after each fails; put the line back and
it passes.
"""

import contextlib
import grp
import hashlib
import io
import json
import os
import pwd
import tempfile
import unittest
from pathlib import Path

import restart_stamp as module
from ansible.module_utils.testing import patch_module_args

FIRST = hashlib.sha256(b"first").hexdigest()
SECOND = hashlib.sha256(b"second").hexdigest()
OWNER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
ME = module.Identity(uid=os.getuid(), gid=os.getgid(), mode=0o600)


def run_main(
    args: dict[str, object], *, check_mode: bool = False
) -> tuple[bool, dict[str, object]]:
    """Run main as Ansible would; return (failed, the JSON it printed)."""
    full = {"owner": OWNER, "group": GROUP, **args, "_ansible_check_mode": check_mode}
    buffer = io.StringIO()
    with patch_module_args(full), contextlib.redirect_stdout(buffer):
        with contextlib.suppress(SystemExit):
            module.main()
    document = json.loads(buffer.getvalue())
    return bool(document.get("failed")), document


class Workdir(unittest.TestCase):
    """A directory of throwaway stamps."""

    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.dir = Path(holder.name)

    def stamp(self, name: str, content: str | None = None) -> Path:
        path = self.dir / name
        if content is not None:
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
        return path


class Read(Workdir):
    def test_a_stamp_that_is_not_there_reads_as_the_absent_word(self) -> None:
        found = module.read_stamps(
            [module.StampClass("a", file=str(self.stamp("a")))], "none", "fail"
        )
        self.assertEqual(found, {"a": "none"})

    def test_a_stamp_reads_back_trimmed(self) -> None:
        path = self.stamp("a", f"{FIRST}\n")
        found = module.read_stamps([module.StampClass("a", file=str(path))], "absent", "fail")
        self.assertEqual(found, {"a": FIRST})

    def test_pending_reads_as_pending_never_as_a_fingerprint(self) -> None:
        path = self.stamp("a", "pending\n")
        found = module.read_stamps([module.StampClass("a", file=str(path))], "absent", "fail")
        self.assertEqual(found, {"a": "pending"})

    def test_an_unreadable_stamp_stops_the_run_when_told_to_fail(self) -> None:
        (self.dir / "a").mkdir()
        with self.assertRaises(module.StampUnreadableError):
            module.read_stamps([module.StampClass("a", file=str(self.dir / "a"))], "absent", "fail")

    def test_an_unreadable_stamp_is_absent_when_told_so(self) -> None:
        (self.dir / "a").mkdir()
        found = module.read_stamps(
            [module.StampClass("a", file=str(self.dir / "a"))], "none", "absent"
        )
        self.assertEqual(found, {"a": "none"})

    def test_a_link_to_nothing_is_there_and_unreadable(self) -> None:
        (self.dir / "a").symlink_to(self.dir / "nowhere")
        with self.assertRaises(module.StampUnreadableError):
            module.read_stamps([module.StampClass("a", file=str(self.dir / "a"))], "absent", "fail")

    def test_main_returns_the_stamps_by_name(self) -> None:
        path = self.stamp("a", f"{FIRST}\n")
        failed, document = run_main(
            {"state": "read", "classes": [{"name": "a", "file": str(path)}]}
        )
        self.assertFalse(failed)
        self.assertEqual(document["stamps"], {"a": FIRST})
        self.assertFalse(document["changed"])

    def test_main_stops_before_anything_for_an_unreadable_stamp(self) -> None:
        (self.dir / "a").mkdir()
        failed, document = run_main(
            {"state": "read", "classes": [{"name": "a", "file": str(self.dir / "a")}]}
        )
        self.assertTrue(failed)
        self.assertIn("cannot be read", str(document["msg"]))

    def test_a_relative_stamp_path_is_refused(self) -> None:
        failed, document = run_main(
            {"state": "read", "classes": [{"name": "a", "file": "a.applied"}]}
        )
        self.assertTrue(failed)
        self.assertIn("absolute", str(document["msg"]))


class Decide(unittest.TestCase):
    def one(
        self,
        stamp: str,
        *,
        drift: bool = False,
        adoptable: bool = False,
        gate: bool = True,
    ) -> module.Decision:
        item = module.StampClass(
            "a", stamp=stamp, fingerprint=FIRST, drift=drift, adoptable=adoptable, gate=gate
        )
        return module.decide([item], "absent")["a"]

    def test_a_stamp_that_is_the_fingerprint_with_no_drift_is_nothing(self) -> None:
        self.assertEqual(self.one(FIRST), module.Decision(adopt=False, due=False, mark=False))

    def test_a_stamp_that_is_not_the_fingerprint_is_due_and_marked(self) -> None:
        self.assertEqual(self.one(SECOND), module.Decision(adopt=False, due=True, mark=True))

    def test_drift_with_an_unchanged_stamp_is_due_and_marked(self) -> None:
        self.assertEqual(self.one(FIRST, drift=True), module.Decision(False, True, True))

    def test_pending_is_never_the_fingerprint_so_it_is_due_again(self) -> None:
        self.assertTrue(self.one("pending").due)

    def test_no_stamp_and_nothing_differs_is_adopted_when_adoptable(self) -> None:
        self.assertEqual(
            self.one("absent", adoptable=True), module.Decision(adopt=True, due=False, mark=False)
        )

    def test_no_stamp_is_due_when_not_adoptable(self) -> None:
        self.assertEqual(self.one("absent"), module.Decision(adopt=False, due=True, mark=True))

    def test_no_stamp_with_drift_is_never_adopted(self) -> None:
        self.assertEqual(
            self.one("absent", adoptable=True, drift=True),
            module.Decision(adopt=False, due=True, mark=True),
        )

    def test_a_closed_gate_is_neither_adopted_nor_due(self) -> None:
        self.assertEqual(
            self.one("absent", adoptable=True, gate=False),
            module.Decision(adopt=False, due=False, mark=False),
        )
        self.assertFalse(self.one(SECOND, gate=False).due)

    def test_a_closed_gate_still_marks_a_file_that_drifts(self) -> None:
        self.assertEqual(
            self.one("absent", drift=True, gate=False),
            module.Decision(adopt=False, due=False, mark=True),
        )

    def test_the_absent_word_is_the_callers(self) -> None:
        item = module.StampClass("a", stamp="none", fingerprint=FIRST, adoptable=True)
        self.assertTrue(module.decide([item], "none")["a"].adopt)
        self.assertFalse(module.decide([item], "absent")["a"].adopt)

    def test_main_decides_from_strings_the_way_a_template_gives_them(self) -> None:
        failed, document = run_main(
            {
                "state": "decide",
                "absent": "none",
                "classes": [
                    {
                        "name": "unit",
                        "stamp": "none",
                        "fingerprint": FIRST,
                        "drift": "false",
                        "adoptable": "true",
                        "gate": "True",
                    }
                ],
            }
        )
        self.assertFalse(failed)
        self.assertEqual(
            document["decisions"], {"unit": {"adopt": True, "due": False, "mark": False}}
        )

    def test_a_class_with_no_fingerprint_is_refused(self) -> None:
        with self.assertRaises(module.ClassKeyMissingError):
            module.decide([module.StampClass("a", stamp="absent")], "absent")


class Write(Workdir):
    def item(
        self,
        name: str,
        *,
        fingerprint: str = FIRST,
        adopt: bool = False,
        read_back: bool = False,
    ) -> module.StampClass:
        return module.StampClass(
            name,
            file=str(self.dir / name),
            fingerprint=fingerprint,
            adopt=adopt,
            read_back=read_back,
        )

    def test_record_writes_the_fingerprint_and_a_newline_with_the_mode(self) -> None:
        names = module.write_stamps(
            [self.item("a", read_back=True)], "record", ME, check_mode=False
        )
        self.assertEqual(names, ["a"])
        self.assertEqual((self.dir / "a").read_text(encoding="utf-8"), f"{FIRST}\n")
        self.assertEqual((self.dir / "a").stat().st_mode & 0o777, 0o600)

    def test_record_writes_only_the_class_that_was_read_back(self) -> None:
        classes = [self.item("a", read_back=True), self.item("b", read_back=False)]
        names = module.write_stamps(classes, "record", ME, check_mode=False)
        self.assertEqual(names, ["a"])
        self.assertFalse((self.dir / "b").exists())

    def test_record_replaces_pending(self) -> None:
        self.stamp("a", "pending\n")
        module.write_stamps([self.item("a", read_back=True)], "record", ME, check_mode=False)
        self.assertEqual((self.dir / "a").read_text(encoding="utf-8"), f"{FIRST}\n")

    def test_record_in_check_mode_does_nothing(self) -> None:
        names = module.write_stamps([self.item("a", read_back=True)], "record", ME, check_mode=True)
        self.assertEqual(names, [])
        self.assertFalse((self.dir / "a").exists())

    def test_adopt_writes_only_the_class_that_is_adopted(self) -> None:
        classes = [self.item("a", adopt=True), self.item("b", adopt=False, read_back=True)]
        names = module.write_stamps(classes, "adopt", ME, check_mode=False)
        self.assertEqual(names, ["a"])
        self.assertFalse((self.dir / "b").exists())

    def test_adopt_in_check_mode_reports_the_change_and_writes_nothing(self) -> None:
        names = module.write_stamps([self.item("a", adopt=True)], "adopt", ME, check_mode=True)
        self.assertEqual(names, ["a"])
        self.assertFalse((self.dir / "a").exists())

    def test_a_second_write_changes_nothing(self) -> None:
        classes = [self.item("a", read_back=True)]
        module.write_stamps(classes, "record", ME, check_mode=False)
        self.assertEqual(module.write_stamps(classes, "record", ME, check_mode=False), [])

    def test_a_stamp_with_the_wrong_mode_is_written_again(self) -> None:
        path = self.stamp("a", f"{FIRST}\n")
        path.chmod(0o644)
        names = module.write_stamps(
            [self.item("a", read_back=True)], "record", ME, check_mode=False
        )
        self.assertEqual(names, ["a"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_a_value_that_is_not_a_sha256_is_never_written(self) -> None:
        for bad in ("pending", "absent", "", FIRST.upper(), FIRST[:-1], FIRST + "0"):
            with self.subTest(bad=bad), self.assertRaises(module.FingerprintNotAllowedError):
                module.write_stamps(
                    [self.item("a", fingerprint=bad, read_back=True)],
                    "record",
                    ME,
                    check_mode=False,
                )
        self.assertFalse((self.dir / "a").exists())

    def test_a_class_that_is_not_written_is_not_checked(self) -> None:
        names = module.write_stamps(
            [self.item("a", fingerprint="pending", read_back=False)], "record", ME, check_mode=False
        )
        self.assertEqual(names, [])

    def test_a_directory_where_the_stamp_goes_is_refused(self) -> None:
        (self.dir / "a").mkdir()
        with self.assertRaises(module.NotARegularFileError):
            module.write_stamps([self.item("a", read_back=True)], "record", ME, check_mode=False)

    def test_a_missing_directory_is_refused(self) -> None:
        item = module.StampClass(
            "a", file=str(self.dir / "gone" / "a"), fingerprint=FIRST, read_back=True
        )
        with self.assertRaises(module.DirectoryMissingError):
            module.write_stamps([item], "record", ME, check_mode=False)

    def test_adopt_in_check_mode_on_a_fresh_host_reports_the_write(self) -> None:
        item = module.StampClass(
            "a", file=str(self.dir / "gone" / "a"), fingerprint=FIRST, adopt=True
        )
        self.assertEqual(module.write_stamps([item], "adopt", ME, check_mode=True), ["a"])

    def test_a_link_is_followed_as_copy_follows_it(self) -> None:
        real = self.stamp("real", "pending\n")
        (self.dir / "a").symlink_to(real)
        module.write_stamps([self.item("a", read_back=True)], "record", ME, check_mode=False)
        self.assertTrue((self.dir / "a").is_symlink())
        self.assertEqual(real.read_text(encoding="utf-8"), f"{FIRST}\n")

    def test_a_write_leaves_no_temporary_file_beside_the_stamp(self) -> None:
        module.write_stamps([self.item("a", read_back=True)], "record", ME, check_mode=False)
        self.assertEqual([path.name for path in self.dir.iterdir()], ["a"])

    def test_the_mode_must_be_four_octal_digits(self) -> None:
        for bad in ("600", "0900", "06000", "rw-"):
            with self.subTest(bad=bad), self.assertRaises(module.ModeNotAllowedError):
                module.identity(OWNER, GROUP, bad)

    def test_an_owner_the_host_does_not_have_is_refused(self) -> None:
        with self.assertRaises(module.OwnerNotKnownError):
            module.identity("no-such-owner-0001", GROUP, "0600")
        with self.assertRaises(module.OwnerNotKnownError):
            module.identity(OWNER, "no-such-group-0001", "0600")

    def test_main_records_and_reports_the_names_it_wrote(self) -> None:
        classes = [
            {"name": "a", "file": str(self.dir / "a"), "fingerprint": FIRST, "read_back": "true"},
            {"name": "b", "file": str(self.dir / "b"), "fingerprint": SECOND, "read_back": "false"},
        ]
        failed, document = run_main({"state": "record", "classes": classes})
        self.assertFalse(failed)
        self.assertTrue(document["changed"])
        self.assertEqual(document["written"], ["a"])
        again_failed, again = run_main({"state": "record", "classes": classes})
        self.assertFalse(again_failed)
        self.assertFalse(again["changed"])

    def test_main_in_check_mode_adopts_without_writing_and_records_nothing(self) -> None:
        classes = [{"name": "a", "file": str(self.dir / "a"), "fingerprint": FIRST}]
        adopt = [{**classes[0], "adopt": True}]
        record = [{**classes[0], "read_back": True}]
        _, adopted = run_main({"state": "adopt", "classes": adopt}, check_mode=True)
        _, recorded = run_main({"state": "record", "classes": record}, check_mode=True)
        self.assertTrue(adopted["changed"])
        self.assertFalse(recorded["changed"])
        self.assertFalse((self.dir / "a").exists())

    def test_main_never_returns_a_fingerprint_from_a_write(self) -> None:
        classes = [
            {"name": "a", "file": str(self.dir / "a"), "fingerprint": FIRST, "read_back": True}
        ]
        _, document = run_main({"state": "record", "classes": classes})
        self.assertNotIn(FIRST, json.dumps(document))

    def test_a_name_used_twice_is_refused(self) -> None:
        classes = [{"name": "a", "file": str(self.dir / "a")}] * 2
        failed, document = run_main({"state": "read", "classes": classes})
        self.assertTrue(failed)
        self.assertIn("more than once", str(document["msg"]))


if __name__ == "__main__":
    unittest.main()
