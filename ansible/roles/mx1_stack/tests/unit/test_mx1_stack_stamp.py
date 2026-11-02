"""Unit tests for mx1_stack_stamp: the decision, the two-step write and the check-mode promise.

Run from the role's directory with library/ on PYTHONPATH, the way
``ansible/checks/run_role_unit_tests.sh`` does. Every secret here is a throwaway made for the test.
"""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

import module_runner
import mx1_stack_stamp as stamp

MARKER = "THROWAWAY_STAMP_MARKER_0001"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class Workdir(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.stamp_path = self.root / "mx1.test.applied"

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def write_stamp(self, text: str, mode: int = 0o600) -> None:
        self.stamp_path.write_text(text, encoding="utf-8")
        self.stamp_path.chmod(mode)


class LinesTest(Workdir):
    def test_a_file_is_hashed_by_its_bytes_and_a_missing_one_is_absent(self) -> None:
        path = self.write("a", "alpha\n")
        self.assertEqual(sha("alpha\n"), stamp.hash_file(str(path)))
        self.assertEqual("absent", stamp.hash_file(str(self.root / "missing")))

    def test_a_link_or_a_directory_is_refused_as_an_input(self) -> None:
        target = self.write("target", "x")
        link = self.root / "link"
        link.symlink_to(target)
        for path in (link, self.root):
            with self.subTest(path=path.name), self.assertRaises(stamp.StampError):
                stamp.hash_file(str(path))

    def test_lines_are_sorted_and_hold_hashes_only(self) -> None:
        path = self.write("b", MARKER)
        lines = stamp.current_lines({"zeta": str(path)}, {"alpha": "value"})
        self.assertEqual(["alpha", "zeta"], list(lines))
        self.assertNotIn(MARKER, "".join(lines.values()))

    def test_a_malformed_or_repeated_input_name_is_refused(self) -> None:
        for files, values in (
            ({"Bad Name": "/x"}, {}),
            ({"a": "/x"}, {"a": "v"}),
            ({}, {"1leading": "v"}),
        ):
            with self.subTest(files=files, values=values), self.assertRaises(stamp.StampError):
                stamp.current_lines(files, values)

    def test_changing_one_input_changes_only_its_line(self) -> None:
        first = self.write("first", "one")
        second = self.write("second", "two")
        third = self.write("third", "three")
        files = {"first": str(first), "second": str(second), "third": str(third)}
        before = stamp.current_lines(files, {"packages": "unbound"})
        for name, path_text in files.items():
            with self.subTest(input=name):
                path = Path(path_text)
                original = path.read_text(encoding="utf-8")
                path.write_text(original + "!", encoding="utf-8")
                after = stamp.current_lines(files, {"packages": "unbound"})
                path.write_text(original, encoding="utf-8")
                changed = [key for key in after if after[key] != before[key]]
                self.assertEqual([name], changed)
                self.assertEqual([name], stamp.differing(stamp.Stamp("recorded", before), after))
        after_value = stamp.current_lines(files, {"packages": "unbound dig"})
        self.assertEqual(
            ["packages"], [key for key in after_value if after_value[key] != before[key]]
        )


class ParseTest(unittest.TestCase):
    def test_a_rendered_stamp_reads_back(self) -> None:
        lines = {"b": sha("b"), "a": sha("a")}
        text = stamp.render(lines)
        self.assertEqual(f"a {sha('a')}\nb {sha('b')}\n", text)
        self.assertEqual(dict(sorted(lines.items())), dict(stamp.parse(text).lines))

    def test_pending_is_a_state(self) -> None:
        self.assertEqual("pending", stamp.parse("pending\n").state)

    def test_every_malformed_stamp_is_refused(self) -> None:
        good = f"a {sha('a')}\n"
        for label, text in (
            ("no line break", f"a {sha('a')}"),
            ("empty", ""),
            ("blank line", "\n"),
            ("short hash", "a 1234\n"),
            ("upper-case hash", f"a {sha('a').upper()}\n"),
            ("repeated input", good + good),
            ("unsorted", f"b {sha('b')}\na {sha('a')}\n"),
            ("two spaces", f"a  {sha('a')}\n"),
            ("pending with more", "pending\nmore\n"),
        ):
            with self.subTest(label), self.assertRaises(stamp.StampError):
                stamp.parse(text)


class ReadStampTest(Workdir):
    def test_an_absent_file_is_the_absent_state(self) -> None:
        self.assertEqual("absent", stamp.read_stamp(str(self.stamp_path)).state)

    def test_a_good_file_is_read(self) -> None:
        self.write_stamp("pending\n")
        self.assertEqual("pending", stamp.read_stamp(str(self.stamp_path)).state)

    def test_an_unreadable_stamp_is_refused_in_each_form(self) -> None:
        target = self.write("target", "pending\n")
        target.chmod(0o600)
        link = self.root / "mx1.link.applied"
        link.symlink_to(target)
        wide = self.root / "wide"
        wide.write_text("pending\n", encoding="utf-8")
        wide.chmod(0o644)
        garbled = self.write("garbled", "this is not a stamp\n")
        garbled.chmod(0o600)
        for label, path in (
            ("a link", link),
            ("a directory", self.root),
            ("readable by others", wide),
            ("malformed", garbled),
        ):
            with self.subTest(label), self.assertRaises(stamp.StampError):
                stamp.read_stamp(str(path))


class DecideTest(unittest.TestCase):
    LINES = {"compose": sha("c"), "env": sha("e")}

    def decide(
        self,
        current: stamp.Stamp,
        *,
        expected: dict[str, str] | None = None,
        live: bool = True,
        stale: bool = False,
        lines: dict[str, str] | None = None,
    ) -> stamp.Decision:
        return stamp.decide(
            current,
            lines or self.LINES,
            expected=self.LINES if expected is None else expected,
            live_ok=live,
            stale=stale,
        )

    def test_a_recorded_stamp_that_matches_is_not_due(self) -> None:
        verdict = self.decide(stamp.Stamp("recorded", self.LINES))
        self.assertFalse(verdict.due)
        self.assertFalse(verdict.adopt)
        self.assertEqual([], verdict.reasons)

    def test_each_reason_makes_a_recorded_class_due(self) -> None:
        recorded = stamp.Stamp("recorded", self.LINES)
        for label, kwargs in (
            ("placed file differs", {"expected": {"compose": sha("newer")}}),
            ("stale input", {"stale": True}),
            ("live state not ok", {"live": False}),
        ):
            with self.subTest(label):
                verdict = self.decide(recorded, **kwargs)
                self.assertTrue(verdict.due)
                self.assertEqual(1, len(verdict.reasons))

    def test_a_differing_input_makes_the_class_due_and_is_named(self) -> None:
        changed = {**self.LINES, "env": sha("other")}
        verdict = self.decide(stamp.Stamp("recorded", self.LINES), lines=changed)
        self.assertTrue(verdict.due)
        self.assertEqual(["env"], verdict.differing)

    def test_an_input_the_stamp_does_not_know_makes_the_class_due(self) -> None:
        more = {**self.LINES, "extra": sha("x")}
        verdict = self.decide(stamp.Stamp("recorded", self.LINES), lines=more)
        self.assertTrue(verdict.due)
        self.assertEqual(["extra"], verdict.differing)

    def test_a_file_with_a_repository_hash_that_it_does_not_match_is_named(self) -> None:
        verdict = self.decide(
            stamp.Stamp("recorded", self.LINES), expected={"compose": sha("newer")}
        )
        self.assertTrue(verdict.due)
        self.assertEqual(["compose"], verdict.repository_differs)

    def test_an_absent_file_with_no_repository_hash_makes_the_class_due(self) -> None:
        lines = {"compose": sha("c"), "env": "absent"}
        verdict = self.decide(
            stamp.Stamp("recorded", lines), expected={"compose": sha("c")}, lines=lines
        )
        self.assertTrue(verdict.due)
        self.assertIn("input env is absent", verdict.reasons)

    def test_an_absent_file_with_a_repository_hash_is_a_difference_from_it(self) -> None:
        lines = {"compose": "absent", "env": sha("e")}
        verdict = self.decide(
            stamp.Stamp("absent", {}), expected={"compose": sha("c")}, lines=lines
        )
        self.assertEqual(["compose"], verdict.repository_differs)
        self.assertFalse(verdict.adopt)

    def test_pending_is_due(self) -> None:
        verdict = self.decide(stamp.Stamp("pending", {}))
        self.assertTrue(verdict.due)
        self.assertFalse(verdict.adopt)

    def test_no_stamp_on_a_clean_host_is_adopted_not_acted_on(self) -> None:
        verdict = self.decide(stamp.Stamp("absent", {}))
        self.assertTrue(verdict.adopt)
        self.assertFalse(verdict.due)

    def test_no_stamp_is_never_adopted_when_anything_is_off(self) -> None:
        absent = stamp.Stamp("absent", {})
        for label, kwargs in (
            ("placed file differs", {"expected": {"compose": sha("newer")}}),
            ("stale input", {"stale": True}),
            ("container down or on the wrong image", {"live": False}),
        ):
            with self.subTest(label):
                verdict = self.decide(absent, **kwargs)
                self.assertFalse(verdict.adopt)
                self.assertTrue(verdict.due)


class ModuleTest(Workdir):
    def params(self, action: str, **more: object) -> dict[str, object]:
        return {"action": action, "stamp_path": str(self.stamp_path), **more}

    def test_mark_then_record_write_a_closed_file(self) -> None:
        path = self.write("input", MARKER)
        failed, _document, _raw = module_runner.run_module(
            stamp.main, self.params("mark", files={"in": str(path)})
        )
        self.assertFalse(failed)
        self.assertEqual("pending\n", self.stamp_path.read_text(encoding="utf-8"))
        self.assertEqual(0o600, self.stamp_path.stat().st_mode & 0o777)
        failed, document, raw = module_runner.run_module(
            stamp.main, self.params("record", files={"in": str(path)})
        )
        self.assertFalse(failed)
        self.assertTrue(document["changed"])
        self.assertEqual(f"in {sha(MARKER)}\n", self.stamp_path.read_text(encoding="utf-8"))
        self.assertEqual(0o600, self.stamp_path.stat().st_mode & 0o777)
        self.assertNotIn(MARKER, raw)
        self.assertEqual(["input", self.stamp_path.name], sorted(os.listdir(self.root)))

    def test_a_second_record_changes_nothing(self) -> None:
        path = self.write("input", "x")
        module_runner.run_module(stamp.main, self.params("record", files={"in": str(path)}))
        _failed, document, _raw = module_runner.run_module(
            stamp.main, self.params("record", files={"in": str(path)})
        )
        self.assertFalse(document["changed"])

    def test_check_mode_writes_nothing_for_mark_and_record(self) -> None:
        path = self.write("input", "x")
        self.write_stamp(f"in {sha('older')}\n")
        before = module_runner.listing(str(self.root))
        modes = {name: (self.root / name).stat().st_mode for name in os.listdir(self.root)}
        for action in ("mark", "record"):
            with self.subTest(action):
                failed, document, _raw = module_runner.run_module(
                    stamp.main,
                    self.params(action, files={"in": str(path)}),
                    check_mode=True,
                )
                self.assertFalse(failed)
                self.assertTrue(document["changed"])
                self.assertEqual(before, module_runner.listing(str(self.root)))
                self.assertEqual(
                    modes, {n: (self.root / n).stat().st_mode for n in os.listdir(self.root)}
                )

    def test_check_mode_on_an_empty_directory_leaves_it_empty(self) -> None:
        for action in ("mark", "record"):
            module_runner.run_module(stamp.main, self.params(action), check_mode=True)
        self.assertEqual([], os.listdir(self.root))

    def test_decide_reads_and_never_writes(self) -> None:
        path = self.write("input", MARKER)
        before = module_runner.listing(str(self.root))
        failed, document, raw = module_runner.run_module(
            stamp.main,
            self.params(
                "decide", files={"in": str(path)}, expected={"in": sha(MARKER)}, live_ok=True
            ),
            check_mode=True,
        )
        self.assertFalse(failed)
        self.assertTrue(document["adopt"])
        self.assertFalse(document["due"])
        self.assertNotIn(MARKER, raw)
        self.assertEqual(before, module_runner.listing(str(self.root)))

    def test_an_unreadable_stamp_stops_the_module_without_echoing_it(self) -> None:
        self.write_stamp(f"{MARKER} not a stamp\n")
        failed, document, raw = module_runner.run_module(
            stamp.main, self.params("decide"), check_mode=True
        )
        self.assertTrue(failed)
        self.assertIn("mx1 stamp", str(document["msg"]))
        self.assertNotIn(MARKER, raw)


class AtomicWriteTest(Workdir):
    def test_a_failed_replace_leaves_no_temporary_file(self) -> None:
        from unittest import mock

        with mock.patch.object(os, "replace", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                stamp.write_atomic(str(self.stamp_path), "pending\n")
        self.assertEqual([], os.listdir(self.root))


if __name__ == "__main__":
    unittest.main()
