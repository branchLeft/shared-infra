"""The two parts of the checks' unit tests together run every test module, once, and CI runs both.

Splitting the step "Test the checks" across two legs must not drop a check: a module left out of
both parts, run in both, or a leg that never runs its part would each pass in silence. Each
test's name states the rule it holds; the reasons are in run_check_tests.md.
"""

from __future__ import annotations

import contextlib
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path

import run_check_tests as rct

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ansible.yml"
RUN_LINE = re.compile(
    r"- name: (?P<name>Test the (?:slow )?checks)\n"
    r"\s+if: matrix\.part == '(?P<leg>[a-z]+)'\n"
    r"\s+run: (?P<command>.+)"
)


class PartsCoverEveryModuleOnce(unittest.TestCase):
    def test_the_two_parts_are_every_test_module_exactly_once(self) -> None:
        everything = rct.all_modules()
        self.assertGreater(len(everything), 60)
        main = rct.modules_of("main")
        slow = rct.modules_of("slow")
        self.assertEqual([], sorted(set(main) & set(slow)))
        self.assertEqual(everything, sorted(main + slow))

    def test_every_slow_module_exists(self) -> None:
        present = set(rct.all_modules())
        self.assertEqual([], [m for m in rct.SLOW_MODULES if f"{m}.py" not in present])
        self.assertEqual(len(rct.SLOW_MODULES), len(set(rct.SLOW_MODULES)))

    def test_the_slow_part_holds_a_module(self) -> None:
        self.assertNotEqual([], rct.modules_of("slow"))

    def test_a_new_module_runs_in_main_with_no_entry_here(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "test_brand_new.py").write_text("", encoding="utf-8")
            self.assertEqual(["test_brand_new.py"], rct.modules_of("main", directory))
            self.assertEqual([], rct.modules_of("slow", directory))

    def test_an_unknown_part_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            rct.modules_of("both")

    def test_a_module_that_fails_to_import_is_a_failed_test_in_its_own_part(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            broken = directory / "test_broken.py"
            broken.write_text("import not_a_module_at_all\n", encoding="utf-8")
            suite = rct.build_suite("main", directory)
            result = unittest.TestResult()
            suite.run(result)
            self.assertEqual(1, suite.countTestCases())
            self.assertEqual(1, len(result.errors))

    def test_an_empty_part_is_not_a_pass(self) -> None:
        self.assertEqual(1, _run_main_on_empty())

    def test_a_part_with_a_failing_test_exits_one(self) -> None:
        body = (
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_fails(self) -> None:\n"
            "        self.fail('a check that fails')\n"
        )
        self.assertEqual(1, _run_main_on({"test_exit_fails_x1.py": body}))

    def test_a_part_with_a_module_that_cannot_import_exits_one(self) -> None:
        self.assertEqual(
            1, _run_main_on({"test_exit_broken_x2.py": "import not_a_module_at_all\n"})
        )

    def test_a_part_whose_tests_all_pass_exits_zero(self) -> None:
        body = (
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_passes(self) -> None:\n"
            "        self.assertTrue(True)\n"
        )
        self.assertEqual(0, _run_main_on({"test_exit_passes_x3.py": body}))


def _run_main_on_empty() -> int:
    return _run_main_on({})


def _run_main_on(modules: dict[str, str]) -> int:
    """The exit status of `main(["main"])` over a directory holding `modules`."""
    with tempfile.TemporaryDirectory() as tmp:
        for name, body in modules.items():
            (Path(tmp) / name).write_text(body, encoding="utf-8")
        original = rct.CHECKS
        rct.CHECKS = Path(tmp)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                return rct.main(["main"])
        finally:
            rct.CHECKS = original
            sys.path[:] = [p for p in sys.path if p != tmp]


class WorkflowRunsBothParts(unittest.TestCase):
    def test_each_part_is_run_by_one_step_in_its_own_leg(self) -> None:
        found = {
            m.group("name"): (m.group("leg"), m.group("command"))
            for m in RUN_LINE.finditer(WORKFLOW.read_text(encoding="utf-8"))
        }
        self.assertEqual({"Test the checks", "Test the slow checks"}, set(found))
        main_leg, main_cmd = found["Test the checks"]
        slow_leg, slow_cmd = found["Test the slow checks"]
        self.assertNotEqual(main_leg, slow_leg)
        self.assertRegex(main_cmd, r"ansible/checks/run_check_tests\.py main'?$")
        self.assertRegex(slow_cmd, r"ansible/checks/run_check_tests\.py slow'?$")

    def test_the_runner_prints_the_slowest_tests(self) -> None:
        source = Path(rct.__file__).read_text(encoding="utf-8")
        self.assertRegex(source, r"durations=[1-9][0-9]*")


if __name__ == "__main__":
    unittest.main()
