"""The two parts of the checks' unit tests together run every test module, once, and CI runs both.

Splitting the step "Test the checks" across two legs must not drop a check: a module left out of
both parts, run in both, or a leg that never runs its part would each pass in silence. Each
test's name states the rule it holds; the reasons are in run_check_tests.md.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


class SlicesCoverEveryTestOnce(unittest.TestCase):
    """The parallel run hands every test to exactly one worker, so none is dropped or doubled."""

    IDS = [f"test_a.A.test_{n}" for n in range(45)] + [f"test_b.B.test_{n}" for n in range(3)]

    def test_every_id_is_in_exactly_one_slice(self) -> None:
        cut = rct.slices(self.IDS)
        flat = [test_id for part in cut for test_id in part]
        self.assertEqual(sorted(self.IDS), sorted(flat))

    def test_a_slice_holds_one_module_and_at_most_the_size(self) -> None:
        for part in rct.slices(self.IDS, 20):
            self.assertLessEqual(len(part), 20)
            self.assertEqual(1, len({test_id.split(".", 1)[0] for test_id in part}))

    def test_a_big_module_is_cut_and_the_biggest_slice_is_first(self) -> None:
        cut = rct.slices(self.IDS, 20)
        self.assertEqual(4, len(cut))
        self.assertEqual(sorted((len(part) for part in cut), reverse=True), [len(p) for p in cut])

    def test_no_ids_make_no_slices(self) -> None:
        self.assertEqual([], rct.slices([]))

    def test_the_jobs_come_from_the_variable_else_the_cores(self) -> None:
        self.assertEqual(3, rct.jobs_from({rct.JOBS_VARIABLE: "3"}))
        self.assertEqual(1, rct.jobs_from({rct.JOBS_VARIABLE: "0"}))
        self.assertEqual(1, rct.jobs_from({rct.JOBS_VARIABLE: "many"}))
        self.assertGreaterEqual(rct.jobs_from({}), 1)


PASSING = (
    "import unittest\n"
    "class T(unittest.TestCase):\n"
    "    def test_one(self) -> None:\n"
    "        self.assertTrue(True)\n"
    "    def test_two(self) -> None:\n"
    "        self.assertTrue(True)\n"
)


class TheParallelRunFailsClosed(unittest.TestCase):
    """A run over several processes fails when any one of them fails, dies or goes missing."""

    def _run(self, modules: dict[str, str], jobs: str) -> int:
        with mock.patch.dict(os.environ, {rct.JOBS_VARIABLE: jobs}):
            return _run_main_on(modules)

    def test_passing_modules_pass_serial_and_parallel(self) -> None:
        modules = {"test_par_ok_a1.py": PASSING, "test_par_ok_b1.py": PASSING}
        self.assertEqual(0, self._run(modules, "1"))
        self.assertEqual(0, self._run(modules, "3"))

    def test_one_failing_test_among_passing_modules_fails_the_run(self) -> None:
        failing = PASSING.replace(
            "self.assertTrue(True)\n    def test_two", "self.fail('red')\n    def test_two"
        )
        modules = {"test_par_red_a2.py": PASSING, "test_par_red_b2.py": failing}
        self.assertEqual(1, self._run(modules, "3"))

    def test_a_worker_that_dies_without_a_result_fails_the_run(self) -> None:
        dying = PASSING.replace(
            "self.assertTrue(True)\n    def test_two", "__import__('os')._exit(0)\n    def test_two"
        )
        modules = {"test_par_die_a3.py": PASSING, "test_par_die_b3.py": dying}
        self.assertEqual(1, self._run(modules, "3"))

    def test_a_class_whose_setup_fails_fails_the_run(self) -> None:
        body = PASSING.replace(
            "class T(unittest.TestCase):\n",
            "class T(unittest.TestCase):\n"
            "    @classmethod\n"
            "    def setUpClass(cls) -> None:\n"
            "        raise RuntimeError('no')\n",
        )
        self.assertEqual(1, self._run({"test_par_setup_a4.py": body}, "3"))

    def test_a_slice_that_never_runs_fails_the_run_on_the_total(self) -> None:
        modules = {"test_par_lost_a6.py": PASSING, "test_par_lost_b6.py": PASSING}
        real = rct.slices

        def drop_the_last(ids: list[str]) -> list[list[str]]:
            return real(ids)[:-1]

        with mock.patch.object(rct, "slices", drop_the_last):
            self.assertEqual(1, self._run(modules, "3"))

    def test_a_module_that_cannot_import_fails_beside_passing_ones(self) -> None:
        modules = {
            "test_par_imp_a5.py": PASSING,
            "test_par_imp_b5.py": "import not_a_module_at_all\n",
        }
        self.assertEqual(1, self._run(modules, "3"))


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
            for name in modules:
                sys.modules.pop(Path(name).stem, None)


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
