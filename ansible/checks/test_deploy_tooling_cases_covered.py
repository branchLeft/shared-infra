"""Check that every case of the deploy_tooling Molecule test runs in exactly one scenario.

The role's cases are split between scenarios so that each shard stays well inside its time
limit (`molecule/<name>/skip-steps.txt`; `ansible/README.md`, "Sharing steps between
scenarios"). A split can lose a case silently: a case file that no scenario's verify play
reaches, or that a scenario reaches but leaves out by skipping `verify`, is a case that never
runs and a job that is still green. A case that two scenarios reach runs twice and costs the
time the split saved. This check reads the include graph of each scenario's verify play and
fails on both. It also holds the reason for the split: the case that waits on the compose
unit's own timers shares its scenario with no other case.

It reads the files only; it starts no container and takes no time.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

import deploy_tooling_vars as role_vars

MOLECULE = role_vars.ROLE / "molecule"
DEFAULT = "default"
# The case that waits, by design, for the unit's own seconds (RestartSec= and the limits).
WAITING_CASE = "case_compose_retry.yml"
# A task or playbook include with a written file name. A templated name cannot be followed.
_INCLUDE = re.compile(
    r"ansible\.builtin\.(?:include_tasks|import_tasks|import_playbook):\s*['\"]?([^\s'\"]+)"
)


def skipped_steps(scenario: Path) -> set[str]:
    """Return the steps the scenario's skip-steps.txt leaves out, none when it has no file."""
    path = scenario / "skip-steps.txt"
    if not path.is_file():
        return set()
    lines = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
    return {line for line in lines if line and not line.startswith("#")}


def includes_of(path: Path) -> tuple[list[Path], list[str]]:
    """Return the files a task file includes, and the includes that name a file that is not there.

    A name is resolved against the including file's directory, which is where Ansible looks first
    for a file in a scenario. A name with a template in it is not followed.
    """
    found: list[Path] = []
    missing: list[str] = []
    for name in _INCLUDE.findall(path.read_text(encoding="utf-8")):
        if "{{" in name:
            continue
        target = (path.parent / name).resolve()
        if target.is_file():
            found.append(target)
        else:
            missing.append(f"{path.name} includes {name}, which does not exist")
    return found, missing


def reachable(start: Path) -> tuple[set[Path], list[str]]:
    """Return every file reached from the start file by includes, the start file included."""
    seen: set[Path] = set()
    problems: list[str] = []
    queue = [start.resolve()]
    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        found, missing = includes_of(current)
        queue.extend(found)
        problems.extend(missing)
    return seen, problems


def case_files(molecule: Path) -> list[str]:
    """Return the names of the case files, which live beside the default scenario's tasks."""
    return sorted(path.name for path in (molecule / DEFAULT / "tasks").glob("case_*.yml"))


def cases_by_scenario(molecule: Path) -> tuple[dict[str, set[str]], list[str]]:
    """Return, per scenario that runs a verify play, the case files that play reaches.

    A scenario that lists `verify` in its skip-steps.txt runs no verify play, so it runs no case.
    """
    names = set(case_files(molecule))
    reached: dict[str, set[str]] = {}
    problems: list[str] = []
    for scenario in sorted(entry for entry in molecule.iterdir() if entry.is_dir()):
        verify = scenario / "verify.yml"
        if "verify" in skipped_steps(scenario) or not verify.is_file():
            continue
        files, missing = reachable(verify)
        problems.extend(f"{scenario.name}: {line}" for line in missing)
        reached[scenario.name] = {path.name for path in files} & names
    return reached, problems


def problems_in(molecule: Path) -> list[str]:
    """Return each way the cases are not run once each, and each include that goes nowhere."""
    reached, problems = cases_by_scenario(molecule)
    for case in case_files(molecule):
        runners = sorted(name for name, cases in reached.items() if case in cases)
        if not runners:
            problems.append(f"{case} runs in no scenario")
        elif len(runners) > 1:
            problems.append(f"{case} runs in {len(runners)} scenarios: {', '.join(runners)}")
    waiting = [name for name, cases in reached.items() if WAITING_CASE in cases]
    for name in waiting:
        others = sorted(reached[name] - {WAITING_CASE})
        if others:
            problems.append(
                f"the scenario {name} runs {WAITING_CASE}, which waits, with {', '.join(others)}"
            )
    return problems


class CasesCoveredTest(unittest.TestCase):
    """The repository's own scenarios, then the same check against trees broken on purpose."""

    def setUp(self) -> None:
        """Copy the role's molecule directory to a scratch tree the controls can break."""
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.copy = Path(scratch.name) / "molecule"
        shutil.copytree(MOLECULE, self.copy, symlinks=True)

    def test_every_case_runs_in_exactly_one_scenario(self) -> None:
        """The scenarios as committed leave no case out and run none twice."""
        self.assertEqual(problems_in(MOLECULE), [])

    def test_the_cases_are_found(self) -> None:
        """A check that finds no case would pass on an empty glob, so the glob is held."""
        names = case_files(MOLECULE)
        self.assertIn(WAITING_CASE, names)
        self.assertGreaterEqual(len(names), 10)

    def test_the_waiting_case_is_alone_and_not_in_the_default_scenario(self) -> None:
        """The split's reason: the case that waits has a shard of its own."""
        reached, _ = cases_by_scenario(MOLECULE)
        self.assertNotIn(WAITING_CASE, reached[DEFAULT])
        owners = [name for name, cases in reached.items() if WAITING_CASE in cases]
        self.assertEqual(len(owners), 1)
        self.assertEqual(reached[owners[0]], {WAITING_CASE})

    def test_a_case_in_no_scenario_is_found(self) -> None:
        """Control: a verify play that drops its case leaves the case in no scenario."""
        verify = self.copy / "sudoers" / "verify.yml"
        text = verify.read_text(encoding="utf-8")
        self.assertIn("case_sudoers.yml", text)
        verify.write_text(text.replace("case_sudoers.yml", "case_sudoers_content.yml"), "utf-8")
        found = problems_in(self.copy)
        self.assertIn("case_sudoers.yml runs in no scenario", found)

    def test_a_case_in_two_scenarios_is_found(self) -> None:
        """Control: a case copied into a second verify play runs twice."""
        verify = self.copy / DEFAULT / "verify.yml"
        verify.write_text(
            verify.read_text(encoding="utf-8")
            + "\n    - name: Again\n      ansible.builtin.include_tasks: tasks/case_chain.yml\n",
            "utf-8",
        )
        found = problems_in(self.copy)
        self.assertIn("case_chain.yml runs in 2 scenarios: chains_parents, default", found)

    def test_a_scenario_that_skips_verify_runs_no_case(self) -> None:
        """Control: a skip-steps.txt that leaves verify out turns its cases into cases never run."""
        skip = self.copy / "retry" / "skip-steps.txt"
        skip.write_text(skip.read_text(encoding="utf-8") + "verify\n", "utf-8")
        found = problems_in(self.copy)
        self.assertIn(f"{WAITING_CASE} runs in no scenario", found)

    def test_the_waiting_case_beside_another_is_found(self) -> None:
        """Control: the waiting case moved into a scenario with another case is not alone."""
        verify = self.copy / "retry" / "verify.yml"
        verify.write_text(
            verify.read_text(encoding="utf-8")
            + "\n    - name: Beside\n"
            + "      ansible.builtin.include_tasks: ../default/tasks/case_interface.yml\n",
            "utf-8",
        )
        found = problems_in(self.copy)
        self.assertTrue(any("which waits, with case_interface.yml" in line for line in found))

    def test_an_include_that_goes_nowhere_is_found(self) -> None:
        """Control: a misspelt include is a case that never runs, so it is reported."""
        verify = self.copy / "retry" / "verify.yml"
        verify.write_text(
            verify.read_text(encoding="utf-8").replace("case_compose_retry.yml", "case_retry.yml"),
            "utf-8",
        )
        found = problems_in(self.copy)
        self.assertTrue(any("case_retry.yml, which does not exist" in line for line in found))


if __name__ == "__main__":
    unittest.main()
