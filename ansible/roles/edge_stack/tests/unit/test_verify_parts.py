"""Unit tests for how the edge_stack verify cases are shared out between the scenarios.

The cases of molecule/default/verify.yml are shared out between several scenarios, each
its own shard, so that no shard takes longer than about twelve minutes. A case that no
scenario runs would pass silently (its shard simply does not run it), so these tests read
the files and fail on a case block with no home, a home with no case block, a case gated
on another case's name, a home that is no scenario, a scenario that is no home, and a
scenario that leaves out a step the default scenario must run. A case has one home
because edge_stack_verify_homes is a mapping, which holds a key once (yamllint's
key-duplicates rule fails a second line for the same key).

Sabotage, the red and then green for the change that made them: delete a case from
`edge_stack_verify_homes`, change a case's `when`, or empty a scenario's cases, and these
tests fail; put it back and they pass.
"""

import unittest
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parents[2]
MOLECULE = ROLE / "molecule"
DEFAULT = MOLECULE / "default"
VERIFY = DEFAULT / "verify.yml"
WHEN = "edge_stack_verify_homes.{case} == edge_stack_verify_part"
# The log scan runs in every scenario, over that scenario's own log: it has no home.
EVERY_SCENARIO = ("p25",)
# The steps only the default scenario runs, one run of each for the whole role (ANS-15).
DEFAULT_ONLY_STEPS = ("check-fresh", "idempotence", "check-configured", "molecule-check")


class VerifyShapeError(Exception):
    """verify.yml does not have the shape these tests read."""


def verify_play() -> dict[str, object]:
    """Return the one play of verify.yml.

    Raises:
        VerifyShapeError: verify.yml is not a list of exactly one play.
    """
    parsed = yaml.safe_load(VERIFY.read_text(encoding="utf-8"))
    if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
        reason = "verify.yml is not one play"
        raise VerifyShapeError(reason)
    return {str(key): value for key, value in parsed[0].items()}


def homes() -> dict[str, str]:
    """Return edge_stack_verify_homes: each case name and the scenario that runs it.

    Raises:
        VerifyShapeError: the play has no such mapping of names to names.
    """
    play_vars = verify_play().get("vars")
    if not isinstance(play_vars, dict):
        reason = "the play has no vars"
        raise VerifyShapeError(reason)
    mapping = play_vars.get("edge_stack_verify_homes")
    if not isinstance(mapping, dict) or not all(isinstance(home, str) for home in mapping.values()):
        reason = "the play has no edge_stack_verify_homes mapping of names"
        raise VerifyShapeError(reason)
    return {str(case): str(home) for case, home in mapping.items()}


def case_blocks() -> dict[str, dict[object, object]]:
    """Return each case block of verify.yml by its case name (its one tag).

    A case is a task named "Case ..." that carries one tag and holds a block.

    Raises:
        VerifyShapeError: a case is not a block with one tag, or two blocks carry one tag.
    """
    tasks = verify_play().get("tasks")
    if not isinstance(tasks, list):
        reason = "the play has no tasks"
        raise VerifyShapeError(reason)
    found: dict[str, dict[object, object]] = {}
    for task in tasks:
        if not isinstance(task, dict) or not str(task.get("name", "")).startswith("Case "):
            continue
        tags = task.get("tags")
        if not isinstance(tags, list) or len(tags) != 1 or "block" not in task:
            reason = f"{task.get('name')} is not a block with one tag"
            raise VerifyShapeError(reason)
        case = str(tags[0])
        if case in found:
            reason = f"two blocks carry the tag {case}"
            raise VerifyShapeError(reason)
        found[case] = task
    return found


def scenario_dirs() -> list[str]:
    """Return the scenario directories: every directory under molecule/ with a molecule.yml."""
    return sorted(
        path.name
        for path in MOLECULE.iterdir()
        if path.is_dir() and (path / "molecule.yml").exists()
    )


def skipped_steps(scenario: str) -> list[str]:
    """Return the steps the scenario's skip-steps.txt leaves out, none when it has no file."""
    path = MOLECULE / scenario / "skip-steps.txt"
    if not path.is_file():
        return []
    lines = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
    return [line for line in lines if line and not line.startswith("#")]


class VerifyParts(unittest.TestCase):
    def test_every_scenario_directory_is_the_home_of_a_case_and_the_other_way_round(self) -> None:
        self.assertEqual(sorted(set(homes().values())), scenario_dirs())

    def test_every_case_block_has_a_home_or_runs_in_every_scenario(self) -> None:
        self.assertEqual(sorted([*homes(), *EVERY_SCENARIO]), sorted(case_blocks()))
        for case in EVERY_SCENARIO:
            self.assertNotIn(case, homes(), f"{case} runs in every scenario, so it has no home")

    def test_every_case_block_is_gated_on_its_own_name(self) -> None:
        for case, block in case_blocks().items():
            with self.subTest(case=case):
                if case in EVERY_SCENARIO:
                    self.assertNotIn("when", block, f"{case} runs in every scenario")
                else:
                    self.assertEqual(block.get("when"), WHEN.format(case=case))

    def test_every_home_runs_verify_and_only_the_default_scenario_plans_and_checks_twice(
        self,
    ) -> None:
        for home in set(homes().values()):
            with self.subTest(home=home):
                self.assertTrue((MOLECULE / home / "verify.yml").is_file())
                skipped = skipped_steps(home)
                self.assertNotIn("verify", skipped)
                if home == "default":
                    self.assertEqual(skipped, [], "the default scenario runs every step")
                else:
                    self.assertEqual(sorted(skipped), sorted(DEFAULT_ONLY_STEPS))

    def test_the_other_scenarios_share_the_default_scenarios_play_files(self) -> None:
        for home in set(homes().values()) - {"default"}:
            with self.subTest(home=home):
                link = MOLECULE / home / "molecule.yml"
                self.assertTrue(link.is_symlink())
                self.assertEqual(link.resolve(), DEFAULT / "molecule.yml")
                for name in ("converge.yml", "prepare.yml", "verify.yml"):
                    text = (MOLECULE / home / name).read_text(encoding="utf-8")
                    self.assertIn(f"import_playbook: ../default/{name}", text)

    def test_the_playbooks_a_case_starts_are_the_default_scenarios(self) -> None:
        # plan.yml and apply.yml sit in the default scenario only; a case run from another
        # scenario's directory must still find them.
        for name in ("plan.yml", "apply.yml"):
            with self.subTest(name=name):
                self.assertTrue((DEFAULT / name).is_file())
        runner = (DEFAULT / "tasks" / "crash_run.yml").read_text(encoding="utf-8")
        self.assertIn("{{ playbook_dir }}/../default/apply.yml", runner)
        verify = VERIFY.read_text(encoding="utf-8")
        self.assertIn("{{ playbook_dir }}/../default/plan.yml", verify)


if __name__ == "__main__":
    unittest.main()
