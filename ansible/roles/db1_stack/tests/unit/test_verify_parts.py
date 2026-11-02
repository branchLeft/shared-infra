"""Unit tests for how the db1_stack verify cases are shared out between the scenarios.

Every case of verify.yml runs in the scenario whose name is its part, and a scenario that
names a part nobody runs would pass with its cases silently absent. assert_parts.yml
catches a listed part with no scenario; these tests catch the other way round, which it
cannot see: a scenario directory that is not listed, a listed part that no `when` names
(its cases would never run), and a `when` naming a part that is not listed (its cases
would never run either, and the name is a typo).

Sabotage, the CI-runnable red and then green for this dispatch: delete the
`verify_part == 'refusals_compose'` include from verify.yml, or the part from
verify_parts, and these tests fail; put it back and they pass.
"""

import re
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
MOLECULE = ROLE / "molecule"
DEFAULT = MOLECULE / "default"
VERIFY = DEFAULT / "verify.yml"
PART_WHEN = re.compile(r"verify_part == '([^']+)'")


def listed_parts() -> list[str]:
    """Return the names in verify_parts, in verify.yml."""
    text = VERIFY.read_text(encoding="utf-8")
    block = re.search(r"^ {4}verify_parts:\n((?: {6}- \S+\n)+)", text, re.MULTILINE)
    if block is None:
        raise AssertionError("verify.yml has no verify_parts list")
    return re.findall(r"- (\S+)", block.group(1))


def scenario_dirs() -> list[str]:
    """Return the scenario directories: every directory under molecule/ with a molecule.yml."""
    return sorted(
        path.name
        for path in MOLECULE.iterdir()
        if path.is_dir() and (path / "molecule.yml").exists()
    )


def conditions() -> dict[str, list[str]]:
    """Return each part named in a `verify_part == ...` condition, with the files that name it."""
    found: dict[str, list[str]] = {}
    for path in [VERIFY, *sorted((DEFAULT / "tasks").glob("*.yml"))]:
        for part in PART_WHEN.findall(path.read_text(encoding="utf-8")):
            found.setdefault(part, []).append(path.name)
    return found


class VerifyParts(unittest.TestCase):
    def test_every_scenario_directory_is_a_listed_part(self) -> None:
        self.assertEqual(sorted(listed_parts()), scenario_dirs())

    def test_every_listed_part_is_named_by_a_condition(self) -> None:
        # default has no case of its own: its checks run in every scenario, unconditionally.
        named = conditions()
        for part in listed_parts():
            if part == "default":
                continue
            with self.subTest(part=part):
                self.assertIn(part, named, f"no `verify_part == '{part}'` runs its cases")

    def test_every_condition_names_a_listed_part(self) -> None:
        parts = set(listed_parts())
        for part, files in conditions().items():
            with self.subTest(part=part, files=files):
                self.assertIn(part, parts, f"{files} names a part that is not listed")

    def test_the_second_compose_file_cases_run_in_their_own_part(self) -> None:
        self.assertEqual(conditions().get("refusals_compose"), ["verify.yml"])
        self.assertTrue((DEFAULT / "tasks" / "verify_compose_names.yml").is_file())


if __name__ == "__main__":
    unittest.main()
