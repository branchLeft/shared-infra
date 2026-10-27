"""Unit tests for the exporters_and_collectors role's fact gathering: the contract of its files.

The pulled playbooks set gather_facts: false, so the role cannot read the facts it uses
until it gathers them itself. The Molecule scenario proves the role on a host. These
tests prove, from the files alone, that the role gathers those facts before its first
read, and that its own scenario does not get them from the play, so a change that
removes or reorders the gathering fails in seconds.
"""

import json
import unittest
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parents[2]
SETUP = "ansible.builtin.setup"

# The facts the role reads from main.yml, which the gathering must come before.
READ_FACTS = ("ansible_all_ipv4_addresses", "ansible_mounts")
REQUIRED_SUBSETS = ("network", "hardware")


def load(relative: str) -> object:
    """Parse one YAML file of the role."""
    parsed: object = yaml.safe_load((ROLE / relative).read_text(encoding="utf-8"))
    return parsed


def as_dict(value: object) -> dict[str, object]:
    """Narrow a parsed value to a mapping, failing the test if it is not one."""
    if not isinstance(value, dict):
        raise AssertionError(f"expected a mapping, got {type(value).__name__}")
    return {str(key): item for key, item in value.items()}


def as_list(value: object) -> list[object]:
    """Narrow a parsed value to a list, failing the test if it is not one."""
    if not isinstance(value, list):
        raise AssertionError(f"expected a list, got {type(value).__name__}")
    return list(value)


def main_tasks() -> list[dict[str, object]]:
    """The tasks of main.yml, in order."""
    return [as_dict(task) for task in as_list(load("tasks/main.yml"))]


def the_gathering(tasks: list[dict[str, object]]) -> tuple[int, dict[str, object]]:
    """The index and the arguments of the one setup task; the test fails if there is not one."""
    found = [(index, task) for index, task in enumerate(tasks) if SETUP in task]
    if len(found) != 1:
        raise AssertionError(f"expected exactly one {SETUP} task in main.yml, found {len(found)}")
    index, task = found[0]
    return index, as_dict(task[SETUP])


class GatheringTests(unittest.TestCase):
    """The role asks for the network and hardware facts it reads, and no others."""

    def test_the_role_gathers_only_the_network_and_hardware_subsets(self) -> None:
        _, arguments = the_gathering(main_tasks())
        subsets = as_list(arguments["gather_subset"])
        self.assertIn("!all", subsets, "the gathering must not fetch every subset")
        self.assertIn("!min", subsets, "the gathering must not fetch the minimal subset twice")
        for subset in REQUIRED_SUBSETS:
            with self.subTest(subset=subset):
                self.assertIn(subset, subsets)

    def test_the_gathering_comes_before_every_read_of_a_gathered_fact(self) -> None:
        tasks = main_tasks()
        gathering, _ = the_gathering(tasks)
        readers = [
            index
            for index, task in enumerate(tasks)
            if any(fact in json.dumps(task) for fact in READ_FACTS)
        ]
        # A control: a scan that found no reader would pass every order check below.
        self.assertTrue(readers, "main.yml reads no gathered fact, so this test tests nothing")
        for index in readers:
            with self.subTest(task=tasks[index].get("name")):
                self.assertGreater(index, gathering)


class MoleculeScenarioTests(unittest.TestCase):
    """The role's own scenario runs the play with facts off, as the pulled playbooks do."""

    def test_the_converge_play_does_not_gather_facts(self) -> None:
        plays = as_list(load("molecule/default/converge.yml"))
        self.assertEqual(1, len(plays))
        self.assertIs(False, as_dict(plays[0])["gather_facts"])


if __name__ == "__main__":
    unittest.main()
