"""ops1's step allow-list is the pull program's, not a copy of its rules.

owner_vars/ops1.yml holds pull_trigger_steps, the list of routine control_plane_db steps the
gated pull may be asked to run on ops1. Which ids exist, that a tag is the id's own and what a
word looks like are the program's rules alone (STEP_IDS, _step_from and WORD_PATTERN in
roles/pull_trigger/files/pull_trigger.py). Here the real file is fed through the program's own
parse_config, so a bad list is refused by the code that would refuse it on the host, and
check_enrolment keeps only the shape. The same file is held to the role: every listed id has a
tagged, never-run import in control_plane_db's tasks and is in the role's own list of ids.

Each sabotage case edits a copy of the data and expects the same function to refuse it, so a
test that accepted everything would fail here and not pass for a strict one.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from types import ModuleType

import yaml  # type: ignore[import-untyped]
from check_enrolment import ROOT

ANSIBLE = ROOT / "ansible"
OWNER_FILE = ANSIBLE / "owner_vars" / "ops1.yml"
PROGRAM = ANSIBLE / "roles" / "pull_trigger" / "files" / "pull_trigger.py"
ROLE = ANSIBLE / "roles" / "control_plane_db"
STEPS_KEY = "pull_trigger_steps"
NEVER = "never"
IMPORT_TASKS = frozenset(("ansible.builtin.import_tasks", "import_tasks"))
SIGNER = "ssh-ed25519 " + "A" * 68

Steps = list[dict[str, object]]


class ProgramLoadError(ImportError):
    """The pull program cannot be loaded as a module."""

    def __init__(self, path: Path) -> None:
        super().__init__(f"cannot load {path}")


def load_program() -> ModuleType:
    """Import the pull program from its file, without putting its directory on the path.

    Raises:
        ProgramLoadError: the file cannot be loaded as a module.
    """
    spec = importlib.util.spec_from_file_location("pull_trigger_for_allowlist", PROGRAM)
    if spec is None or spec.loader is None:
        raise ProgramLoadError(PROGRAM)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def real_steps() -> Steps:
    """The allow-list as committed in owner_vars/ops1.yml."""
    doc = yaml.safe_load(OWNER_FILE.read_text(encoding="utf-8"))
    steps: Steps = doc[STEPS_KEY]
    return steps


def parse_allowlist(program: ModuleType, steps: object) -> list[tuple[str, str, str]]:
    """Run the list through the program's own configuration parser and return what it kept.

    The rest of the configuration is a fixed, valid one: only the steps differ between cases.
    """
    text = json.dumps(
        {
            "remote_url": "https://example.invalid/EXAMPLE_ORG/EXAMPLE_REPO",
            "signers": [{"format": "ssh", "key": SIGNER}],
            "playbooks": ["ansible/playbooks/ops1.yml"],
            "playbook": "ansible/playbooks/ops1.yml",
            "ansible_playbook": "/usr/local/bin/ansible-playbook",
            "state_dir": "/var/lib/pull-trigger",
            "log_dir": "/var/log/pull-trigger",
            "timeout_seconds": 3600,
            "keep_runs": 50,
            "steps": steps,
        }
    )
    config = program.parse_config(text)
    return [(step.step_id, step.tag, step.word) for step in config.steps]


def tagged_imports(tasks_text: str) -> dict[str, list[str]]:
    """Map each tag of the role's step imports to the tags of that import, by tag."""
    found: dict[str, list[str]] = {}
    for task in yaml.safe_load(tasks_text):
        if not any(key in task for key in IMPORT_TASKS):
            continue
        tags = [str(tag) for tag in task.get("tags", [])]
        for tag in tags:
            found[tag] = tags
    return found


def missing_from_role(steps: Steps, tasks_text: str, role_ids: list[str]) -> list[str]:
    """Problems in how a list of steps lines up with the role: an id the role does not know, or
    one whose tag is not on a never-run import in the role's tasks."""
    imports = tagged_imports(tasks_text)
    problems: list[str] = []
    for entry in steps:
        step_id, tag = str(entry["id"]), str(entry["tag"])
        if step_id not in role_ids:
            problems.append(f"{step_id} is not in the role's control_plane_db_step_ids")
        if NEVER not in imports.get(tag, []):
            problems.append(f"{tag} is not on a never-tagged import in the role's tasks")
    return problems


class RealAllowlist(unittest.TestCase):
    def setUp(self) -> None:
        self.program = load_program()
        self.steps = real_steps()
        self.tasks = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        role_vars = yaml.safe_load((ROLE / "vars" / "main.yml").read_text(encoding="utf-8"))
        self.role_ids: list[str] = role_vars["control_plane_db_step_ids"]

    # Control: the committed file is accepted by the program's own parser, and what it keeps is
    # the file's three entries in order. A parser fed nothing would keep none.
    def test_the_real_list_is_accepted_by_the_program(self) -> None:
        kept = parse_allowlist(self.program, self.steps)
        self.assertEqual([(str(s["id"]), str(s["tag"]), str(s["word"])) for s in self.steps], kept)
        self.assertEqual({"migrate", "identity", "provision"}, {step_id for step_id, _, _ in kept})

    # The words are per step and distinct, so a request for one step with another step's word
    # is a mismatch the program refuses.
    def test_the_words_are_distinct(self) -> None:
        words = [str(step["word"]) for step in self.steps]
        self.assertEqual(len(words), len(set(words)))

    # W9: every listed id is a step the role knows and has a never-tagged import under its tag.
    def test_every_listed_id_is_a_tagged_step_of_the_role(self) -> None:
        self.assertEqual([], missing_from_role(self.steps, self.tasks, self.role_ids))

    # W9 sabotage: rename a role tag and the same check names it.
    def test_a_renamed_role_tag_is_found(self) -> None:
        renamed = self.tasks.replace("- control_plane_db_identity", "- control_plane_db_ident", 1)
        self.assertNotEqual(self.tasks, renamed, "the sabotage matched nothing")
        problems = missing_from_role(self.steps, renamed, self.role_ids)
        self.assertEqual(
            ["control_plane_db_identity is not on a never-tagged import in the role's tasks"],
            problems,
        )

    # W9 sabotage: an id the role does not list is named.
    def test_an_id_missing_from_the_role_list_is_found(self) -> None:
        problems = missing_from_role(self.steps, self.tasks, ["migrate", "identity"])
        self.assertEqual(["provision is not in the role's control_plane_db_step_ids"], problems)

    # W9 sabotage: an import that has lost its never tag would run on every plain apply.
    def test_an_import_without_the_never_tag_is_found(self) -> None:
        tasks = self.tasks.replace(
            "    - never\n    - control_plane_db_migrate", "    - control_plane_db_migrate"
        )
        self.assertNotEqual(self.tasks, tasks, "the sabotage matched nothing")
        problems = missing_from_role(self.steps, tasks, self.role_ids)
        self.assertEqual(
            ["control_plane_db_migrate is not on a never-tagged import in the role's tasks"],
            problems,
        )


class ProgramRefusesBadLists(unittest.TestCase):
    """W6: each edit of the real list is refused by the program's parser, not by a rule here."""

    def setUp(self) -> None:
        self.program = load_program()
        self.steps = real_steps()

    def _refused(self, steps: object) -> None:
        with self.assertRaises(self.program.ConfigError):
            parse_allowlist(self.program, steps)

    def test_a_tag_that_is_not_the_ids_own(self) -> None:
        steps = copy.deepcopy(self.steps)
        steps[0]["tag"] = "control_plane_db_other"
        self._refused(steps)

    def test_a_tag_that_is_another_steps(self) -> None:
        steps = copy.deepcopy(self.steps)
        steps[0]["tag"] = "control_plane_db_provision"
        self._refused(steps)

    def test_an_id_outside_the_closed_list(self) -> None:
        steps = copy.deepcopy(self.steps)
        steps.append(
            {"id": "break_glass", "tag": "control_plane_db_break_glass", "word": "BREAK-1"}
        )
        self._refused(steps)

    def test_a_duplicate_id(self) -> None:
        steps = copy.deepcopy(self.steps)
        steps.append(copy.deepcopy(steps[0]))
        self._refused(steps)

    def test_a_word_with_lower_case(self) -> None:
        steps = copy.deepcopy(self.steps)
        steps[0]["word"] = "migrate-ops1"
        self._refused(steps)

    def test_a_word_too_short(self) -> None:
        steps = copy.deepcopy(self.steps)
        steps[0]["word"] = "ABC"
        self._refused(steps)

    def test_a_fourth_field(self) -> None:
        steps = copy.deepcopy(self.steps)
        steps[0]["extra"] = "x"
        self._refused(steps)

    def test_a_string_in_place_of_the_list(self) -> None:
        self._refused("migrate")


if __name__ == "__main__":
    unittest.main()
