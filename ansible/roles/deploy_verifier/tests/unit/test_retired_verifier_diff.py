"""The plan hides the diff of one replacement only: the retired shell verifier's.

The verifier was a shell program before it became files/branchleft-verify-image.py. The shell
program held a placeholder token line that the delivery plan's secret scan reads as a credential
assignment, so a plan that replaces it prints that line as removed and the host is withheld. The
role hides the copy's diff only when the host holds that program, named by its sha256, and says
what it replaces. These tests read the role's tasks and fail when that is lost; the Molecule case
molecule/default/tasks/plan_retired_verifier.yml runs both plans.
"""

import re
import unittest
from pathlib import Path

import yaml  # type: ignore[import-untyped,unused-ignore]

ROLE = Path(__file__).resolve().parents[2]
TASKS = ROLE / "tasks" / "main.yml"
LOOK = "Look at the verifier path before it is written"
REPLACE = "Replace the verifier, hiding only the lines of the retired shell program"
SAY = "Say the plan replaces the retired shell verifier without showing its lines"
COPY = "Install the verifier from the role's files, the one home of the program"
# The sha256 of hetzner/provision/branchleft-verify-image as last delivered, at shared-infra
# c1d37372: `git show c1d37372:hetzner/provision/branchleft-verify-image | shasum -a 256`.
RETIRED = "4739d9e574c5448ce5720e28668c9b03b978f19c2a3a2ef0caec25438ce30fa5"
HOLDS_RETIRED = (
    "deploy_verifier_verifier_before.stat.checksum | default('') "
    "== deploy_verifier_retired_shell_sha256"
)
SHOWN = (
    "{{ deploy_verifier_verifier_before.stat.checksum | default('') "
    "!= deploy_verifier_retired_shell_sha256 }}"
)
# The plan scan's credential-assignment pattern (github-workflows ssh-check-hosts).
SCAN = re.compile(
    r"(passw(or)?d|passphrase|secret|token|api[_-]?key|private[_-]?key|credential)"
    r'[A-Za-z0-9_.-]*"?\s*[:=]\s*"?[^\s"]{4,}',
    re.IGNORECASE,
)


def _mappings(node: object) -> list[dict[str, object]]:
    """Return the mappings in a parsed YAML list, in order."""
    if not isinstance(node, list):
        return []
    return [
        {str(key): value for key, value in item.items()} for item in node if isinstance(item, dict)
    ]


def _tasks() -> list[dict[str, object]]:
    """Return the role's top-level tasks, parsed, in order."""
    return _mappings(yaml.safe_load(TASKS.read_text(encoding="utf-8")))


def _named(tasks: list[dict[str, object]], name: str) -> dict[str, object]:
    """Return the first task with this name, or an empty mapping when there is none."""
    found = [task for task in tasks if task.get("name") == name]
    return found[0] if found else {}


def _names(tasks: list[dict[str, object]]) -> list[str]:
    """Return the names of the tasks, in order."""
    return [str(task.get("name")) for task in tasks]


def _module(task: dict[str, object], name: str) -> dict[str, object]:
    """Return a task's module arguments, or an empty mapping."""
    args = task.get(name)
    return {str(key): value for key, value in args.items()} if isinstance(args, dict) else {}


class RetiredVerifierDiffTests(unittest.TestCase):
    """The diff is hidden for the retired program alone, and the plan says so."""

    def setUp(self) -> None:
        self.tasks = _tasks()
        self.replace = _named(self.tasks, REPLACE)
        self.inner = _mappings(self.replace.get("block"))

    def test_the_path_is_read_with_its_sha256_before_the_replacement(self) -> None:
        """The digest the condition compares is read first, as sha256."""
        names = _names(self.tasks)
        self.assertIn(LOOK, names)
        self.assertIn(REPLACE, names)
        self.assertLess(names.index(LOOK), names.index(REPLACE))
        stat = _module(_named(self.tasks, LOOK), "ansible.builtin.stat")
        self.assertIs(stat.get("get_checksum", True), True)
        self.assertEqual(stat.get("checksum_algorithm"), "sha256")

    def test_the_retired_digest_is_pinned_on_the_replacement(self) -> None:
        """The one digest whose diff is hidden is the retired shell program's."""
        block_vars = self.replace.get("vars")
        pinned = (
            block_vars.get("deploy_verifier_retired_shell_sha256")
            if isinstance(block_vars, dict)
            else None
        )
        self.assertEqual(pinned, RETIRED)

    def test_the_copy_shows_its_diff_unless_the_host_holds_the_retired_program(self) -> None:
        """Every other content at the path is shown; diff: false would hide them all."""
        self.assertEqual(_names(self.inner), [SAY, COPY])
        self.assertEqual(_named(self.inner, COPY).get("diff"), SHOWN)

    def test_the_plan_says_what_it_replaces_when_it_hides_the_diff(self) -> None:
        """The report runs exactly when the diff is hidden (ANS-10)."""
        say = _named(self.inner, SAY)
        self.assertEqual(say.get("when"), HOLDS_RETIRED)
        message = str(_module(say, "ansible.builtin.debug").get("msg", ""))
        self.assertIn("holds the retired shell verifier", message)
        self.assertIsNone(SCAN.search(message), "the report itself would be withheld")


if __name__ == "__main__":
    unittest.main()
