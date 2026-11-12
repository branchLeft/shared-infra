"""The mail collector's role and its input check name the same two paths, and run in one order.

mail_collector installs the unit that reads the owner's credentials file and the descriptor
directory. mail_collector_inputs reads the same two paths to refuse a file that is wrong before the
collector can start on it. The two roles are written separately and a role may not load another
(ANS-12), so each keeps its own copy of the paths and this test holds both to one literal. A rename
in either role alone would pass that role's own tests and leave the check reading a file the unit
never uses, so the check would pass on a file that does not matter and the unit would start on one
that was never checked.

The two roles land in separate changes, so the test reads whichever of them is in the tree and
requires at least one, and checks the two together when both are. The order check applies to the
playbook only when both are applied: the input check goes first, so a refusal stops the play before
the collector's role writes a descriptor or starts the unit.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
PLAYBOOK = ROOT / "ansible" / "playbooks" / "ops1.yml"
CREDENTIALS = "/etc/branchleft/mail-collector/credentials.env"
DESCRIPTORS = "/etc/branchleft/mail-collector/descriptors"
COLLECTOR_ROLE = "mail_collector"
CHECK_ROLE = "mail_collector_inputs"
# Each role's variable names for the two paths.
PATH_VARIABLES = {
    COLLECTOR_ROLE: ("mail_collector_credentials_file", "mail_collector_descriptor_dir"),
    CHECK_ROLE: ("mail_collector_inputs_credentials_path", "mail_collector_inputs_descriptor_dir"),
}


def role_vars(role: str) -> dict[str, object] | None:
    """Return a role's vars/main.yml, or None when the role is not in the tree.

    Raises:
        AssertionError: when the file cannot be read as a mapping.
    """
    path = ROLES / role / "vars" / "main.yml"
    if not path.is_file():
        return None
    document, problem = load_yaml(path)
    if problem is not None or not isinstance(document, dict):
        raise AssertionError(problem or f"{role}/vars/main.yml is not a mapping")
    return {str(key): value for key, value in document.items()}


def applied_roles() -> list[str]:
    """Return the roles ops1's playbook applies, in order, by name.

    Raises:
        AssertionError: when the playbook cannot be read as a list of plays.
    """
    document, problem = load_yaml(PLAYBOOK)
    if problem is not None or not isinstance(document, list):
        raise AssertionError(problem or "ops1.yml is not a list of plays")
    names: list[str] = []
    for play in document:
        for entry in play.get("roles", []) if isinstance(play, dict) else []:
            if isinstance(entry, dict):
                names.append(str(entry["role"]).rsplit("/", 1)[-1])
    return names


class PathsAgree(unittest.TestCase):
    """The two roles agree on the owner's file and the descriptor directory."""

    def present(self) -> dict[str, dict[str, object]]:
        found = {role: variables for role in PATH_VARIABLES if (variables := role_vars(role))}
        self.assertTrue(found, "neither mail collector role is in the tree: the test reads nothing")
        return found

    def test_each_role_present_names_the_one_credentials_file_and_descriptor_directory(
        self,
    ) -> None:
        for role, variables in self.present().items():
            credentials, descriptors = PATH_VARIABLES[role]
            with self.subTest(role=role):
                self.assertEqual(variables.get(credentials), CREDENTIALS)
                self.assertEqual(variables.get(descriptors), DESCRIPTORS)

    def test_the_credentials_file_is_named_after_the_unit_that_reads_it(self) -> None:
        # Where the collector role is not in the tree there is no unit to read, and the test above
        # has already required that one of the two roles is.
        unit = ROLES / COLLECTOR_ROLE / "files" / "mail-collector.service"
        if unit.is_file():
            text = unit.read_text(encoding="utf-8")
            self.assertIn(f"ConditionFileNotEmpty={CREDENTIALS}\n", text)
            self.assertIn(f"--env-file {CREDENTIALS} ", text)
            self.assertIn(f"ConditionDirectoryNotEmpty={DESCRIPTORS}\n", text)

    def test_the_input_check_runs_before_the_collector_when_both_are_applied(self) -> None:
        names = applied_roles()
        if CHECK_ROLE in names and COLLECTOR_ROLE in names:
            self.assertLess(names.index(CHECK_ROLE), names.index(COLLECTOR_ROLE))


if __name__ == "__main__":
    unittest.main()
