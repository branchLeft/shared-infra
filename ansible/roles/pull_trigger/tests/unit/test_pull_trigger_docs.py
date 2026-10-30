"""The README's one command for reading the push receiver's result is the command the scenario runs.

The command is what the person who applies a push reads at the end, so a copy that drifted from
the one the push scenario proves would be a command nobody has run. This file reads the two texts
and compares them. It is not copied into the container (the role directory is not there), and it
fails, not skips, if either text cannot be found.
"""

import re
import textwrap
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
README = ROLE / "README.md"
VERIFY = ROLE / "molecule" / "push" / "verify.yml"
MARKER = "floor=%s"


def readme_commands() -> list[str]:
    """Return every fenced shell block of the README that prints the floor."""
    text = README.read_text(encoding="utf-8")
    blocks = [str(block) for block in re.findall(r"^```bash\n(.*?)^```$", text, re.S | re.M)]
    return [block.rstrip("\n") for block in blocks if MARKER in block]


def scenario_commands() -> list[str]:
    """Return the value of each ``verify_result_command`` literal block of the push scenario."""
    lines = VERIFY.read_text(encoding="utf-8").splitlines()
    found: list[str] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)verify_result_command: \|-$", line)
        if match is None:
            continue
        indent = len(match.group(1))
        body: list[str] = []
        for following in lines[index + 1 :]:
            if following.strip() and len(following) - len(following.lstrip()) <= indent:
                break
            body.append(following)
        found.append(textwrap.dedent("\n".join(body)).strip("\n"))
    return found


class ReadmeCommandTests(unittest.TestCase):
    """The documented command and the proven command are one text."""

    def test_each_text_holds_exactly_one_command(self) -> None:
        """A missing or doubled command fails here, not as an empty comparison."""
        self.assertEqual(len(readme_commands()), 1)
        self.assertEqual(len(scenario_commands()), 1)

    def test_the_readme_command_is_the_command_the_push_scenario_runs(self) -> None:
        """A change to one without the other fails here."""
        self.assertEqual(readme_commands(), scenario_commands())

    def test_the_command_reads_the_floor_and_the_last_verdict_and_no_time(self) -> None:
        """It names the floor file and the log, and picks out only the fixed fields."""
        for command in scenario_commands():
            self.assertIn("/var/lib/pull-trigger/last-applied", command)
            self.assertIn("/var/log/pull-trigger/pull-trigger.log", command)
            self.assertIn("(verdict|exit|changed)=", command)


if __name__ == "__main__":
    unittest.main()
