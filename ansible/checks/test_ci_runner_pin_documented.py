"""The runner image pin has a written owner and exit: every pinned workflow is named there.

The Ansible workflows run on a fixed Ubuntu image, not `ubuntu-latest`, until the harness is
verified on the next image. A pin nobody wrote down drifts, so ansible/README.md carries a
section on it, and this test fails when a workflow takes the pin without being named in that
section or when the section is gone. The text is read as text: the rule is one word on a line.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
README = ROOT / "ansible" / "README.md"

PIN = "ubuntu-24.04"
HEADING = "## The CI runner image pin"
PIN_LINE = re.compile(r"^\s*runs-on:\s*" + re.escape(PIN) + r"\s*$", re.MULTILINE)


def pin_section(readme_text: str) -> str:
    """The text from the pin heading to the next second-level heading, or empty."""
    start = readme_text.find(HEADING)
    if start == -1:
        return ""
    rest = readme_text[start + len(HEADING) :]
    end = re.search(r"^## ", rest, re.MULTILINE)
    return rest[: end.start()] if end else rest


def pinned_workflows(directory: Path) -> list[str]:
    return sorted(
        path.name for path in directory.glob("*.yml") if PIN_LINE.search(path.read_text())
    )


def undocumented(readme_text: str, names: list[str]) -> list[str]:
    section = pin_section(readme_text)
    return [name for name in names if f"`{name}`" not in section]


class RunnerPinDocumented(unittest.TestCase):
    def test_some_workflow_holds_the_pin(self) -> None:
        self.assertTrue(pinned_workflows(WORKFLOWS))

    def test_readme_has_the_pin_section(self) -> None:
        self.assertTrue(pin_section(README.read_text()).strip())

    def test_every_pinned_workflow_is_named_in_the_section(self) -> None:
        self.assertEqual(
            undocumented(README.read_text(), pinned_workflows(WORKFLOWS)),
            [],
        )

    def test_section_says_who_holds_the_pin_and_how_it_comes_off(self) -> None:
        section = pin_section(README.read_text())
        for word in ("**Who holds it.**", "**When it comes off.**", "**Status.**"):
            self.assertIn(word, section)

    def test_a_workflow_missing_from_the_section_is_reported(self) -> None:
        readme = f"{HEADING}\n\n`ansible.yml` only.\n\n## Next\n"
        self.assertEqual(undocumented(readme, ["ansible.yml", "new.yml"]), ["new.yml"])

    def test_a_name_outside_the_section_does_not_count(self) -> None:
        readme = f"{HEADING}\n\nnothing.\n\n## Next\n\n`ansible.yml`\n"
        self.assertEqual(undocumented(readme, ["ansible.yml"]), ["ansible.yml"])


if __name__ == "__main__":
    unittest.main()
