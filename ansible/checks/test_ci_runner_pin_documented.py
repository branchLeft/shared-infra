"""The runner image pin has a written owner and exit: every pinned workflow points at it.

The Ansible workflows run on a fixed Ubuntu image, not `ubuntu-latest`, until the harness is
verified on the next image. A pin nobody wrote down drifts, so ansible/README.md carries a
section on it, and this test fails when a workflow takes the pin without a comment naming that
section or when the section is gone. The workflows are not listed in the README: the pointer is
in each workflow, so a new pinned workflow adds nothing to a shared page. The text is read as
text: the rule is one word on a line.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
README = ROOT / "ansible" / "README.md"

PIN = "ubuntu-24.04"
HEADING = "## The CI runner image pin"
POINTER = "The CI runner image pin"
PIN_LINE = re.compile(r"^\s*runs-on:\s*" + re.escape(PIN) + r"\s*$", re.MULTILINE)


def pin_section(readme_text: str) -> str:
    """The text from the pin heading to the next second-level heading, or empty."""
    start = readme_text.find(HEADING)
    if start == -1:
        return ""
    rest = readme_text[start + len(HEADING) :]
    end = re.search(r"^## ", rest, re.MULTILINE)
    return rest[: end.start()] if end else rest


def comment_text(workflow_text: str) -> str:
    """The comments of a workflow file as one line, with comment marks and line breaks removed."""
    lines = [line.strip() for line in workflow_text.splitlines() if line.strip().startswith("#")]
    return " ".join(" ".join(line.lstrip("#") for line in lines).split())


def pinned_workflows(directory: Path) -> list[str]:
    return sorted(
        path.name for path in directory.glob("*.yml") if PIN_LINE.search(path.read_text())
    )


def without_pointer(directory: Path, names: list[str]) -> list[str]:
    """The pinned workflows whose own comments do not name the README section."""
    return [name for name in names if POINTER not in comment_text((directory / name).read_text())]


class RunnerPinDocumented(unittest.TestCase):
    def test_some_workflow_holds_the_pin(self) -> None:
        self.assertTrue(pinned_workflows(WORKFLOWS))

    def test_readme_has_the_pin_section(self) -> None:
        self.assertTrue(pin_section(README.read_text()).strip())

    def test_every_pinned_workflow_names_the_section_in_a_comment(self) -> None:
        self.assertEqual(without_pointer(WORKFLOWS, pinned_workflows(WORKFLOWS)), [])

    def test_section_says_who_holds_the_pin_and_how_it_comes_off(self) -> None:
        section = pin_section(README.read_text())
        for word in ("**Who holds it.**", "**When it comes off.**", "**Status.**"):
            self.assertIn(word, section)

    def test_a_workflow_with_the_pin_and_no_pointer_is_reported(self) -> None:
        self.assertEqual(
            self._check({"new.yml": f"jobs:\n  a:\n    runs-on: {PIN}\n"}), ["new.yml"]
        )

    def test_a_pointer_that_is_not_a_comment_does_not_count(self) -> None:
        text = f"jobs:\n  a:\n    name: {POINTER}\n    runs-on: {PIN}\n"
        self.assertEqual(self._check({"new.yml": text}), ["new.yml"])

    def test_a_pointer_wrapped_over_two_comment_lines_counts(self) -> None:
        comment = '    # Pinned (README, "The\n    # CI runner image pin").\n'
        text = f"jobs:\n  a:\n{comment}    runs-on: {PIN}\n"
        self.assertEqual(self._check({"ok.yml": text}), [])

    def _check(self, files: dict[str, str]) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            for name, text in files.items():
                (Path(directory) / name).write_text(text)
            return without_pointer(Path(directory), pinned_workflows(Path(directory)))


if __name__ == "__main__":
    unittest.main()
