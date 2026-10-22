"""Fails while a role includes another role and no merged ANS-12 amendment is cited.

Why, and how to cite the amendment: ansible/roles/restart_stamp/README.md, "Composition (ANS-12)".
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from role_tasks import parsed_tasks, short_name

ROOT = Path(__file__).resolve().parents[2]
ROLE_DIRS = (ROOT / "ansible" / "roles", ROOT / "ansible" / "patterns")
CITATION = ROOT / "ansible" / "checks" / "ans12_composition_citation.txt"

INCLUDING = frozenset({"include_role", "import_role"})
CITATION_FORM = re.compile(
    r"https://github\.com/branchLeft/standards/pull/[0-9]+ merged [0-9a-f]{40}"
)

NO_CITATION = (
    "a role includes another role, which ANS-12 leaves to an amendment, and {citation} "
    "is {state}. Merge the amendment in the standards repository, then record one line: "
    "https://github.com/branchLeft/standards/pull/<number> merged <40-hex merge commit>"
)


def including_roles(bases: tuple[Path, ...]) -> dict[str, list[str]]:
    """Return each role that has a task including another role, with the files of those tasks."""
    found: dict[str, set[str]] = {}
    for base in bases:
        if not base.is_dir():
            continue
        for role in sorted(base.iterdir()):
            if not role.is_dir():
                continue
            for name, task in parsed_tasks(role):
                if any(short_name(str(key)) in INCLUDING for key in task):
                    found.setdefault(f"{base.name}/{role.name}", set()).add(name)
    return {role: sorted(files) for role, files in found.items()}


def gate(bases: tuple[Path, ...], citation: Path) -> list[str]:
    """Return what stops a merge: roles that include a role, with no citation of the amendment."""
    roles = including_roles(bases)
    if not roles:
        return []
    shown = ", ".join(f"{role} ({', '.join(files)})" for role, files in roles.items())
    if not citation.is_file():
        return [f"{shown}: " + NO_CITATION.format(citation=citation.name, state="missing")]
    if not CITATION_FORM.fullmatch(citation.read_text(encoding="utf-8").strip()):
        return [f"{shown}: " + NO_CITATION.format(citation=citation.name, state="malformed")]
    return []


def make_including_role(base: Path, text: str) -> None:
    """Write a throwaway role named ``caller`` with one task file."""
    (base / "roles" / "caller" / "tasks").mkdir(parents=True)
    (base / "roles" / "caller" / "tasks" / "main.yml").write_text(text, encoding="utf-8")


INCLUDE = "---\n- name: Call\n  ansible.builtin.include_role:\n    name: other\n"
CITED = "https://github.com/branchLeft/standards/pull/155 merged " + "a" * 40 + "\n"


class RoleCompositionGateTest(unittest.TestCase):
    def test_the_real_tree_has_the_amendment_cited_for_every_role_that_includes_a_role(
        self,
    ) -> None:
        self.assertEqual([], gate(ROLE_DIRS, CITATION))

    def test_the_scan_finds_the_include_of_the_real_edge_stack(self) -> None:
        # A control for the test above: a clean result means something only if the scan
        # sees the include that is there.
        found = including_roles(ROLE_DIRS)
        self.assertEqual(["roles/edge_stack"], sorted(found))

    def test_an_include_with_no_citation_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            make_including_role(Path(tmp), INCLUDE)
            problems = gate((Path(tmp) / "roles",), Path(tmp) / "citation.txt")
            self.assertEqual(1, len(problems))
            self.assertIn("roles/caller (tasks/main.yml)", problems[0])
            self.assertIn("is missing", problems[0])

    def test_an_include_with_the_citation_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            make_including_role(Path(tmp), INCLUDE)
            citation = Path(tmp) / "citation.txt"
            citation.write_text(CITED, encoding="utf-8")
            self.assertEqual([], gate((Path(tmp) / "roles",), citation))

    def test_a_citation_that_is_not_a_merged_standards_pull_request_is_reported(self) -> None:
        wrong = (
            "https://github.com/branchLeft/standards/pull/155\n",
            "https://github.com/branchLeft/shared-infra/pull/155 merged " + "a" * 40 + "\n",
            "https://github.com/branchLeft/standards/pull/155 merged abc123\n",
            "TBD\n",
            "",
        )
        for text in wrong:
            with self.subTest(text=text), tempfile.TemporaryDirectory() as tmp:
                make_including_role(Path(tmp), INCLUDE)
                citation = Path(tmp) / "citation.txt"
                citation.write_text(text, encoding="utf-8")
                problems = gate((Path(tmp) / "roles",), citation)
                self.assertEqual(1, len(problems))
                self.assertIn("is malformed", problems[0])

    def test_an_include_inside_a_block_and_an_import_are_reported(self) -> None:
        nested = (
            "---\n- name: Outer\n  block:\n    - name: Inner\n"
            "      ansible.builtin.import_role:\n        name: other\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            make_including_role(Path(tmp), nested)
            self.assertEqual(1, len(gate((Path(tmp) / "roles",), Path(tmp) / "citation.txt")))

    def test_no_include_needs_no_citation(self) -> None:
        text = "---\n- name: Say\n  ansible.builtin.debug:\n    msg: x\n"
        with tempfile.TemporaryDirectory() as tmp:
            make_including_role(Path(tmp), text)
            self.assertEqual([], gate((Path(tmp) / "roles",), Path(tmp) / "citation.txt"))


if __name__ == "__main__":
    unittest.main()
