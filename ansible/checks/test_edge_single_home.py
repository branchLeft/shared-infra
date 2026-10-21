"""One home for the edge stack's files and for the restart of its unit.

The edge_stack role is the only role that delivers the files in /opt/branchleft/edge
and the only role that restarts branchleft-compose@edge.service. Two homes for a file,
or two roles that restart one unit, make the restart depend on which role ran last and
when: that is the defect the stamps of edge_stack exist to remove.

These tests read the roles' code (tasks, handlers, vars and defaults) and fail when
another role

- names the project directory /opt/branchleft/edge, or a file of the stack by its path
  under it, or delivers from the stack directory hetzner/edge/stack, or
- names the edge unit (a restart, a start or a reload of it).

The one thing another role may name is the directory of drop-ins of the unit,
``branchleft-compose@edge.service.d``: a drop-in changes how the unit starts and
restarts nothing.

The files of the stack are read from the stack directory itself, and the test that the
owner puts each of them in a class is here too, so there is no second list to keep in
step.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
STACK = ROOT / "hetzner" / "edge" / "stack"
OWNER = "edge_stack"
PROJECT_DIR = "/opt/branchleft/edge"
UNIT = "branchleft-compose@edge"
DROP_IN_DIRECTORY = "branchleft-compose@edge.service.d"
CODE_AREAS = ("tasks", "handlers", "vars", "defaults")

LIST_ITEM = re.compile(r"^\s*-\s+['\"]?([^'\"\s#]+)['\"]?\s*(?:#.*)?$")
# The directory name is a prefix of nothing else: a path component that continues with
# another word character is a different directory (edge1, edge-staging).
PROJECT_DIR_PATTERN = re.compile(re.escape(PROJECT_DIR) + r"(?![\w.-])")


def stack_files() -> list[str]:
    """Return the path of every regular file in the stack directory, relative to it."""
    return sorted(p.relative_to(STACK).as_posix() for p in STACK.rglob("*") if p.is_file())


def code_of(role: Path) -> dict[str, str]:
    """Map the path of each YAML file in a role's code areas to its text."""
    found: dict[str, str] = {}
    for area in CODE_AREAS:
        base = role / area
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in {".yml", ".yaml"}:
                found[path.relative_to(role).as_posix()] = path.read_text(encoding="utf-8")
    return found


def delivers_from_stack(role: Path, stack: Path) -> bool:
    """Say whether a link under the role's files/ points into the edge stack directory."""
    files = role / "files"
    if not files.is_dir():
        return False
    for path in files.rglob("*"):
        if not path.is_symlink():
            continue
        target = (path.parent / path.readlink()).resolve()
        if target == stack.resolve() or stack.resolve() in target.parents:
            return True
    return False


def violations(role: Path, stack: Path = STACK) -> list[str]:
    """Return every way a role names the edge project directory, a stack file or the unit."""
    found: list[str] = []
    if delivers_from_stack(role, stack):
        found.append("files/ links into the edge stack directory")
    for name, text in code_of(role).items():
        if UNIT in text.replace(DROP_IN_DIRECTORY, ""):
            found.append(f"{name} names the edge unit")
        if PROJECT_DIR_PATTERN.search(text):
            found.append(f"{name} names {PROJECT_DIR}")
    return found


def make_role(base: Path, name: str, vars_text: str, link_to: Path | None) -> Path:
    """Write a throwaway role with a vars file and, when asked, a files/stack link."""
    role = base / name
    (role / "vars").mkdir(parents=True)
    (role / "vars" / "main.yml").write_text(vars_text, encoding="utf-8")
    if link_to is not None:
        (role / "files").mkdir()
        (role / "files" / "stack").symlink_to(link_to)
    return role


class EdgeSingleHomeTest(unittest.TestCase):
    def test_the_owner_puts_every_file_of_the_stack_in_a_class(self) -> None:
        owner_vars = (ROLES / OWNER / "vars" / "main.yml").read_text(encoding="utf-8")
        named = {
            m.group(1)
            for line in owner_vars.splitlines()
            if (m := LIST_ITEM.match(line)) and "/" in m.group(1)
        }
        named |= {"Caddyfile", "compose.yml"}
        stack = stack_files()
        self.assertNotEqual([], stack, "the stack directory must hold the edge files")
        unclassified = [
            f for f in stack if f not in named and not f.startswith("crowdsec/acquis.d/")
        ]
        self.assertEqual([], unclassified, "every stack file must be in a class of the owner")

    def test_no_other_role_names_the_project_directory_the_stack_or_the_edge_unit(self) -> None:
        found: dict[str, list[str]] = {}
        for role in sorted(ROLES.iterdir()):
            if not role.is_dir() or role.name == OWNER:
                continue
            problems = violations(role)
            if problems:
                found[role.name] = problems
        self.assertEqual({}, found, "only edge_stack may deliver these files or name this unit")

    def test_the_scan_finds_what_it_is_meant_to_find(self) -> None:
        # A control: pointed at the owner itself, the scan must report the directory, the
        # unit and the link, or a clean result for the other roles proves nothing.
        owner = violations(ROLES / OWNER)
        self.assertTrue(any("names the edge unit" in problem for problem in owner), owner)
        self.assertTrue(any(PROJECT_DIR in problem for problem in owner), owner)
        self.assertIn("files/ links into the edge stack directory", owner)

    def test_a_role_that_names_the_edge_unit_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(
                Path(tmp), "other", "other_unit: branchleft-compose@edge.service\n", None
            )
            self.assertEqual(["vars/main.yml names the edge unit"], violations(role))

    def test_a_role_that_names_a_file_of_the_stack_by_its_host_path_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(
                Path(tmp), "other", "other_dest: /opt/branchleft/edge/Caddyfile\n", None
            )
            self.assertEqual([f"vars/main.yml names {PROJECT_DIR}"], violations(role))

    def test_a_role_that_delivers_from_the_stack_directory_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", "other_files: []\n", STACK)
            self.assertEqual(["files/ links into the edge stack directory"], violations(role))

    def test_the_drop_in_directory_of_the_unit_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(
                Path(tmp),
                "other",
                "other_dir: /etc/systemd/system/branchleft-compose@edge.service.d\n",
                None,
            )
            self.assertEqual([], violations(role))

    def test_a_directory_that_only_starts_like_the_project_directory_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", "other_dest: /opt/branchleft/edge1/x\n", None)
            self.assertEqual([], violations(role))

    def test_a_role_with_its_own_compose_file_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", "other_files:\n  - compose.yml\n", None)
            self.assertEqual([], violations(role))


if __name__ == "__main__":
    unittest.main()
