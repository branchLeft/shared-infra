"""One home for the monitoring stack's eight files and for the restart of its unit.

The monitoring_stack role is the only role that delivers the eight files in
/opt/branchleft/monitoring and the only role that restarts
branchleft-compose@monitoring.service. Two homes for a file, or two roles that
restart one unit, make the restart depend on which role ran last and when: that was
the defect of the monitoring_stack role before its restart moved into one fingerprint.

These tests read the roles' code (tasks, handlers, vars and defaults) and fail when
another role

- names one of the eight files, either by its path under /opt/branchleft/monitoring
  or as a list entry or ``stack/<file>`` source in a role that delivers from the
  monitoring stack directory, or
- names the monitoring unit at all (a restart, a start or a reload of it).

The list of the eight files is read from monitoring_stack's own vars, so there is no
second list to keep in step. The ninth file in that directory, the Alertmanager
renderer, is not one of the eight: ntfy_pager delivers it and monitoring_stack only
hashes it.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
STACK = ROOT / "hetzner" / "monitoring" / "stack"
OWNER = "monitoring_stack"
PROJECT_DIR = "/opt/branchleft/monitoring"
UNIT = "branchleft-compose@monitoring"
RENDERER = "render_alertmanager_config.py"
CODE_AREAS = ("tasks", "handlers", "vars", "defaults")

LIST_ITEM = re.compile(r"^\s*-\s+['\"]?([^'\"\s#]+)['\"]?\s*(?:#.*)?$")


def owned_files(vars_text: str) -> list[str]:
    """Return the entries of the monitoring_stack_files list in the owner's vars/main.yml."""
    files: list[str] = []
    inside = False
    for line in vars_text.splitlines():
        if line.startswith("monitoring_stack_files:"):
            inside = True
            continue
        if not inside:
            continue
        item = LIST_ITEM.match(line)
        if item is None:
            break
        files.append(item.group(1))
    return files


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
    """Say whether a link under the role's files/ points into the monitoring stack directory."""
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


def violations(role: Path, files: list[str], stack: Path = STACK) -> list[str]:
    """Return every way a role names one of the eight files or the monitoring unit."""
    found: list[str] = []
    from_stack = delivers_from_stack(role, stack)
    for name, text in code_of(role).items():
        if UNIT in text:
            found.append(f"{name} names the monitoring unit")
        for entry in files:
            if f"{PROJECT_DIR}/{entry}" in text:
                found.append(f"{name} names {PROJECT_DIR}/{entry}")
            if from_stack and f"stack/{entry}" in text:
                found.append(f"{name} delivers stack/{entry}")
        if from_stack:
            for line in text.splitlines():
                item = LIST_ITEM.match(line)
                if item is not None and item.group(1) in files:
                    found.append(f"{name} lists {item.group(1)}")
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


class MonitoringSingleHomeTest(unittest.TestCase):
    def setUp(self) -> None:
        owner_vars = (ROLES / OWNER / "vars" / "main.yml").read_text(encoding="utf-8")
        self.files = owned_files(owner_vars)

    def test_the_owner_lists_eight_files_and_each_is_in_the_stack_directory(self) -> None:
        self.assertEqual(
            8, len(self.files), "monitoring_stack_files must hold the eight stack files"
        )
        self.assertEqual([], [f for f in self.files if not (STACK / f).is_file()])
        self.assertNotIn(RENDERER, self.files)

    def test_no_other_role_names_a_stack_file_or_the_monitoring_unit(self) -> None:
        found: dict[str, list[str]] = {}
        for role in sorted(ROLES.iterdir()):
            if not role.is_dir() or role.name == OWNER:
                continue
            problems = violations(role, self.files)
            if problems:
                found[role.name] = problems
        self.assertEqual(
            {}, found, "only monitoring_stack may deliver these files or name this unit"
        )

    def test_ntfy_pager_delivers_the_renderer_and_nothing_else_of_the_stack(self) -> None:
        text = (ROLES / "ntfy_pager" / "vars" / "main.yml").read_text(encoding="utf-8")
        listed = [m.group(1) for line in text.splitlines() if (m := LIST_ITEM.match(line))]
        self.assertEqual([RENDERER], listed)

    def test_the_scan_finds_what_it_is_meant_to_find(self) -> None:
        # A control: pointed at the owner itself, the scan must report the files and the
        # unit, or a clean result for the other roles proves nothing.
        owner = violations(ROLES / OWNER, self.files)
        self.assertTrue(any("compose.yml" in problem for problem in owner), owner)
        self.assertTrue(any("names the monitoring unit" in problem for problem in owner), owner)

    def test_a_role_that_lists_a_stack_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", "other_files:\n  - prometheus/alerts.yml\n", STACK)
            self.assertEqual(
                ["vars/main.yml lists prometheus/alerts.yml"], violations(role, self.files)
            )

    def test_a_role_that_names_the_monitoring_unit_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(
                Path(tmp), "other", "other_unit: branchleft-compose@monitoring.service\n", None
            )
            self.assertEqual(
                ["vars/main.yml names the monitoring unit"], violations(role, self.files)
            )

    def test_a_role_that_names_a_stack_file_by_its_host_path_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(
                Path(tmp), "other", "other_dest: /opt/branchleft/monitoring/compose.yml\n", None
            )
            self.assertEqual(
                ["vars/main.yml names /opt/branchleft/monitoring/compose.yml"],
                violations(role, self.files),
            )

    def test_a_role_with_its_own_compose_file_is_not_reported(self) -> None:
        # nextcloud_stack lists a compose.yml of its own: a name alone is not a delivery from
        # the monitoring stack.
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", "other_files:\n  - compose.yml\n", None)
            self.assertEqual([], violations(role, self.files))

    def test_a_role_that_lists_only_the_renderer_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = make_role(Path(tmp), "other", f"other_files:\n  - {RENDERER}\n", STACK)
            self.assertEqual([], violations(role, self.files))


if __name__ == "__main__":
    unittest.main()
