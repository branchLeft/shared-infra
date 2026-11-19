"""Unit tests for the restore drill's failure alert (branchLeft/workspace#2023).

The drill unit is the release's pinned file, so the role gives it an `OnFailure=` in a drop-in. The
unit that names marks the failure in the textfile directory, and the alert rule in
`hetzner/monitoring/render.ts` reads the mark. The chain breaks silently if any link moves, because a
selector that matches nothing reads as "nothing is wrong". Each test below holds one link to its other
home, and each goes red when that link is cut.
"""

import re
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
REPO = ROLE.parents[2]
TASKS = ROLE / "tasks" / "main.yml"
VARS = ROLE / "vars" / "main.yml"
DROPIN = ROLE / "templates" / "restore-drill-on-failure.conf.j2"
FAILED_UNIT = ROLE / "templates" / "restore-drill-failed.service.j2"
NODE_EXPORTER_VARS = ROLE.parent / "node_exporter" / "vars" / "main.yml"
ALERT_RULES = REPO / "hetzner" / "monitoring" / "render.ts"

UNIT_NAME = "branchleft-restore-drill-failed.service"
MARKER_NAME = "restore_drill_unit_failed.prom"


def role_var(text: str, name: str) -> str:
    """The value of one top-level `name: value` line of a vars file, quotes removed."""
    match = re.search(rf"^{re.escape(name)}:\s*(.+?)\s*$", text, re.MULTILINE)
    if match is None:
        raise AssertionError(f"{name} is not defined")
    return match.group(1).strip("'\"")


def active_lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]


class OnFailureDropInTests(unittest.TestCase):
    def test_the_drop_in_names_the_failure_unit_under_unit(self) -> None:
        self.assertEqual(
            active_lines(DROPIN),
            ["[Unit]", "OnFailure={{ backup_restore_drill_failed_unit }}"],
            "the drill's drop-in must set OnFailure= in [Unit] and nothing else",
        )

    def test_the_variable_the_drop_in_reads_is_the_unit_the_role_installs(self) -> None:
        self.assertEqual(role_var(VARS.read_text(encoding="utf-8"), "backup_restore_drill_failed_unit"), UNIT_NAME)

    def test_the_drop_in_sorts_after_the_registry_key_drop_in_and_in_the_same_directory(self) -> None:
        text = VARS.read_text(encoding="utf-8")
        self.assertEqual(
            role_var(text, "backup_restore_drill_on_failure_dropin_file"),
            "{{ backup_restore_drill_dropin_dir }}/20-on-failure.conf",
        )
        self.assertEqual(
            role_var(text, "backup_restore_drill_dropin_file"),
            "{{ backup_restore_drill_dropin_dir }}/10-registry-key.conf",
        )
        self.assertTrue(role_var(text, "backup_restore_drill_dropin_dir").endswith("/branchleft-restore-drill.service.d"))


class TaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = TASKS.read_text(encoding="utf-8")

    def _block(self, task_name: str) -> str:
        match = re.search(rf"^- name: {re.escape(task_name)}\n(.*?)(?=^\S|\Z)", self.text, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match, f"{task_name!r} is not a task of tasks/main.yml")
        assert match is not None
        return match.group(1)

    def test_the_unit_is_written_before_the_drop_in_that_names_it(self) -> None:
        unit = self.text.index("- name: Install the unit that marks a failed restore drill\n")
        dropin = self.text.index("- name: Make a failed restore drill start the unit that marks it\n")
        self.assertLess(unit, dropin, "a drop-in must never name a unit that is not on the host yet")

    def test_both_files_are_root_0644_from_their_templates_and_reload_systemd(self) -> None:
        for task, src, dest in (
            ("Install the unit that marks a failed restore drill", "restore-drill-failed.service.j2", "backup_restore_drill_failed_unit_file"),
            ("Make a failed restore drill start the unit that marks it", "restore-drill-on-failure.conf.j2", "backup_restore_drill_on_failure_dropin_file"),
        ):
            body = self._block(task)
            for line in (
                f"src: {src}",
                f"dest: '{{{{ {dest} }}}}'",
                "owner: root",
                "group: root",
                "mode: '0644'",
                "notify: Reload systemd after the restore units change",
            ):
                self.assertIn(line, body, f"{task!r} must carry {line!r}")


class FailureUnitTests(unittest.TestCase):
    def test_the_unit_marks_the_file_the_rule_reads_and_runs_nothing_else(self) -> None:
        lines = active_lines(FAILED_UNIT)
        exec_lines = [line for line in lines if line.startswith("Exec")]
        self.assertEqual(
            exec_lines,
            ["ExecStart=/usr/bin/install -D -m 0644 /dev/null {{ backup_restore_drill_failed_marker }}"],
        )
        self.assertIn("Type=oneshot", lines)
        self.assertNotIn("OnFailure=", "\n".join(lines), "the failure unit must not name a failure unit of its own")

    def test_the_unit_does_not_depend_on_what_the_drill_depends_on(self) -> None:
        text = "\n".join(active_lines(FAILED_UNIT))
        for needle in ("docker", "network-online", "Requires=", "After="):
            self.assertNotIn(needle, text, f"a failed drill whose dependency failed must still be marked: {needle}")


class OneHomeTests(unittest.TestCase):
    def test_the_marker_is_the_file_the_alert_rule_selects(self) -> None:
        text = VARS.read_text(encoding="utf-8")
        self.assertEqual(
            role_var(text, "backup_restore_drill_failed_marker"),
            f"{{{{ backup_restore_textfile_dir }}}}/{MARKER_NAME}",
        )
        rules = ALERT_RULES.read_text(encoding="utf-8")
        self.assertIn(f'file="{MARKER_NAME}"', rules, "hetzner/monitoring/render.ts must select the file this role writes")

    def test_the_textfile_directory_is_the_one_node_exporter_reads(self) -> None:
        self.assertEqual(
            role_var(VARS.read_text(encoding="utf-8"), "backup_restore_textfile_dir"),
            role_var(NODE_EXPORTER_VARS.read_text(encoding="utf-8"), "node_exporter_textfile_dir"),
        )


if __name__ == "__main__":
    unittest.main()
