"""Unit tests for the db1_backup_timers role's files and its schedule.

The role copies programs and units; these tests read the role's own files and
its vars, and fail when a unit names a program the role does not deliver, when a
local import is not delivered, or when a schedule value drifts from the runbook.
"""

import re
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
FILES = ROLE / "files"
VARS = ROLE / "vars" / "main.yml"
UNITS = FILES / "units"
PROVISION = FILES / "provision"
RECOVERY = FILES / "recovery"


def _list_under(key: str) -> list[str]:
    """Return the items of one YAML list in vars/main.yml, read as text."""
    items: list[str] = []
    inside = False
    for line in VARS.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}:"):
            inside = True
            continue
        if inside:
            match = re.match(r"^  - (\S+)\s*$", line)
            if match:
                items.append(match.group(1))
            elif line.strip():
                break
    return items


def _unit_value(unit: str, key: str) -> list[str]:
    """Return every value of one key in a unit file."""
    text = (UNITS / unit).read_text(encoding="utf-8")
    return [m.group(1).strip() for m in re.finditer(rf"^{key}=(.*)$", text, re.MULTILINE)]


class ScheduleTests(unittest.TestCase):
    def test_dump_timer_runs_at_0310_utc(self) -> None:
        self.assertEqual(_unit_value("branchleft-db-dump.timer", "OnCalendar"), ["*-*-* 03:10:00"])

    def test_prune_timer_runs_at_0345_utc(self) -> None:
        self.assertEqual(_unit_value("branchleft-db-prune.timer", "OnCalendar"), ["*-*-* 03:45:00"])

    def test_binlog_ship_timer_is_five_minutes_after_boot_then_every_fifteen(self) -> None:
        self.assertEqual(_unit_value("branchleft-db-binlog-ship.timer", "OnBootSec"), ["5min"])
        self.assertEqual(_unit_value("branchleft-db-binlog-ship.timer", "OnUnitActiveSec"), ["15min"])


class DeliveryTests(unittest.TestCase):
    def test_every_listed_unit_is_a_file_in_files_units(self) -> None:
        for unit in _list_under("db1_backup_timers_units"):
            self.assertTrue((UNITS / unit).is_file(), unit)

    def test_every_program_a_service_runs_is_delivered(self) -> None:
        delivered = set(_list_under("db1_backup_timers_provision_files")) | set(
            _list_under("db1_backup_timers_recovery_files")
        )
        for unit in _list_under("db1_backup_timers_units"):
            if not unit.endswith(".service"):
                continue
            for exec_start in _unit_value(unit, "ExecStart"):
                program = Path(exec_start.split()[-1]).name
                self.assertIn(program, delivered, f"{unit} runs {program}, which the role does not deliver")

    def test_every_local_import_of_a_delivered_program_is_delivered(self) -> None:
        provision = set(_list_under("db1_backup_timers_provision_files"))
        for program in provision:
            text = (PROVISION / program).read_text(encoding="utf-8")
            for match in re.finditer(r"^from (\w+) import", text, re.MULTILINE):
                module = match.group(1) + ".py"
                if (PROVISION / module).exists():
                    self.assertIn(module, provision, f"{program} imports {module}, which the role does not deliver")

    def test_listed_programs_exist_in_their_directories(self) -> None:
        for name in _list_under("db1_backup_timers_provision_files"):
            self.assertTrue((PROVISION / name).is_file(), name)
        for name in _list_under("db1_backup_timers_recovery_files"):
            self.assertTrue((RECOVERY / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
