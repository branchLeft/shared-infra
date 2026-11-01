"""Unit tests for the db1_backup_timers role's files, its pins and its schedule.

The role copies the unit files and fetches the programs from ghost-platform at a
pinned commit. These tests read the role's own files and its vars, and fail when a
unit names a program the role does not fetch, when the pins are not a full commit
and a digest per program, when a schedule value drifts from the runbook, or when a
program has crept back into the role as a copy.
"""

import re
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]
FILES = ROLE / "files"
VARS = ROLE / "vars" / "main.yml"
UNITS = FILES / "units"


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


def _mapping_under(key: str) -> dict[str, str]:
    """Return the key and value pairs of one YAML mapping in vars/main.yml, read as text."""
    pairs: dict[str, str] = {}
    inside = False
    for line in VARS.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}:"):
            inside = True
            continue
        if inside:
            match = re.match(r"^  (\S+): (\S+)\s*$", line)
            if match:
                pairs[match.group(1)] = match.group(2)
            elif line.strip():
                break
    return pairs


def _scalar(key: str) -> str:
    """Return the value of one top-level scalar in vars/main.yml, read as text."""
    for line in VARS.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError(f"{key} is not set in vars/main.yml")


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

    def test_every_program_a_service_runs_is_fetched(self) -> None:
        fetched = set(_list_under("db1_backup_timers_provision_files")) | set(
            _list_under("db1_backup_timers_recovery_files")
        )
        for unit in _list_under("db1_backup_timers_units"):
            if not unit.endswith(".service"):
                continue
            for exec_start in _unit_value(unit, "ExecStart"):
                program = Path(exec_start.split()[-1]).name
                self.assertIn(program, fetched, f"{unit} runs {program}, which the role does not fetch")

    def test_every_fetched_program_has_a_pinned_digest(self) -> None:
        digests = _mapping_under("db1_backup_timers_program_sha256")
        fetched = set(_list_under("db1_backup_timers_provision_files")) | set(
            _list_under("db1_backup_timers_recovery_files")
        )
        self.assertEqual(set(digests), fetched)
        for name, digest in digests.items():
            self.assertRegex(digest, r"^[0-9a-f]{64}$", name)


class PinTests(unittest.TestCase):
    def test_the_commit_is_a_full_forty_character_sha(self) -> None:
        self.assertRegex(_scalar("db1_backup_timers_ghost_commit"), r"^[0-9a-f]{40}$")

    def test_the_fetch_base_names_the_pinned_commit(self) -> None:
        self.assertIn("{{ db1_backup_timers_ghost_commit }}", _scalar("db1_backup_timers_ghost_raw_base"))
        self.assertIn("raw.githubusercontent.com/branchLeft/ghost-platform/", _scalar("db1_backup_timers_ghost_raw_base"))


class CrossRoleTests(unittest.TestCase):
    """db1_grants runs a program that this role delivers; the two roles' pins must agree."""

    GRANTS_VARS = ROLE.parent / "db1_grants" / "vars" / "main.yml"

    def _grants_list(self, key: str) -> list[str]:
        items: list[str] = []
        inside = False
        for line in self.GRANTS_VARS.read_text(encoding="utf-8").splitlines():
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

    def _grants_mapping(self, key: str) -> dict[str, str]:
        pairs: dict[str, str] = {}
        inside = False
        for line in self.GRANTS_VARS.read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{key}:"):
                inside = True
                continue
            if inside:
                match = re.match(r"^  (\S+): (\S+)\s*$", line)
                if match:
                    pairs[match.group(1)] = match.group(2)
                elif line.strip():
                    break
        return pairs

    def test_every_file_db1_grants_runs_is_delivered_here_at_the_same_digest(self) -> None:
        staged = self._grants_list("db1_grants_staged_files")
        self.assertTrue(staged, "db1_grants_staged_files is empty or not read")
        delivered = set(_list_under("db1_backup_timers_provision_files"))
        mine = _mapping_under("db1_backup_timers_program_sha256")
        theirs = self._grants_mapping("db1_grants_program_sha256")
        for name in staged:
            self.assertIn(name, delivered, f"db1_grants runs {name}, which this role does not deliver")
            self.assertIn(name, mine, f"{name} is delivered here with no pinned digest")
            self.assertEqual(mine[name], theirs.get(name), f"{name} is pinned to a different digest in db1_grants")

    def test_db1_grants_pins_the_commit_this_role_fetches_at(self) -> None:
        grants_commit = next(
            line.split(":", 1)[1].strip()
            for line in self.GRANTS_VARS.read_text(encoding="utf-8").splitlines()
            if line.startswith("db1_grants_source_commit:")
        )
        self.assertEqual(grants_commit, _scalar("db1_backup_timers_ghost_commit"))


if __name__ == "__main__":
    unittest.main()
