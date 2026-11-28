"""The units agree with the role's variables: the same state directory, account and timer, and the timer is off by default."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROLE / relative).read_text(encoding="utf-8")


class UnitTests(unittest.TestCase):
    def test_the_service_runs_as_the_role_account_in_the_role_state_directory(self) -> None:
        vars_text = read("vars/main.yml")
        service = read("files/warmup-controller.service")
        state_dir = re.search(r"^warmup_controller_state_dir: (\S+)$", vars_text, re.M)
        account = re.search(r"^warmup_controller_account: (\S+)$", vars_text, re.M)
        self.assertIsNotNone(state_dir)
        self.assertIsNotNone(account)
        assert state_dir is not None and account is not None
        self.assertIn(f"User={account.group(1)}", service)
        self.assertIn(f"ReadWritePaths={state_dir.group(1)}", service)
        self.assertIn(f"--ledger {state_dir.group(1)}/ledger.jsonl", service)

    def test_the_service_is_a_single_run_and_refuses_to_start_on_an_absent_package(self) -> None:
        service = read("files/warmup-controller.service")
        self.assertIn("Type=oneshot", service)
        self.assertIn("ConditionPathIsDirectory=/opt/branchleft/warmup-controller/current/", service)
        self.assertNotIn("Restart=", service)

    def test_the_timer_fires_daily_after_the_utc_day_and_starts_the_service(self) -> None:
        timer = read("files/warmup-controller.timer")
        self.assertIn("OnCalendar=*-*-* 01:15:00 UTC", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("Unit=warmup-controller.service", timer)

    def test_the_timer_is_held_off_by_default(self) -> None:
        self.assertIn("warmup_controller_timer_enabled: false", read("defaults/main.yml"))


if __name__ == "__main__":
    unittest.main()
