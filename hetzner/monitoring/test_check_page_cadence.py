#!/usr/bin/env python3
"""Unit tests for the pure parts of `check_page_cadence.py`: retargeting the
page receiver and judging what was observed. The timing itself needs Docker
and runs as its own CI step; see `check_page_cadence.md`.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
MODULE_PATH = HERE / "check_page_cadence.py"
TEMPLATE_PATH = HERE / "stack" / "alertmanager" / "alertmanager.yml.tmpl"

_spec = importlib.util.spec_from_file_location("check_page_cadence", MODULE_PATH)
assert _spec is not None and _spec.loader is not None
check_page_cadence = importlib.util.module_from_spec(_spec)
# A dataclass looks its own module up by name while it is being defined.
sys.modules[_spec.name] = check_page_cadence
_spec.loader.exec_module(check_page_cadence)

NTFY_LINE = "      - url: 'http://ntfy:80/branchleft-pages?template=alertmanager&priority=5'\n"


class RetargetPagerTest(unittest.TestCase):
    def test_points_the_one_ntfy_receiver_at_the_stand_in(self) -> None:
        out = check_page_cadence.retarget_pager(NTFY_LINE, "http://host.docker.internal:9/pages")
        self.assertEqual(out, "      - url: 'http://host.docker.internal:9/pages'\n")

    def test_leaves_every_other_line_alone(self) -> None:
        text = "a: 1\n" + NTFY_LINE + "b: 2\n"
        out = check_page_cadence.retarget_pager(text, "http://x:1/p")
        self.assertTrue(out.startswith("a: 1\n"))
        self.assertTrue(out.endswith("b: 2\n"))

    def test_refuses_a_config_with_no_ntfy_receiver(self) -> None:
        with self.assertRaises(ValueError):
            check_page_cadence.retarget_pager("a: 1\n", "http://x:1/p")

    def test_refuses_a_config_with_two(self) -> None:
        with self.assertRaises(ValueError):
            check_page_cadence.retarget_pager(NTFY_LINE + NTFY_LINE, "http://x:1/p")

    def test_finds_exactly_one_receiver_in_the_committed_template(self) -> None:
        out = check_page_cadence.retarget_pager(TEMPLATE_PATH.read_text(), "http://x:1/p")
        self.assertIn("url: 'http://x:1/p'", out)
        self.assertNotIn("http://ntfy:80", out)


class JudgeTest(unittest.TestCase):
    def test_a_prompt_further_estate_page_and_a_quiet_tenant_group_is_clean(self) -> None:
        self.assertEqual(check_page_cadence.judge(True, 60.0, False), [])

    def test_a_further_estate_page_that_never_arrives_is_a_problem(self) -> None:
        problems = check_page_cadence.judge(True, None, False)
        self.assertEqual(len(problems), 1)
        self.assertIn("did not reach", problems[0])

    def test_a_further_estate_page_past_the_bound_is_a_problem(self) -> None:
        bound = check_page_cadence.FURTHER_PAGE_BOUND_SECONDS
        self.assertEqual(check_page_cadence.judge(True, bound, False), [])
        self.assertEqual(len(check_page_cadence.judge(True, bound + 1, False)), 1)

    def test_a_noisy_tenant_group_is_a_problem(self) -> None:
        problems = check_page_cadence.judge(True, 60.0, True)
        self.assertEqual(len(problems), 1)
        self.assertIn("tenant", problems[0])

    def test_no_first_page_is_a_problem(self) -> None:
        self.assertEqual(len(check_page_cadence.judge(False, 60.0, False)), 1)


class ReceiverTest(unittest.TestCase):
    def test_records_each_alert_of_a_webhook_post_with_its_scenario(self) -> None:
        receiver = check_page_cadence.Receiver()
        body = json.dumps(
            {
                "alerts": [
                    {"labels": {"alertname": "EdgeBanIssued", "reason": "a"}},
                    {"labels": {"alertname": "EdgeBanIssued", "reason": "b"}},
                ]
            }
        ).encode()
        receiver.record(body)
        self.assertTrue(receiver.has("EdgeBanIssued", "a"))
        self.assertTrue(receiver.has("EdgeBanIssued", "b"))
        self.assertFalse(receiver.has("EdgeBanIssued", "c"))

    def test_a_post_with_no_alerts_records_nothing(self) -> None:
        receiver = check_page_cadence.Receiver()
        receiver.record(b"{}")
        self.assertEqual(receiver.seen, [])


if __name__ == "__main__":
    unittest.main()
