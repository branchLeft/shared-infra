"""Tests for promtool_shards.py: the split keeps every group, once, unchanged."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from promtool_shards import balance, check_partition, duration_seconds, group_cost, split_test_file

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "alert_rules_test.yml"
EVAL = re.compile(r"^\s*(?:- )?eval_time:", re.MULTILINE)

SAMPLE = """rule_files:
  - stack/prometheus/alerts.yml

evaluation_interval: 30s

tests:
  # first group
  - interval: 30s
    input_series:
      - series: 'up{job="a"}'
        values: '1 0 1'
    alert_rule_test:
      - eval_time: 1m
        alertname: A
  - interval: 1h
    input_series: []
    alert_rule_test:
      - eval_time: 2h
        alertname: B
      - eval_time: 3h
        alertname: C
"""


class SplitTest(unittest.TestCase):
    def test_header_and_groups_round_trip(self) -> None:
        split = split_test_file(SAMPLE)
        self.assertEqual(split.rule_files, ("stack/prometheus/alerts.yml",))
        self.assertIn("tests:\n", split.header)
        self.assertEqual(len(split.groups), 2)
        self.assertEqual(split.header + "".join(split.groups), SAMPLE)

    def test_shards_hold_every_group_once(self) -> None:
        split = split_test_file(SAMPLE)
        for shards in (1, 2, 3, 5):
            texts = [
                split.header + "".join(split.groups[i] for i in bucket)
                for bucket in balance(split.groups, shards)
                if bucket
            ]
            self.assertEqual(check_partition(split, texts), (2, 3))

    def test_durations_read_every_form_the_suite_uses(self) -> None:
        self.assertEqual(duration_seconds("30s"), 30)
        self.assertEqual(duration_seconds("98m"), 98 * 60)
        self.assertEqual(duration_seconds("1h30m"), 5400)
        self.assertEqual(duration_seconds("624h"), 624 * 3600)
        with self.assertRaises(ValueError):
            duration_seconds("1 day")

    def test_group_cost_is_its_total_eval_window(self) -> None:
        split = split_test_file(SAMPLE)
        self.assertEqual(group_cost(split.groups[0]), 60)
        self.assertEqual(group_cost(split.groups[1]), 2 * 3600 + 3 * 3600)

    def test_a_dropped_group_fails_the_partition(self) -> None:
        split = split_test_file(SAMPLE)
        with self.assertRaises(AssertionError):
            check_partition(split, [split.header + split.groups[0]])

    def test_the_real_suite_splits_into_its_groups(self) -> None:
        split = split_test_file(SOURCE.read_text(encoding="utf-8"))
        self.assertEqual(split.header + "".join(split.groups), SOURCE.read_text(encoding="utf-8"))
        self.assertEqual(
            sum(len(EVAL.findall(g)) for g in split.groups),
            len(EVAL.findall(SOURCE.read_text(encoding="utf-8"))),
        )



if __name__ == "__main__":
    unittest.main()
