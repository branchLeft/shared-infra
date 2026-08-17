#!/usr/bin/env python3
"""Unit tests for list_and_clear_blocked_ips.py's selection logic -- no
network access, no live server needed. Run with: python3 -m unittest
discover -s mail/provision -p 'test_*.py' -v
"""
import unittest

from list_and_clear_blocked_ips import select_ids_to_clear

# Documentation-range addresses (RFC 5737). A blocked-IP list is a record of
# somebody else's host, so a real one never becomes a committed fixture.
OPERATOR_IP = "198.51.100.7"
SCANNER_IP = "198.51.100.42"

BLOCKED = [
    {"id": "b1", "address": OPERATOR_IP, "reason": "portScanning"},
    {"id": "b2", "address": SCANNER_IP, "reason": "portScanning"},
]


class SelectIdsToClearTests(unittest.TestCase):
    def test_all_selects_every_id(self):
        self.assertCountEqual(select_ids_to_clear(BLOCKED, [], True), ["b1", "b2"])

    def test_single_ip_selects_only_its_id(self):
        self.assertEqual(select_ids_to_clear(BLOCKED, [OPERATOR_IP], False), ["b1"])

    def test_multiple_ips_select_their_ids_only(self):
        # The scenario this design exists for: a genuine scanner (b2) stays
        # blocked while an operator's own false-positive (b1) is cleared --
        # selecting by explicit address, never by "all".
        result = select_ids_to_clear(BLOCKED, [OPERATOR_IP], False)
        self.assertEqual(result, ["b1"])
        self.assertNotIn("b2", result)

    def test_neither_all_nor_ip_is_refused(self):
        with self.assertRaises(ValueError):
            select_ids_to_clear(BLOCKED, [], False)

    def test_all_and_ip_together_is_refused(self):
        with self.assertRaises(ValueError):
            select_ids_to_clear(BLOCKED, [OPERATOR_IP], True)

    def test_ip_not_currently_blocked_is_refused_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            select_ids_to_clear(BLOCKED, ["1.2.3.4"], False)

    def test_all_on_empty_blocked_list_selects_nothing(self):
        self.assertEqual(select_ids_to_clear([], [], True), [])


if __name__ == "__main__":
    unittest.main()
