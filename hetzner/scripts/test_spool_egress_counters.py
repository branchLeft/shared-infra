#!/usr/bin/env python3
"""Tests for the spool forward-drop counter reader in lib/spool-egress-counters.sh.

test-spool-bridge-egress.sh needs root and a Docker-in-Docker host, so its
counter check cannot run here. The check's only logic that can be wrong on its
own is which line of the DOCKER-USER listing it reads, and that is exercised
here against listings in the shape `ip6tables -nvxL DOCKER-USER --line-numbers`
prints. The real tables are never touched.
"""

import pathlib
import re
import subprocess
import unittest

HERE = pathlib.Path(__file__).resolve().parent
LIB = HERE / "lib" / "spool-egress-counters.sh"
SUITE = HERE / "test-spool-bridge-egress.sh"

# Shape of the IPv6 DOCKER-USER chain on a host where the spool policy is
# applied: Docker's RETURN is line 1 on this family, the spool's forward drop
# is beneath it. A counter read from line 1 is Docker's, not the spool's.
LISTING_DROP_PRESENT = """\
Chain DOCKER-USER (1 references)
num       pkts      bytes target     prot opt in     out     source               destination
1             {ret_pkts}      420 RETURN     all  --  *      *       ::/0                 ::/0
2             {drop_pkts}        0 DROP       all  --  br-mailspool !br-mailspool  ::/0  ::/0
"""

# The sabotage: the spool's forward drop removed. Line 1 still moves, which is
# exactly the false pass the check used to report.
LISTING_DROP_ABSENT = """\
Chain DOCKER-USER (1 references)
num       pkts      bytes target     prot opt in     out     source               destination
1             {ret_pkts}      420 RETURN     all  --  *      *       ::/0                 ::/0
"""

# A rule on the same bridge that is not the drop: an ACCEPT, and a DROP whose
# out side is not negated. Neither is the forward drop the check is about.
LISTING_DECOYS = """\
Chain DOCKER-USER (1 references)
num       pkts      bytes target     prot opt in     out     source               destination
1             7      420 RETURN     all  --  *      *       ::/0                 ::/0
2             9        0 ACCEPT     all  --  br-mailspool br-mailspool  ::/0  ::/0
3             4        0 DROP       all  --  br-mailspool *  ::/0  ::/0
"""


def read_drop_counter(listing):
    """Run the library's reader over a listing on stdin, as the suite does."""
    proc = subprocess.run(
        ["sh", "-c", f'. "$1" && spool_forward_drop_packets', "sh", str(LIB)],
        input=listing,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout.strip()


class SpoolForwardDropCounterTests(unittest.TestCase):
    def test_reads_the_drop_counter_not_the_first_line(self):
        # The RETURN counter moves 5 -> 12 between the two reads, as in the
        # sabotage run. The drop never moves. The reader must say 0 both times.
        rc, before = read_drop_counter(
            LISTING_DROP_PRESENT.format(ret_pkts=5, drop_pkts=0)
        )
        self.assertEqual((rc, before), (0, "0"))
        rc, after = read_drop_counter(
            LISTING_DROP_PRESENT.format(ret_pkts=12, drop_pkts=0)
        )
        self.assertEqual((rc, after), (0, "0"))

    def test_reports_a_moved_drop_counter(self):
        rc, out = read_drop_counter(
            LISTING_DROP_PRESENT.format(ret_pkts=12, drop_pkts=3)
        )
        self.assertEqual((rc, out), (0, "3"))

    def test_a_missing_drop_is_a_failure_not_a_zero(self):
        rc, out = read_drop_counter(LISTING_DROP_ABSENT.format(ret_pkts=12))
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, "")

    def test_decoy_rules_on_the_same_bridge_are_not_the_drop(self):
        rc, out = read_drop_counter(LISTING_DECOYS)
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, "")


class SuiteUsesTheReaderTests(unittest.TestCase):
    def test_the_ipv6_counter_check_does_not_read_line_one(self):
        # The regression this fixes: the check read `DOCKER-USER 1`. A pin on the
        # text, because the suite itself needs root and cannot run here.
        text = SUITE.read_text()
        self.assertIsNone(re.search(r"DOCKER-USER 1\b", text))
        self.assertIn("spool_forward_drop_packets", text)


if __name__ == "__main__":
    unittest.main()
