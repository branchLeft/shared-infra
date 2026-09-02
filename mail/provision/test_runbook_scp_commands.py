#!/usr/bin/env python3
"""Unit tests for RUNBOOK-mx1-provision.md's scp command shapes.

The runbook describes provisioning mail/provision onto mx1, which may already
carry a copy from an earlier run. scp's semantics make the exact command shape
the whole difference between refreshing that copy in place and nesting a stale
one under it. A test process cannot exercise real scp/SFTP semantics without
a real sshd, so this asserts the command shape itself rather than the copy
behaviour. Run with: python3 -m unittest discover -s mail/provision -p 'test_*.py' -v
"""

import os
import unittest

RUNBOOK = os.path.join(
    os.path.dirname(__file__), "..", "RUNBOOK-mx1-provision.md"
)


def _extract_scp_commands():
    """Pull every provisioning `scp` line out of RUNBOOK-mx1-provision.md."""
    with open(RUNBOOK, encoding="utf-8") as handle:
        lines = handle.readlines()
    return [line.strip() for line in lines if line.strip().startswith("scp ")]


class RunbookScpCommandTests(unittest.TestCase):
    """RUNBOOK-mx1-provision.md's `scp` commands copy mail/provision/
    onto a host that may already carry a copy from an earlier run, and scp's
    own semantics make the exact command shape the whole difference between
    refreshing that copy in place and nesting a stale one under it. A test
    process cannot exercise real scp/SFTP semantics without a real sshd, so
    this asserts the command shape itself rather than the copy behaviour.
    """

    def test_every_scp_site_copies_provision_dot_to_a_slash_free_destination(self):
        commands = _extract_scp_commands()
        self.assertEqual(len(commands), 2, commands)
        for command in commands:
            tokens = command.split()
            source = next(
                (t for t in tokens if t.startswith("mail/provision")),
                None,
            )
            self.assertIsNotNone(
                source,
                f"command missing 'mail/provision' source token: {command}",
            )
            destination = tokens[-1]
            self.assertTrue(
                source.endswith("provision/."),
                f"source must copy the directory's contents, not itself: {command}",
            )
            self.assertFalse(
                destination.endswith("/"),
                "a destination trailing slash makes scp fail outright in "
                f"SFTP mode when the destination does not yet exist: {command}",
            )


if __name__ == "__main__":
    unittest.main()
