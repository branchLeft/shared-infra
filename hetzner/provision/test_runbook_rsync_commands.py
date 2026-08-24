#!/usr/bin/env python3
"""The runbooks' `rsync` commands must not carry workstation permissions onto a host.

`rsync -a` implies `-p`, `-o` and `-g`, and the last two take effect because the
receiving side is `root`. So a plain `rsync -av` reproduces the *workstation's*
file modes and uid/gid on the host — while every container in both stacks reads
its config through a bind mount **as the container-side user**, not as root.

That combination broke a real deploy. `prometheus.yml` is written by
`npm run render` (a Vitest file snapshot), which left it `0600` in one
workstation checkout. Git records `100644` and cannot see the difference — it
tracks only the executable bit — so the mode is invisible to review, to
`git status`, and to CI, which checks out its own copy at `0644`. `rsync -av`
copied `0600 uid=501 gid=20` onto the host and Prometheus, running as `nobody`,
crash-looped on `permission denied`.

Nothing available to CI can observe a workstation's file modes, so the deploy
command itself has to be immune to them. That makes the command *shape* the
control, and this asserts the shape — the same reasoning, and the same
technique, as `RunbookScpCommandTests` in `test_branchleft_nat.py`.
"""

import pathlib
import re
import unittest

HETZNER = pathlib.Path(__file__).resolve().parent.parent

# Set modes on the receiving side instead of copying them. `u=rwX,go=rX` gives
# 0644 for files and 0755 for directories; `X` is "execute only where it is
# already set, or on a directory".
REQUIRED_FLAGS = ("--no-owner", "--no-group", "--chmod=u=rwX,go=rX")

# A fenced command may be wrapped over several lines with trailing backslashes.
RSYNC_COMMAND = re.compile(r"^rsync .*?(?:\\\n.*?)*$", re.MULTILINE)


def runbooks() -> list[pathlib.Path]:
    return sorted(p for p in HETZNER.glob("RUNBOOK-*.md"))


def rsync_commands() -> list[tuple[pathlib.Path, str]]:
    found = []
    for runbook in runbooks():
        for match in RSYNC_COMMAND.finditer(runbook.read_text(encoding="utf-8")):
            found.append((runbook, " ".join(match.group(0).replace("\\\n", " ").split())))
    return found


class RunbookRsyncCommandTests(unittest.TestCase):
    def test_the_runbooks_and_their_rsync_commands_were_actually_found(self):
        """A regex that matched nothing would pass every assertion below."""
        self.assertTrue(runbooks(), "no RUNBOOK-*.md found")
        self.assertGreaterEqual(len(rsync_commands()), 5)

    def test_every_rsync_sets_modes_on_the_receiving_side(self):
        for runbook, command in rsync_commands():
            with self.subTest(runbook=runbook.name, command=command):
                for flag in REQUIRED_FLAGS:
                    self.assertIn(
                        flag,
                        command,
                        f"{runbook.name}: this rsync would copy the workstation's "
                        f"permissions and uid/gid onto the host. Add {' '.join(REQUIRED_FLAGS)}.",
                    )

    def test_no_rsync_uses_the_rsync_3_chmod_spelling(self):
        """`--chmod=D755,F644` is rsync 3.0 syntax. macOS ships rsync 2.6.9,
        which rejects it outright with `Invalid argument passed to --chmod`, so
        a runbook written that way fails on the workstation it is run from."""
        for runbook, command in rsync_commands():
            with self.subTest(runbook=runbook.name):
                self.assertNotRegex(
                    command,
                    r"--chmod=[DF]\d",
                    f"{runbook.name}: rsync 2.6.9 on macOS rejects the D/F chmod form",
                )


if __name__ == "__main__":
    unittest.main()
