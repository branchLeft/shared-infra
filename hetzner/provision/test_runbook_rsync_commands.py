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

Additionally, `rsync --no-owner --no-group` does not modify the ownership of
files that already exist on the receiving host. Files copied with incorrect
ownership must be corrected with an explicit `chown -R root:root` after the
rsync.

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


def rsync_commands_with_following_context() -> list[tuple[pathlib.Path, str, str]]:
    """Find rsync commands and capture the text that follows them within the same code fence.

    Returns tuples of (runbook_path, rsync_command, following_context).
    The following_context includes lines after the rsync until the closing ``` of the code fence.
    This ensures the assertion only checks commands that are intended to follow this rsync,
    not other commands that might appear later in the same runbook section.
    """
    found = []
    for runbook in runbooks():
        text = runbook.read_text(encoding="utf-8")
        for match in RSYNC_COMMAND.finditer(text):
            # Get the rsync command
            rsync_cmd = " ".join(match.group(0).replace("\\\n", " ").split())

            # Get text from end of rsync to the closing ``` of the code fence
            start_pos = match.end()
            remaining = text[start_pos:]
            # Find the closing ``` that ends this code fence
            fence_end = re.search(r"\n```", remaining)
            if fence_end:
                context = remaining[:fence_end.start()]
            else:
                # Malformed markdown, but include everything remaining
                context = remaining

            found.append((runbook, rsync_cmd, context))
    return found


def rsync_commands() -> list[tuple[pathlib.Path, str]]:
    """Find rsync commands without context. Reuses rsync_commands_with_following_context
    to avoid duplication."""
    return [(runbook, cmd) for runbook, cmd, _ in rsync_commands_with_following_context()]


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

    def test_every_rsync_is_followed_by_chown_root_root(self):
        """Each rsync must be followed by an explicit chown -R root:root to fix
        file ownership on the receiving end. rsync --no-owner --no-group does
        not modify the ownership of files that already exist on the host."""
        for runbook, command, context in rsync_commands_with_following_context():
            with self.subTest(runbook=runbook.name, rsync=command):
                self.assertRegex(
                    context,
                    r"chown\s+-R\s+root:root\s+/opt/branchleft/\S+/?",
                    f"{runbook.name}: this rsync must be followed by a 'chown -R root:root' "
                    f"command to fix file ownership on the receiving end. The rsync command "
                    f"with --no-owner --no-group does not modify existing file ownership.",
                )

    def test_monitoring_chown_does_not_target_alertmanager_directory(self):
        """The monitoring stack's chown must not be -R on /opt/branchleft/monitoring/
        because alertmanager/alertmanager.yml is generated by render_alertmanager_config.py
        and must remain owned by uid 65534 (the nobody user that Alertmanager runs as).
        A root-owned 0600 file is unreadable to the container through a bind mount,
        and Alertmanager crash-loops on startup with 'permission denied'."""
        text = (HETZNER / "RUNBOOK-monitoring.md").read_text(encoding="utf-8")
        # Find any chown commands targeting /opt/branchleft/monitoring/ with -R
        # (not just the one in §4, since a future editor might add another)
        bad_chown = re.search(r"chown\s+-R\s+root:root\s+/opt/branchleft/monitoring/?", text)
        if bad_chown:
            # This is only allowed if it's immediately followed by a restart of the monitoring
            # unit to trigger ExecStartPre re-render and re-chown of alertmanager.yml
            start_pos = bad_chown.end()
            following = text[start_pos:start_pos + 500]
            self.assertRegex(
                following,
                r"systemctl\s+restart\s+branchleft-compose@monitoring",
                "RUNBOOK-monitoring.md: a 'chown -R root:root /opt/branchleft/monitoring/' "
                "would make alertmanager.yml unreadable to Alertmanager. It must be immediately "
                "followed by 'systemctl restart branchleft-compose@monitoring' so ExecStartPre "
                "regenerates and re-chowns the file to uid 65534.",
            )


if __name__ == "__main__":
    unittest.main()
