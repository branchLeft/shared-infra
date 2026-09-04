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

# An address-shaped placeholder standing in for a permanently fixed host
# (e.g. `<edge1-ipv4>`) pasted into a fenced command silently breaks every
# command that reaches it: `db1` is private-only, so any command reaching it
# is proxied through `edge1`, and an unresolved placeholder fails each hop
# identically rather than loudly on the first.
#
# Deliberately narrower than "no `<...>` anywhere in a fenced block":
# - Only a `bash` fence counts as a command block in these runbooks — `json`
#   and `text` fences here hold illustrative sample output, never something
#   pasted and run.
# - Only a token that both reads as an *address* (`ip`/`ipv4`/`address`/
#   `addr` as the placeholder's trailing word) and names a known,
#   single-valued, permanently fixed host is flagged: `edge1` (its address is
#   in `RUNBOOK-edge.md`'s own opening line) and `db1` (this runbook's own
#   gateway section names its address directly). `app1`'s private address is
#   fixed too, but its public one is assigned at server creation and
#   resolved fresh each run — "Run the whole set" below sets it from
#   `hcloud server list` rather than substituting a literal — so `app1` is
#   excluded.
# - The address word must be *trailing*, not merely present, so a resource
#   id such as `<edge1-ipv4-id>` is left alone: `RUNBOOK-estate-project-move
#   .md` deliberately works those by id rather than a hardcoded literal, to
#   keep a destructive deletion from ever running against the wrong project's
#   resource by a typo'd guess.
# - A token that legitimately varies per invocation (`<stack>`, `<host>`,
#   `<repo>`, `<image>`, `<digest>`) is not this bug and is left alone.
FIXED_HOSTS = ("edge1", "db1")
COMMAND_FENCE_LANGS = {"bash"}
FENCE_LANG = re.compile(r"^```([a-zA-Z0-9_-]*)\s*$")
PLACEHOLDER = re.compile(r"<[^<>\n]+>")
ADDRESS_WORD = re.compile(r"(?:^|[^a-z])(?:ip|ipv4|address|addr)$", re.IGNORECASE)


def runbooks() -> list[pathlib.Path]:
    return sorted(p for p in HETZNER.glob("RUNBOOK-*.md"))


def command_blocks(text: str) -> list[str]:
    """The bodies of every fenced block whose language is a command language
    this repo's runbooks use. An unterminated fence is still scanned — a
    runbook malformed enough to lose its closing fence is exactly when a
    placeholder needs catching most, not a reason to skip it."""
    blocks: list[str] = []
    current: list[str] | None = None
    lang = ""
    for line in text.split("\n"):
        match = FENCE_LANG.match(line)
        if match:
            if current is None:
                lang = match.group(1).lower()
                current = []
            else:
                if lang in COMMAND_FENCE_LANGS:
                    blocks.append("\n".join(current))
                current = None
            continue
        if current is not None:
            current.append(line)
    if current is not None and lang in COMMAND_FENCE_LANGS:
        blocks.append("\n".join(current))
    return blocks


def fixed_host_placeholders(block_text: str) -> list[str]:
    """Address-shaped placeholder tokens in `block_text` that name a fixed host."""
    found = []
    for match in PLACEHOLDER.finditer(block_text):
        token = match.group(0)
        inner = token[1:-1].lower()  # strip the angle brackets before anchoring on the end
        if not ADDRESS_WORD.search(inner):
            continue
        if any(host in inner for host in FIXED_HOSTS):
            found.append(token)
    return found


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

    def test_monitoring_chown_is_safe_from_alertmanager_yml_clobber(self):
        """alertmanager.yml is generated by render_alertmanager_config.py and must remain
        owned by uid 65534 (the nobody user that Alertmanager runs as). A root-owned 0600
        file becomes unreadable through a bind mount, and Alertmanager crashes on startup.

        A chown -R on /opt/branchleft/monitoring/ is safe only if EITHER:
        1. It's immediately preceded by an rsync --delete that removes alertmanager.yml, OR
        2. It's followed by a systemctl restart so ExecStartPre regenerates the file.

        This guard prevents introducing a third pattern that breaks the invariant.
        """
        text = (HETZNER / "RUNBOOK-monitoring.md").read_text(encoding="utf-8")

        # Find all chown commands targeting /opt/branchleft/monitoring/
        for match in re.finditer(r"chown\s+-R\s+root:root\s+/opt/branchleft/monitoring/?", text):
            chown_pos = match.start()

            # Check backward for a nearby rsync --delete into that directory
            preceding = text[max(0, chown_pos - 1000):chown_pos]
            has_preceding_rsync = bool(
                re.search(r"rsync\s+.*?--delete.*?/opt/branchleft/monitoring/", preceding, re.DOTALL)
            )

            # Check forward for a following systemctl restart
            following = text[match.end():match.end() + 500]
            has_following_restart = bool(
                re.search(r"systemctl\s+restart\s+branchleft-compose@monitoring", following)
            )

            self.assertTrue(
                has_preceding_rsync or has_following_restart,
                f"RUNBOOK-monitoring.md: a 'chown -R root:root /opt/branchleft/monitoring/' at "
                f"position {chown_pos} must be EITHER (1) immediately preceded by an "
                f"'rsync --delete' into that directory (which removes alertmanager.yml before "
                f"chown can touch it), OR (2) followed by 'systemctl restart "
                f"branchleft-compose@monitoring' (which regenerates alertmanager.yml via "
                f"ExecStartPre). Without one or the other, alertmanager.yml could become "
                f"unreadable to Alertmanager and crash the service.",
            )

    def test_the_monitoring_copy_step_says_a_restart_is_mandatory(self):
        """A copy step whose effect depends on a later restart must say so in its
        own body, not only at the step that eventually restarts.

        Prometheus and Alertmanager read their config files at container start
        only, and this stack does not pass --web.enable-lifecycle, so nothing
        short of `systemctl restart branchleft-compose@monitoring` makes a
        copied change take effect. A reader who stops after the copy step
        alone must not be able to conclude the change is deployed -- a prose
        fix at the step that restarts is not enough, because that is not the
        step the reader is reading.
        """
        text = (HETZNER / "RUNBOOK-monitoring.md").read_text(encoding="utf-8")
        match = re.search(
            r"## \d+\. Copy the monitoring stack directory onto the host\n.*?"
            r"(?=\n## \d+\.)",
            text,
            re.DOTALL,
        )
        self.assertIsNotNone(
            match, "RUNBOOK-monitoring.md: the monitoring stack's copy step was not found"
        )
        section = match.group(0)
        # Markdown prose wraps at ~80 columns, so a multi-word phrase can carry
        # an internal newline that a plain substring check would miss.
        normalized = " ".join(section.split())

        self.assertIn(
            "systemctl restart branchleft-compose@monitoring",
            normalized,
            "the copy step must name the restart command inline, not only at a later step",
        )
        self.assertRegex(
            normalized,
            r"(?i)changes nothing|is inert|does not deploy",
            "the copy step must say plainly that the copy alone does not deploy the change",
        )
        self.assertIn(
            "--delete",
            section,
            "sanity: expected to find the rsync --delete flag inside the copy step",
        )
        self.assertIn(
            "alertmanager.yml",
            section,
            "the --delete/missing-alertmanager.yml window must be explained where the "
            "reader meets --delete, i.e. inside the copy step itself",
        )
        self.assertIn(
            "on disk at all",
            normalized,
            "the copy step must state that an un-restarted copy leaves no "
            "alertmanager.yml on disk at all, not just that it gets deleted",
        )


class RunbookFixedHostPlaceholderTests(unittest.TestCase):
    def test_no_bash_fence_contains_a_fixed_host_address_placeholder(self):
        violations = []
        for runbook in runbooks():
            text = runbook.read_text(encoding="utf-8")
            for block in command_blocks(text):
                for token in fixed_host_placeholders(block):
                    violations.append(f"{runbook.name}: {token}")
        self.assertEqual(
            violations,
            [],
            "found unresolved fixed-host placeholder(s) in a fenced bash "
            "command block:\n" + "\n".join(violations),
        )

    # Self-tests: prove the scanner still draws the distinction it exists
    # for, against synthetic input rather than today's tree, so a
    # coincidentally clean tree can't hide a scanner that quietly stopped
    # matching.

    def test_self_scanner_catches_a_fixed_host_placeholder_in_a_bash_fence(self):
        sample = (
            "Some prose that never mentions a fence.\n\n"
            "```bash\n"
            'JUMP="ssh -i ~/.ssh/id_ed25519_hetzner -W %h:%p root@<edge1-ipv4>"\n'
            "```\n"
        )
        blocks = command_blocks(sample)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(fixed_host_placeholders(blocks[0]), ["<edge1-ipv4>"])

    def test_self_scanner_ignores_the_same_placeholder_mentioned_in_prose(self):
        sample = (
            "`<edge1-ipv4>` is edge1's public address, substitute it below.\n\n"
            "```bash\n"
            'echo "no placeholder in this command"\n'
            "```\n"
        )
        blocks = command_blocks(sample)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(fixed_host_placeholders(blocks[0]), [])

    def test_self_scanner_leaves_a_per_invocation_placeholder_alone(self):
        sample = (
            "```bash\n"
            "git clone https://github.com/branchLeft/ghost-tenant-<slug>.git\n"
            "```\n"
        )
        blocks = command_blocks(sample)
        self.assertEqual(fixed_host_placeholders(blocks[0]), [])

    def test_self_scanner_does_not_scan_a_non_bash_fence(self):
        sample = "```text\nroot@<edge1-ipv4>\n```\n"
        self.assertEqual(command_blocks(sample), [])

    def test_self_scanner_leaves_a_non_address_placeholder_naming_a_fixed_host_alone(self):
        sample = "```bash\nssh -i \"<db1 host key fingerprint>\" root@localhost\n```\n"
        blocks = command_blocks(sample)
        self.assertEqual(fixed_host_placeholders(blocks[0]), [])


if __name__ == "__main__":
    unittest.main()
