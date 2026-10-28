"""Hold the runbook steps that edit a host by hand to a frozen count: a new one fails until listed.

A hand step is a fenced shell block in a ``RUNBOOK*.md`` file that reaches a host (``ssh``,
``scp`` or ``rsync``) and changes it (writes a file, installs a package, manages a unit, moves
files, changes a firewall). ``hand_runbook_steps.yml`` lists how many such blocks each runbook
holds. More blocks than listed fails, as does fewer, so the number only ever goes down.
"""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = Path("ansible/checks/hand_runbook_steps.yml")
REASONS = ("stays-as-code", "pending-role")
ROLE = re.compile(r"[a-z][a-z0-9_]*")
PRUNED = frozenset((".git", "node_modules"))
SHELL_FENCES = frozenset(("", "bash", "sh", "shell", "console", "zsh"))
FENCE = re.compile(r"^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)")
REACHES_HOST = re.compile(r"(?<![\w./-])(ssh|scp|rsync)(?![\w./-])")
CHANGES_HOST = re.compile(
    r"(?<![\w./-])("
    r"tee|sed\s+-[A-Za-z]*i|install|chmod|chown|chgrp|mkdir|rmdir|rm|mv|cp|ln|touch|truncate|dd"
    r"|systemctl\s+(?:--now\s+)?(?:enable|disable|start|stop|restart|reload|daemon-reload|mask|unmask)"
    r"|apt(?:-get)?\s+(?:install|remove|purge|upgrade|dist-upgrade)|dpkg\s+-i|pip3?\s+install"
    r"|useradd|usermod|userdel|groupadd|ufw|iptables|ip6tables|nft|sysctl\s+-w"
    r"|docker\s+(?:run|compose\s+(?:up|down)|rm|stop|start|restart|volume\s+rm)"
    r"|crontab|visudo|passwd|reboot|shutdown|bash\s+\S+\.sh|sh\s+\S+\.sh"
    r")(?![\w-])"
    r"|(?<![>&\d])>>?\s*/(?:etc|usr|opt|var|srv|root|home)/"
    r"|\bscp\b|\brsync\b"
)


def runbooks(root: Path) -> list[str]:
    """Return the repo-relative path of every ``RUNBOOK*.md`` under ``root``."""
    found: list[str] = []
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if name not in PRUNED]
        for name in files:
            if name.startswith("RUNBOOK") and name.endswith(".md"):
                found.append(Path(directory, name).relative_to(root).as_posix())
    return sorted(found)


def fences(text: str) -> list[tuple[str, str]]:
    """Return ``(info string, body)`` for every fenced block; an unclosed fence runs to the end."""
    blocks: list[tuple[str, str]] = []
    marker = ""
    info = ""
    body: list[str] = []
    for line in text.splitlines():
        match = FENCE.match(line)
        if not marker:
            if match:
                marker, info, body = match.group(1), match.group(2).lower(), []
        elif match and match.group(1)[0] == marker[0] and len(match.group(1)) >= len(marker):
            if not line.strip().strip(marker[0]):
                blocks.append((info, "\n".join(body)))
                marker = ""
                continue
            body.append(line)
        else:
            body.append(line)
    if marker:
        blocks.append((info, "\n".join(body)))
    return blocks


def is_hand_step(info: str, body: str) -> bool:
    """A shell block that reaches a host and changes it."""
    if info not in SHELL_FENCES:
        return False
    code = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))
    return bool(REACHES_HOST.search(code) and CHANGES_HOST.search(code))


def hand_steps(root: Path) -> dict[str, int]:
    """Return the hand-step count of every runbook that has one."""
    counts: dict[str, int] = {}
    for name in runbooks(root):
        text = (root / name).read_text(encoding="utf-8")
        count = sum(1 for info, body in fences(text) if is_hand_step(info, body))
        if count:
            counts[name] = count
    return counts


def check(root: Path) -> list[str]:
    """Return one finding per runbook with more, fewer or unlisted hand steps, and per bad entry."""
    try:
        document = YAML(typ="safe").load((root / ALLOWLIST).read_text(encoding="utf-8"))
    except (OSError, YAMLError) as error:
        return [f"{ALLOWLIST} cannot be read as YAML: {type(error).__name__}"]
    if document is None:
        document = {}
    if not isinstance(document, dict):
        return [f"{ALLOWLIST} must map each runbook path to its entry"]
    findings: list[str] = []
    for name, entry in document.items():
        findings.extend(_entry_findings(str(name), entry))
    found = hand_steps(root)
    listed = {
        str(name): entry["steps"]
        for name, entry in document.items()
        if isinstance(entry, dict) and type(entry.get("steps")) is int
    }
    for name, count in sorted(found.items()):
        if name not in document:
            findings.append(
                f"{name} has {count} hand step(s) and is not in {ALLOWLIST}: "
                "move the step into an Ansible role, or list it"
            )
        elif name in listed and count > listed[name]:
            findings.append(
                f"{name} has {count} hand step(s), {ALLOWLIST} allows {listed[name]}: "
                "a new step that edits a host by hand"
            )
        elif name in listed and count < listed[name]:
            findings.append(
                f"{name} has {count} hand step(s), {ALLOWLIST} lists {listed[name]}: "
                "lower the count"
            )
    for name in sorted(set(document) - set(found)):
        findings.append(
            f"{name} is in {ALLOWLIST} but has no hand step or no such runbook: remove it"
        )
    return findings


def _entry_findings(name: str, entry: object) -> list[str]:
    if not isinstance(entry, dict):
        return [f"{name}: the entry must be a mapping with steps and a reason"]
    findings = [
        f"{name}: unknown key {key}" for key in entry if key not in ("steps", "reason", "role")
    ]
    steps = entry.get("steps")
    if type(steps) is not int or steps < 1:
        findings.append(f"{name}: steps must be a whole number of 1 or more")
    reason = entry.get("reason")
    if reason not in REASONS:
        findings.append(f"{name}: reason must be one of {', '.join(REASONS)}")
    elif reason == "pending-role":
        role = entry.get("role")
        if not isinstance(role, str) or not ROLE.fullmatch(role):
            findings.append(f"{name}: pending-role must name its role, [a-z][a-z0-9_]*")
    elif "role" in entry:
        findings.append(f"{name}: stays-as-code takes no role")
    return findings


class RealTree(unittest.TestCase):
    def test_every_hand_step_is_listed_and_no_more(self) -> None:
        self.assertEqual(check(ROOT), [])

    def test_the_scan_reaches_nested_runbooks_and_finds_steps(self) -> None:
        names = runbooks(ROOT)
        self.assertIn("hetzner/dns/RUNBOOK-dns-cutover.md", names)
        self.assertIn("mail/RUNBOOK-mx1-provision.md", names)
        self.assertGreaterEqual(len(hand_steps(ROOT)), 5)


class Classifier(unittest.TestCase):
    def test_an_ssh_block_that_writes_a_file_is_a_hand_step(self) -> None:
        body = "ssh root@host 'tee /etc/x.conf' < x.conf"
        self.assertTrue(is_hand_step("bash", body))

    def test_a_bare_fence_counts_and_a_text_fence_does_not(self) -> None:
        body = "ssh root@host systemctl restart caddy"
        self.assertTrue(is_hand_step("", body))
        self.assertFalse(is_hand_step("text", body))
        self.assertFalse(is_hand_step("yaml", body))

    def test_a_read_only_ssh_block_is_not_a_hand_step(self) -> None:
        self.assertFalse(is_hand_step("bash", "ssh root@host systemctl is-active docker"))
        self.assertFalse(is_hand_step("bash", "ssh root@host 'cat /etc/os-release'"))

    def test_a_local_only_change_is_not_a_hand_step(self) -> None:
        self.assertFalse(is_hand_step("bash", "mkdir -p out && cp a b"))
        self.assertFalse(is_hand_step("bash", "pulumi up"))

    def test_a_copy_to_a_host_is_a_hand_step(self) -> None:
        self.assertTrue(is_hand_step("bash", "scp x.sh root@host:/root/"))
        self.assertTrue(is_hand_step("bash", "rsync -a dir/ root@host:/opt/dir/"))

    def test_a_comment_line_does_not_count(self) -> None:
        self.assertFalse(is_hand_step("bash", "# ssh root@host systemctl restart caddy"))

    def test_a_command_word_inside_a_longer_word_does_not_count(self) -> None:
        self.assertFalse(is_hand_step("bash", "ssh root@host journalctl -u cp-sync --no-pager"))

    def test_a_redirect_into_a_system_path_over_ssh_is_a_hand_step(self) -> None:
        self.assertTrue(is_hand_step("bash", 'ssh root@host "echo x > /etc/motd"'))

    def test_fences_pairs_open_and_close_and_keeps_the_info_string(self) -> None:
        text = "a\n```bash\nls\n```\nb\n~~~\nssh h rm x\n~~~\n"
        self.assertEqual(fences(text), [("bash", "ls"), ("", "ssh h rm x")])

    def test_a_longer_fence_is_not_closed_by_a_shorter_one(self) -> None:
        text = "````bash\n```\nssh h rm x\n````\n"
        self.assertEqual(fences(text), [("bash", "```\nssh h rm x")])

    def test_an_unclosed_fence_runs_to_the_end(self) -> None:
        self.assertEqual(fences("```bash\nssh h rm x\n"), [("bash", "ssh h rm x")])


STEP = "```bash\nssh root@host 'tee /etc/x' < x\n```\n"


class Tree(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def _write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _list(self, *entries: str) -> None:
        self._write(str(ALLOWLIST), "".join(entries))

    ONE = "hetzner/RUNBOOK-a.md:\n  steps: 1\n  reason: stays-as-code\n"

    def test_a_listed_count_passes(self) -> None:
        self._write("hetzner/RUNBOOK-a.md", STEP)
        self._list(self.ONE)
        self.assertEqual(check(self.root), [])

    def test_a_new_step_in_a_listed_runbook_is_red_until_the_count_is_raised(self) -> None:
        self._write("hetzner/RUNBOOK-a.md", STEP)
        self._list(self.ONE)
        self.assertEqual(check(self.root), [])
        self._write("hetzner/RUNBOOK-a.md", STEP + "\n" + STEP)
        findings = check(self.root)
        self.assertEqual(len(findings), 1)
        self.assertIn("a new step that edits a host by hand", findings[0])
        self._list("hetzner/RUNBOOK-a.md:\n  steps: 2\n  reason: stays-as-code\n")
        self.assertEqual(check(self.root), [])

    def test_an_unlisted_runbook_with_a_step_fails_naming_it(self) -> None:
        self._write("mail/RUNBOOK-new.md", STEP)
        self._list()
        self.assertEqual(
            check(self.root),
            [
                f"mail/RUNBOOK-new.md has 1 hand step(s) and is not in {ALLOWLIST}: "
                "move the step into an Ansible role, or list it"
            ],
        )

    def test_an_unlisted_runbook_without_a_step_passes(self) -> None:
        self._write("RUNBOOK-read-only.md", "```bash\nssh root@host cat /etc/hostname\n```\n")
        self._list()
        self.assertEqual(check(self.root), [])

    def test_fewer_steps_than_listed_fails_so_the_count_only_falls(self) -> None:
        self._write("hetzner/RUNBOOK-a.md", "no blocks\n")
        self._list(self.ONE)
        self.assertEqual(
            check(self.root),
            [
                f"hetzner/RUNBOOK-a.md is in {ALLOWLIST} "
                "but has no hand step or no such runbook: remove it"
            ],
        )
        self._write("hetzner/RUNBOOK-a.md", STEP)
        self._list("hetzner/RUNBOOK-a.md:\n  steps: 3\n  reason: stays-as-code\n")
        self.assertIn("lower the count", check(self.root)[0])

    def test_a_runbook_anywhere_is_walked_and_other_markdown_is_not(self) -> None:
        self._write("a/b/c/RUNBOOK-deep.md", STEP)
        self._write("hetzner/README.md", STEP)
        self._write("hetzner/NOTES-RUNBOOK.md", STEP)
        self._list()
        findings = check(self.root)
        self.assertEqual(len(findings), 1)
        self.assertIn("a/b/c/RUNBOOK-deep.md", findings[0])

    def test_a_pending_role_entry_without_a_role_fails(self) -> None:
        self._write("hetzner/RUNBOOK-a.md", STEP)
        self._list("hetzner/RUNBOOK-a.md:\n  steps: 1\n  reason: pending-role\n")
        self.assertEqual(
            check(self.root),
            ["hetzner/RUNBOOK-a.md: pending-role must name its role, [a-z][a-z0-9_]*"],
        )

    def test_a_bad_steps_value_or_reason_fails(self) -> None:
        self._write("hetzner/RUNBOOK-a.md", STEP)
        for value in ("0", "many", "true", "1.5"):
            with self.subTest(steps=value):
                self._list(f"hetzner/RUNBOOK-a.md:\n  steps: {value}\n  reason: stays-as-code\n")
                self.assertIn("steps must be a whole number", check(self.root)[0])
        self._list("hetzner/RUNBOOK-a.md:\n  steps: 1\n  reason: later\n")
        self.assertIn("reason must be one of", check(self.root)[0])

    def test_a_stays_as_code_entry_with_a_role_or_an_unknown_key_fails(self) -> None:
        self._write("hetzner/RUNBOOK-a.md", STEP)
        self._list("hetzner/RUNBOOK-a.md:\n  steps: 1\n  reason: stays-as-code\n  role: x\n")
        self.assertEqual(check(self.root), ["hetzner/RUNBOOK-a.md: stays-as-code takes no role"])
        self._list("hetzner/RUNBOOK-a.md:\n  steps: 1\n  reason: stays-as-code\n  why: x\n")
        self.assertEqual(check(self.root), ["hetzner/RUNBOOK-a.md: unknown key why"])

    def test_an_entry_that_is_not_a_mapping_fails(self) -> None:
        self._write("hetzner/RUNBOOK-a.md", STEP)
        self._list("hetzner/RUNBOOK-a.md: 1\n")
        self.assertIn("must be a mapping", check(self.root)[0])

    def test_a_missing_allowlist_fails(self) -> None:
        self._write("hetzner/RUNBOOK-a.md", STEP)
        self.assertEqual(
            check(self.root), [f"{ALLOWLIST} cannot be read as YAML: FileNotFoundError"]
        )


if __name__ == "__main__":
    unittest.main()
