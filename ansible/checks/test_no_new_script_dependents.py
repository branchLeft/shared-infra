"""Hold the callers of the pending-role scripts to a frozen baseline: nothing new may build on one.

A pending-role script is listed in ``hand_installers.yml`` and is due for removal in favour of an
Ansible role (the script-removal programme). A tracked file depends on a script when its text names
the script's repo-relative path or its basename, and a shared basename counts for every script that
carries it. ``hand_installers_dependents.yml`` maps each dependent file to the sorted list of
pending-role scripts it names. The test fails on a new dependency, on a file that names one with no
row, on a row naming a script the file no longer names, and on a row for a file that is gone. The
baseline only shrinks. To change it, edit it by hand in the same change; nothing regenerates it.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path, PurePosixPath

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = Path("ansible/checks/hand_installers.yml")
BASELINE = Path("ansible/checks/hand_installers_dependents.yml")
SELF = Path("ansible/checks/test_no_new_script_dependents.py")
EXCLUDED = frozenset((ALLOWLIST.as_posix(), BASELINE.as_posix(), SELF.as_posix()))
PENDING = "pending-role"
MESSAGE = (
    "{rel} depends on {script}, which is pending-role and due for removal (the script-removal "
    "programme). Build this path as an Ansible role; do not add callers to the script."
)


def load(text: str) -> object:
    return YAML(typ="safe").load(text)


def pending(document: object) -> list[str]:
    """Return the sorted path of every hand_installers.yml entry marked pending-role."""
    if not isinstance(document, dict):
        return []
    return sorted(
        str(name)
        for name, entry in document.items()
        if isinstance(entry, dict) and entry.get("reason") == PENDING
    )


def _git(root: Path, *args: str) -> bytes:
    done = subprocess.run(  # noqa: S603
        ["git", "-C", str(root), *args],  # noqa: S607
        check=True,
        capture_output=True,
    )
    return done.stdout


def tracked(root: Path) -> list[str]:
    """Return the repo-relative path of every file git tracks under ``root``, outside ``.git``."""
    names = _git(root, "ls-files", "-z").decode("utf-8").split("\0")
    return [name for name in names if name and ".git" not in PurePosixPath(name).parts]


def dependents(root: Path, scripts: list[str]) -> dict[str, list[str]]:
    """Return each tracked file that names a script, with the sorted scripts it names."""
    rows: dict[str, list[str]] = {}
    for rel in tracked(root):
        if rel in EXCLUDED or not (root / rel).is_file():
            continue
        data = (root / rel).read_bytes()
        if b"\0" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        for script in scripts:
            if script == rel:
                continue
            basename = PurePosixPath(script).name
            if basename.encode("utf-8") not in data:
                continue
            named = re.compile(
                r"(?<![\w.-])(?:" + re.escape(script) + "|" + re.escape(basename) + r")(?![\w-])"
            )
            if named.search(text):
                rows.setdefault(rel, []).append(script)
    return {rel: sorted(found) for rel, found in sorted(rows.items())}


def _well_formed(listed: object) -> bool:
    return isinstance(listed, list) and bool(listed) and all(isinstance(s, str) for s in listed)


def check(root: Path) -> list[str]:
    """Return one finding per new dependency, stale row, malformed row or missing file."""
    try:
        allowlist = load((root / ALLOWLIST).read_text(encoding="utf-8"))
        baseline = load((root / BASELINE).read_text(encoding="utf-8"))
    except (OSError, YAMLError) as error:
        return [f"{ALLOWLIST} or {BASELINE} cannot be read as YAML: {type(error).__name__}"]
    if baseline is None:
        baseline = {}
    if not isinstance(baseline, dict):
        return [f"{BASELINE} must map each file to the list of scripts it names"]
    findings: list[str] = []
    for name, listed in baseline.items():
        if not _well_formed(listed):
            findings.append(f"{name}: the row must be a non-empty list of script paths")
    rows = {str(name): listed for name, listed in baseline.items() if isinstance(listed, list)}
    found = dependents(root, pending(allowlist))
    for rel, scripts in found.items():
        for script in scripts:
            if script not in rows.get(rel, []):
                findings.append(MESSAGE.format(rel=rel, script=script))
    present = set(tracked(root))
    for rel, listed in rows.items():
        if rel not in present:
            findings.append(f"{rel} is in {BASELINE} but no such file is tracked: remove it")
            continue
        for script in listed:
            if script not in found.get(rel, []):
                findings.append(
                    f"{rel} is in {BASELINE} for {script} but no longer names it: remove it"
                )
    return findings


class RealTree(unittest.TestCase):
    def test_no_new_script_dependents(self) -> None:
        self.assertEqual(check(ROOT), [])

    def test_the_scan_finds_the_callers_of_the_pending_scripts(self) -> None:
        found = dependents(ROOT, pending(load((ROOT / ALLOWLIST).read_text(encoding="utf-8"))))
        self.assertIn("hetzner/provision/run-all.sh", found)
        self.assertGreater(len(found), 0)


class Tree(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        _git(self.root, "init", "-q")

    def _write(self, relative: str, text: str = "echo\n") -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        _git(self.root, "add", relative)

    def _allowlist(self, *entries: str) -> None:
        self._write(ALLOWLIST.as_posix(), "".join(entries))

    def _baseline(self, text: str) -> None:
        self._write(BASELINE.as_posix(), text)

    def test_a_listed_dependent_passes(self) -> None:
        self._allowlist("hetzner/provision/a.sh:\n  reason: pending-role\n  role: host_baseline\n")
        self._write("hetzner/provision/a.sh")
        self._write("ansible/roles/x/tasks/main.yml", "run: hetzner/provision/a.sh\n")
        self._baseline("ansible/roles/x/tasks/main.yml:\n  - hetzner/provision/a.sh\n")
        self.assertEqual(check(self.root), [])

    def test_a_new_dependent_with_no_row_fails_naming_both(self) -> None:
        self._allowlist("hetzner/provision/a.sh:\n  reason: pending-role\n  role: host_baseline\n")
        self._write("hetzner/provision/a.sh")
        self._write("scripts/new.sh", "bash hetzner/provision/a.sh\n")
        self._baseline("")
        self.assertEqual(
            check(self.root),
            [
                "scripts/new.sh depends on hetzner/provision/a.sh, which is pending-role and due "
                "for removal (the script-removal programme). Build this path as an Ansible role; "
                "do not add callers to the script."
            ],
        )

    def test_a_second_script_named_in_a_listed_file_fails(self) -> None:
        self._allowlist(
            "hetzner/provision/a.sh:\n  reason: pending-role\n  role: host_baseline\n",
            "hetzner/provision/b.sh:\n  reason: pending-role\n  role: docker_host\n",
        )
        self._write("hetzner/provision/a.sh")
        self._write("hetzner/provision/b.sh")
        self._write("ansible/roles/x/tasks/main.yml", "a: a.sh\nb: b.sh\n")
        self._baseline("ansible/roles/x/tasks/main.yml:\n  - hetzner/provision/a.sh\n")
        findings = check(self.root)
        self.assertEqual(len(findings), 1)
        self.assertIn(
            "ansible/roles/x/tasks/main.yml depends on hetzner/provision/b.sh", findings[0]
        )

    def test_a_shared_basename_is_attributed_to_both_scripts(self) -> None:
        self._allowlist(
            "hetzner/provision/run-all.sh:\n  reason: pending-role\n  role: host_baseline\n",
            "mail/provision/run-all.sh:\n  reason: pending-role\n  role: mail_stalwart\n",
        )
        self._write("hetzner/provision/run-all.sh")
        self._write("mail/provision/run-all.sh")
        self._write("docs/note.md", "runs run-all.sh\n")
        self._baseline("")
        findings = check(self.root)
        self.assertEqual(len(findings), 2)
        self.assertIn("docs/note.md depends on hetzner/provision/run-all.sh", findings[0])
        self.assertIn("docs/note.md depends on mail/provision/run-all.sh", findings[1])

    def test_a_stays_as_code_script_is_not_counted(self) -> None:
        self._allowlist("hetzner/scripts/lib/d.sh:\n  reason: stays-as-code\n")
        self._write("hetzner/scripts/lib/d.sh")
        self._write("docs/note.md", "uses d.sh\n")
        self._baseline("")
        self.assertEqual(check(self.root), [])

    def test_an_untracked_file_is_not_counted(self) -> None:
        self._allowlist("hetzner/provision/a.sh:\n  reason: pending-role\n  role: host_baseline\n")
        self._write("hetzner/provision/a.sh")
        (self.root / "scratch.md").write_text("hetzner/provision/a.sh\n", encoding="utf-8")
        self._baseline("")
        self.assertEqual(check(self.root), [])

    def test_a_stale_row_for_a_script_no_longer_named_fails(self) -> None:
        self._allowlist("hetzner/provision/a.sh:\n  reason: pending-role\n  role: host_baseline\n")
        self._write("hetzner/provision/a.sh")
        self._write("ansible/roles/x/tasks/main.yml", "nothing here\n")
        self._baseline("ansible/roles/x/tasks/main.yml:\n  - hetzner/provision/a.sh\n")
        self.assertEqual(
            check(self.root),
            [
                f"ansible/roles/x/tasks/main.yml is in {BASELINE} for hetzner/provision/a.sh "
                "but no longer names it: remove it"
            ],
        )

    def test_a_row_for_a_file_that_is_gone_fails(self) -> None:
        self._allowlist("hetzner/provision/a.sh:\n  reason: pending-role\n  role: host_baseline\n")
        self._write("hetzner/provision/a.sh")
        self._baseline("ansible/roles/gone/tasks/main.yml:\n  - hetzner/provision/a.sh\n")
        self.assertEqual(
            check(self.root),
            [
                f"ansible/roles/gone/tasks/main.yml is in {BASELINE} but no such file is "
                "tracked: remove it"
            ],
        )

    def test_an_empty_row_fails(self) -> None:
        self._allowlist("hetzner/provision/a.sh:\n  reason: pending-role\n  role: host_baseline\n")
        self._write("hetzner/provision/a.sh")
        self._baseline("scripts/x.sh:\n  []\n")
        self._write("scripts/x.sh")
        self.assertEqual(
            check(self.root),
            ["scripts/x.sh: the row must be a non-empty list of script paths"],
        )

    def test_a_missing_baseline_fails(self) -> None:
        self._allowlist("hetzner/provision/a.sh:\n  reason: pending-role\n  role: host_baseline\n")
        self._write("hetzner/provision/a.sh")
        self.assertEqual(
            check(self.root),
            [f"{ALLOWLIST} or {BASELINE} cannot be read as YAML: FileNotFoundError"],
        )


if __name__ == "__main__":
    unittest.main()
