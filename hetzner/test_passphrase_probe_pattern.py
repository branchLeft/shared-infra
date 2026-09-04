#!/usr/bin/env python3
"""Guard against `pulumi stack export --show-secrets` being used to prove decryption.

`pulumi stack export --show-secrets` exits 0 even under a wrong passphrase (observed
Pulumi v3.255.0, INC-4 in ghost-platform-docs/INCIDENTS.md), so any verification built
on it passes vacuously. `pulumi preview` fails closed on a wrong passphrase with
"error: getting stack configuration: get stack secrets manager: incorrect passphrase".

Detection here is deny-by-default on the literal `--show-secrets` flag,
never on recognising "a passphrase-verification section" or "a command
shaped like the anti-pattern": free-prose shape matching cannot distinguish
a reworded anti-pattern from a legitimate warning against one, so any
rewording it doesn't already know about passes silently -- keying on the
literal flag text has no such blind spot. The ALLOWLIST below keys each
accepted occurrence on its exact line text *and* its occurrence count
together, not text alone: keying on text alone would let a verbatim copy of
an allowlisted line, pasted into a new location, pass unnoticed even though
it is a second, unreviewed occurrence there.

Known, deliberate limits of this design: a flag built from string
fragments that no single scanned line contains in full (e.g. concatenated
shell variables) is invisible to a per-line literal scan; the allowlist's
exact-text keying means reformatting an allowlisted line for any reason --
punctuation, a typo fix, a rewrap -- fails the check even though nothing
security-relevant changed, which is an accepted trade against fuzzy matching
that could hide a real reintroduction; and `scripts/pulumi-stack-inventory.json`
is deliberately out of scope, since it is a data file recording completed
operations rather than prose or code a future reader could learn the
anti-pattern from.
"""

import pathlib
import subprocess
import unittest
from collections import defaultdict

HETZNER = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HETZNER.parent


def runbooks() -> list[pathlib.Path]:
    """Find all RUNBOOK-*.md files: hetzner/, mail/, and the repo root.

    Non-recursive per directory, matching this repo's own convention -- every
    RUNBOOK lives directly in one of these three places, never nested
    further -- but all three, not just hetzner/ and mail/: RUNBOOK-ci-bootstrap.md
    and RUNBOOK-edge-state-move.md live at the repo root, and a scan that
    skips it never sees either.
    """
    found: set[pathlib.Path] = set()
    for base in (HETZNER, REPO_ROOT / "mail", REPO_ROOT):
        if base.exists():
            found.update(base.glob("RUNBOOK-*.md"))
    return sorted(found)


_SCAN_EXTENSIONS = (".py", ".sh", ".yml", ".yaml")

# This module's own path, relative to the repo root: excluded from the scan
# below because a guard whose whole job is discussing the flag necessarily
# mentions it dozens of times, in docstrings, comments and the ALLOWLIST
# literal itself -- none of that is a runbook or script that could teach a
# reader the anti-pattern is safe, which is the harm this scan exists to
# catch. Excluding it by path, rather than trying to allowlist its own
# literals, keeps the ALLOWLIST meaningful: every entry in it should describe
# a real occurrence outside this file, not this file's own vocabulary.
_SELF_PATH = str(pathlib.Path(__file__).resolve().relative_to(pathlib.Path(__file__).resolve().parent.parent))


def _tracked_scan_files() -> list[pathlib.Path]:
    """Every git-tracked .py/.sh/.yml/.yaml file in the repo, except graphify-out/ and this file.

    Uses `git ls-files` rather than a hand-maintained directory list: a
    fixed glob can leave a whole class of tracked files unscanned -- scripts
    and workflow files outside a runbook-only glob, for instance, while the
    literal flag still appears in them. This one grows automatically with
    the tracked tree instead of needing a second edit whenever a new script
    or workflow is added. graphify-out/ is excluded: it is a
    generated AST/semantic cache of every source file, so anything findable
    there is a duplicate of a source file this scan already inspects
    directly, and it must never be hand-edited regardless (workspace root
    CLAUDE.md's graphify section).
    """
    result = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return [
        REPO_ROOT / rel
        for rel in result.stdout.splitlines()
        if not rel.startswith("graphify-out/") and rel != _SELF_PATH and rel.endswith(_SCAN_EXTENSIONS)
    ]


def scanned_files() -> list[pathlib.Path]:
    """Every file this guard inspects for the literal `--show-secrets` flag."""
    return runbooks() + _tracked_scan_files()


def show_secrets_occurrences() -> list[tuple[pathlib.Path, int, str]]:
    """Every line in every scanned file containing the literal `--show-secrets` flag.

    Deliberately not scoped to code fences, a preceding `pulumi stack
    export`, or nearby keywords: the anti-pattern is exactly this flag being
    used to prove a stack decrypts, and catching every way of writing that
    needs to key on the one thing every such command has in common -- the
    flag's own name appearing somewhere in the source a human would type,
    paste, or read as an instruction. A per-line scan also gives a useful
    failure message (file, line number, exact text) with no surrounding-
    context machinery needed to produce it.
    """
    found = []
    for path in scanned_files():
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "--show-secrets" in line:
                found.append((path, lineno, line.strip()))
    return found


# ALLOWLIST keys every current, reviewed appearance of the literal flag by
# (path relative to the repo root, exact stripped line text) -> (expected
# occurrence count, justification).
#
# The count is load-bearing, not decoration: keying on text alone, with no
# count, lets one allowlisted prose line also allowlist every future
# identical line in that file, including a live one pasted into a new code
# fence where the same backticked text becomes a real command. Requiring the
# *count* of a (file, text) pair to match exactly means a duplicate --
# benign copy-paste or a live reintroduction disguised as one -- moves the
# count from N to N+1 and fails. Line numbers are deliberately not part of
# the key: they shift under every unrelated edit to the file, and keying on
# them too would fail the check on an edit that made no security-relevant
# change to this line at all.
#
# Seeded from the whole corpus as it exists today, across every file this
# scan inspects (all RUNBOOK-*.md, plus every tracked .py/.sh/.yml/.yaml).
# Every entry below is prose warning against the anti-pattern -- a `#`
# comment or backticked inline text in surrounding prose -- never a line a
# shell would execute. There are currently zero legitimate live uses of the
# flag anywhere in the scanned tree.
ALLOWLIST: dict[tuple[str, str], tuple[int, str]] = {
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "#    --show-secrets` does not (it exits 0 regardless, observed v3.255.0 --",
    ): (1, "prose explaining why the anti-pattern is unsafe, wrapped across a shell comment"),
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "# --show-secrets` does not)",
    ): (1, "prose explaining why the anti-pattern is unsafe, wrapped across a shell comment"),
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "# `pulumi preview`, not `stack export --show-secrets`: export exits 0 under a",
    ): (1, "prose explaining why the anti-pattern is unsafe, in a shell comment"),
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "around `stack export --show-secrets` on the theory that emitting plaintext",
    ): (1, "prose explaining why the anti-pattern is unsafe"),
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "# export --show-secrets` exits 0 under",
    ): (1, "prose explaining why the anti-pattern is unsafe, in a shell comment"),
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "`pulumi stack export --show-secrets` is deliberately not used — for two",
    ): (1, "prose explaining why the anti-pattern is unsafe"),
    (
        "hetzner/RUNBOOK-new-stack.md",
        "`pulumi stack export --show-secrets` is **not** a decrypt proof — observed on",
    ): (1, "prose explaining why the anti-pattern is unsafe"),
    (
        "hetzner/RUNBOOK-new-stack.md",
        "equally conclusive. Do not use `stack export --show-secrets` for either",
    ): (1, "prose explaining why the anti-pattern is unsafe"),
    (
        "scripts/audit-pulumi-secrets.py",
        "and this script cannot detect it. `pulumi stack export --show-secrets`",
    ): (1, "docstring prose describing a detection gap, not an instruction to use the flag"),
    (
        "scripts/test_verify_archive_passphrase.py",
        "# `plaintext` keys mean the export was taken with --show-secrets. It is",
    ): (1, "comment describing what a fixture's data represents, not a live command"),
    (
        "scripts/verify-archive-passphrase.py",
        "`pulumi stack export --show-secrets` is deliberately *not* used. It is the",
    ): (1, "docstring prose explaining why the anti-pattern is unsafe"),
    (
        "scripts/verify-archive-passphrase.py",
        "# An export taken with --show-secrets. It is not wrapped at all, so it",
    ): (1, "comment describing what a fixture's data represents, not a live command"),
}


class ShowSecretsAllowlistTests(unittest.TestCase):
    def test_runbooks_found(self):
        """Sanity check: the flag scan must have files to scan in the first place."""
        found = runbooks()
        self.assertGreater(len(found), 0, "No RUNBOOK-*.md files found")

    def test_show_secrets_is_allowlisted_everywhere_it_appears(self):
        """Deny-by-default: every `--show-secrets` occurrence must be on ALLOWLIST.

        Two ways an occurrence can be wrong, both checked: unlisted entirely
        (not on ALLOWLIST at all), or listed with the wrong count (the file
        now has more, or fewer, copies of that exact line than the entry
        says it should). Also guards the guard itself against scanning
        nothing: scanned_files() returning zero files would otherwise make
        this pass by finding zero problems among zero files scanned, the
        same vacuous-pass failure this file exists to prevent -- so a
        non-zero scanned-file count is asserted here directly.
        """
        files = scanned_files()
        self.assertGreater(
            len(files),
            0,
            "scanned_files() returned 0 files -- the --show-secrets scan below would "
            "silently check nothing and pass vacuously",
        )

        actual_by_key: dict[tuple[str, str], list[int]] = defaultdict(list)
        for path, lineno, line in show_secrets_occurrences():
            relpath = str(path.relative_to(REPO_ROOT))
            actual_by_key[(relpath, line)].append(lineno)

        problems = []
        for key in sorted(set(actual_by_key) | set(ALLOWLIST)):
            relpath, line = key
            linenos = actual_by_key.get(key, [])
            actual_count = len(linenos)
            if key not in ALLOWLIST:
                problems.append(
                    f"{relpath}:{linenos}: unlisted occurrence of {line!r} "
                    f"({actual_count} found) -- add an ALLOWLIST entry with a justification, "
                    f"or fix the file if this is a live use of the anti-pattern"
                )
                continue
            expected_count, justification = ALLOWLIST[key]
            if actual_count != expected_count:
                problems.append(
                    f"{relpath}:{linenos}: expected {expected_count} occurrence(s) of "
                    f"{line!r} (allowlisted: {justification!r}), found {actual_count} -- "
                    f"a count above expected is either a benign duplicate needing its own "
                    f"ALLOWLIST entry or the anti-pattern reintroduced as a copy of allowlisted "
                    f"prose; a count below expected means the ALLOWLIST entry is stale and "
                    f"should be removed"
                )

        self.assertEqual(
            problems,
            [],
            "hetzner/test_passphrase_probe_pattern.py's ALLOWLIST no longer matches reality:\n"
            + "\n".join(problems),
        )


if __name__ == "__main__":
    unittest.main()
