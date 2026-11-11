#!/usr/bin/env python3
"""Guard against `pulumi stack export --show-secrets` being used to prove decryption.

Narrative, the ALLOWLIST rules and the known limits: hetzner/test_passphrase_probe_pattern.md.
"""

import contextlib
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from collections import defaultdict
from unittest import mock

HETZNER = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HETZNER.parent


_SELF_PATH = str(pathlib.Path(__file__).resolve().relative_to(pathlib.Path(__file__).resolve().parent.parent))


def scanned_files() -> list[pathlib.Path]:
    """Every git-tracked file in the repo, except this module.

    Every tracked file, not a set of extensions or a RUNBOOK-* glob: a live
    anti-pattern in a Markdown file with any name, at any depth, is a finding.
    Scope rationale: hetzner/test_passphrase_probe_pattern.md, section SCAN SCOPE.
    """
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True
    )
    # is_file() skips a tracked symlink to a directory (its real files are tracked
    # and scanned under their own paths) and a tracked submodule gitlink.
    paths = [
        REPO_ROOT / rel
        for rel in result.stdout.decode("utf-8").split("\0")
        if rel and rel != _SELF_PATH
    ]
    return [path for path in paths if path.is_file()]


def show_secrets_occurrences() -> list[tuple[pathlib.Path, int, str]]:
    """Every line in every scanned file containing the literal `--show-secrets` flag.

    See hetzner/test_passphrase_probe_pattern.md, section SCAN SCOPE.
    """
    found = []
    for path in scanned_files():
        # strict decoding: a tracked file that is not UTF-8 text fails the test
        # instead of being skipped.
        text = path.read_bytes().decode("utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "--show-secrets" in line:
                found.append((path, lineno, line.strip()))
    return found


# ALLOWLIST keying rules and the seeding rationale are in
# hetzner/test_passphrase_probe_pattern.md, section ALLOWLIST.
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
    (
        'hetzner/test_passphrase_probe_pattern.md',
        '`pulumi stack export --show-secrets` exits 0 even under a wrong passphrase (observed',
    ): (1, "prose in this guard's own narrative document describing the anti-pattern"),
    (
        'hetzner/test_passphrase_probe_pattern.md',
        'Detection here is deny-by-default on the literal `--show-secrets` flag,',
    ): (1, "prose in this guard's own narrative document describing the anti-pattern"),
    (
        'scripts/audit-pulumi-secrets.md',
        'and this script cannot detect it. `pulumi stack export --show-secrets`',
    ): (1, 'prose warning that the audit script cannot detect the anti-pattern'),
    (
        'scripts/pulumi-stack-inventory.json',
        '"evidence": "pulumi stack change-secrets-provider passphrase completed (\\"Migrating old configuration and state to new secrets provider\\") and pulumi stack export --show-secrets succeeded afterwards; secrets_providers read back from the gs://branchleft-pulumi-state checkpoint: passphrase, salt prefix v1:v6UAjuKhH, 12 resources. Wrapped by ghost-platform\'s existing repo-level passphrase; the stored copy was independently re-typed from the password manager and verified against the live checkpoint."',
    ): (1, 'recorded past-tense evidence of a completed re-wrap, data not a command or instruction'),
    (
        'scripts/pulumi-stack-inventory.json',
        '"evidence": "Re-wrapped the same way as branchleft-ghost-provisioning/blog; pulumi stack export --show-secrets succeeded afterwards. secrets_providers read back from the gs://branchleft-blog-pulumi-state checkpoint: passphrase, salt prefix v1:rLDLxMTFD, matching the value placed in the PULUMI_SALT_BLOG repository secret, 33 resources. Wrapped by a newly minted 32-character passphrase, escrowed in the platform owner\'s password manager and set as PULUMI_CONFIG_PASSPHRASE on branchLeft/ghost-tenant-blog before the re-wrap; the stored copy was independently re-typed and verified. Post-merge deploy green: \\"Restore the stack\'s encryption salt\\" and the delete-guard both passed, and Apply reported 31 unchanged with no creates, updates, deletes or replaces."',
    ): (1, 'recorded past-tense evidence of a completed re-wrap, data not a command or instruction'),
}


LIVE_LINE = "pulumi stack export --show-secrets --stack <stack> --file out.json"

EXISTING_STACK_RUNBOOK = "hetzner/RUNBOOK-existing-stack-migration.md"
# A live decrypt gate is a line that runs `pulumi preview --stack` as a command.
# Prose mentions are not counted. The pinned count is the four live gates the
# runbook carries: three in the A.2 per-stack sequence (steps 4, 6 and 7) and
# one in the B.1 move sequence (step 5). Replacing one with another command
# lowers the count; adding one raises it. Either change must update this pin.
DECRYPT_GATE = re.compile(r"^\s*pulumi preview --stack\b", re.MULTILINE)
EXPECTED_DECRYPT_GATES = 4


def decrypt_gate_problems(text: str) -> list[str]:
    """Empty when the runbook carries exactly the pinned number of live decrypt gates."""
    found = len(DECRYPT_GATE.findall(text))
    if found != EXPECTED_DECRYPT_GATES:
        return [
            f"{EXISTING_STACK_RUNBOOK}: found {found} live `pulumi preview --stack` "
            f"decrypt gate(s), expected {EXPECTED_DECRYPT_GATES}; a gate replaced by "
            f"another command (e.g. `pulumi stack ls`) is not a decrypt proof"
        ]
    return []


@contextlib.contextmanager
def repo_with(files: dict[str, str]):
    """A throwaway git repo holding exactly `files`, with REPO_ROOT pointed at it."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        with mock.patch.object(sys.modules[__name__], "REPO_ROOT", root):
            yield root


def flagged_paths() -> set[str]:
    return {str(p.relative_to(REPO_ROOT)) for p, _, _ in show_secrets_occurrences()}


class ShowSecretsAllowlistTests(unittest.TestCase):
    def test_markdown_outside_runbook_glob_is_scanned(self):
        """Gap 1: a live instruction in a non-RUNBOOK Markdown file must be seen."""
        with repo_with({"PULUMI-BACKEND-INVENTORY.md": LIVE_LINE + "\n"}):
            self.assertIn("PULUMI-BACKEND-INVENTORY.md", flagged_paths())

    def test_nested_runbook_is_scanned(self):
        """Gap 2: the RUNBOOK glob is not recursive, so a nested runbook must be seen."""
        with repo_with({"hetzner/docs/RUNBOOK-nested.md": LIVE_LINE + "\n"}):
            self.assertIn("hetzner/docs/RUNBOOK-nested.md", flagged_paths())

    def test_unglobbed_markdown_name_is_scanned(self):
        """Gap 2: a Markdown file whose name does not match RUNBOOK-* must be seen."""
        with repo_with({"hetzner/MIGRATION-GUIDE.md": LIVE_LINE + "\n"}):
            self.assertIn("hetzner/MIGRATION-GUIDE.md", flagged_paths())

    def test_existing_stack_runbook_keeps_its_decrypt_gates(self):
        """Gap 3: the good gate must be present, not only the bad string absent."""
        text = (REPO_ROOT / EXISTING_STACK_RUNBOOK).read_text(encoding="utf-8")
        self.assertEqual(decrypt_gate_problems(text), [])

    def test_gate_replaced_by_stack_ls_is_caught(self):
        """Gap 3 proof: swapping one live gate for `pulumi stack ls` must fail."""
        text = (REPO_ROOT / EXISTING_STACK_RUNBOOK).read_text(encoding="utf-8")
        mutated = text.replace(
            "pulumi preview --stack <stack> > /dev/null && echo 'decrypt OK'",
            "pulumi stack ls --stack <stack> > /dev/null && echo 'decrypt OK'",
            1,
        )
        self.assertNotEqual(mutated, text, "sabotage text not found in the runbook")
        self.assertNotEqual(decrypt_gate_problems(mutated), [])

    def test_show_secrets_is_allowlisted_everywhere_it_appears(self):
        """Deny-by-default: every `--show-secrets` occurrence must be on ALLOWLIST.

        See hetzner/test_passphrase_probe_pattern.md, section SCAN SCOPE.
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
