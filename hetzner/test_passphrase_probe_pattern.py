#!/usr/bin/env python3
"""Passphrase probes must use `pulumi preview`, never `stack export --show-secrets`.

`pulumi stack export --show-secrets` exits 0 even under a wrong passphrase (observed
Pulumi v3.255.0, INC-4 in ghost-platform-docs/INCIDENTS.md), so a verification built
on it passes vacuously. `pulumi preview` fails closed on a wrong passphrase with
"error: getting stack configuration: get stack secrets manager: incorrect passphrase".

This test prevents reintroduction of the anti-pattern in the migration runbooks.
See branchLeft/workspace#208 for the incident and fix.
"""

import pathlib
import re
import unittest

HETZNER = pathlib.Path(__file__).resolve().parent


def runbooks() -> list[pathlib.Path]:
    """Find all RUNBOOK-*.md files in the hetzner directory and mail subdirectory."""
    found = []
    for p in HETZNER.glob("RUNBOOK-*.md"):
        found.append(p)
    # Also check mail runbooks
    mail_dir = HETZNER.parent / "mail"
    if mail_dir.exists():
        for p in mail_dir.glob("RUNBOOK-*.md"):
            found.append(p)
    return sorted(found)


def code_fences(text: str) -> list[tuple[int, int, str]]:
    """Pair up markdown code fences by position, alternating open/close.

    A single non-greedy regex from an opening fence to "the next line that
    starts with backticks" over-matches on a document with more than one
    code block: a closing fence is itself such a line, so it gets consumed
    as the *next* block's opener. That drifts the pairing for every fence
    after the first, silently skipping some real code blocks entirely and
    fabricating fake ones out of the prose between two real blocks. Markdown
    fences strictly alternate open/close, so pairing fence-start lines by
    position (1st-2nd, 3rd-4th, ...) instead of by a single regex match
    keeps every real block intact.
    """
    fence_line = re.compile(r"^```[^\n]*\n", re.MULTILINE)
    marks = list(fence_line.finditer(text))
    return [
        (opener.start(), closer.end(), text[opener.end() : closer.start()])
        for opener, closer in zip(marks[0::2], marks[1::2])
    ]


def passphrase_verification_sections() -> list[tuple[pathlib.Path, str, str]]:
    """Find sections where passphrases are being verified (steps mentioning decrypt/proof).

    Returns tuples of (runbook_path, code_block, context) for sections mentioning verify/decrypt/proof.
    Context window expanded to 2000 chars to capture distant section headers.
    """
    found = []
    for runbook in runbooks():
        text = runbook.read_text(encoding="utf-8")
        for start, end, code_block in code_fences(text):
            # Look for code blocks that are in a step mentioning decrypt or verify
            # Expanded context window to 2000 chars to capture distant keywords in headers
            start_pos = max(0, start - 2000)
            context = text[start_pos : end + 100]
            if any(word in context.lower() for word in ["decrypt", "verify", "proof", "passphrase check"]):
                found.append((runbook, code_block, context))
    return found


class PassphraseProbePatternTests(unittest.TestCase):
    def test_runbooks_found(self):
        """Verify we actually found runbooks to test."""
        self.assertGreater(len(runbooks()), 0, "No RUNBOOK-*.md files found")

    def test_no_stack_export_show_secrets_used_as_passphrase_proof(self):
        """Passphrase verification never uses `stack export --show-secrets` as a proof gate.

        The anti-pattern is: `pulumi stack export --show-secrets ... && <continue or assert>`.
        This exits 0 under a wrong passphrase, so it proves nothing. Use `pulumi preview`
        which fails closed on an incorrect passphrase.
        """
        for runbook, code_block, context in passphrase_verification_sections():
            with self.subTest(runbook=runbook.name):
                # The anti-pattern: export as a gate for continuing. Matches
                # "stack export ... --show-secrets ... &&" on one logical
                # command line, but not inspection commands like piping to
                # jq/head with no following `&&`. `[^\n]*?` (not `\s*?`)
                # between --show-secrets and && so a redirect in between
                # (` > /dev/null && echo 'decrypt OK'`, the exact shape the
                # real anti-pattern took) still matches.
                bad_pattern = re.search(
                    r"pulumi\s+stack\s+export\s+[^\n`]*?--show-secrets[^\n`]*?&&",
                    code_block,
                    re.IGNORECASE
                )

                self.assertIsNone(
                    bad_pattern,
                    f"{runbook.name}: found `stack export --show-secrets &&` (continues/asserts). "
                    f"This exits 0 under a wrong passphrase (Pulumi v3.255.0, INC-4) and proves nothing. "
                    f"Use `pulumi preview` instead, which fails closed on incorrect passphrase. "
                    f"See branchLeft/workspace#208."
                )


if __name__ == "__main__":
    unittest.main()
