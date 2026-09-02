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


def passphrase_verification_sections() -> list[tuple[pathlib.Path, str, str]]:
    """Find sections where passphrases are being verified (steps mentioning decrypt/proof).

    Returns tuples of (runbook_path, code_block, context) for sections mentioning verify/decrypt/proof.
    Context window expanded to 2000 chars to capture distant section headers.
    """
    found = []
    for runbook in runbooks():
        text = runbook.read_text(encoding="utf-8")
        # Find code fences and their surrounding context
        fence_pattern = re.compile(r"^```(?:bash)?\n(.+?)\n```", re.MULTILINE | re.DOTALL)
        for match in fence_pattern.finditer(text):
            code_block = match.group(1)
            # Look for code blocks that are in a step mentioning decrypt or verify
            # Expanded context window to 2000 chars to capture distant keywords in headers
            start_pos = max(0, match.start() - 2000)
            context = text[start_pos : match.end() + 100]
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
                # The anti-pattern: export as a gate for continuing. More specific pattern:
                # matches "stack export ... --show-secrets ... &&" but not inspection commands
                # like piping to jq/head. The &&-continuation is the smoking gun.
                bad_pattern = re.search(
                    r"pulumi\s+stack\s+export\s+[^`]*?--show-secrets\s*&&",
                    code_block,
                    re.IGNORECASE | re.DOTALL
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
