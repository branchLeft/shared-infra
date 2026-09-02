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


def passphrase_verification_sections() -> list[tuple[pathlib.Path, str]]:
    """Find sections where passphrases are being verified (steps mentioning decrypt/proof).

    Returns tuples of (runbook_path, section_text) for sections mentioning verify/decrypt/proof.
    """
    found = []
    for runbook in runbooks():
        text = runbook.read_text(encoding="utf-8")
        # Find code fences and their surrounding context
        fence_pattern = re.compile(r"^```(?:bash)?\n(.+?)\n```", re.MULTILINE | re.DOTALL)
        for match in fence_pattern.finditer(text):
            code_block = match.group(1)
            # Look for code blocks that are in a step mentioning decrypt or verify
            start_pos = max(0, match.start() - 500)  # Get some context before the block
            context = text[start_pos : match.end() + 100]
            if any(word in context.lower() for word in ["decrypt", "verify", "proof", "passphrase check"]):
                found.append((runbook, code_block))
    return found


class PassphraseProbePatternTests(unittest.TestCase):
    def test_runbooks_found(self):
        """Verify we actually found runbooks to test."""
        self.assertGreater(len(runbooks()), 0, "No RUNBOOK-*.md files found")

    def test_passphrase_probes_use_pulumi_preview_not_stack_export(self):
        """Passphrase probes must use `pulumi preview`, never `stack export --show-secrets`."""
        for runbook, code_block in passphrase_verification_sections():
            with self.subTest(runbook=runbook.name):
                # If the code block has "pulumi preview" it's likely correct
                has_preview = "pulumi preview" in code_block

                # The problematic pattern: using export --show-secrets for verification
                # A correct pattern would be something like:
                #   pulumi preview ... && echo 'decrypt OK'
                # or just
                #   pulumi preview ...
                # Not:
                #   pulumi stack export --show-secrets ... && echo 'decrypt OK'

                bad_pattern = re.search(
                    r"pulumi\s+stack\s+export\s+.*?--show-secrets.*?&&\s*echo\s+['\"].*?(?:decrypt|proof|ok)",
                    code_block,
                    re.IGNORECASE | re.DOTALL
                )

                self.assertIsNone(
                    bad_pattern,
                    f"{runbook.name}: found passphrase verification using "
                    f"`pulumi stack export --show-secrets`. This exits 0 under a wrong passphrase "
                    f"(Pulumi v3.255.0, INC-4) and proves nothing. Use `pulumi preview` instead, "
                    f"which fails closed on incorrect passphrase. See branchLeft/workspace#208."
                )

    def test_no_stack_export_show_secrets_used_as_decrypt_proof(self):
        """Extra check: grep for the exact anti-pattern anywhere in migration runbooks."""
        for runbook in runbooks():
            text = runbook.read_text(encoding="utf-8")
            # Look for the pattern in code blocks
            code_blocks = re.findall(
                r"^```(?:bash)?\n(.+?)\n```", text, re.MULTILINE | re.DOTALL
            )
            for code_block in code_blocks:
                # The anti-pattern: using export as a gate for continuing
                self.assertNotRegex(
                    code_block,
                    r"stack\s+export.*--show-secrets.*&&",
                    f"{runbook.name}: found `stack export --show-secrets` used as a proof/gate. "
                    f"This pattern exits 0 under a wrong passphrase and is unsafe. "
                    f"Use `pulumi preview` instead (fails closed on wrong passphrase). "
                    f"See branchLeft/workspace#208."
                )


if __name__ == "__main__":
    unittest.main()
