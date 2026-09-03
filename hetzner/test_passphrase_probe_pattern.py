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
    """Find all RUNBOOK-*.md files: hetzner/, mail/, and the repo root.

    Non-recursive per directory, matching this repo's own convention -- every
    RUNBOOK lives directly in one of these three places, never nested
    further -- but all three, not just hetzner/ and mail/: RUNBOOK-ci-bootstrap.md
    and RUNBOOK-edge-state-move.md live at the repo root, and a scan that
    skips it never sees either.
    """
    repo_root = HETZNER.parent
    found: set[pathlib.Path] = set()
    for base in (HETZNER, repo_root / "mail", repo_root):
        if base.exists():
            found.update(base.glob("RUNBOOK-*.md"))
    return sorted(found)


class MalformedFencesError(ValueError):
    """Raised when a document's code fences don't close in pairs.

    A malformed document must fail the scan loudly, never scan a truncated
    subset of it and report OK.
    """


_FENCE_MARKER = re.compile(r"^[ \t]*(`{3,}|~{3,})[^\n]*\n", re.MULTILINE)


def code_fences(text: str) -> list[tuple[int, int, str]]:
    """Pair up markdown code fences by character-matched open/close state.

    Recognises both ``` and ~~~ fences, at any indentation -- list items and
    blockquotes routinely indent a fence, and a regex anchored to column 0
    misses every one of those (proven against a real indented block in
    mail/RUNBOOK-mail-history-migration.md). A same-position pairing
    (1st-2nd marker, 3rd-4th, ...) also silently drops the wrong block
    whenever a document's marker count is odd or a fence stays open to EOF;
    tracking open/close state instead makes both cases raise
    MalformedFencesError rather than truncate. A marker of a *different*
    fence character while one is already open is not a fence under
    CommonMark -- it's literal content inside the open block -- so it is
    skipped rather than mistaken for a stray opener or closer.
    """
    blocks: list[tuple[int, int, str]] = []
    open_char: str | None = None
    open_pos = 0
    for m in _FENCE_MARKER.finditer(text):
        ch = m.group(1)[0]
        if open_char is None:
            open_char, open_pos = ch, m.end()
        elif ch == open_char:
            blocks.append((open_pos, m.start(), text[open_pos : m.start()]))
            open_char = None
        # else: a different fence character nested inside an open fence is
        # literal content under CommonMark -- not a marker, skip it.
    if open_char is not None:
        raise MalformedFencesError(
            f"unclosed code fence (opened with {open_char * 3!r}) at byte offset {open_pos}"
        )
    return blocks


def _join_line_continuations(code_block: str) -> str:
    """Collapse shell backslash-newline continuations into one logical line.

    `pulumi stack export --stack <s> \\\n  --show-secrets ...` is one shell
    command split across two source lines. A check that only ever looks
    within a single `\n`-delimited line reads that as two harmless halves;
    joining first is what lets the anti-pattern regex below see it whole.
    """
    return re.sub(r"\\\n[ \t]*", " ", code_block)


_ANTI_PATTERN = re.compile(
    r"pulumi\s+stack\s+export\s+[^\n`]*--show-secrets", re.IGNORECASE
)


def passphrase_verification_sections() -> list[tuple[pathlib.Path, str, str]]:
    """Find code blocks in sections where passphrases are being verified.

    Returns tuples of (runbook_path, code_block, context) for every fenced
    code block whose surrounding 2000-char window mentions verify/decrypt/
    proof/passphrase-check -- wide enough to reach a distant section header.
    A malformed runbook (code_fences() raising) propagates rather than being
    swallowed: a scan that silently skips a broken document is the same
    failure class this file exists to prevent.
    """
    found = []
    for runbook in runbooks():
        text = runbook.read_text(encoding="utf-8")
        for start, end, code_block in code_fences(text):
            start_pos = max(0, start - 2000)
            context = text[start_pos : end + 100]
            if any(word in context.lower() for word in ["decrypt", "verify", "proof", "passphrase check"]):
                found.append((runbook, code_block, context))
    return found


class CodeFencesParserTests(unittest.TestCase):
    """Direct coverage of code_fences() -- the load-bearing parser.

    Exercised end-to-end through real runbooks elsewhere in this file, but
    each shape that has previously defeated it (indentation, an unclosed
    fence, an odd marker count, a language tag, a tilde fence) gets its own
    minimal, deliberately malformed input here.
    """

    def test_plain_fence(self):
        text = "prose\n```\ncode line\n```\nmore prose\n"
        blocks = code_fences(text)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0][2], "code line\n")

    def test_language_tagged_fence(self):
        text = "```bash\necho hi\n```\n"
        blocks = code_fences(text)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0][2], "echo hi\n")

    def test_indented_fence_inside_list_item(self):
        """A 3-space-indented fence (the shape a markdown list item produces)."""
        text = "1. Step one:\n   ```bash\n   echo hi\n   ```\n2. Step two.\n"
        blocks = code_fences(text)
        self.assertEqual(
            len(blocks), 1, "an indented fence must still be recognised, not silently skipped"
        )
        self.assertIn("echo hi", blocks[0][2])

    def test_tilde_fence(self):
        text = "~~~\necho hi\n~~~\n"
        blocks = code_fences(text)
        self.assertEqual(len(blocks), 1)
        self.assertIn("echo hi", blocks[0][2])

    def test_unclosed_fence_raises(self):
        text = "prose\n```bash\necho hi\n"
        with self.assertRaises(MalformedFencesError):
            code_fences(text)

    def test_odd_marker_count_raises_not_truncates(self):
        """Three markers (open, close, open-again-unclosed) must raise, not drop the third."""
        text = "```\nblock one\n```\n```\nblock two -- never closed\n"
        with self.assertRaises(MalformedFencesError):
            code_fences(text)

    def test_different_fence_characters_do_not_cross_pair(self):
        """A ~~~ line inside an open ``` block is literal content, not a closer."""
        text = "```bash\necho '~~~ this is not a fence'\n```\n"
        blocks = code_fences(text)
        self.assertEqual(len(blocks), 1)
        self.assertIn("~~~", blocks[0][2])


class PassphraseProbePatternTests(unittest.TestCase):
    def test_runbooks_found(self):
        """Verify we actually found runbooks to test."""
        found = runbooks()
        self.assertGreater(len(found), 0, "No RUNBOOK-*.md files found")

    def test_verification_sections_found(self):
        """The scan must find a non-zero number of verification sections.

        A purely editorial rewording that drops the trigger words (decrypt/
        verify/proof/passphrase check) near a code block -- or a
        code_fences() regression that silently returns nothing -- would
        otherwise leave test_no_stack_export_show_secrets_used_as_passphrase_proof
        passing with zero subTests: green because it checked nothing, the
        same failure class as the bug this file exists to prevent.
        """
        sections = passphrase_verification_sections()
        self.assertGreater(
            len(sections),
            0,
            f"Found 0 passphrase-verification sections across {len(runbooks())} runbooks "
            "-- either the keyword list no longer matches any runbook prose, or the "
            "fence/section scan is broken. A guard that scans zero sections passes vacuously.",
        )

    def test_no_stack_export_show_secrets_used_as_passphrase_proof(self):
        """Passphrase verification never uses `stack export --show-secrets` as a proof.

        The defect is the command being used to verify decryption at all --
        its exit code is 0 regardless of whether the passphrase is right, so
        no shell punctuation around it changes that. Earlier versions of this
        test required a trailing `&&`, which a bare sequential command, a
        `;`, a `||`, an `if`/`then` gate, or a backslash-continued `&&` on the
        next source line all defeat -- none of those is checked here; the
        command's mere presence in a verification-context code block is
        the finding.
        """
        sections = passphrase_verification_sections()
        self.assertGreater(len(sections), 0, "no verification sections to check (see test_verification_sections_found)")
        for runbook, code_block, context in sections:
            with self.subTest(runbook=runbook.name):
                joined = _join_line_continuations(code_block)
                bad_pattern = _ANTI_PATTERN.search(joined)

                self.assertIsNone(
                    bad_pattern,
                    f"{runbook.name}: found `pulumi stack export ... --show-secrets` used inside "
                    f"a passphrase-verification section. This exits 0 under a wrong passphrase "
                    f"(Pulumi v3.255.0, INC-4) and proves nothing, however the surrounding shell "
                    f"is punctuated. Use `pulumi preview` instead, which fails closed on an "
                    f"incorrect passphrase. See branchLeft/workspace#208."
                )


if __name__ == "__main__":
    unittest.main()
