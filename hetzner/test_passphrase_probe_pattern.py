#!/usr/bin/env python3
"""Guard against `pulumi stack export --show-secrets` being used to prove decryption.

`pulumi stack export --show-secrets` exits 0 even under a wrong passphrase (observed
Pulumi v3.255.0, INC-4 in ghost-platform-docs/INCIDENTS.md), so any verification built
on it passes vacuously. `pulumi preview` fails closed on a wrong passphrase with
"error: getting stack configuration: get stack secrets manager: incorrect passphrase".

DESIGN, after three rounds of a shape-matching heuristic each got bypassed by
a new rewording (workspace#208): this file does not try to recognise "a
passphrase-verification section" or "a command shaped like the anti-pattern".
Both are free prose, and free prose is infinitely reword-able around any
fixed set of trigger words or regex shapes. Instead it is deny-by-default:
every literal appearance of `--show-secrets` in any runbook must be on the
explicit ALLOWLIST below, with a justification. There is no way to use the
flag while avoiding its own name, so a plain substring scan cannot be
defeated by paraphrase, a new shell operator, or splitting a command across
lines -- see the "Known limit" note on ALLOWLIST for the one thing it
genuinely cannot catch.

See branchLeft/workspace#208 for the incident and the fix's history.
"""

import pathlib
import re
import unittest

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


# ALLOWLIST keys every current, reviewed appearance of the literal flag by
# (path relative to the repo root, exact stripped line text) -> justification.
# Keying on line text rather than line number means an unrelated edit
# elsewhere in the file can never silently "unlist" or "relist" an entry by
# shifting its line number; keying per-occurrence rather than per-file means
# allow-listing one mention never allow-lists the whole file for a later,
# different, live use of the flag.
#
# Seeded from the whole corpus as it exists today: every one of the eight
# occurrences below is prose warning against the anti-pattern (a `#` shell
# comment or backticked inline code inside surrounding prose), never a line a
# shell would actually execute. There are currently zero legitimate live
# uses of the flag in any runbook -- the two real archive/backup steps in
# RUNBOOK-existing-stack-migration.md use plain `pulumi stack export`, no
# `--show-secrets` -- so this list starts as close to empty as the real
# corpus allows, which is the point of deny-by-default: nothing is on it
# by convenience, only by review.
#
# Known limit (see the module docstring and the PR body): this scan finds
# the literal string `--show-secrets`. It cannot find the flag built from
# fragments a shell would still assemble at runtime -- string concatenation,
# or a variable holding the flag itself (`FLAG=--show-secrets; ... $FLAG`)
# with the flag's own text moved to a *different* line that itself contains
# no dashes at all. That is a deliberate non-goal, not an oversight: a
# runbook is prose meant for a human to read and copy by hand, and
# constructing a flag from fragments is not a realistic accident for that
# reader to make -- it would have to be deliberately obfuscated, which is a
# different threat model than the one workspace#208 is about.
ALLOWLIST: dict[tuple[str, str], str] = {
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "#    --show-secrets` does not (it exits 0 regardless, observed v3.255.0 --",
    ): "prose explaining why the anti-pattern is unsafe, wrapped across a shell comment",
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "# --show-secrets` does not)",
    ): "prose explaining why the anti-pattern is unsafe, wrapped across a shell comment",
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "# `pulumi preview`, not `stack export --show-secrets`: export exits 0 under a",
    ): "prose explaining why the anti-pattern is unsafe, in a shell comment",
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "around `stack export --show-secrets` on the theory that emitting plaintext",
    ): "prose explaining why the anti-pattern is unsafe",
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "# export --show-secrets` exits 0 under",
    ): "prose explaining why the anti-pattern is unsafe, in a shell comment",
    (
        "hetzner/RUNBOOK-existing-stack-migration.md",
        "`pulumi stack export --show-secrets` is deliberately not used — for two",
    ): "prose explaining why the anti-pattern is unsafe",
    (
        "hetzner/RUNBOOK-new-stack.md",
        "`pulumi stack export --show-secrets` is **not** a decrypt proof — observed on",
    ): "prose explaining why the anti-pattern is unsafe",
    (
        "hetzner/RUNBOOK-new-stack.md",
        "equally conclusive. Do not use `stack export --show-secrets` for either",
    ): "prose explaining why the anti-pattern is unsafe",
}


def show_secrets_occurrences() -> list[tuple[pathlib.Path, int, str]]:
    """Every line in every runbook containing the literal `--show-secrets` flag.

    Deliberately not scoped to code fences, a preceding `pulumi stack
    export`, or nearby keywords: the anti-pattern is exactly this flag being
    used to prove a stack decrypts, and catching every way of writing that
    needs to key on the one thing every such command has in common -- the
    flag's own name appearing somewhere in the source a human would type or
    paste. A per-line scan also gives a useful failure message (file, line
    number, exact text) without needing any surrounding-context machinery.
    """
    found = []
    for runbook in runbooks():
        text = runbook.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "--show-secrets" in line:
                found.append((runbook, lineno, line.strip()))
    return found


class MalformedFencesError(ValueError):
    """Raised when a document's code fences don't close in pairs.

    A malformed document must fail the scan loudly, never scan a truncated
    subset of it and report OK. Not used by the flag scan above (which does
    not need to know about fences at all) -- kept, fixed and independently
    tested because it is a correct, load-bearing parser worth having right,
    and a future check may still want it for a richer error message.
    """


_FENCE_MARKER = re.compile(r"^[ \t]*(`{3,}|~{3,})[^\n]*(?:\n|\Z)", re.MULTILINE)


def code_fences(text: str) -> list[tuple[int, int, str]]:
    """Pair up markdown code fences by character-matched open/close state.

    Recognises both ``` and ~~~ fences, at any indentation -- list items and
    blockquotes routinely indent a fence, and a regex anchored to column 0
    misses every one of those (proven against a real indented block in
    mail/RUNBOOK-mail-history-migration.md). A same-position pairing
    (1st-2nd marker, 3rd-4th, ...) also silently drops the wrong block
    whenever a document's marker count is odd or a fence stays open to EOF;
    tracking open/close state instead makes both cases raise
    MalformedFencesError rather than truncate. The closing-marker line's
    trailing `\\n` is optional (`(?:\\n|\\Z)`) so a document whose last byte
    is the closing fence, with no final newline, still parses as valid --
    that shape is a normal file, not a malformed one, and treating it as
    unclosed was a false positive with no bearing on whether the fence
    actually closed. A marker of a *different* fence character while one is
    already open is not a fence under CommonMark -- it's literal content
    inside the open block -- so it is skipped rather than mistaken for a
    stray opener or closer.
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


class CodeFencesParserTests(unittest.TestCase):
    """Direct coverage of code_fences() -- the load-bearing parser.

    Not used by the primary flag scan (see the module docstring), but kept
    correct and independently tested rather than dropped: each shape that has
    previously defeated a fence parser here (indentation, an unclosed fence,
    an odd marker count, a language tag, a tilde fence, no trailing newline
    at EOF) gets its own minimal, deliberately constructed input.
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

    def test_closing_fence_at_eof_with_no_trailing_newline(self):
        """A document ending exactly at the closing fence's backticks, no final \\n.

        A correctly-closed fence at the very end of a file is a valid
        document -- the requirement that the closing marker line end with a
        newline was a parser bug, not a real malformation, and it would
        raise on an ordinary web-UI edit that happens to save without a
        trailing newline.
        """
        text = "prose\n```bash\necho hi\n```"
        blocks = code_fences(text)
        self.assertEqual(len(blocks), 1, "a fence closed at EOF with no trailing newline must still parse")
        self.assertEqual(blocks[0][2], "echo hi\n")


class ShowSecretsAllowlistTests(unittest.TestCase):
    def test_runbooks_found(self):
        """Sanity check: the flag scan must have files to scan in the first place."""
        found = runbooks()
        self.assertGreater(len(found), 0, "No RUNBOOK-*.md files found")

    def test_show_secrets_is_allowlisted_everywhere_it_appears(self):
        """Deny-by-default: every `--show-secrets` occurrence must be on ALLOWLIST.

        Guards the guard itself against scanning nothing: `runbooks()`
        returning zero files would otherwise make this pass by finding zero
        unlisted occurrences among zero files scanned, which is the same
        vacuous-pass failure this whole file exists to prevent -- so a
        non-zero runbook count is asserted here directly, not left to
        test_runbooks_found alone.
        """
        scanned = runbooks()
        self.assertGreater(
            len(scanned),
            0,
            "runbooks() returned 0 files -- the --show-secrets scan below would "
            "silently check nothing and pass vacuously",
        )

        unlisted = []
        for runbook, lineno, line in show_secrets_occurrences():
            relpath = str(runbook.relative_to(REPO_ROOT))
            if (relpath, line) not in ALLOWLIST:
                unlisted.append(f"{relpath}:{lineno}: {line!r}")

        self.assertEqual(
            unlisted,
            [],
            "Found `--show-secrets` not on hetzner/test_passphrase_probe_pattern.py's "
            "ALLOWLIST. If this is prose warning against the anti-pattern, add a "
            "(relative-path, exact-stripped-line-text) entry with a justification. If "
            "it is a live command using the flag to verify decryption, it is the "
            "anti-pattern workspace#208 is about -- fix the runbook to use `pulumi "
            "preview` instead, which fails closed on an incorrect passphrase:\n"
            + "\n".join(unlisted),
        )


if __name__ == "__main__":
    unittest.main()
