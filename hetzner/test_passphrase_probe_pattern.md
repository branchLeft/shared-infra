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
accepted occurrence on its exact line text _and_ its occurrence count
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

## ALLOWLIST

```text
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
```

## SCAN SCOPE

Why the scan is built this way, moved out of the .py docstrings and comments.

The scan is not scoped to code fences, a preceding `pulumi stack export`, or nearby keywords. The anti-pattern is exactly this flag being used to prove a stack decrypts, and catching every way of writing that needs to key on the one thing every such command has in common: the flag's own name appearing somewhere in the source a human would type, paste, or read as an instruction. A per-line scan also gives a useful failure message (file, line number, exact text) with no surrounding-context machinery needed to produce it.

Runbook discovery is non-recursive per directory, matching this repo's own convention: every RUNBOOK lives directly in one of three places, never nested further. All three are scanned, not just hetzner/ and mail/, because RUNBOOK-edge-state-move.md lives at the repo root, and a scan that skips it never sees it.

This module's own path is excluded from the tracked-file scan. A guard whose whole job is discussing the flag necessarily mentions it dozens of times, in docstrings, comments and the ALLOWLIST literal itself. None of that is a runbook or script that could teach a reader the anti-pattern is safe, which is the harm this scan exists to catch. Excluding the file by path, rather than trying to allowlist its own literals, keeps the ALLOWLIST meaningful: every entry should describe a real occurrence outside this file, not this file's own vocabulary.

Tracked files come from `git ls-files` rather than a hand-maintained directory list. A fixed glob can leave a whole class of tracked files unscanned: scripts and workflow files outside a runbook-only glob, for instance, while the literal flag still appears in them. This list grows automatically with the tracked tree instead of needing a second edit whenever a new script or workflow is added.

The test has two checks. An occurrence is wrong if it is unlisted entirely, or if it is listed with the wrong count: the file now has more, or fewer, copies of that exact line than the entry says. The test also guards against scanning nothing. If scanned_files() returned zero files, the check would pass by finding zero problems among zero files, the same vacuous pass this file exists to prevent. So a non-zero scanned-file count is asserted directly.
