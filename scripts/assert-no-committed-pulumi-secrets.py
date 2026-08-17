#!/usr/bin/env python3
"""Refuse a `Pulumi.<stack>.yaml` that carries an `encryptionsalt` or a
`secure:` value.

An `encryptionsalt` is an offline verifier for the stack passphrase: whoever
holds it can test candidate passphrases at their own rate, with nothing in the
loop to notice and no service to rate-limit them. A `secure:` value is the
wrapped ciphertext itself. Neither belongs in a repository anyone can clone.

This has to be a mechanical check rather than a rule people follow, because
neither is added by hand. Pulumi writes both back into the file itself, during
an ordinary `pulumi config set` or `pulumi stack init`, and the diff then looks
like exactly what the command was asked to do.

Usage:

    assert-no-committed-pulumi-secrets.py PATH [PATH...]   # scan named files
    assert-no-committed-pulumi-secrets.py --scan-tree DIR  # find them itself
    assert-no-committed-pulumi-secrets.py --self-test

`--scan-tree` exists so CI does not inherit pre-commit's `files:` pattern as
its only definition of which files matter. A hook whose pattern silently stops
matching is a hook that passes everything, and the pattern lives in a different
file from this one.

**What it does not see.** It reads lines, not YAML: a real parser is not
available here, the same stdlib-only constraint every script in this repo works
under. A key written inside an inline flow mapping (`config: {secure: x}`) is
therefore missed. Pulumi has never emitted that shape -- it writes block style
throughout -- so the gap is between what Pulumi writes and what YAML permits,
not a case anything here produces.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import pathlib
import re
import sys
import tempfile

# Anchored at the start of a mapping entry, optionally as a list item, so the
# key has to *be* `encryptionsalt` or `secure` rather than merely end with it.
# An unanchored `.*secure:` matches `insecure:` -- a real key name, and one
# whose value is not a secret -- and a guard that cries wolf is a guard people
# start passing --no-verify to.
FORBIDDEN_KEY = re.compile(r"^\s*(?:-\s+)?(encryptionsalt|secure)\s*:")

# A stack config, not a project file: `Pulumi.yaml` declares the project and
# never holds either key, while `Pulumi.<stack>.yaml` holds both.
STACK_CONFIG = re.compile(r"^Pulumi\.[^/]+\.yaml$")

SKIP_DIRS = {".git", ".worktrees", "node_modules", "graphify-out", "dist", "vendor"}


def is_commented(line: str) -> bool:
    """Whether the line is entirely a comment.

    Only a leading `#` counts. A `#` further along may be inside a value, and
    treating it as a comment marker would let `encryptionsalt: v1:x#y` through.
    """
    return line.lstrip().startswith("#")


def offending_lines(text: str) -> list[tuple[int, str]]:
    """Every (1-based line number, line) that commits a secret."""
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        if is_commented(line):
            continue
        if FORBIDDEN_KEY.search(line):
            found.append((number, line.rstrip()))
    return found


def is_stack_config(path: pathlib.Path) -> bool:
    return bool(STACK_CONFIG.match(path.name))


def find_stack_configs(root: pathlib.Path) -> list[pathlib.Path]:
    found = []
    for path in sorted(root.rglob("Pulumi.*.yaml")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if is_stack_config(path):
            found.append(path)
    return found


def check(paths: list[pathlib.Path]) -> int:
    failed = False
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            # Not a pass. A file this cannot read is a file it cannot clear,
            # and reporting clean for it is the failure mode that matters.
            print(f"::error::cannot read {path}: {exc}", file=sys.stderr)
            failed = True
            continue
        for number, line in offending_lines(text):
            print(f"::error file={path},line={number}::{line}", file=sys.stderr)
            failed = True
    if failed:
        print(
            "\nRemove these before committing. The salt is supplied at deploy from a "
            "repository secret, and an operator supplies it by hand for the stacks CI "
            "does not apply -- see CLAUDE.md.",
            file=sys.stderr,
        )
        return 1
    return 0


# --------------------------------------------------------------------------
# Self-test
#
# Hermetic: fixtures in this file and a temp directory, nothing about the real
# repository. It must pass in every state of the tree, so it can run on every
# edit to this script.
# --------------------------------------------------------------------------

SALTED = "config:\n  gcp:project: p\nencryptionsalt: v1:AAA=:v1:BBB:CCC==\n"
SECURE_VALUE = "config:\n  proj:token:\n    secure: AAAABBBBCCCC\n"
INDENTED_SALT = "config:\n  a: b\n  encryptionsalt: v1:AAA=\n"
LIST_SECURE = "config:\n  proj:list:\n    - secure: AAAA\n"
COMMENTED = (
    "# `encryptionsalt` is deliberately absent from this committed file.\n"
    "#     printf '\\nencryptionsalt: %s\\n' \"$SALT\" >> Pulumi.production.yaml\n"
    "#    secure: this is prose about the key, not the key\n"
    "config:\n  gcp:project: p\n"
)
INSECURE_KEY = "config:\n  proj:insecure: true\n  proj:secure_boot: false\n  proj:not-secure: x\n"
CLEAN = "config:\n  gcp:project: branchleft-prod\n  proj:region: europe-west1\n"
SALT_WITH_HASH = "encryptionsalt: v1:AAA=#notacomment\n"


def _quiet_check(paths: list[pathlib.Path]) -> tuple[int, str]:
    """`check` with its report captured, so a fixture's own error output does
    not read as a self-test failure."""
    buffer = io.StringIO()
    with contextlib.redirect_stderr(buffer):
        code = check(paths)
    return code, buffer.getvalue()


def _self_test() -> int:
    cases = [
        ("a committed salt is caught", SALTED, [3]),
        ("a secure: value is caught", SECURE_VALUE, [3]),
        ("an indented salt is caught", INDENTED_SALT, [3]),
        ("a secure: value as a list item is caught", LIST_SECURE, [3]),
        ("commented-out mentions are ignored", COMMENTED, []),
        ("insecure:, secure_boot: and not-secure: are not flagged", INSECURE_KEY, []),
        ("a clean stack config passes", CLEAN, []),
        ("a # inside a value does not make the line a comment", SALT_WITH_HASH, [1]),
    ]

    failures = 0
    for label, text, expected in cases:
        actual = [number for number, _ in offending_lines(text)]
        if actual == expected:
            print(f"PASS: {label} -> lines {actual} (expected {expected})")
        else:
            print(f"FAIL: {label} -> lines {actual} (expected {expected})", file=sys.stderr)
            failures += 1

    name_cases = [
        ("Pulumi.production.yaml", True),
        ("Pulumi.blog.yaml", True),
        ("Pulumi.yaml", False),
        ("Pulumi.production.yaml.bak", False),
        ("something.yaml", False),
    ]
    for name, expected in name_cases:
        actual = is_stack_config(pathlib.Path("a/b") / name)
        if actual == expected:
            print(f"PASS: {name} is{'' if expected else ' not'} a stack config")
        else:
            print(f"FAIL: {name} -> {actual} (expected {expected})", file=sys.stderr)
            failures += 1

    with tempfile.TemporaryDirectory() as raw:
        root = pathlib.Path(raw)
        (root / "Pulumi.production.yaml").write_text(CLEAN, encoding="utf-8")
        (root / "mail").mkdir()
        (root / "mail" / "Pulumi.production.yaml").write_text(SALTED, encoding="utf-8")
        (root / "Pulumi.yaml").write_text("name: x\nruntime: nodejs\n", encoding="utf-8")
        skipped = root / "node_modules" / "pkg"
        skipped.mkdir(parents=True)
        (skipped / "Pulumi.fixture.yaml").write_text(SALTED, encoding="utf-8")

        found = {p.relative_to(root).as_posix() for p in find_stack_configs(root)}
        expected_found = {"Pulumi.production.yaml", "mail/Pulumi.production.yaml"}
        if found == expected_found:
            print(f"PASS: --scan-tree finds {sorted(found)} and skips Pulumi.yaml and node_modules")
        else:
            print(f"FAIL: --scan-tree found {sorted(found)} (expected {sorted(expected_found)})", file=sys.stderr)
            failures += 1

        code, report = _quiet_check(find_stack_configs(root))
        if code == 1 and "mail/Pulumi.production.yaml" in report.replace("\\", "/"):
            print("PASS: a tree containing a salted stack config exits 1, naming the file")
        else:
            print(f"FAIL: salted tree -> exit {code}, report {report!r}", file=sys.stderr)
            failures += 1

        (root / "mail" / "Pulumi.production.yaml").write_text(COMMENTED, encoding="utf-8")
        code, _ = _quiet_check(find_stack_configs(root))
        if code == 0:
            print("PASS: a clean tree exits 0")
        else:
            print("FAIL: a clean tree did not exit 0", file=sys.stderr)
            failures += 1

        code, _ = _quiet_check([root / "Pulumi.missing.yaml"])
        if code == 1:
            print("PASS: an unreadable path fails rather than reporting clean")
        else:
            print("FAIL: an unreadable path did not fail", file=sys.stderr)
            failures += 1

    if failures:
        print(f"\n{failures} self-test failure(s)", file=sys.stderr)
        return 1
    print("\nOK: assert-no-committed-pulumi-secrets.py self-test passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", help="stack config files to check")
    parser.add_argument("--scan-tree", metavar="DIR", help="find every Pulumi.<stack>.yaml under DIR")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    targets = [pathlib.Path(p) for p in args.paths]
    if args.scan_tree:
        targets += find_stack_configs(pathlib.Path(args.scan_tree))
    if not targets:
        parser.error("pass at least one path, or --scan-tree DIR, or --self-test")
    return check(targets)


if __name__ == "__main__":
    sys.exit(main())
