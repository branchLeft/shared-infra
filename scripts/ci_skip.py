#!/usr/bin/env python3
"""Decide, from the changed paths, whether one ci.yml job's steps need to run.

Standard library only: the composite action `.github/actions/ci-skip` runs it
right after Checkout, before any job has set up a Python of its own. The
interface, the rules and why every error means "run" are written up in
ci_skip.md.

    EVENT_NAME=pull_request BASE_SHA=<sha> HEAD_SHA=<sha> \
        python3 scripts/ci_skip.py --unit monitoring-config-validate

prints two lines, `run=true|false` and `reason=<one line>`, ready to append to
$GITHUB_OUTPUT. This file is the one home of the path map: trace_reads.py and
the tests import it, none of them keep a copy.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

# The jobs that may skip their steps, each with every repository path that job
# reads (a prefix ending in "/" is a directory, anything else one file). A job
# reads these and nothing else; test_ci_skip.py checks the paths its steps
# name, and trace_reads.py checks the Python it runs, so the map cannot drift
# quietly.
UNITS: dict[str, tuple[str, ...]] = {
    "mail-typecheck": ("mail/",),
    "mail-provision-checks": ("mail/",),
    "edge-config-validate": ("hetzner/edge/",),
    "monitoring-config-validate": ("hetzner/monitoring/", "hetzner/RUNBOOK-monitoring.md"),
    "nextcloud1-config-validate": ("hetzner/nextcloud1/",),
    "shim-image-starts": ("mail/provision/",),
    "control-plane-config-validate": (
        "hetzner/control-plane/",
        "hetzner/provision/stack_keys_check.py",
        "hetzner/provision/fixtures/",
    ),
}

# The jobs that never skip, because they read the whole tree or most of it
# scripts-tests and pulumi-inventory-audit were
# ruled by the owner; the other four were found by tracing what their tests
# open. Changing this set is a reviewed edit to test_ci_skip.py as well.
ALWAYS_RUN: frozenset[str] = frozenset(
    {
        "scripts-tests",
        "pulumi-inventory-audit",
        "typecheck",
        "hetzner-typecheck",
        "hetzner-host-typecheck",
        "hetzner-provision-checks",
    }
)

# A changed path outside every zone is a file or directory this map has never
# heard of, so every job runs.
ZONES: tuple[str, ...] = (
    "ansible/",
    "hetzner/",
    "hetzner-host/",
    "mail/",
    "scripts/",
    ".github/",
    ".claude/",
)

# A change here alters how every skippable job behaves, so every one runs.
UNIVERSAL: tuple[str, ...] = (
    ".github/workflows/ci.yml",
    ".github/actions/ci-skip/",
    "scripts/ci_skip.py",
    "scripts/trace_reads.py",
)

EVENTS = ("pull_request", "merge_group")
SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
GIT_TIMEOUT_SECONDS = 120


def under(path: str, prefix: str) -> bool:
    """True when `path` is the file `prefix` names, or inside the directory it names."""
    if prefix.endswith("/"):
        return path.startswith(prefix)
    return path == prefix


def in_any(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(under(path, prefix) for prefix in prefixes)


def reads_of(unit: str) -> tuple[str, ...]:
    return UNITS[unit]


def decide(unit: str, event: str, changed: list[str] | None) -> tuple[bool, str]:
    """(run, reason). Every doubt is `run`: only a clean, fully mapped diff skips."""
    if event not in EVENTS:
        return True, "event is not a pull request or merge queue entry, so every job runs"
    if unit in ALWAYS_RUN:
        return True, "this job reads the whole tree and never skips"
    if unit not in UNITS:
        return True, "this job is not in the path map"
    if changed is None:
        return True, "the changed paths could not be read"
    if not changed:
        return True, "the diff is empty"
    for path in changed:
        if not isinstance(path, str) or not path or not in_any(path, ZONES):
            return True, "a changed path is outside every mapped zone"
    for path in changed:
        if in_any(path, UNIVERSAL):
            return True, "the CI skip machinery itself changed"
        if in_any(path, reads_of(unit)):
            return True, "a changed path is one this job reads"
    return False, "no changed path is one this job reads"


def git(args: list[str], runner=subprocess.run, cwd: str | None = None) -> subprocess.CompletedProcess:
    return runner(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )


def has_commit(sha: str, runner=subprocess.run, cwd: str | None = None) -> bool:
    return git(["cat-file", "-e", f"{sha}^{{commit}}"], runner, cwd).returncode == 0


def changed_files(
    base: str | None, head: str | None, runner=subprocess.run, cwd: str | None = None
) -> list[str] | None:
    """The paths that differ between two commits, or None when they cannot be read.

    The checkout is depth 1, so the base commit is usually absent: one
    anonymous depth-1 fetch of that sha fetches it, with no credential. The
    diff is two-point (`--no-renames`, so a moved file names both ends).
    """
    try:
        if not base or not head or not SHA.match(base) or not SHA.match(head):
            return None
        if not has_commit(head, runner, cwd):
            return None
        if not has_commit(base, runner, cwd):
            fetched = git(["fetch", "--no-tags", "--depth=1", "--quiet", "origin", base], runner, cwd)
            if fetched.returncode != 0 or not has_commit(base, runner, cwd):
                return None
        diff = git(["diff", "--name-only", "-z", "--no-renames", base, head], runner, cwd)
        if diff.returncode != 0:
            return None
        return [p for p in diff.stdout.decode("utf-8", "surrogateescape").split("\0") if p]
    except Exception:  # noqa: BLE001 - every failure is "could not read", which runs the job
        return None


def one_line(text: str) -> str:
    """A reason is printed into $GITHUB_OUTPUT: it must stay one plain line."""
    return re.sub(r"[^A-Za-z0-9 ,.;:()/_-]", "?", text)[:200]


def main(argv: list[str] | None = None, environ=None, runner=subprocess.run) -> int:
    environ = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--unit", required=True, help="the ci.yml job key")
    args = parser.parse_args(argv)
    try:
        event = environ.get("EVENT_NAME", "")
        changed = None
        if event in EVENTS and args.unit in UNITS:
            changed = changed_files(environ.get("BASE_SHA"), environ.get("HEAD_SHA"), runner)
        run, reason = decide(args.unit, event, changed)
    except Exception as error:  # noqa: BLE001 - a crash must widen the run, never skip it
        run, reason = True, f"the decision failed: {type(error).__name__}"
    print(f"run={'true' if run else 'false'}")
    print(f"reason={one_line(reason)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
