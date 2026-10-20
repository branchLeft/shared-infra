#!/usr/bin/env python3
"""Decide whether an older waiting run of ci.yml is superseded by this push.

Run by the cancel step of each plan job, after Checkout, with the run's jobs
listing on stdin. Prints `cancel: <reason>` or `keep: <reason>`; exits 1 on an
unreadable listing. The rules are in decide().
"""

import argparse
import json
import sys

APPLY_PREFIX = "Apply ("

# Apply job name prefix -> the changes job output that says this push planned
# that stack. Each name is the job's `name:` in ci.yml.
STACK_OF_APPLY = (
    ("Apply (mail,", "mail"),
    ("Apply (hetzner network,", "hetzner_network"),
    ("Apply (hetzner estate,", "hetzner_estate"),
)


def stack_of(job_name):
    for prefix, stack in STACK_OF_APPLY:
        if job_name.startswith(prefix):
            return stack
    return None


def decide(jobs, planned):
    """Return (verdict, reason) for one older run's jobs.

    `planned` maps a stack to True when this push planned it (the changes
    job's path filter). Keeps a run with no apply, a job in progress, an
    incomplete apply on an unplanned stack, or no waiting apply; cancels
    otherwise. A completed apply, whatever its conclusion, never keeps a run.
    """
    applies = [j for j in jobs if j.get("name", "").startswith(APPLY_PREFIX)]
    if not applies:
        return "keep", "the run has no apply job"
    running = [j.get("name", "") for j in jobs if j.get("status") == "in_progress"]
    if running:
        return "keep", "job %r is in progress" % running[0]
    unplanned = [
        j.get("name", "")
        for j in applies
        if j.get("status") != "completed"
        and not planned.get(stack_of(j.get("name", "")), False)
    ]
    if unplanned:
        return "keep", (
            "apply %r is not complete and this push did not plan its stack"
            % unplanned[0]
        )
    waiting = [j.get("name", "") for j in applies if j.get("status") == "waiting"]
    if not waiting:
        return "keep", "no apply is waiting for approval"
    return "cancel", (
        "apply %r is waiting for approval on a stack this push planned"
        % waiting[0]
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--mail", required=True, choices=("true", "false"))
    parser.add_argument("--network", required=True, choices=("true", "false"))
    parser.add_argument("--estate", required=True, choices=("true", "false"))
    args = parser.parse_args(argv)
    try:
        jobs = json.load(sys.stdin)["jobs"]
        if not isinstance(jobs, list):
            raise TypeError("jobs is not a list")
    except (ValueError, KeyError, TypeError):
        return 1
    planned = {
        "mail": args.mail == "true",
        "hetzner_network": args.network == "true",
        "hetzner_estate": args.estate == "true",
    }
    verdict, reason = decide(jobs, planned)
    print("%s: %s" % (verdict, reason))
    return 0


if __name__ == "__main__":
    sys.exit(main())
