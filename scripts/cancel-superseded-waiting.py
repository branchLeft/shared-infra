#!/usr/bin/env python3
"""Decide whether one older run of ci.yml is superseded by this push.

Called by the "Cancel older runs that are still waiting for approval" step in
each plan job of ci.yml, once per older push run still waiting. The step pipes
that run's `jobs` listing (from `gh api`) on stdin and passes which stacks this
push planned. "Planned" is the changes job's path filter for the stack, not the
plan's has_changes output: a stack whose plan ran still counts as planned when
its apply is then skipped as a no-op.

Prints one line, `cancel: <reason>` or `keep: <reason>`, and exits 0. A listing
that cannot be read exits 1 and prints nothing, so the step keeps the run.

The rule, in order:
  1. A run with no apply job is kept.
  2. A run with any job in progress is kept.
  3. A run with an apply that is not complete on a stack this push did not
     plan is kept. A completed apply, whatever its conclusion, does not count.
  4. A run with no apply waiting for approval is kept.
  5. Otherwise the run is cancelled: its waiting apply is on a stack this push
     planned, and the newer run supersedes it.
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

    `planned` maps a stack name to True when this push planned that stack.
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
