#!/usr/bin/env python3
"""Cancel older Ansible deliveries that wait for approval when a newer push lands.

The apply of ansible-delivery.yml sits in a concurrency group that never cancels a
run in progress, so an older run whose apply waits for approval holds the group and
the newer run's apply queues behind it, silently, until someone approves or cancels
the old one. Run by ansible-supersede.yml on every push to main, this cancels each
older run of ansible-delivery.yml that is superseded by the pushed commit, and prints
the run it cancelled, or the reason it kept a run, so the holder is always named.

A run is cancelled only when all of these hold (decide() has the rule for the jobs):
- it is a push run on main of ansible-delivery.yml, status `waiting`;
- its commit is a strict ancestor of the pushed commit (the compare reads `ahead`):
  the apply is declarative over the whole commit, so the newer delivery applies
  everything the older one would have;
- no job of it is in progress, and its apply job is the one waiting. An apply that
  has started is never cancelled.

An unreadable answer keeps the run and fails the step: the message names the run.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

WORKFLOW = "ansible-delivery.yml"
APPLY_NAME = "Apply the planned commit (after approval)"

Jobs = List[Dict[str, Any]]
Gh = Callable[[Sequence[str]], Any]


def decide(jobs: Jobs, relation: str) -> Tuple[str, str]:
    """Return (verdict, reason) for one older run: `cancel` or `keep`.

    `relation` is the compare status of the older commit against the pushed one.
    """
    if relation != "ahead":
        return "keep", "its commit is not an ancestor of this push (compare says %r)" % relation
    running = [str(j.get("name", "")) for j in jobs if j.get("status") == "in_progress"]
    if running:
        return "keep", "job %r is in progress" % running[0]
    applies = [j for j in jobs if str(j.get("name", "")).endswith(APPLY_NAME)]
    if len(applies) != 1:
        return "keep", "it has %d apply jobs named %r, not one" % (len(applies), APPLY_NAME)
    status = applies[0].get("status")
    if status != "waiting":
        return "keep", "its apply is %r, not waiting for approval" % status
    return "cancel", "its apply waits for approval and this push is a newer commit"


def gh_api(args: Sequence[str]) -> Any:
    """`gh api` with the caller's GH_TOKEN, parsed as JSON; an empty answer is None."""
    done = subprocess.run(
        ["gh", "api", *args], check=True, capture_output=True, text=True
    )
    return json.loads(done.stdout) if done.stdout.strip() else None


def waiting_runs(gh: Gh, repo: str) -> List[Dict[str, Any]]:
    blob = gh(
        [
            "repos/%s/actions/workflows/%s/runs" % (repo, WORKFLOW),
            "-X", "GET",
            "-f", "branch=main",
            "-f", "event=push",
            "-f", "status=waiting",
            "-f", "per_page=100",
        ]
    )
    runs = blob.get("workflow_runs") if isinstance(blob, dict) else None
    if not isinstance(runs, list):
        raise ValueError("the waiting runs listing did not parse")
    return runs


def supersede(gh: Gh, repo: str, sha: str, out: Callable[[str], None]) -> int:
    """Cancel every older waiting delivery this commit supersedes. Returns the exit code."""
    code = 0
    for run in waiting_runs(gh, repo):
        run_id = run.get("id")
        older = run.get("head_sha")
        if older == sha:
            out("kept run %s: it is this commit's own delivery" % run_id)
            continue
        try:
            compare = gh(["repos/%s/compare/%s...%s" % (repo, older, sha)])
            relation = compare.get("status") if isinstance(compare, dict) else None
            listing = gh(["repos/%s/actions/runs/%s/jobs?per_page=100" % (repo, run_id)])
            jobs = listing.get("jobs") if isinstance(listing, dict) else None
            if not isinstance(jobs, list):
                raise ValueError("the jobs listing did not parse")
        except (subprocess.CalledProcessError, ValueError) as exc:
            out("kept run %s: it could not be read: %s" % (run_id, exc))
            code = 1
            continue
        verdict, reason = decide(jobs, str(relation))
        if verdict != "cancel":
            out("kept run %s: %s" % (run_id, reason))
            continue
        try:
            gh(["--method", "POST", "repos/%s/actions/runs/%s/cancel" % (repo, run_id)])
        except subprocess.CalledProcessError as exc:
            out("kept run %s: the cancel call failed: %s" % (run_id, exc))
            code = 1
            continue
        out("cancelled run %s at %s: %s" % (run_id, older, reason))
    return code


def main(argv: Optional[Sequence[str]] = None, gh: Gh = gh_api) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args(argv)
    try:
        return supersede(gh, args.repo, args.sha, print)
    except (subprocess.CalledProcessError, ValueError) as exc:
        print("could not list the waiting deliveries: %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
