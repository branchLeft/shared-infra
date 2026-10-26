"""Decide whether the merge queue already tested the commit a delivery is about to ship.

Reads the answer of ``gh api repos/OWNER/REPO/actions/workflows/ansible.yml/runs`` for one
commit and prints ``tested=true`` or ``tested=false`` and a ``reason=`` line, ready to append to
``$GITHUB_OUTPUT``. It is true only when one run of the Ansible gate workflow has the event
``merge_group``, the pushed commit as its head, a branch of the merge queue, and finished with
the conclusion ``success``. A push run of the same commit is green too (it has no diff to test),
so the event is judged here and never narrowed by the API's own ``event`` filter. Anything
unreadable, truncated or short of that is false, and false means the delivery tests in full.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

WORKFLOW_PATH = ".github/workflows/ansible.yml"
EVENT = "merge_group"
QUEUE_BRANCH_PREFIX = "gh-readonly-queue/"
SHA_LENGTH = 40
HEX = frozenset("0123456789abcdef")


def as_mapping(value: object) -> dict[str, object] | None:
    """Return ``value`` with string keys when it is a mapping, else None."""
    if not isinstance(value, dict):
        return None
    return {str(key): item for key, item in value.items()}


def refusal(run: object, sha: str) -> str | None:
    """Return why ``run`` does not prove the merge queue passed ``sha``, or None when it does.

    Each clause is one way a green run can still be the wrong evidence: the push run of the same
    commit is green, a run of another workflow or commit is green, a run on a branch that is not
    the queue's is not the queue's, and a run that is not finished has no result yet.
    """
    mapping = as_mapping(run)
    if mapping is None:
        return "an entry of the answer is not a run"
    if mapping.get("path") != WORKFLOW_PATH:
        return "a run is of another workflow"
    if mapping.get("event") != EVENT:
        return "a run is not of the merge queue event"
    if mapping.get("head_sha") != sha:
        return "a run is of another commit"
    branch = mapping.get("head_branch")
    if not isinstance(branch, str) or not branch.startswith(QUEUE_BRANCH_PREFIX):
        return "a run is not on a merge queue branch"
    if mapping.get("status") != "completed":
        return "a merge queue run has not completed"
    if mapping.get("conclusion") != "success":
        return "a merge queue run did not succeed"
    return None


def judge(document: object, sha: str) -> tuple[bool, str]:
    """Return whether ``document`` proves the merge queue passed ``sha``, and why.

    ``document`` is the answer of the runs call for ``sha``. The reason is one line made only of
    this file's own words, so it can be written to ``$GITHUB_OUTPUT`` as it is.
    """
    if len(sha) != SHA_LENGTH or not set(sha) <= HEX:
        return False, "the commit is not 40 lowercase hex digits"
    answer = as_mapping(document)
    runs = answer.get("workflow_runs") if answer is not None else None
    total = answer.get("total_count") if answer is not None else None
    if not isinstance(runs, list):
        return False, "the answer holds no list of runs"
    if isinstance(total, bool) or not isinstance(total, int):
        return False, "the answer does not say how many runs there are"
    if total > len(runs):
        return False, "the answer is truncated: it holds fewer runs than exist"
    if any(refusal(run, sha) is None for run in runs):
        return True, "a successful merge queue run of the Ansible workflow tested this commit"
    return False, "no successful merge queue run of the Ansible workflow was found for this commit"


def main(argv: Sequence[str]) -> int:
    """Print the verdict as output lines and return 0, whatever the input held."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", maxsplit=1)[0])
    parser.add_argument("--runs", type=Path, required=True, help="the JSON answer of the runs call")
    parser.add_argument("--sha", required=True, help="the commit the delivery would ship")
    args = parser.parse_args(argv)
    try:
        document: object = json.loads(args.runs.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        document = None
    tested, reason = judge(document, args.sha)
    print(f"tested={'true' if tested else 'false'}")
    print(f"reason={reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
