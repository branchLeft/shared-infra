"""Prepare a delivery in one answer: did the merge queue test this commit, and which shards run.

The reusable workflow's discover job runs this program on a push to main (its ``prepare-command``
input), so the two things the delivery used to find out in jobs of their own cost no runner of
their own. It prints ``name=value`` lines in the form of ``$GITHUB_OUTPUT``: ``tested`` (the
proof of ``merge_group_proof.py``, read from the runs of ``ansible.yml`` for the pushed commit),
and ``shards`` and ``directories`` (the choice of ``delivery_select.py``).

Both halves fail toward testing: a proof that cannot be read is ``tested=false``, a selection that
cannot be made is every role and pattern. The program always exits 0, and the discover job
replaces an answer that lacks either line by ``shards=true`` and ``tested=false``.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

import delivery_select
import merge_group_proof

REPO_ROOT = Path(__file__).resolve().parents[2]
# The runs of the Ansible gate workflow for one commit; the API's own ``event`` filter is not used,
# because the proof judges the event itself (merge_group_proof.py).
RUNS_PATH = "actions/workflows/ansible.yml/runs"
PAGE_SIZE = "100"


def prove(api: delivery_select.Api, sha: str) -> tuple[bool, str]:
    """Return whether the merge queue passed ``sha``, and why; a failed read is false."""
    try:
        document: object = api(RUNS_PATH, {"head_sha": sha, "per_page": PAGE_SIZE})
    except Exception as error:  # noqa: BLE001 - whatever goes wrong, the commit is not proven
        return False, f"the runs of the commit could not be read ({type(error).__name__})"
    return merge_group_proof.judge(document, sha)


def render(tested: bool, selection: delivery_select.Selection) -> str:
    """Return the answer as the ``name=value`` text a step appends to ``$GITHUB_OUTPUT``."""
    return f"tested={'true' if tested else 'false'}\n" + delivery_select.render(selection)


def main(argv: Sequence[str]) -> int:
    """Print the answer for a delivery of ``--sha`` over ``--before``; always return 0."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", maxsplit=1)[0])
    parser.add_argument("--before", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--repository", default=os.environ.get("REPO", ""))
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    try:
        args = parser.parse_args(argv)
        api = delivery_select.gh_api(args.repository)
        tested, proof_reason = prove(api, args.sha)
        selection = delivery_select.select_delivery(args.root, args.before, args.sha, api)
    except SystemExit:
        tested, proof_reason = False, "the arguments could not be read"
        selection = delivery_select.full("the arguments could not be read")
    print(f"merge queue proof: tested={tested}: {proof_reason}", file=sys.stderr)
    print(f"delivery selection: {selection.reason}", file=sys.stderr)
    print(
        f"  shards run: {selection.run_shards}; directories: {', '.join(selection.directories)}",
        file=sys.stderr,
    )
    sys.stdout.write(render(tested, selection))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
