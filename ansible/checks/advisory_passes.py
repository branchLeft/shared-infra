"""Count how many daily full runs in a row a container test has passed.

A pull request that puts a test on the blocking list, or takes one off, cites this count.
It reads the newest completed scheduled runs of the Ansible workflow on main, where every
shard is blocking for the run's own result, and counts the unbroken passes from the newest
run back. A run in which the shard did not pass, or in which no job of that name exists,
ends the streak. It only reads: the token in the environment needs no write scope.

    advisory_passes.py <shard id> [--n 5]

Prints ``PASS-STREAK=<k>`` and one line per run examined; exits 0 when k is at least n.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from shard_results import (
    ApiError,
    FixtureSource,
    Source,
    live_source_from_environment,
    shard_results,
)

DEFAULT_RUNS = 5


def examine(source: Source, shard: str, wanted: int) -> list[tuple[str, str]]:
    """Return (run URL, shard conclusion) for the newest ``wanted`` completed daily runs.

    The conclusion is ``absent`` when the run has no job for the shard.
    """
    examined: list[tuple[str, str]] = []
    for run in source.schedule_runs(wanted):
        run_id = int(str(run.get("id") or 0))
        matches = [
            result
            for result in shard_results(source.run_jobs(run_id))
            if result.shard == shard and result.blocking
        ]
        conclusion = (matches[0].conclusion or "unfinished") if matches else "absent"
        examined.append((str(run.get("html_url") or run_id), conclusion))
    return examined


def streak(examined: Sequence[tuple[str, str]]) -> int:
    """Return how many runs, from the newest, passed without a break."""
    passes = 0
    for _, conclusion in examined:
        if conclusion != "success":
            break
        passes += 1
    return passes


def main(argv: Sequence[str]) -> int:
    """Print the streak; return 0 when it reaches ``--n``."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", maxsplit=1)[0])
    parser.add_argument("shard", help="the shard id, such as 'ansible/roles/ci_jump'")
    parser.add_argument("--n", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--fixture", type=Path, default=None, help="recorded answers (tests)")
    args = parser.parse_args(argv)
    try:
        source: Source = (
            FixtureSource.from_file(args.fixture)
            if args.fixture
            else live_source_from_environment()
        )
        examined = examine(source, args.shard, args.n)
    except (ApiError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    passes = streak(examined)
    print(f"PASS-STREAK={passes}")
    for url, conclusion in examined:
        print(f"{conclusion} {url}")
    if len(examined) < args.n:
        print(f"Only {len(examined)} completed daily run(s) exist; {args.n} are needed.")
    return 0 if passes >= args.n else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
