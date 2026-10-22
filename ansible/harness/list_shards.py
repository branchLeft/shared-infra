"""List the shards of the Ansible workflow from the repository tree.

Prints the job matrix as one line of JSON. Standard library only, because the
discovery job installs nothing. See ansible/README.md for what a shard is.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GROUPS = ("roles", "patterns")
SKELETON = "ansible/role_skeleton"
DEFAULT_SCENARIO = "default"


def directories(parent: Path) -> list[Path]:
    """Return the directories directly under ``parent``, hidden ones left out, sorted."""
    if not parent.is_dir():
        return []
    return sorted(
        entry for entry in parent.iterdir() if entry.is_dir() and not entry.name.startswith(".")
    )


def scenarios_of(directory: Path) -> list[str]:
    """Return the scenarios a role or pattern is run with: ``default``, then every other one.

    ``default`` is always listed, whether or not the directory has a ``molecule/``
    directory: a role with no scenario still gets a shard, and the harness fails it at
    ``scenario-limits``, so it cannot pass untested.
    """
    others = [
        entry.name
        for entry in directories(directory / "molecule")
        if entry.name != DEFAULT_SCENARIO
    ]
    return [DEFAULT_SCENARIO, *others]


def shard_name(path: str, scenario: str) -> str:
    """Return a job name that is unique to a directory and scenario."""
    return path if scenario == DEFAULT_SCENARIO else f"{path} ({scenario})"


class NothingToTestError(Exception):
    """The tree holds no role or pattern directory, so the matrix would be empty."""

    def __init__(self) -> None:
        super().__init__(
            "No role or pattern directory was found, so nothing would be tested "
            "(an empty matrix would skip the shard job silently)."
        )


def shards(repo_root: Path) -> list[dict[str, str]]:
    """Return one shard per (directory, scenario) pair, then the fresh-role skeleton.

    Raises:
        NothingToTestError: no role or pattern directory exists.
    """
    found: list[dict[str, str]] = []
    for group in GROUPS:
        for directory in directories(repo_root / "ansible" / group):
            path = f"ansible/{group}/{directory.name}"
            for scenario in scenarios_of(directory):
                found.append(
                    {
                        "name": shard_name(path, scenario),
                        "path": path,
                        "scenario": scenario,
                        "kind": "role",
                    }
                )
    if not found:
        raise NothingToTestError
    found.append(
        {
            "name": "fresh role from the skeleton",
            "path": SKELETON,
            "scenario": DEFAULT_SCENARIO,
            "kind": "skeleton",
        }
    )
    return found


def main(repo_root: Path = REPO_ROOT) -> int:
    """Print the matrix to standard output, and a readable list to standard error.

    Returns 1, printing the reason, when there is nothing to test.
    """
    try:
        listed = shards(repo_root)
    except NothingToTestError as refusal:
        print(refusal, file=sys.stderr)
        return 1
    print(f"The harness runs {len(listed)} shard(s):", file=sys.stderr)
    for shard in listed:
        print(f"  {shard['name']}", file=sys.stderr)
    print(json.dumps({"include": listed}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
