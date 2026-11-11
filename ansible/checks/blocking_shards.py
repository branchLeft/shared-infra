"""Say which container tests (harness shards) fail the required check, from one list.

The list is ansible/checks/blocking_shards.json. Every shard runs on every pull request;
a shard on the list is a blocking shard, and the required check waits for it and fails
with it. Every other shard is advisory: it runs, it shows red on its own check line when
it fails, and the required check does not wait for it. A scheduled or manual run treats
every shard as blocking. ansible/checks/README.md has the rules and the reasons.

Standard library only, because the discover job installs nothing.

    blocking_shards.py validate --all-file all-shards.json
    blocking_shards.py split --event E --all-file all-shards.json --selection-file S

``split`` prints the job outputs of the discover job as ``name=value`` lines.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from ci_select import MERGE_GROUP, NO_SHARD, PULL_REQUEST

LIST_FILE = Path(__file__).with_name("blocking_shards.json")
KEY = "blocking"
# The events whose shards are split between blocking and advisory. Every other event
# (the scheduled sweep, a manual run, one nobody planned for) treats every shard as
# blocking, so an event the split does not know fails closed.
SPLIT_EVENTS = (PULL_REQUEST, MERGE_GROUP)


class ListError(Exception):
    """The list file or the matrix it is read against cannot be used."""


def read_list(path: Path = LIST_FILE) -> list[str]:
    """Return the blocking shard ids in the file, in file order.

    Raises:
        ListError: The file is missing, is not JSON, or does not hold exactly one key.
    """
    try:
        document: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        message = f"{path.name} cannot be read as JSON: {error}"
        raise ListError(message) from error
    if not isinstance(document, dict) or set(document) != {KEY}:
        message = f"{path.name} must be one JSON object with the single key '{KEY}'"
        raise ListError(message)
    listed = document[KEY]
    if not isinstance(listed, list) or not all(isinstance(entry, str) for entry in listed):
        message = f"'{KEY}' in {path.name} must be a list of shard ids (strings)"
        raise ListError(message)
    return [str(entry) for entry in listed]


def problems(listed: Sequence[str], known: Sequence[str]) -> list[str]:
    """Return what is wrong with a list read against the shard ids that exist."""
    found = [f"unknown shard id: {entry!r}" for entry in listed if entry not in known]
    found += [
        f"duplicate shard id: {entry!r}" for entry in sorted(set(listed)) if listed.count(entry) > 1
    ]
    if list(listed) != sorted(listed):
        found.append("the list is not sorted (plain string order)")
    return found


def parse_matrix(text: str) -> list[dict[str, str]]:
    """Return the entries of a matrix document ({"include": [...]}).

    Raises:
        ListError: The text is not a matrix of string-valued entries.
    """
    try:
        document: object = json.loads(text)
    except ValueError as error:
        message = f"the matrix is not JSON: {error}"
        raise ListError(message) from error
    include = document.get("include") if isinstance(document, dict) else None
    if not isinstance(include, list) or not all(
        isinstance(entry, dict) and isinstance(entry.get("name"), str) for entry in include
    ):
        message = "the matrix must be an object with an 'include' list of entries that have a name"
        raise ListError(message)
    return [{str(key): str(value) for key, value in entry.items()} for entry in include]


def partition(
    event: str, selected: Sequence[Mapping[str, str]], blocking: frozenset[str]
) -> tuple[list[Mapping[str, str]], list[Mapping[str, str]]]:
    """Return the selected shards as (blocking, advisory) for this event."""
    if event not in SPLIT_EVENTS:
        return list(selected), []
    return (
        [shard for shard in selected if shard["name"] in blocking],
        [shard for shard in selected if shard["name"] not in blocking],
    )


def matrix_lines(label: str, shards: Sequence[Mapping[str, str]]) -> list[str]:
    """Return the two output lines for one kind of shard."""
    chosen = list(shards) or [NO_SHARD]
    return [
        f"{label}={'true' if shards else 'false'}",
        f"{label}_matrix=" + json.dumps({"include": chosen}, separators=(",", ":")),
    ]


def selected_from(selection: str) -> list[dict[str, str]]:
    """Return the shards ci_select.py chose, from the output lines it printed.

    Raises:
        ListError: The output has no ``matrix=`` line.
    """
    for line in selection.splitlines():
        if line.startswith("matrix="):
            entries = parse_matrix(line.removeprefix("matrix="))
            return [entry for entry in entries if entry.get("kind") != NO_SHARD["kind"]]
    message = "the selection has no matrix= line"
    raise ListError(message)


def main(argv: Sequence[str]) -> int:
    """Run ``validate`` or ``split``; return 1, with the reasons on stderr, when the list is bad."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", maxsplit=1)[0])
    parser.add_argument("command", choices=("validate", "split"))
    parser.add_argument("--all-file", type=Path, required=True)
    parser.add_argument("--list-file", type=Path, default=LIST_FILE)
    parser.add_argument("--event", default="")
    parser.add_argument("--selection-file", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        known = [shard["name"] for shard in parse_matrix(args.all_file.read_text(encoding="utf-8"))]
        listed = read_list(args.list_file)
        wrong = problems(listed, known)
        if wrong:
            for reason in wrong:
                print(f"{args.list_file.name}: {reason}", file=sys.stderr)
            return 1
        if args.command == "validate":
            print(f"{len(listed)} blocking shard id(s) of {len(known)} shard(s): all known.")
            return 0
        if args.selection_file is None:
            print("split needs --selection-file", file=sys.stderr)
            return 1
        selected = selected_from(args.selection_file.read_text(encoding="utf-8"))
    except (ListError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    blocking, advisory = partition(args.event, selected, frozenset(listed))
    print(
        f"{args.event}: {len(blocking)} blocking and {len(advisory)} advisory shard(s).",
        file=sys.stderr,
    )
    for shard in advisory:
        print(f"  advisory: {shard['name']}", file=sys.stderr)
    for line in [*matrix_lines("blocking", blocking), *matrix_lines("advisory", advisory)]:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
