"""Choose the Ansible shards a CI run must execute.

The rules, and why each errs towards running more, are in ansible/checks/README.md. This
program reads the event, the changed files and the repository tree, and prints the two job
outputs as ``name=value`` lines. It uses only the standard library, because discover installs
nothing.
"""

from __future__ import annotations

import argparse
import functools
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GROUPS = ("roles", "patterns")
SKELETON = "ansible/role_skeleton"

MERGE_GROUP = "merge_group"
PULL_REQUEST = "pull_request"
PUSH = "push"

# A path ending in "/" names everything under it; any other entry names one file.
# What decides the verdict of every role: a change to any of these executes every shard.
EVERY_SHARD = (
    "ansible/harness/",
    "ansible/checks/",
    "ansible/pyproject.toml",
    "ansible/requirements.in",
    "ansible/requirements.txt",
    "ansible/requirements.yml",
    ".ansible-lint",
    ".yamllint",
    ".github/workflows/ansible.yml",
)
# Under ansible/ but read by no shard: the lint job runs the tests that read them.
LINT_ONLY = (
    "ansible/README.md",
    "ansible/inventories/",
    "ansible/playbooks/",
    "ansible/tools/",
    "ansible/trust/",
)

# The repository directories a role test reads outside ansible/.
OUTSIDE = r"(?:hetzner-host|hetzner)"
# A literal path in a file, such as '{{ verify_repo }}/hetzner/provision/x.service'.
LITERAL = re.compile(r"(?<![\w.-])(" + OUTSIDE + r"/[A-Za-z0-9_./@-]+)")
# A path built in Python, such as REPO / "hetzner" / "provision".
JOINED = re.compile(r'"(' + OUTSIDE + r')"((?:\s*/\s*"[^"]+")+)')
PART = re.compile(r'"([^"]+)"')
# A role or pattern directory, with a file or directory inside it.
UNIT = re.compile(r"^(ansible/(?:roles|patterns)/[^/]+)/")

# The entry that stands in for "no shard" in the matrix: GitHub refuses an empty one, and
# the shard job refuses to run for it.
NO_SHARD = {"name": "none", "path": "", "scenario": "", "kind": "none"}


def inside(path: str, entries: Sequence[str]) -> bool:
    """Return whether ``path`` is one of ``entries`` or under one that ends in a slash."""
    return any(
        path.startswith(entry) if entry.endswith("/") else path == entry for entry in entries
    )


def outside_reads(text: str) -> set[str]:
    """Return the paths outside ansible/ that a file names, with no trailing slash or dot."""
    found: set[str] = set()
    for match in LITERAL.finditer(text):
        found.add(match.group(1).rstrip("/."))
    for match in JOINED.finditer(text):
        parts = [match.group(1), *PART.findall(match.group(2))]
        found.add("/".join(parts).rstrip("/."))
    return found


def outside_links(unit: Path, root: Path) -> set[str]:
    """Return the paths outside ansible/ that a unit's symlinks point at.

    A role ships a file or directory by linking to it, so the link's target is read
    whenever the role is applied.
    """
    found: set[str] = set()
    for path in unit.rglob("*"):
        if not path.is_symlink():
            continue
        target = (path.parent / path.readlink()).resolve()
        try:
            relative = target.relative_to(root.resolve())
        except ValueError:
            continue
        if relative.parts and relative.parts[0] != "ansible":
            found.add(relative.as_posix())
    return found


def unit_text(unit: Path, areas: tuple[str, ...]) -> str:
    """Return the text of every file in the named areas of a role or pattern."""
    chunks = []
    for area in areas:
        base = unit / area
        if base.is_dir():
            for path in sorted(base.rglob("*")):
                if path.is_file():
                    chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n".join(chunks)


def units(root: Path) -> list[Path]:
    """Return every role and pattern directory, hidden ones left out, in a fixed order."""
    found: list[Path] = []
    for group in GROUPS:
        parent = root / "ansible" / group
        if parent.is_dir():
            found.extend(
                entry
                for entry in sorted(parent.iterdir())
                if entry.is_dir() and not entry.name.startswith(".")
            )
    return found


def unit_path(unit: Path, root: Path) -> str:
    """Return a unit's path from the repository root, as a shard names it."""
    return unit.relative_to(root).as_posix()


@functools.cache
def reads_by_path(root: Path) -> dict[str, set[str]]:
    """Map each path outside ansible/ that a role or pattern reads to the units that read it.

    The answer is kept for the life of the process: one run reads the tree once.

    A unit reads a file either by its full path (found in molecule/ and tests/) or by its
    name inside a directory outside ansible/ that the unit names, such as the four
    reconciler sources the egress_nat verify reads from hetzner/provision. Those names
    are looked for in the unit's molecule/, tests/, vars/ and defaults/ text.
    """
    reads: dict[str, set[str]] = {}
    for unit in units(root):
        tokens = outside_reads(unit_text(unit, ("molecule", "tests")))
        tokens |= outside_links(unit, root)
        everything = unit_text(unit, ("molecule", "tests", "vars", "defaults"))
        for token in list(tokens):
            directory = root / token
            if directory.is_dir():
                for child in directory.iterdir():
                    if child.is_file() and child.name in everything:
                        tokens.add(f"{token}/{child.name}")
        for token in tokens:
            reads.setdefault(token, set()).add(unit_path(unit, root))
    return reads


@functools.cache
def references(root: Path) -> dict[str, set[str]]:
    """Map each role or pattern to the other ones whose files name it.

    A unit names another by its collection name (``branchleft.name``), by a relative path
    (``../name``) or by its path from ansible/ (``roles/name``). A README that names a
    neighbour counts too: it runs one shard more, never one less.
    """
    paths = [unit_path(unit, root) for unit in units(root)]
    texts: dict[str, str] = {}
    for unit in units(root):
        chunks = [
            path.read_text(encoding="utf-8", errors="ignore")
            for path in sorted(unit.rglob("*"))
            if path.is_file() and not path.is_symlink()
        ]
        texts[unit_path(unit, root)] = "\n".join(chunks)
    named_by: dict[str, set[str]] = {path: set() for path in paths}
    for target in paths:
        name = re.escape(target.rsplit("/", 1)[1])
        pattern = re.compile(
            r"(?:branchleft\.|\.\./|roles/|patterns/)" + name + r"(?![A-Za-z0-9_])"
        )
        for other, text in texts.items():
            if other != target and pattern.search(text) is not None:
                named_by[target].add(other)
    return named_by


def needed_units(changed: Sequence[str], root: Path) -> set[str] | None:
    """Return the roles and patterns (and the skeleton) the changed files call for.

    None means every shard: a file that decides what every role is held to, or a file under
    ansible/ that no rule here names.
    """
    wanted: set[str] = set()
    outside: list[str] = []
    for path in changed:
        if inside(path, EVERY_SHARD):
            return None
        match = UNIT.match(path)
        if match is not None:
            wanted.add(match.group(1))
        elif path.startswith("ansible/role_skeleton/"):
            wanted.add(SKELETON)
        elif path.startswith("ansible/"):
            if not inside(path, LINT_ONLY):
                return None
        else:
            outside.append(path)
    if outside:
        reads = reads_by_path(root)
        for path in outside:
            for read, readers in reads.items():
                if path == read or path.startswith(read + "/"):
                    wanted |= readers
    if wanted:
        named_by = references(root)
        pending = list(wanted)
        while pending:
            for dependent in named_by.get(pending.pop(), set()):
                if dependent not in wanted:
                    wanted.add(dependent)
                    pending.append(dependent)
    return wanted


def select(
    event: str, changed: Sequence[str] | None, shards: list[dict[str, str]], root: Path
) -> list[dict[str, str]]:
    """Return the shards a run of ``event`` must execute, given the files it changed.

    ``changed`` is None when the run cannot say what changed. A pull request and a merge-queue
    entry are narrowed by their diff, by the same rules. Every other event (the weekly sweep, a
    manual run, one nobody planned for) runs every shard, whatever ``changed`` says.
    """
    if event == PUSH:
        return []
    if event not in (PULL_REQUEST, MERGE_GROUP) or changed is None:
        return shards
    wanted = needed_units(changed, root)
    if wanted is None:
        return shards
    return [shard for shard in shards if shard["path"] in wanted]


def parse_matrix(text: str) -> list[dict[str, str]] | None:
    """Return the shards of the matrix list_shards.py prints, or None when it is malformed."""
    try:
        document: object = json.loads(text)
    except ValueError:
        return None
    include = document.get("include") if isinstance(document, dict) else None
    if not isinstance(include, list) or not include:
        return None
    shards: list[dict[str, str]] = []
    for entry in include:
        if not isinstance(entry, dict):
            return None
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in entry.items()):
            return None
        shards.append(dict(entry))
    return shards


def read_changed(path: Path | None) -> list[str] | None:
    """Return the changed files from a NUL-separated list, or None when it was not written.

    A missing file means the workflow could not diff (the base commit is unknown), so the
    caller runs everything.
    """
    if path is None or not path.is_file():
        return None
    return [name for name in path.read_text(encoding="utf-8").split("\0") if name]


def main(argv: Sequence[str]) -> int:
    """Print ``shards=`` and ``matrix=`` for the workflow's outputs; return 1 on a bad matrix."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", maxsplit=1)[0])
    parser.add_argument("--event", required=True)
    parser.add_argument("--matrix-file", type=Path, required=True)
    parser.add_argument("--changed-file", type=Path, default=None)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    every = parse_matrix(args.matrix_file.read_text(encoding="utf-8"))
    if every is None:
        print(
            "The shard matrix is empty or malformed, so nothing can be selected.", file=sys.stderr
        )
        return 1
    chosen = select(args.event, read_changed(args.changed_file), every, args.root)
    print(f"{args.event}: {len(chosen)} of {len(every)} shard(s) selected.", file=sys.stderr)
    for shard in chosen:
        print(f"  {shard['name']}", file=sys.stderr)
    print(f"shards={'true' if chosen else 'false'}")
    print("matrix=" + json.dumps({"include": chosen or [NO_SHARD]}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
