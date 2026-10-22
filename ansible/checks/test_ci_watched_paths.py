"""Tests for the Ansible path filter.

The filter in .github/workflows/ansible.yml decides whether the Ansible shards run. A role
test that reads a file outside ansible/ must run when that file changes, so every such
path has to be named in the filter. These tests find the paths the roles read and fail
when one is not named.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from role_tasks import role_files

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ansible.yml"
ROLES = ROOT / "ansible" / "roles"

# The repository directories a role test reads outside ansible/.
OUTSIDE = r"(?:hetzner-host|hetzner)"
# A literal path in a file, such as '{{ verify_repo }}/hetzner/provision/x.service'.
LITERAL = re.compile(r"(?<![\w.-])(" + OUTSIDE + r"/[A-Za-z0-9_./@-]+)")
# A path built in Python, such as REPO / "hetzner" / "provision".
JOINED = re.compile(r'"(' + OUTSIDE + r')"((?:\s*/\s*"[^"]+")+)')
PART = re.compile(r'"([^"]+)"')
FILTER = re.compile(r"watched=\(\n(.*?)\n\s*\)", re.DOTALL)


def parse_watched(workflow_text: str) -> list[str]:
    """Return the entries of the watched=( ... ) array, or [] when the array is absent."""
    match = FILTER.search(workflow_text)
    if match is None:
        return []
    return [line.strip() for line in match.group(1).splitlines() if line.strip()]


def outside_reads(text: str) -> set[str]:
    """Return the paths outside ansible/ that a file names, with no trailing slash or dot."""
    found: set[str] = set()
    for match in LITERAL.finditer(text):
        found.add(match.group(1).rstrip("/."))
    for match in JOINED.finditer(text):
        parts = [match.group(1), *PART.findall(match.group(2))]
        found.add("/".join(parts).rstrip("/."))
    return found


def outside_links(role: Path) -> set[str]:
    """Return the paths outside ansible/ that a role's symlinks point at.

    A role ships a file or directory by linking to it, so the link's target is read
    whenever the role is applied.
    """
    found: set[str] = set()
    for path in role.rglob("*"):
        if not path.is_symlink():
            continue
        target = (path.parent / path.readlink()).resolve()
        try:
            relative = target.relative_to(ROOT)
        except ValueError:
            continue
        if relative.parts and relative.parts[0] != "ansible":
            found.add(relative.as_posix())
    return found


def role_text(role: Path, areas: tuple[str, ...]) -> str:
    """Return the text of every file in the named areas of a role."""
    files = role_files(role, areas, suffixes=None)
    return "\n".join(path.read_text(encoding="utf-8", errors="ignore") for _, path in files)


def role_reads(roles: Path) -> dict[str, set[str]]:
    """Map each outside path that a role reads to the roles that read it.

    A role reads a file either by its full path (found in molecule/ and tests/) or by its
    name inside a directory outside ansible/ that the role names, such as the four
    reconciler sources the egress_nat verify reads from hetzner/provision. Those names
    are looked for in the role's molecule/, tests/, vars/ and defaults/ text.
    """
    reads: dict[str, set[str]] = {}
    for role in sorted(roles.iterdir()):
        if not role.is_dir():
            continue
        tokens = outside_reads(role_text(role, ("molecule", "tests")))
        tokens |= outside_links(role)
        everything = role_text(role, ("molecule", "tests", "vars", "defaults"))
        for token in list(tokens):
            directory = ROOT / token
            if directory.is_dir():
                for child in directory.iterdir():
                    if child.is_file() and child.name in everything:
                        tokens.add(f"{token}/{child.name}")
        for token in tokens:
            reads.setdefault(token, set()).add(role.name)
    return reads


def uncovered(reads: set[str], watched: list[str]) -> list[str]:
    """Return the reads the filter does not name.

    A read is named when the filter lists it exactly, lists a directory that holds it, or
    lists files under it (a directory a verify step only reads the parts of).
    """
    names = {entry.rstrip("/") for entry in watched}
    dirs = {entry.rstrip("/") for entry in watched if entry.endswith("/")}
    missing = []
    for read in sorted(reads):
        if read in names:
            continue
        if any(read.startswith(d + "/") for d in dirs):
            continue
        if any(name.startswith(read + "/") for name in names):
            continue
        missing.append(read)
    return missing


class WatchedPathsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.watched = parse_watched(WORKFLOW.read_text(encoding="utf-8"))
        self.reads = role_reads(ROLES)

    def test_every_outside_path_a_role_reads_is_watched(self) -> None:
        self.assertTrue(self.watched, "the workflow has no watched=( ... ) array")
        missing = uncovered(set(self.reads), self.watched)
        detail = [f"{path} (read by {', '.join(sorted(self.reads[path]))})" for path in missing]
        self.assertEqual([], detail, "these paths are read by role tests but not in the filter")

    def test_scanner_finds_known_reads(self) -> None:
        # A control: the scan must see the reads it is meant to find, or a clean result
        # proves nothing.
        self.assertIn("hetzner/monitoring/stack", self.reads)
        self.assertIn("hetzner/provision/branchleft-nat.service", self.reads)
        self.assertIn("hetzner/provision/branchleft-db-tunnel.service", self.reads)
        # Read through a symlink in files/, not through a path in molecule/ or tests/.
        self.assertIn("hetzner/control-plane/stack", self.reads)

    def test_a_read_with_no_entry_is_reported(self) -> None:
        watched = ["ansible", "hetzner/provision/branchleft_deploy.py"]
        self.assertEqual(
            ["hetzner/provision/branchleft-nat.service"],
            uncovered({"hetzner/provision/branchleft-nat.service"}, watched),
        )

    def test_a_directory_entry_covers_the_files_under_it(self) -> None:
        self.assertEqual(
            [], uncovered({"hetzner/monitoring/stack/snds/x.py"}, ["hetzner/monitoring/stack/"])
        )
        self.assertEqual(
            ["hetzner/monitoring/stack"],
            uncovered(
                {"hetzner/monitoring/stack"},
                ["hetzner/monitoring/systemd/monitoring.override.conf"],
            ),
        )


if __name__ == "__main__":
    unittest.main()
