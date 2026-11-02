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
import posixpath
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
# The three checks files are named one by one, because the shards read them and the rest of
# ansible/checks/ is lint-only. The order matters: needed_units tests EVERY_SHARD before
# LINT_ONLY, so these three win over the folder entry in LINT_ONLY below.
EVERY_SHARD = (
    "ansible/harness/",
    "ansible/checks/ci_select.py",
    "ansible/checks/check_pins.py",
    "ansible/checks/pip-requirements.txt",
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
    "ansible/checks/",
    "ansible/inventories/",
    "ansible/playbooks/",
    "ansible/tools/",
    "ansible/trust/",
)

# The repository directories a role test reads outside ansible/.
OUTSIDE = r"(?:hetzner-host|hetzner|mail)"
# A literal path in a file, such as '{{ verify_repo }}/hetzner/provision/x.service' or
# 'mail/provision/65-install-local-resolver.sh' (the mx1_stack role reads the mail host's scripts).
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
    """Return the paths outside ansible/ that a file names, with no trailing slash or dot.

    A path only a comment names is not a read, so the comments are removed first.
    """
    text = without_comments(text)
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


def strip_comment(line: str) -> str:
    """Return ``line`` without its comment, if it has one.

    A ``#`` starts a comment only at the start of a line or after a space, and only outside a
    quoted string. A quote left open by an apostrophe in prose keeps the rest of the line
    quoted, so a comment missed that way is still scanned: the failure is a false positive.
    """
    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if quote:
            if escaped:
                escaped = False
            elif quote == '"' and char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def without_comments(text: str) -> str:
    """Return ``text`` with every YAML, shell or Python comment removed, line by line."""
    return "\n".join(strip_comment(line) for line in text.splitlines())


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
        everything = without_comments(unit_text(unit, ("molecule", "tests", "vars", "defaults")))
        for token in list(tokens):
            directory = root / token
            if directory.is_dir():
                for child in directory.iterdir():
                    if child.is_file() and child.name in everything:
                        tokens.add(f"{token}/{child.name}")
        for token in tokens:
            reads.setdefault(token, set()).add(unit_path(unit, root))
    return reads


# The role references the structured scan reads (see RoleScan). A call of a role by name.
ROLE_CALL = re.compile(
    r"^(\s*(?:-\s+)?)(?:ansible\.(?:builtin|legacy)\.)?(?:include_role|import_role)\s*:\s*(.*?)\s*$"
)
# A playbook that another playbook pulls in.
PLAYBOOK_CALL = re.compile(
    r"^\s*(?:-\s+)?(?:ansible\.(?:builtin|legacy)\.)?(?:import|include)_playbook\s*:\s*(.*?)\s*$"
)
# A list of roles: a play's ``roles:`` or a role's ``dependencies:`` in meta/main.yml.
ROLE_LIST = re.compile(r"^(\s*)(?:roles|dependencies)\s*:\s*(.*?)\s*$")
# A handler notification, or the name a handler listens for.
NOTIFY_KEY = re.compile(r"^(\s*)(?:-\s+)?notify\s*:\s*(.*?)\s*$")
LISTEN_KEY = re.compile(r"^(\s*)(?:-\s+)?listen\s*:\s*(.*?)\s*$")
NAME_KEY = re.compile(r"^\s*(?:-\s+)?name\s*:\s*(.+?)\s*$")
HANDLERS_BLOCK = re.compile(r"^(\s*)handlers\s*:\s*$")
# The name or role key of a role call or of one entry in a list of roles.
NAMED = re.compile(r"^(?:-\s+)?(?:name|role)\s*:\s*(.+?)\s*$")
NAME_ARGUMENT = re.compile(r"(?:^|\s)name=(\"[^\"]*\"|'[^']*'|\S+)")
INLINE_NAME = re.compile(r"[{,]\s*(?:name|role)\s*:\s*([^,}]+)")
# A key with a value, anywhere in a unit: where a templated role name may have been defined.
ASSIGNMENT = re.compile(r"^\s*(?:-\s+)?([A-Za-z_]\w*)\s*:\s*(\S.*?)\s*$")
WHOLE_VARIABLE = re.compile(r"\{\{\s*([A-Za-z_]\w*)\s*\}\}")
PATH_VARIABLE = re.compile(r"\{\{\s*(?:playbook_dir|role_path)\s*\}\}(/[^{}]*)")
TRAILING_NAME = re.compile(r"\{\{[^{}]*~\s*[\"']/([A-Za-z0-9_]+)[\"']\s*\}\}")
BARE_NAME = re.compile(r"[A-Za-z0-9_]+")
# Where a line that holds a reference starts, once its dashes and module namespace are gone.
MODULE_PREFIXES = ("ansible.builtin.", "ansible.legacy.")
KEY_STARTS = (
    "include_role",
    "import_role",
    "import_playbook",
    "include_playbook",
    "roles",
    "dependencies",
    "notify",
)
NO_LIST = ("false", "true", "null", "~", "[]", "{}")
YAML_SUFFIXES = (".yml", ".yaml")
VARIABLE_DEPTH = 3


def indent_of(line: str) -> int:
    """Return how many spaces ``line`` starts with."""
    return len(line) - len(line.lstrip(" "))


def unquote(value: str) -> str:
    """Return ``value`` without one pair of surrounding quotes."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def block_lines(
    lines: list[str], number: int, indent: int, dashes: bool = False
) -> list[tuple[int, str]]:
    """Return the lines under the key on ``lines[number]``, which sits at ``indent``.

    The block ends at the first line that is no deeper than the key. A list may sit level with
    its key, so with ``dashes`` a line at the key's depth that starts a list item stays in.
    """
    found: list[tuple[int, str]] = []
    for position in range(number + 1, len(lines)):
        line = lines[position]
        if not line.strip():
            continue
        depth = indent_of(line)
        if depth < indent or (depth == indent and not (dashes and line.lstrip().startswith("-"))):
            break
        found.append((position, line))
    return found


def key_values(lines: list[str], number: int, indent: int, rest: str) -> list[str] | None:
    """Return the values of a key that holds a scalar, an inline list or a list of scalars.

    None means the value cannot be read: a list of mappings, or an inline list left open.
    """
    if rest.startswith("["):
        if not rest.endswith("]"):
            return None
        return [unquote(part) for part in rest[1:-1].split(",") if part.strip()]
    if rest:
        return [unquote(rest)]
    values: list[str] = []
    for _, line in block_lines(lines, number, indent, dashes=True):
        text = line.strip()
        if not text.startswith("- "):
            return None
        values.append(unquote(text[1:].strip()))
    return values


def named_in(lines: list[tuple[int, str]]) -> str | None:
    """Return the ``name`` or ``role`` value among the keys at the depth of the first line."""
    if not lines:
        return None
    depth = indent_of(lines[0][1])
    for _, line in lines:
        if indent_of(line) == depth:
            match = NAMED.match(line.strip())
            if match is not None:
                return match.group(1)
    return None


class RoleScan:
    """What a structured read of every role and pattern says about how they reach each other.

    The textual scan in ``text_references`` finds a neighbour that a file names. This one reads
    the Ansible keys that make one unit run another: ``include_role``, ``import_role``,
    ``roles:``, ``dependencies:``, ``import_playbook``, a handler that only another unit
    defines, and a symlink into another unit. A reference it cannot map to a unit goes in
    ``unresolved``, because a selection that cannot see every way a unit is reached must not
    narrow.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.paths = {unit_path(unit, root): unit for unit in units(root)}
        self.by_name: dict[str, list[str]] = {}
        for path in self.paths:
            self.by_name.setdefault(path.rsplit("/", 1)[1], []).append(path)
        self.edges: dict[str, set[str]] = {path: set() for path in self.paths}
        self.unresolved: list[tuple[str, str]] = []
        self.sites = 0
        self.assigned: dict[str, dict[str, list[str]]] = {}
        self.handlers: dict[str, set[str]] = {}
        self.texts: dict[str, list[tuple[str, list[str]]]] = {}
        self.links: dict[str, list[Path]] = {}
        for path, unit in self.paths.items():
            self.texts[path] = self.read_unit(path, unit)
        for path in self.paths:
            self.handlers[path] = self.handler_names(path)
        for path in self.paths:
            self.scan_unit(path)

    def fail(self, where: str, text: str) -> None:
        """Record a reference that cannot be mapped to a unit."""
        self.unresolved.append((where, text.strip()))

    def read_unit(self, path: str, unit: Path) -> list[tuple[str, list[str]]]:
        """Return each YAML file of a unit as its path and its lines with comments removed.

        The unit's symlinks are kept aside in ``links``, for ``scan_link``.
        """
        files: list[tuple[str, list[str]]] = []
        self.links[path] = []
        try:
            found = sorted(unit.rglob("*"))
        except OSError:
            self.fail(path, "the unit cannot be listed")
            return files
        for file in found:
            if file.is_symlink():
                self.links[path].append(file)
                continue
            if file.suffix not in YAML_SUFFIXES or not file.is_file():
                continue
            relative = file.relative_to(self.root).as_posix()
            try:
                text = file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                self.fail(relative, "the file cannot be read")
                continue
            files.append((relative, without_comments(text).splitlines()))
        return files

    def handler_names(self, path: str) -> set[str]:
        """Return the handler names a unit defines, by ``name:`` or ``listen:``."""
        names: set[str] = set()
        for relative, lines in self.texts[path]:
            in_directory = "handlers" in relative.split("/")
            depth = -1
            for number, line in enumerate(lines):
                if "name" not in line and "listen" not in line and "handlers" not in line:
                    if depth >= 0 and line.strip() and indent_of(line) <= depth:
                        depth = -1
                    continue
                if depth >= 0 and line.strip() and indent_of(line) <= depth:
                    depth = -1
                block = HANDLERS_BLOCK.match(line)
                if block is not None and depth < 0:
                    depth = len(block.group(1))
                    continue
                if not (in_directory or depth >= 0):
                    continue
                name = NAME_KEY.match(line)
                if name is not None:
                    names.add(unquote(name.group(1)))
                listen = LISTEN_KEY.match(line)
                if listen is not None:
                    names.update(
                        key_values(lines, number, len(listen.group(1)), listen.group(2)) or []
                    )
        return names

    def assignments(self, path: str) -> dict[str, list[str]]:
        """Return every ``key: value`` line of a unit, by key (where a variable is defined)."""
        if path not in self.assigned:
            found: dict[str, list[str]] = {}
            for _, lines in self.texts[path]:
                for line in lines:
                    match = ASSIGNMENT.match(line)
                    if match is not None:
                        found.setdefault(match.group(1), []).append(match.group(2))
            self.assigned[path] = found
        return self.assigned[path]

    def owner(self, relative: str) -> str | None:
        """Return the unit that holds the repository path ``relative``, if one does."""
        parts = relative.split("/")
        if len(parts) >= 3 and parts[0] == "ansible":
            candidate = "/".join(parts[:3])
            if candidate in self.paths:
                return candidate
        return None

    def named_unit(self, name: str) -> set[str] | None:
        """Return the units a role name without a template names, or None for no unit."""
        name = name.strip()
        if name.startswith("branchleft."):
            name = name[len("branchleft.") :]
        elif "/" in name:
            name = name.rstrip("/").rsplit("/", 1)[1]
        if BARE_NAME.fullmatch(name) is None or name not in self.by_name:
            return None
        return set(self.by_name[name])

    def relative_units(self, file: str, unit: str, tail: str) -> set[str] | None:
        """Return the units a path under ``playbook_dir`` can reach from a file in ``unit``.

        The playbook that includes a file may sit in the file's directory or in any directory
        above it up to the unit's root, so each is tried and every unit reached is returned.
        """
        found: set[str] = set()
        base = posixpath.dirname(file)
        while True:
            reached = posixpath.normpath(base + tail)
            if reached in self.paths:
                found.add(reached)
            if base == unit or "/" not in base:
                break
            base = posixpath.dirname(base)
        return found or None

    def resolve(self, file: str, unit: str, value: str, depth: int = 0) -> set[str] | None:
        """Return the units the role name ``value`` names, or None when it cannot say.

        A name resolves when it is ``branchleft.U``, a bare ``U``, or a path ending in ``U``,
        where U is a role or pattern. A ``{{ variable }}`` is read through the unit's own
        definitions of it (every one must resolve); a ``{{ playbook_dir }}`` path is tried from
        the file's directory and each one above it; a name built with a trailing ``~ "/U"``
        names U. Anything else is left unresolved.
        """
        value = unquote(value)
        if "{{" not in value and "{%" not in value:
            return self.named_unit(value)
        whole = WHOLE_VARIABLE.fullmatch(value)
        if whole is not None:
            definitions = self.assignments(unit).get(whole.group(1))
            if not definitions or depth >= VARIABLE_DEPTH:
                return None
            found: set[str] = set()
            for definition in definitions:
                reached = self.resolve(file, unit, definition, depth + 1)
                if reached is None:
                    return None
                found |= reached
            return found
        under = PATH_VARIABLE.fullmatch(value)
        if under is not None:
            return self.relative_units(file, unit, under.group(1))
        trailing = TRAILING_NAME.fullmatch(value)
        if trailing is not None:
            return self.named_unit(trailing.group(1))
        return None

    def reach(self, unit: str, found: set[str] | None, where: str, text: str) -> None:
        """Record that ``unit`` runs the units in ``found``; None goes in as unresolved."""
        self.sites += 1
        if found is None:
            self.fail(where, text)
            return
        for other in found:
            if other != unit:
                self.edges[other].add(unit)

    def scan_unit(self, unit: str) -> None:
        """Read every structured reference in one role or pattern."""
        for relative, lines in self.texts[unit]:
            for number, line in enumerate(lines):
                self.scan_line(unit, relative, lines, number, line)
        for link in self.links[unit]:
            self.scan_link(unit, link)

    def scan_line(self, unit: str, file: str, lines: list[str], number: int, line: str) -> None:
        """Read the one reference a line may hold."""
        head = line.lstrip(" -")
        for prefix in MODULE_PREFIXES:
            if head.startswith(prefix):
                head = head[len(prefix) :]
        if not head.startswith(KEY_STARTS):
            return
        where = f"{file}:{number + 1}"
        call = ROLE_CALL.match(line)
        if call is not None:
            name = self.role_name(lines, number, call)
            found = None if name is None else self.resolve(file, unit, name)
            self.reach(unit, found, where, f"{line.strip()} {name or '(no name)'}")
            return
        playbook = PLAYBOOK_CALL.match(line)
        if playbook is not None:
            self.reach(unit, self.playbook(unit, file, playbook.group(1)), where, line)
            return
        listed = ROLE_LIST.match(line)
        if listed is not None:
            for found in self.role_list(unit, file, lines, number, listed):
                self.reach(unit, found, where, line)
            return
        notify = NOTIFY_KEY.match(line)
        if notify is not None:
            names = key_values(lines, number, len(notify.group(1)), notify.group(2))
            for name in names if names is not None else [None]:
                self.reach(unit, self.handler(unit, name), where, line)

    @staticmethod
    def role_name(lines: list[str], number: int, call: re.Match[str]) -> str | None:
        """Return the role name an ``include_role`` or ``import_role`` gives, in any form."""
        rest = call.group(2)
        if not rest:
            return named_in(block_lines(lines, number, len(call.group(1))))
        match = INLINE_NAME.search(rest) if rest.startswith("{") else NAME_ARGUMENT.search(rest)
        return match.group(1) if match is not None else None

    def playbook(self, unit: str, file: str, value: str) -> set[str] | None:
        """Resolve an ``import_playbook``: the file it names, as a unit it lies in."""
        value = unquote(value)
        if not value or "{{" in value or "{%" in value or value.startswith("/"):
            return None
        reached = posixpath.normpath(posixpath.join(posixpath.dirname(file), value))
        owner = self.owner(reached)
        if owner is None or not (self.root / reached).is_file():
            return None
        return {owner}

    def role_list(
        self, unit: str, file: str, lines: list[str], number: int, listed: re.Match[str]
    ) -> list[set[str] | None]:
        """Resolve each entry of a ``roles:`` or ``dependencies:`` list."""
        rest = listed.group(2)
        if rest in NO_LIST:
            return []
        if rest.startswith("["):
            if "{" in rest or not rest.endswith("]"):
                return [None]
            return [
                self.resolve(file, unit, part) for part in rest[1:-1].split(",") if part.strip()
            ]
        if rest:
            return [None]
        body = block_lines(lines, number, len(listed.group(1)), dashes=True)
        entries: list[list[tuple[int, str]]] = []
        for position, line in body:
            if line.lstrip().startswith("-") and (
                not entries or indent_of(line) == indent_of(entries[0][0][1])
            ):
                entries.append([(position, line)])
            elif entries:
                entries[-1].append((position, line))
        return [self.entry_role(unit, file, entry) for entry in entries]

    def entry_role(self, unit: str, file: str, entry: list[tuple[int, str]]) -> set[str] | None:
        """Resolve one entry of a list of roles: ``- x``, ``- role: x`` or ``- { role: x }``."""
        first = entry[0][1].strip()[1:].strip()
        if first.startswith("{"):
            match = INLINE_NAME.search(first)
            name = match.group(1) if match is not None else None
        elif not first:
            name = named_in(entry[1:])
        elif NAMED.match(first) is not None:
            match = NAMED.match(first)
            name = match.group(1) if match is not None else None
        elif re.match(r"[\w.-]+\s*:", first) is not None:
            name = named_in(entry[1:])
        else:
            name = first
        return None if name is None else self.resolve(file, unit, name)

    def handler(self, unit: str, name: str | None) -> set[str] | None:
        """Resolve a notified handler: its own unit's, or the only other unit defining it."""
        if name is None or "{{" in name or "{%" in name:
            return None
        if name in self.handlers[unit]:
            return {unit}
        elsewhere = {path for path, names in self.handlers.items() if name in names}
        return elsewhere or None

    def scan_link(self, unit: str, link: Path) -> None:
        """Read a symlink: one into another unit makes the unit run when that one changes."""
        relative = link.relative_to(self.root).as_posix()
        try:
            target = (link.parent / link.readlink()).resolve()
            exists = target.exists()
            inside_root = target.relative_to(self.root.resolve()).as_posix()
        except (OSError, ValueError):
            self.reach(unit, None, relative, "a link out of the repository or unreadable")
            return
        if not exists:
            self.reach(unit, None, relative, f"a link to {inside_root}, which is missing")
            return
        if not inside_root.startswith("ansible/"):
            return  # read by reads_by_path, which maps it to the files outside ansible/
        owner = self.owner(inside_root)
        if owner is not None:
            self.reach(unit, {owner}, relative, inside_root)
        elif not inside(inside_root, EVERY_SHARD):
            self.reach(unit, None, relative, f"a link to {inside_root}, which no rule names")


@functools.cache
def scan_references(root: Path) -> RoleScan:
    """Return the structured scan of the tree, kept for the life of the process."""
    return RoleScan(root)


def unresolved_references(root: Path) -> list[tuple[str, str]]:
    """Return ``(path:line, text)`` of each role reference the structured scan cannot map.

    While this list is not empty, a change to a role or pattern runs every shard, because one
    of these may be a way the changed unit is reached that the selection cannot see.
    """
    return scan_references(root).unresolved


@functools.cache
def text_references(root: Path) -> dict[str, set[str]]:
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


@functools.cache
def references(root: Path) -> dict[str, set[str]]:
    """Map each role or pattern to the other ones that run when it changes.

    Every edge the textual scan finds, and every edge the structured scan finds (a role
    called by name, a play's ``roles:``, a handler another unit defines, a link into another
    unit). The union only ever adds edges to the textual scan, so a selection never narrows.
    """
    joined = {path: set(named) for path, named in text_references(root).items()}
    for path, named in scan_references(root).edges.items():
        joined.setdefault(path, set()).update(named)
    return joined


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
        if unresolved_references(root):
            return None
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
    changed = read_changed(args.changed_file)
    chosen = select(args.event, changed, every, args.root)
    unresolved = unresolved_references(args.root) if changed is not None else []
    if unresolved and args.event in (PULL_REQUEST, MERGE_GROUP):
        print(
            f"{len(unresolved)} role reference(s) cannot be mapped to a role or pattern, so a "
            "change to one runs every shard. The first:",
            file=sys.stderr,
        )
        for where, text in unresolved[:5]:
            print(f"  {where}: {text}", file=sys.stderr)
    print(f"{args.event}: {len(chosen)} of {len(every)} shard(s) selected.", file=sys.stderr)
    for shard in chosen:
        print(f"  {shard['name']}", file=sys.stderr)
    print(f"shards={'true' if chosen else 'false'}")
    print("matrix=" + json.dumps({"include": chosen or [NO_SHARD]}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
