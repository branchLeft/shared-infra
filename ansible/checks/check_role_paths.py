"""Check that no two roles write the same path: a path has one home, in one role.

It reads the tasks of every role under ansible/roles, finds the modules that put content
at a path, and resolves `{{ name }}` from the roles' defaults and vars (names carry the role
prefix, ANS-7). A path that still holds a template after that (a loop item, a filter) is not
compared. A directory made by two roles is not a write: only content and links count.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
WRITERS = frozenset(
    ("copy", "template", "get_url", "lineinfile", "blockinfile", "replace", "assemble")
)
LINK_STATES = frozenset(("link", "hard", "touch"))
VARIABLE = re.compile(r"\{\{\s*([A-Za-z_]\w*)\s*\}\}")
DEPTH = 5


def _scalars(role: Path) -> dict[str, str]:
    """Return the role's string variables from defaults/ and vars/."""
    found: dict[str, str] = {}
    for directory in ("defaults", "vars"):
        for path in sorted((role / directory).rglob("*.y*ml")):
            document, _problem = load_yaml(path)
            if isinstance(document, dict):
                found.update({str(k): v for k, v in document.items() if isinstance(v, str)})
    return found


def _resolve(text: str, own: dict[str, str], every: dict[str, str]) -> str:
    """Replace each plain `{{ name }}` the roles define, a few levels deep."""
    for _ in range(DEPTH):
        text = VARIABLE.sub(lambda m: own.get(m[1], every.get(m[1], m[0])), text)
    return text


def _paths(node: object) -> list[str]:
    """Return the literal path each writing task in ``node`` puts content at."""
    found: list[str] = []
    if isinstance(node, list):
        for item in node:
            found.extend(_paths(item))
    elif isinstance(node, dict):
        for key, value in node.items():
            module = str(key).rsplit(".", 1)[-1]
            if isinstance(value, dict):
                target = value.get("dest", value.get("path"))
                links = module == "file" and value.get("state") in LINK_STATES
                writes = module in WRITERS or links
                if writes and isinstance(target, str):
                    found.append(target)
            found.extend(_paths(value))
    return found


def writers_of(root: Path) -> tuple[dict[str, set[str]], int]:
    """Return the roles that write each resolved path, and how many paths stayed templated."""
    roles = sorted(path for path in (root / "ansible" / "roles").glob("*") if path.is_dir())
    own = {role.name: _scalars(role) for role in roles}
    every = {k: v for variables in own.values() for k, v in variables.items()}
    writers: dict[str, set[str]] = defaultdict(set)
    templated = 0
    for role in roles:
        for path in sorted((role / "tasks").rglob("*.y*ml")):
            document, _problem = load_yaml(path)
            for target in _paths(document):
                resolved = _resolve(target, own[role.name], every)
                if "{{" in resolved:
                    templated += 1
                else:
                    writers[resolved.rstrip("/") or "/"].add(role.name)
    return writers, templated


def check(root: Path) -> list[str]:
    """Return one finding per path that tasks of two or more roles write."""
    return [
        f"{target} is written by {', '.join(sorted(names))}"
        for target, names in sorted(writers_of(root)[0].items())
        if len(names) > 1
    ]


def main() -> int:
    """Print every finding and return 1 if there is one."""
    findings = check(ROOT)
    writers, templated = writers_of(ROOT)
    for finding in findings:
        print(f"FAIL {finding}")
    print(f"note {len(writers)} path(s) compared, {templated} left templated and not compared")
    print(f"check_role_paths: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
