"""Read the deploy_tooling role's constants for the checks that compare them with other files.

The role's `vars/main.yml` is the single home of the paths, modes and sources the role
installs. The checks in `test_deploy_tooling_*.py` read it through this module and never
restate a path or a mode, so a value changes in one place.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ruamel.yaml import YAML

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLE = REPO_ROOT / "ansible" / "roles" / "deploy_tooling"
PROVISION = REPO_ROOT / "hetzner" / "provision"

TARGET_LISTS = (
    "deploy_tooling_directory_targets",
    "deploy_tooling_common_file_targets",
    "deploy_tooling_app_file_targets",
)
_REFERENCE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


class RoleVarsError(Exception):
    """The role's variables file is missing or not the shape the checks read."""


@dataclass(frozen=True)
class Target:
    """One path the role makes true: where it is, its mode, and for a file the program it is."""

    group: str
    label: str
    path: str
    mode: str
    kind: str
    program: str


def load_vars(role: Path = ROLE) -> dict[str, object]:
    """Return the top-level mapping of the role's `vars/main.yml`.

    Raises:
        RoleVarsError: the file is not a mapping.
    """
    document: object = YAML(typ="safe").load((role / "vars" / "main.yml").read_text("utf-8"))
    if not isinstance(document, dict):
        message = "vars/main.yml is not a mapping"
        raise RoleVarsError(message)
    return {str(key): value for key, value in document.items()}


def resolve(text: str, variables: dict[str, object]) -> str:
    """Replace each `{{ name }}` in ``text`` by that variable's own resolved text."""

    def substitute(match: re.Match[str]) -> str:
        value = variables.get(match.group(1))
        if not isinstance(value, str):
            message = f"{match.group(1)} is not a text variable in vars/main.yml"
            raise RoleVarsError(message)
        return resolve(value, variables)

    return _REFERENCE.sub(substitute, text)


def _text(entry: dict[object, object], key: str, variables: dict[str, object]) -> str:
    value = entry.get(key, "")
    if not isinstance(value, str):
        message = f"target field {key} is not text"
        raise RoleVarsError(message)
    return resolve(value, variables)


def targets(variables: dict[str, object]) -> list[Target]:
    """Return every target of the role's three lists, with its path resolved.

    Raises:
        RoleVarsError: a list or an entry of it is not the shape the role declares.
    """
    found: list[Target] = []
    for group in TARGET_LISTS:
        entries = variables.get(group)
        if not isinstance(entries, list):
            message = f"{group} is not a list in vars/main.yml"
            raise RoleVarsError(message)
        for entry in entries:
            if not isinstance(entry, dict):
                message = f"{group} holds an entry that is not a mapping"
                raise RoleVarsError(message)
            found.append(
                Target(
                    group=group,
                    label=_text(entry, "label", variables),
                    path=_text(entry, "path", variables),
                    mode=_text(entry, "mode", variables),
                    kind=_text(entry, "kind", variables),
                    program=_text(entry, "program", variables),
                )
            )
    return found


def program_names(variables: dict[str, object]) -> tuple[str, ...]:
    """Return the file name of every program the role installs, from the target lists.

    The `program` field of the file targets is the one home of these names, so a program
    added there is covered by every check that reads this, and no check restates the list.
    """
    return tuple(sorted({target.program for target in targets(variables) if target.program}))
