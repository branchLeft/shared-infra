"""Hold the default a capability role runs with to the default its argument_specs declares.

ANS-12 leaves this equality to review: Ansible does not apply the ``default`` of an
``argument_specs`` entry, so the value an omitted option takes at run time is a second copy,
and for an option of a list element it is an inline ``| default(...)`` in the tasks of the
entry point. A gate that reads the spec and the call cannot see which value runs. This check
reads both copies for one role, ``restart_stamp``, and fails when they differ, so a change to
one copy that leaves the other is stopped here and not found by a rerun on a host.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from role_tasks import mapping_at, option_specs

# ``c.drift | default(false)``: the option name after a dot, and the literal inside the call.
INLINE_DEFAULT = re.compile(r"\.(?P<name>\w+)\s*\|\s*default\(\s*(?P<value>[^()|]*?)\s*\)")
INTEGER = re.compile(r"-?\d+")
QUOTED = re.compile(r"'(?P<single>[^']*)'|\"(?P<double>[^\"]*)\"")
WORDS = {"true": True, "false": False, "none": None}
UNREADABLE = object()


def declared_defaults(role: Path) -> list[tuple[str, str, object]]:
    """Return the entry point, the option path and the default of each option that has one."""
    specs = mapping_at(role / "meta" / "argument_specs.yml", "argument_specs")
    found: list[tuple[str, str, object]] = []
    for entry, spec in specs.items():
        options = spec.get("options") if isinstance(spec, Mapping) else None
        for path, option in option_specs(options):
            if isinstance(option, Mapping) and "default" in option:
                found.append((str(entry), path, option["default"]))
    return found


def literal(text: str) -> object:
    """Return the value of a Jinja literal (a word, integer or quoted string), else UNREADABLE."""
    word = text.strip()
    if word.lower() in WORDS:
        return WORDS[word.lower()]
    if INTEGER.fullmatch(word):
        return int(word)
    quoted = QUOTED.fullmatch(word)
    if quoted:
        return (
            quoted.group("single") if quoted.group("single") is not None else quoted.group("double")
        )
    return UNREADABLE


def same_value(running: object, declared: object) -> bool:
    """Say whether two values are one: of the same type, so ``0`` is not ``false``."""
    return running is not UNREADABLE and type(running) is type(declared) and running == declared


def running_default_problems(role: Path) -> list[str]:
    """Return each option whose running default is not the one its spec declares.

    Every option with a ``default`` must be an option of a list element, and every
    ``<name> | default(<literal>)`` for it in the tasks file of its entry point must be that
    literal. An option with no such copy, or one this reading cannot place, is reported: the
    check fails closed rather than pass what it did not see.
    """
    problems: list[str] = []
    for entry, path, declared in declared_defaults(role):
        where = f"{role.name} {path} ({entry})"
        if "[]." not in path:
            problems.append(
                f"{where}: declares a default but is not an option of a list element, and this "
                "check reads only the tasks of the entry point, where those run"
            )
            continue
        tasks = role / "tasks" / f"{entry}.yml"
        text = tasks.read_text(encoding="utf-8") if tasks.is_file() else ""
        name = path.rsplit(".", 1)[1]
        copies = [
            found["value"] for found in INLINE_DEFAULT.finditer(text) if found["name"] == name
        ]
        if not copies:
            problems.append(
                f"{where}: no `.{name} | default(...)` in tasks/{entry}.yml, so the value it runs "
                "with is not shown"
            )
        problems.extend(
            f"{where}: meta/argument_specs.yml declares default {declared!r} but "
            f"tasks/{entry}.yml runs with default({copy})"
            for copy in copies
            if not same_value(literal(copy), declared)
        )
    return problems
