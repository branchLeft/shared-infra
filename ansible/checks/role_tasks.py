"""Read the tasks of a role's task and handler files, for the checks that scan roles.

The scan of the tasks, the module a task calls and the role or file an include names is
written once, here, and the checks that read roles call it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

from ruamel.yaml import YAML

CODE_AREAS = ("tasks", "handlers")
YAML_SUFFIXES = frozenset({".yml", ".yaml"})
BLOCK_KEYS = ("block", "rescue", "always")

YAML_LOADER = YAML(typ="safe")

# The keywords of a task. Any other key of a task is the module it calls, so a module this
# list does not know is read as a module: the checks that screen tasks then fail closed.
TASK_KEYWORDS = frozenset(
    {
        "any_errors_fatal",
        "args",
        "async",
        "become",
        "become_exe",
        "become_flags",
        "become_method",
        "become_user",
        "changed_when",
        "check_mode",
        "collections",
        "connection",
        "debugger",
        "delay",
        "delegate_facts",
        "delegate_to",
        "diff",
        "environment",
        "failed_when",
        "ignore_errors",
        "ignore_unreachable",
        "listen",
        "loop",
        "loop_control",
        "module_defaults",
        "name",
        "no_log",
        "notify",
        "poll",
        "port",
        "register",
        "remote_user",
        "retries",
        "run_once",
        "tags",
        "throttle",
        "timeout",
        "until",
        "vars",
        "when",
        *BLOCK_KEYS,
    }
)
WRAPPING_KEYS = frozenset({"action", "local_action"})
TASK_FILE_MODULES = frozenset({"include_tasks", "import_tasks"})
ROLE_MODULES = frozenset({"include_role", "import_role"})

# The name an include gives its target. The only form that reaches the role from every
# working directory is a path built from the caller's own role_path.
SIBLING_BY_PATH = re.compile(
    r"\{\{\s*role_path\s*\|\s*realpath\s*\|\s*dirname\s*\}\}/([a-z][a-z0-9_]*)"
)
WHOLE_VARIABLE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
BARE_ROLE_NAME = re.compile(r"[a-z][a-z0-9_]*")
OWN_FILE_PATH = re.compile(
    r"(?P<rooted>\{\{\s*role_path\s*\}\}/)?(?P<path>[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)"
)
KEY_VALUE = re.compile(r"(?:^|\s)(\w+)=(\S+)")
MAX_VARIABLE_HOPS = 5


@dataclass(frozen=True)
class Target:
    """The role an include names: its directory name, and whether the name is a path."""

    name: str
    by_path: bool


def short_name(key: str) -> str:
    """Return the module name of a task key: ``ansible.builtin.copy`` is ``copy``."""
    return key.rsplit(".", 1)[-1]


def tasks_in(items: object) -> Iterator[Mapping[str, object]]:
    """Yield every task of a parsed task list, going into blocks, rescues and always sections."""
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, Mapping):
            continue
        yield item
        for key in BLOCK_KEYS:
            yield from tasks_in(item.get(key))


def parsed_tasks(role: Path) -> Iterator[tuple[str, Mapping[str, object]]]:
    """Yield the file name and each task of a role's task and handler files."""
    for area in CODE_AREAS:
        base = role / area
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in YAML_SUFFIXES:
                name = path.relative_to(role).as_posix()
                for task in tasks_in(YAML_LOADER.load(path.read_text(encoding="utf-8"))):
                    yield name, task


def task_modules(task: Mapping[str, object]) -> list[tuple[str, object]]:
    """Return each module a task calls, by short name, with its arguments.

    ``action:`` and ``local_action:`` are read by the module word they carry (the first word
    of a string, or the ``module`` key of a mapping), not as a module called ``action``.
    """
    found: list[tuple[str, object]] = []
    for key, value in task.items():
        word = str(key)
        if word in TASK_KEYWORDS or word.startswith("with_"):
            continue
        if word not in WRAPPING_KEYS:
            found.append((short_name(word), value))
        elif isinstance(value, str) and value.split():
            module, _, rest = value.strip().partition(" ")
            found.append((short_name(module), rest.strip()))
        elif isinstance(value, Mapping) and isinstance(value.get("module"), str):
            rest_of = {key: item for key, item in value.items() if key != "module"}
            found.append((short_name(str(value["module"])), rest_of))
        else:
            found.append((word, value))
    return found


def text_of(value: object) -> str:
    """Return a value as one text, so a pattern can be searched in all of it."""
    return repr(value)


def mapping_at(path: Path, *keys: str) -> Mapping[str, object]:
    """Return the mapping found by following keys in a YAML file, or an empty one.

    The one reader of a role's YAML file as a mapping: it is empty when the file is absent or
    holds anything but a mapping at the end of the keys.
    """
    value: object = YAML_LOADER.load(path.read_text(encoding="utf-8")) if path.is_file() else None
    for key in keys:
        value = value.get(key) if isinstance(value, Mapping) else None
    return value if isinstance(value, Mapping) else {}


def role_vars(role: Path) -> Mapping[str, object]:
    """Return the variables a role sets in ``vars/main.yml`` and ``defaults/main.yml``."""
    merged: dict[str, object] = {}
    for area in ("defaults", "vars"):
        loaded = mapping_at(role / area / "main.yml")
        merged.update({str(key): value for key, value in loaded.items()})
    return merged


def included_role(role: Path, name: object, hops: int = MAX_VARIABLE_HOPS) -> Target | None:
    """Return the role an include of ``role`` names, or None when the name cannot be resolved.

    A variable is read from the including role's own ``vars/`` and ``defaults/``; a name
    built from anything else cannot be shown to name one role, so the checks report it.
    """
    if not isinstance(name, str):
        return None
    text = name.strip()
    sibling = SIBLING_BY_PATH.fullmatch(text)
    if sibling:
        return Target(sibling.group(1), by_path=True)
    variable = WHOLE_VARIABLE.fullmatch(text)
    if variable and hops > 0:
        return included_role(role, role_vars(role).get(variable.group(1)), hops - 1)
    if BARE_ROLE_NAME.fullmatch(text):
        return Target(text, by_path=False)
    return None


def role_call(arguments: object) -> tuple[object, str]:
    """Return the name and the entry point (``tasks_from``, else ``main``) of an include_role."""
    given: Mapping[str, object] = {}
    if isinstance(arguments, Mapping):
        given = {str(key): value for key, value in arguments.items()}
    elif isinstance(arguments, str):
        given = dict(KEY_VALUE.findall(arguments))
    return given.get("name"), str(given.get("tasks_from", "main")).removesuffix(".yml")


def own_file(role: Path, arguments: object) -> bool:
    """Say whether an include_tasks or import_tasks names a literal file the scan reads.

    The path is a YAML file, relative and with no ``..``, or ``{{ role_path }}/`` and then the
    same. The scan reads only ``tasks/`` and ``handlers/`` (``CODE_AREAS``), so the file must
    be there: a rooted path must start with one of them, and a relative path must not also
    name a file anywhere else in the role, where Ansible might find it instead. A computed
    path cannot be shown to stay inside the role, so it is not an own file.
    """
    path = arguments
    if isinstance(arguments, Mapping):
        path = arguments.get("file", arguments.get("_raw_params"))
    if not isinstance(path, str):
        return False
    match = OWN_FILE_PATH.fullmatch(path.strip())
    if not match:
        return False
    relative = match.group("path")
    parts = relative.split("/")
    if ".." in parts or Path(relative).suffix not in YAML_SUFFIXES:
        return False
    if match.group("rooted"):
        return parts[0] in CODE_AREAS
    candidates = [role / area / relative for area in CODE_AREAS] + [role / relative]
    return all(
        candidate.relative_to(role).parts[0] in CODE_AREAS
        for candidate in candidates
        if candidate.is_file()
    )
