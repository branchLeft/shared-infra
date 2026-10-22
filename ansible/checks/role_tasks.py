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


def var_names(task: Mapping[str, object]) -> frozenset[str]:
    """Return the names a task sets in its ``vars``: what it hands to every task it holds."""
    given = task.get("vars")
    return frozenset(str(key) for key in (given if isinstance(given, Mapping) else ()))


def tasks_in(
    items: object, inherited: frozenset[str] = frozenset()
) -> Iterator[tuple[Mapping[str, object], frozenset[str]]]:
    """Yield every task of a parsed task list, going into blocks, rescues and always sections.

    Each task comes with the names of the vars the blocks around it set, because those reach
    the task (and any role it includes) as its own do.
    """
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, Mapping):
            continue
        yield item, inherited
        for key in BLOCK_KEYS:
            yield from tasks_in(item.get(key), inherited | var_names(item))


def task_files(role: Path) -> list[tuple[str, Path]]:
    """Return the name and path of each task and handler file the scan reads."""
    found: list[tuple[str, Path]] = []
    for area in CODE_AREAS:
        base = role / area
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in YAML_SUFFIXES:
                found.append((path.relative_to(role).as_posix(), path))
    return found


def parsed_tasks_with_inputs(
    role: Path,
) -> Iterator[tuple[str, Mapping[str, object], frozenset[str]]]:
    """Yield the file name, each task and the names of the vars that reach it from above.

    Above a task are the blocks around it and the ``include_tasks`` or ``import_tasks`` that
    name its file, whatever file that is, as many levels up as there are: all of their vars
    reach the task, and so reach an ``include_role`` in it.
    """
    files = task_files(role)
    loaded = {
        name: list(tasks_in(YAML_LOADER.load(path.read_text(encoding="utf-8"))))
        for name, path in files
    }
    names_at: dict[Path, list[str]] = {}
    for name, path in files:
        names_at.setdefault(path.resolve(), []).append(name)
    reaching: dict[str, frozenset[str]] = {name: frozenset() for name in loaded}
    changed = True
    while changed:
        changed = False
        for name, entries in loaded.items():
            for task, around in entries:
                passed = reaching[name] | around | var_names(task)
                for module, arguments in task_modules(task):
                    if module not in TASK_FILE_MODULES:
                        continue
                    for path in own_files(role, arguments):
                        for target in names_at.get(path.resolve(), ()):
                            if not passed <= reaching[target]:
                                reaching[target] = reaching[target] | passed
                                changed = True
    for name, entries in loaded.items():
        for task, around in entries:
            yield name, task, reaching[name] | around


def parsed_tasks(role: Path) -> Iterator[tuple[str, Mapping[str, object]]]:
    """Yield the file name and each task of a role's task and handler files."""
    for name, task, _ in parsed_tasks_with_inputs(role):
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


def option_specs(options: object, prefix: str = "") -> Iterator[tuple[str, object]]:
    """Yield the path and spec of every option of an ``argument_specs`` entry, at any depth.

    An option of a list element or of a dictionary is an input like any other (ANS-12), so the
    walk goes into every ``options`` it finds. A path names the way down: ``classes[].gate`` is
    the option ``gate`` of each element of the list ``classes``, ``group.mode`` an option of
    the dictionary ``group``.
    """
    if not isinstance(options, Mapping):
        return
    for key, spec in options.items():
        path = f"{prefix}{key}"
        yield path, spec
        if isinstance(spec, Mapping):
            joint = "[]." if spec.get("type") == "list" else "."
            yield from option_specs(spec.get("options"), f"{path}{joint}")


def options_without_default(options: object) -> list[str]:
    """Return the path of every option that is neither ``required: true`` nor has a default.

    The words are those of ANS-12. An option is optional when it is not ``required: true``. It
    has a default when its spec has a ``default`` key, whatever the value: ``false``, ``0`` and
    ``null`` count, and a default that is only in ``defaults/main.yml``, in group vars or in the
    caller's vars does not, because it is not in the spec. A spec that is not a mapping states
    neither, so its option is reported.
    """
    return [
        path
        for path, spec in option_specs(options)
        if not (isinstance(spec, Mapping) and (spec.get("required") is True or "default" in spec))
    ]


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


def read_by_the_scan(role: Path, candidate: Path) -> bool:
    """Say whether a file, once its links are followed, is one under ``tasks/`` or ``handlers/``.

    The scan lists those two directories and does not go into a linked directory, so only the
    resolved path shows whether it reads the file an include would run.
    """
    resolved = candidate.resolve()
    return any(resolved.is_relative_to((role / area).resolve()) for area in CODE_AREAS)


def own_files(role: Path, arguments: object) -> list[Path]:
    """Return the files an include_tasks or import_tasks may run, none unless the scan reads all.

    The path is a YAML file, relative and with no ``..``, or ``{{ role_path }}/`` and then the
    same. The scan reads only ``tasks/`` and ``handlers/`` (``CODE_AREAS``), so the file must
    exist there, once links are followed. Where Ansible looks for a relative path is in the
    role and then in the playbook's directory and the working directory, which the scan does
    not read: a path that names no file in the role is not an own file. Nor is one that also
    names a file elsewhere in the role, where Ansible might find it instead. A computed path
    cannot be shown to stay inside the role either, so it names none.
    """
    path = arguments
    if isinstance(arguments, Mapping):
        path = arguments.get("file", arguments.get("_raw_params"))
    if not isinstance(path, str):
        return []
    match = OWN_FILE_PATH.fullmatch(path.strip())
    if not match:
        return []
    relative = match.group("path")
    parts = relative.split("/")
    if ".." in parts or Path(relative).suffix not in YAML_SUFFIXES:
        return []
    if match.group("rooted"):
        if parts[0] not in CODE_AREAS:
            return []
        candidates = [role / relative]
    else:
        candidates = [role / area / relative for area in CODE_AREAS] + [role / relative]
    found = [candidate for candidate in candidates if candidate.is_file()]
    return found if all(read_by_the_scan(role, candidate) for candidate in found) else []


def own_file(role: Path, arguments: object) -> bool:
    """Say whether an include_tasks or import_tasks names a file, and only files, the scan reads."""
    return bool(own_files(role, arguments))
