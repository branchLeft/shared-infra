"""Read the tasks of a role's task and handler files, for the checks that scan roles.

The scan of the tasks is written once, here, and the checks that read roles call it.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from pathlib import Path

from ruamel.yaml import YAML

CODE_AREAS = ("tasks", "handlers")
BLOCK_KEYS = ("block", "rescue", "always")

YAML_LOADER = YAML(typ="safe")


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
            if path.is_file() and path.suffix in {".yml", ".yaml"}:
                name = path.relative_to(role).as_posix()
                for task in tasks_in(YAML_LOADER.load(path.read_text(encoding="utf-8"))):
                    yield name, task
