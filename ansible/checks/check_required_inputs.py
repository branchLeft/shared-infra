"""Every required input of a role a host applies must come from somewhere on that host.

A role's argument spec marks an input required, with no default. A pulled host passes no argument,
so the input must be supplied by one of these, all of them visible in the tree:

- the role's own defaults;
- the play's own vars;
- the role entry's own vars in the playbook;
- the host's row of the host_inputs loader, when the loader is applied earlier in the same play
  (the loader sets its facts only then, so a row after the role supplies nothing).

An input with none of these stops the host's run at the role's argument check, and that stop is
seen only by a plan on the host. This check finds it in the tree instead.

Usage (from the repository root, with the tool environment's interpreter):

    python ansible/checks/check_required_inputs.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
LOADER = "host_inputs"
ROW_VAR = "host_inputs_required_by_host"
OPTIONAL_VAR = "host_inputs_optional_by_host"


def _load(path: Path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None


def _mapping(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    return {}


def _items(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def _names(value: object) -> set[str]:
    return {str(item) for item in value} if isinstance(value, list) else set()


def required_inputs(role_dir: Path) -> set[str]:
    """The names the role's main entry point requires with no default."""
    main = _mapping(_mapping(_load(role_dir / "meta" / "argument_specs.yml")).get("argument_specs"))
    options = _mapping(_mapping(main.get("main")).get("options"))
    found: set[str] = set()
    for name, spec in options.items():
        body = _mapping(spec)
        if body.get("required") is True and "default" not in body:
            found.add(name)
    return found


def defaulted_names(role_dir: Path) -> set[str]:
    """The names the role's own defaults and its own vars set, which a caller need not pass."""
    return set(_mapping(_load(role_dir / "defaults" / "main.yml"))) | set(
        _mapping(_load(role_dir / "vars" / "main.yml"))
    )


def vars_file_names(playbook: Path, entries: list[str]) -> tuple[set[str], list[str]]:
    """The names the play's vars_files set, and the entries that do not resolve to a file."""
    names: set[str] = set()
    missing: list[str] = []
    for entry in entries:
        path = Path(entry.replace("{{ playbook_dir }}", str(playbook.parent)))
        if "{{" in str(path) or not path.is_file():
            missing.append(entry)
            continue
        names |= set(_mapping(_load(path)))
    return names, missing


def loader_rows(root: Path) -> dict[str, set[str]]:
    """Each host's row of the loader: its required names and its optional names."""
    loader = _mapping(_load(root / "ansible" / "roles" / LOADER / "vars" / "main.yml"))
    required = _mapping(loader.get(ROW_VAR))
    optional = _mapping(loader.get(OPTIONAL_VAR))
    hosts = set(required) | set(optional)
    return {host: _names(required.get(host, [])) | _names(optional.get(host, [])) for host in hosts}


def play_roles(playbook: Path) -> tuple[set[str], list[str], list[tuple[str, str, set[str]]]]:
    """The play's own var names, its vars_files entries, and each role entry in order as
    (role path, role name, vars). A playbook that is not one play yields nothing to check."""
    loaded = _load(playbook)
    if not isinstance(loaded, list) or len(loaded) != 1:
        return set(), [], []
    play = _mapping(loaded[0])
    entries: list[tuple[str, str, set[str]]] = []
    for entry in _items(play.get("roles")):
        if isinstance(entry, str):
            path, role_vars = entry, set()
        else:
            body = _mapping(entry)
            path = str(body.get("role", ""))
            role_vars = set(_mapping(body.get("vars")))
        entries.append((path, Path(path).name, role_vars))
    files = [str(item) for item in _items(play.get("vars_files"))]
    return set(_mapping(play.get("vars"))), files, entries


def findings(root: Path = ROOT) -> list[str]:
    """One line per required input that a host's role needs and nothing on the host supplies."""
    playbooks = root / "ansible" / "playbooks"
    rows = loader_rows(root)
    found: list[str] = []
    for playbook in sorted(playbooks.glob("*.yml")):
        host = playbook.stem
        play_vars, files, entries = play_roles(playbook)
        file_names, unresolved = vars_file_names(playbook, files)
        for entry in unresolved:
            found.append(f"{host}: vars_files entry {entry} does not resolve to a file")
        play_vars = play_vars | file_names
        loader_at = next((i for i, (_, name, _) in enumerate(entries) if name == LOADER), None)
        row = rows.get(host, set())
        for index, (path, name, entry_vars) in enumerate(entries):
            role_dir = (playbook.parent / path).resolve()
            if not role_dir.is_dir():
                found.append(f"{host}: role path {path} is not a directory")
                continue
            supplied = defaulted_names(role_dir) | play_vars | entry_vars
            if loader_at is not None and loader_at < index:
                supplied |= row
            for needed in sorted(required_inputs(role_dir) - supplied):
                found.append(
                    f"{host}: role {name} requires {needed}, which neither its defaults or vars, "
                    f"the play or its vars_files, the role entry nor {host}'s host_inputs row "
                    "(loaded earlier) supplies"
                )
    return found


def main(argv: list[str]) -> int:
    """Usage: check_required_inputs.py [--root DIR], DIR defaulting to the repository."""
    if argv and not (len(argv) == 2 and argv[0] == "--root"):
        print("usage: check_required_inputs.py [--root DIR]", file=sys.stderr)
        return 2
    root = Path(argv[1]) if argv else ROOT
    problems = findings(root)
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
