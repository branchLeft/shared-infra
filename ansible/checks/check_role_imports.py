"""Check that no role imports another role except as a capability role (ANS-12).

A role under ansible/roles or ansible/patterns may not apply, import or depend on another
role, with one exception: it may include (include_role) a capability role, a role that
declares its inputs in meta/argument_specs.yml, is given every input, owns no service and
restarts nothing, and whose README names the roles that call it. Any other composition is in
a playbook. The molecule/ directories are playbooks and may name roles. The check reads the
literal keys of tasks/, handlers/ and meta/; a role loaded through a templated name is not
seen, and a templated include_role name is refused.

The inputs are the task's own ``vars`` keyword beside include_role; a ``vars`` inside the
include_role mapping, or on an enclosing block, is refused. "Restarts" is read from notify and
service-module tasks only: a restart through command, shell or a Compose tool is review only.
Review only, not checked here: that a capability role writes only the paths its inputs name.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
TREES = ("roles", "patterns")
READ_DIRS = ("tasks", "handlers", "meta")
ROLE_LOADERS = frozenset(("include_role", "import_role"))
FILE_LOADERS = frozenset(
    ("include_tasks", "import_tasks", "include_vars", "include", "import_playbook")
)
SERVICE_MODULES = frozenset(("service", "systemd", "systemd_service", "sysvinit"))
ROLE_NAME = re.compile(r"[a-z][a-z0-9_]*")


@dataclass
class Scan:
    """What one role's files say, and the capability roles it includes."""

    root: Path
    caller: str
    where: str
    findings: list[str]
    callees: set[str] = field(default_factory=set)


def _short(key: object) -> str:
    """Return a module key without its collection prefix, so every spelling matches."""
    return str(key).rsplit(".", 1)[-1]


def _role_dir(root: Path, name: object) -> Path | None:
    """Return the directory of the role called ``name`` in this repository, or None."""
    if not isinstance(name, str) or not ROLE_NAME.fullmatch(name):
        return None
    for tree in TREES:
        candidate = root / "ansible" / tree / name
        if candidate.is_dir():
            return candidate
    return None


def _inputs(role: Path) -> frozenset[str] | None:
    """Return the input names a capability role declares, or None if it is not one."""
    path = role / "meta" / "argument_specs.yml"
    if not path.is_file():
        return None
    document, problem = load_yaml(path)
    if problem is not None or not isinstance(document, dict):
        return None
    specs = document.get("argument_specs")
    main = specs.get("main") if isinstance(specs, dict) else None
    if not isinstance(main, dict):
        return None
    options = main.get("options") or {}
    return frozenset(str(key) for key in options) if isinstance(options, dict) else None


def _restarts(role: Path) -> list[str]:
    """Return the places a capability role notifies a handler or runs a service module."""
    found: list[str] = []

    def visit(node: object, where: str) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item, where)
        elif isinstance(node, dict):
            for key, value in node.items():
                if key == "notify" or _short(key) in SERVICE_MODULES:
                    found.append(f"{where}: {key}")
                visit(value, where)

    for directory in ("tasks", "handlers"):
        for path in sorted((role / directory).rglob("*.y*ml")):
            document, problem = load_yaml(path)
            if problem is None:
                visit(document, path.name)
    return found


def _include_problem(scan: Scan, args: object, task: dict[object, object]) -> str | None:
    """Return why an include_role is refused, or None when it names a capability role fully.

    The inputs are the task's own ``vars`` keyword, beside ``include_role``: Ansible rejects a
    ``vars`` inside the include_role mapping. A ``vars`` on an enclosing block is not counted.
    """
    if not isinstance(args, dict):
        return f"{scan.where}: include_role must name its role and inputs as a mapping"
    if "vars" in args:
        return f"{scan.where}: include_role takes vars as a task keyword, not inside its mapping"
    name = args.get("name")
    role = _role_dir(scan.root, name)
    if role is None:
        return f"{scan.where}: include_role names {name!r}, which is not a role in this repository"
    inputs = _inputs(role)
    if inputs is None:
        return f"{scan.where}: include_role names {name}, which is not a capability role"
    given = task.get("vars")
    given_names = set(given) if isinstance(given, dict) else set()
    missing = sorted(inputs - given_names)
    if missing:
        return f"{scan.where}: include_role {name} does not give every input: {', '.join(missing)}"
    restarts = _restarts(role)
    if restarts:
        return f"{scan.where}: include_role {name} restarts or reloads: {restarts[0]}"
    scan.callees.add(str(name))
    return None


def _walk(node: object, scan: Scan) -> None:
    """Add a finding for each import of a role found anywhere in ``node``."""
    if isinstance(node, list):
        for item in node:
            _walk(item, scan)
    elif isinstance(node, dict):
        for key, value in node.items():
            name = _short(key)
            if name == "include_role" and key != "roles":
                problem = _include_problem(scan, value, node)
                if problem is not None:
                    scan.findings.append(problem)
            elif name in ROLE_LOADERS or key == "roles":
                scan.findings.append(f"{scan.where}: {key} applies another role")
            elif name in FILE_LOADERS and ".." in str(value):
                scan.findings.append(f"{scan.where}: {key} reaches outside the role: {value}")
            _walk(value, scan)


def _readme_findings(root: Path, callers: dict[str, set[str]]) -> list[str]:
    """Return a finding for each capability role whose README does not name a caller."""
    findings: list[str] = []
    for callee, names in sorted(callers.items()):
        role = _role_dir(root, callee)
        readme = role / "README.md" if role is not None else None
        text = readme.read_text(encoding="utf-8") if readme and readme.is_file() else ""
        for caller in sorted(names):
            if not re.search(rf"\b{re.escape(caller)}\b", text):
                findings.append(f"{callee}/README.md does not name its caller {caller}")
    return findings


def check(root: Path) -> list[str]:
    """Return one finding per way a role under ``root`` imports another role."""
    findings: list[str] = []
    callers: dict[str, set[str]] = {}
    for tree in TREES:
        for role in sorted(path for path in (root / "ansible" / tree).glob("*") if path.is_dir()):
            for directory in READ_DIRS:
                for path in sorted((role / directory).rglob("*.y*ml")):
                    where = path.relative_to(root).as_posix()
                    document, problem = load_yaml(path)
                    if problem is not None:
                        findings.append(f"{where}: {problem}")
                    elif directory == "meta":
                        if isinstance(document, dict) and document.get("dependencies"):
                            findings.append(f"{where}: dependencies name another role")
                    elif directory != "meta":
                        scan = Scan(root, role.name, where, findings)
                        _walk(document, scan)
                        for callee in scan.callees:
                            callers.setdefault(callee, set()).add(role.name)
    findings.extend(_readme_findings(root, callers))
    return findings


def main() -> int:
    """Print every finding and return 1 if there is one."""
    findings = check(ROOT)
    for finding in findings:
        print(f"FAIL {finding}")
    print(f"check_role_imports: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
