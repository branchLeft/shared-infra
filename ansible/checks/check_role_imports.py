"""Check that no role imports another role (ANS-12): composition is in a playbook.

A role under ansible/roles or ansible/patterns may not apply, include or depend on another
role. The molecule/ directories are playbooks and may name roles. The check reads the literal
keys of tasks/, handlers/ and meta/; a role loaded through a templated name is not seen.
"""

from __future__ import annotations

import sys
from pathlib import Path

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
TREES = ("roles", "patterns")
READ_DIRS = ("tasks", "handlers", "meta")
ROLE_LOADERS = frozenset(("include_role", "import_role"))
FILE_LOADERS = frozenset(
    ("include_tasks", "import_tasks", "include_vars", "include", "import_playbook")
)


def _short(key: object) -> str:
    """Return a module key without its collection prefix, so every spelling matches."""
    return str(key).rsplit(".", 1)[-1]


def _walk(node: object, where: str, out: list[str]) -> None:
    """Add a finding for each import of a role found anywhere in ``node``."""
    if isinstance(node, list):
        for item in node:
            _walk(item, where, out)
    elif isinstance(node, dict):
        for key, value in node.items():
            name = _short(key)
            if name in ROLE_LOADERS or key == "roles":
                out.append(f"{where}: {key} applies another role")
            elif name in FILE_LOADERS and ".." in str(value):
                out.append(f"{where}: {key} reaches outside the role: {value}")
            _walk(value, where, out)


def check(root: Path) -> list[str]:
    """Return one finding per way a role under ``root`` imports another role."""
    findings: list[str] = []
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
                        _walk(document, where, findings)
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
