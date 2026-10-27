"""Check that tunnel_account_inputs_ancestors is the parents of tunnel_account_inputs_dir.

The role refuses an input path whose parent is not root's, so the list of parents must
match the inputs path exactly, root first. Both values are read from the role's vars and
resolved from the `{{ name }}` references between them, so a change to either one that
leaves the other behind fails here rather than in a run on a host.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path, PurePosixPath

from check_pins import load_yaml

ROOT = Path(__file__).resolve().parents[2]
VARS = ROOT / "ansible" / "roles" / "tunnel_account" / "vars" / "main.yml"
VARIABLE = re.compile(r"\{\{\s*([A-Za-z_]\w*)\s*\}\}")
DEPTH = 5


def _resolve(text: str, values: dict[str, object]) -> str:
    """Replace each plain `{{ name }}` with its value, a few levels deep."""
    for _ in range(DEPTH):
        text = VARIABLE.sub(lambda m: str(values.get(m[1], m[0])), text)
    return text


def check(vars_file: Path) -> list[str]:
    """Return one finding when the ancestor list is not the parents of the inputs directory."""
    document, problem = load_yaml(vars_file)
    if problem is not None or not isinstance(document, dict):
        return [f"{vars_file.name} cannot be read as a variables file"]
    inputs = _resolve(str(document.get("tunnel_account_inputs_dir", "")), document)
    listed = document.get("tunnel_account_inputs_ancestors")
    if not inputs.startswith("/") or not isinstance(listed, list):
        return [f"{vars_file.name} has no absolute tunnel_account_inputs_dir or no ancestor list"]
    expected = [parent.as_posix() for parent in reversed(PurePosixPath(inputs).parents)]
    actual = [_resolve(str(entry), document) for entry in listed]
    if actual == expected:
        return []
    return [
        "tunnel_account_inputs_ancestors is not the parents of "
        f"{inputs}: the list holds {actual}, the parents are {expected}"
    ]


def main() -> int:
    """Print the finding, if any, and return 1 if there is one."""
    findings = check(VARS)
    for finding in findings:
        print(f"FAIL {finding}")
    print(f"check_tunnel_account_ancestors: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
