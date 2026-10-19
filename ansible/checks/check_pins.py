"""Check the toolchain lock and the route that keeps it current (ANS-4).

It fails on anything ansible/README.md lists under "How a check proves the lock".
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# The community package carries the collections, so it is pinned like a tool.
# The others are the tools ANS-4 names and yamllint, which the harness runs
# (ANS-6).
REQUIRED_TOOLS = frozenset(
    {
        "ansible",
        "ansible-core",
        "ansible-lint",
        "molecule",
        "molecule-plugins",
        "mypy",
        "ruff",
        "yamllint",
    }
)
# Used with fullmatch and in ASCII mode: a trailing newline or a digit from
# another script is not part of a version or a hash. A lock line holds a name, an
# optional extras list, an exact version, an optional environment marker (which
# narrows where the pin applies and never loosens it) and one or more hashes.
VERSION = r"\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?"
REQUIREMENT = re.compile(
    rf"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9._,-]+\])?==(?P<version>{VERSION})"
    r"(?: ?; ?[A-Za-z0-9_.'\" =!<>()]+?)?"
    r"(?P<hashes>(?: +--hash=sha256:[0-9a-f]{64})*)",
    re.ASCII,
)
HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}", re.ASCII)

LINT_REPOSITORY = "https://github.com/ansible/ansible-lint"
# Where Dependabot must watch the lock: it is the only thing that raises a bump
# of the package that carries the collections.
UPDATE_DIRECTORY = "/ansible"
# Anything that makes a copy of a collection live in git hides it from the lock.
COPY_SUFFIXES = (".tar.gz", ".tgz", ".tar")


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Return the requirement lines of a pip file, with backslash continuations joined."""
    joined: list[tuple[int, str]] = []
    pending = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1].rstrip() + " "
            continue
        joined.append((start, (pending + line).strip()))
        pending = ""
    if pending:
        joined.append((start, pending.strip()))
    return joined


def locked_packages(requirements: Path) -> tuple[dict[str, str], list[str]]:
    """Return the locked versions by normalised name, and a finding for every line not locked."""
    findings: list[str] = []
    pins: dict[str, str] = {}
    try:
        text = requirements.read_text(encoding="utf-8")
    except OSError as error:
        return pins, [f"{requirements.name} cannot be read: {type(error).__name__}"]
    for number, line in logical_lines(text):
        match = REQUIREMENT.fullmatch(line)
        if match is None:
            findings.append(f"{requirements.name} line {number} is not name==version: {line!r}")
            continue
        name = re.sub(r"[-_.]+", "-", match["name"]).lower()
        if not HASH.search(match["hashes"]):
            findings.append(f"{requirements.name} line {number} pins {name} with no --hash")
        if name in pins:
            findings.append(f"{requirements.name} line {number} pins {name} a second time")
        pins[name] = match["version"]
    findings.extend(
        f"{requirements.name} does not pin {name}" for name in sorted(REQUIRED_TOOLS - pins.keys())
    )
    return pins, findings


def load_yaml(path: Path) -> tuple[object, str | None]:
    """Return the parsed YAML in ``path``, or a finding saying why it could not be read."""
    try:
        document: object = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    except (OSError, YAMLError) as error:
        return None, f"{path.name} cannot be read as YAML: {type(error).__name__}"
    return document, None


def check_no_galaxy_collections(path: Path) -> list[str]:
    """Check requirements.yml lists no collection and no role: the lock is the one record."""
    document, problem = load_yaml(path)
    if problem is not None:
        return [problem]
    if not isinstance(document, dict) or document.get("collections") != []:
        return [f"{path.name} must hold only 'collections: []', the lock is requirements.txt"]
    extra = sorted(str(key) for key in document if key != "collections")
    return [f"{path.name} sets {key}; nothing is fetched outside the lock" for key in extra]


def check_no_copies(ansible_dir: Path) -> list[str]:
    """Check no collection copy (an archive or an ansible_collections tree) sits under ansible/."""
    found = sorted(
        item.relative_to(ansible_dir).as_posix()
        for item in ansible_dir.rglob("*")
        if item.name == "ansible_collections" or item.name.endswith(COPY_SUFFIXES)
    )
    return [f"{name} is a copy of third-party code; the lock carries collections" for name in found]


def check_dependabot(config: Path) -> list[str]:
    """Check Dependabot is set to watch the lock, so an upstream release raises a pull request."""
    document, problem = load_yaml(config)
    if problem is not None:
        return [problem]
    updates = document.get("updates") if isinstance(document, dict) else None
    entries = updates if isinstance(updates, list) else []
    for entry in entries:
        if (
            isinstance(entry, dict)
            and entry.get("package-ecosystem") == "pip"
            and entry.get("directory") == UPDATE_DIRECTORY
            and isinstance(entry.get("schedule"), dict)
        ):
            return []
    return [f"{config.name} has no scheduled pip update for {UPDATE_DIRECTORY}"]


def lint_hook_revs(config: Path) -> tuple[list[str], list[str]]:
    """Return the revs of the ansible-lint hook repositories, and a finding per odd one."""
    document, problem = load_yaml(config)
    if problem is not None:
        return [], [problem]
    repos = document.get("repos") if isinstance(document, dict) else None
    if not isinstance(repos, list):
        return [], [f"{config.name} has no repos list"]
    revs: list[str] = []
    findings: list[str] = []
    for repo in repos:
        url = repo.get("repo") if isinstance(repo, dict) else None
        if not isinstance(url, str) or url.rstrip("/").rsplit("/", 1)[-1] != "ansible-lint":
            continue
        if url != LINT_REPOSITORY:
            findings.append(f"{config.name} takes ansible-lint from {url}, not {LINT_REPOSITORY}")
        revs.append(str(repo.get("rev")))
    return revs, findings


def check_lint_rev(config: Path, pins: dict[str, str]) -> tuple[list[str], int]:
    """Check the ansible-lint hook rev equals the pin; return findings and the hooks compared."""
    revs, findings = lint_hook_revs(config)
    pin = pins.get("ansible-lint")
    findings.extend(
        f"{config.name} runs ansible-lint at {rev}, the requirements pin is v{pin}"
        for rev in revs
        if pin is not None and rev != f"v{pin}"
    )
    return findings, len(revs)


def check_scenarios(ansible_dir: Path) -> tuple[list[str], int]:
    """Check every scenario disables Molecule's dependency step; return findings and the count."""
    findings: list[str] = []
    scenarios = sorted(
        [
            *ansible_dir.glob("roles/*/molecule/*/molecule.yml"),
            *ansible_dir.glob("patterns/*/molecule/*/molecule.yml"),
            *ansible_dir.glob("role_skeleton/molecule/*/molecule.yml"),
        ]
    )
    for scenario in scenarios:
        document, problem = load_yaml(scenario)
        name = scenario.relative_to(ansible_dir).as_posix()
        dependency = document.get("dependency") if isinstance(document, dict) else None
        if problem is not None:
            findings.append(f"{name}: {problem}")
        elif not isinstance(dependency, dict) or dependency.get("enabled") is not False:
            findings.append(
                f"{name} does not set dependency.enabled to false, so the step could reach Galaxy"
            )
    return findings, len(scenarios)


def run_checks(root: Path) -> tuple[list[str], list[str]]:
    """Run every check under ``root``; return the findings and the notes."""
    ansible_dir = root / "ansible"
    pins, findings = locked_packages(ansible_dir / "requirements.txt")
    findings.extend(check_no_galaxy_collections(ansible_dir / "requirements.yml"))
    findings.extend(check_no_copies(ansible_dir))
    findings.extend(check_dependabot(root / ".github" / "dependabot.yml"))
    scenario_findings, scenarios = check_scenarios(ansible_dir)
    findings.extend(scenario_findings)
    hooks, compared = check_lint_rev(root / ".pre-commit-config.yaml", pins)
    findings.extend(hooks)
    notes = [f"{len(pins)} locked package(s) and {scenarios} scenario(s) read"]
    if compared == 0:
        notes.append("no ansible-lint hook in .pre-commit-config.yaml, so no rev was compared")
    return findings, notes


def main(argv: Sequence[str]) -> int:
    """Print every finding and return 1 if there is one."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", maxsplit=1)[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root to check")
    args = parser.parse_args(argv)
    findings, notes = run_checks(args.root)
    for finding in findings:
        print(f"FAIL {finding}")
    for note in notes:
        print(f"note {note}")
    print(f"check_pins: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
