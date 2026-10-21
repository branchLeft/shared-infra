"""Check the toolchain lock and the route that keeps it current (ANS-4).

It fails on anything ansible/README.md lists under "How a check proves the lock".
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# install_runtime.py is the one home of the lock reader and of the marker set. It runs alone on
# the host under python3 -I, with nothing installed, so it cannot be imported from here. This
# file loads it by path and keeps no copy, so a change to the reader is the change this checks.
RUNTIME_PROGRAM = (
    REPO_ROOT / "ansible" / "roles" / "ansible_runtime" / "files" / "install_runtime.py"
)


def load_runtime_program() -> ModuleType:
    """Load install_runtime.py by path under its own name and return the module.

    Raises:
        ImportError: The file cannot be loaded as a module.
    """
    spec = importlib.util.spec_from_file_location("install_runtime", RUNTIME_PROGRAM)
    if spec is None or spec.loader is None:
        raise ImportError(RUNTIME_PROGRAM.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RUNTIME: ModuleType = load_runtime_program()
# These three come from the program and are not copied: the reader that joins the lock's lines,
# the encoding check that runs before it, and the set of characters a marker may hold. The
# patterns below (REQUIREMENT, VERSION, HASH) are this check's own: the program's patterns say
# what it will install, these say what the lock must also be (a pin of a named tool).
logical_lines = RUNTIME.logical_lines
check_lock_encoding = RUNTIME.check_lock_encoding
MARKER_CHARS: str = RUNTIME.MARKER_CHARS

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
    rf"(?: ?; ?{MARKER_CHARS}+?)?"
    r"(?P<hashes>(?: +--hash=sha256:[0-9a-f]{64})*)",
    re.ASCII,
)
HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}", re.ASCII)

# The chosen packages live in requirements.in, one exact pin per line, and the
# lock is compiled from it with `uv pip compile`. ansible-core is not chosen:
# the `ansible` package fixes its release, so it is in the lock and not here.
INPUT_FILE = "requirements.in"
INPUT_TOOLS = REQUIRED_TOOLS - {"ansible-core"}
INPUT_LINE = re.compile(
    rf"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9._,-]+\])?==(?P<version>{VERSION})",
    re.ASCII,
)
# A lock entry starts in column 0; its hashes and `# via` comments are indented.
ENTRY_START = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9._,-]+\])?==")
# What the header uv writes must say. Dependabot reads --universal and the Python
# version from it when it recompiles the lock, and keeps the header as it is.
HEADER_FACTS = (
    ("uv pip compile", r"uv pip compile"),
    (INPUT_FILE, r"uv pip compile " + re.escape(INPUT_FILE)),
    ("--universal", r"--universal"),
    ("--generate-hashes", r"--generate-hashes"),
    ("--python-version", r"--python-version \d+\.\d+"),
)

LINT_REPOSITORY = "https://github.com/ansible/ansible-lint"
# Where Dependabot must watch the lock: it is the only thing that raises a bump
# of the package that carries the collections. The `uv` ecosystem is the one that
# recompiles a `uv pip compile` lock from requirements.in; `pip` would run
# pip-compile, which cannot write a universal lock.
UPDATE_ECOSYSTEM = "uv"
UPDATE_DIRECTORY = "/ansible"
# Anything that makes a copy of a collection live in git hides it from the lock.
COPY_SUFFIXES = (".tar.gz", ".tgz", ".tar")


def locked_packages(requirements: Path) -> tuple[dict[str, str], list[str]]:
    """Return the locked versions by normalised name, and a finding for every line not locked."""
    findings: list[str] = []
    pins: dict[str, str] = {}
    try:
        data = requirements.read_bytes()
    except OSError as error:
        return pins, [f"{requirements.name} cannot be read: {type(error).__name__}"]
    try:
        check_lock_encoding(data)
    except RUNTIME.Refusal as refusal:
        return pins, [f"{requirements.name} {refusal.reason.value} ({refusal.detail})"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return pins, [f"{requirements.name} is not UTF-8 text"]
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


def normalise(name: str) -> str:
    """Return a package name in the form pip compares it."""
    return re.sub(r"[-_.]+", "-", name).lower()


def read_input(path: Path) -> tuple[dict[str, str], list[str]]:
    """Return the chosen packages of requirements.in, each an exact pin without hashes."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return {}, [f"{path.name} cannot be read: {type(error).__name__}"]
    chosen: dict[str, str] = {}
    findings: list[str] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = INPUT_LINE.fullmatch(line)
        if match is None:
            findings.append(f"{path.name} line {number} is not an exact name==version: {line!r}")
            continue
        name = normalise(match["name"])
        if name in chosen:
            findings.append(f"{path.name} line {number} names {name} a second time")
        chosen[name] = match["version"]
    findings.extend(
        f"{path.name} does not name {name}" for name in sorted(INPUT_TOOLS - chosen.keys())
    )
    return chosen, findings


def header_text(text: str) -> str:
    """Return the comment lines at the top of a file, joined."""
    lines: list[str] = []
    for line in text.splitlines():
        if not line.startswith("#"):
            break
        lines.append(line)
    return " ".join(lines)


def check_header(text: str) -> list[str]:
    """Check the lock's own header records the command that makes it reproducible."""
    header = header_text(text)
    return [
        f"requirements.txt header does not record {what}"
        for what, pattern in HEADER_FACTS
        if re.search(pattern, header, re.ASCII) is None
    ]


def lock_entries(text: str) -> list[tuple[str, str]]:
    """Return each lock entry's name and the comment lines that follow it."""
    entries: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        match = ENTRY_START.match(line)
        if match is not None:
            entries.append((normalise(match["name"]), []))
        elif entries and line.strip().startswith("#"):
            entries[-1][1].append(line.strip())
    return [(name, " ".join(comments)) for name, comments in entries]


def check_provenance(ansible_dir: Path, pins: dict[str, str]) -> list[str]:
    """Check requirements.in, the lock's header and its `# via` comments explain every line."""
    chosen, findings = read_input(ansible_dir / INPUT_FILE)
    try:
        text = (ansible_dir / "requirements.txt").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return findings
    findings.extend(check_header(text))
    direct: set[str] = set()
    for name, via in lock_entries(text):
        if "# via" not in via:
            findings.append(f"requirements.txt pins {name} with no '# via' comment")
        if f"-r {INPUT_FILE}" in via:
            direct.add(name)
    findings.extend(
        f"requirements.txt marks {name} as chosen but {INPUT_FILE} does not name it"
        for name in sorted(direct - chosen.keys())
    )
    findings.extend(
        f"{INPUT_FILE} names {name} but requirements.txt does not mark it '-r {INPUT_FILE}'"
        for name in sorted(chosen.keys() - direct)
    )
    findings.extend(
        f"{INPUT_FILE} pins {name} {version}, requirements.txt has {pins[name]}"
        for name, version in sorted(chosen.items())
        if name in pins and pins[name] != version
    )
    return findings


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
            and entry.get("package-ecosystem") == UPDATE_ECOSYSTEM
            and entry.get("directory") == UPDATE_DIRECTORY
            and isinstance(entry.get("schedule"), dict)
        ):
            return []
    return [f"{config.name} has no scheduled {UPDATE_ECOSYSTEM} update for {UPDATE_DIRECTORY}"]


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
    findings.extend(check_provenance(ansible_dir, pins))
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
