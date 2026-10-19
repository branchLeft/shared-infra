"""Check the toolchain pins and the vendored collections (ANS-4).

It fails when a pin is not exact, when a vendored collection is not the one its
pin names or does not match its recorded hash, when a collection's own
dependencies are not pinned too, when ansible.cfg points Ansible anywhere but
the install directory, when a Molecule scenario leaves its dependency step on,
and when the pre-commit hook for ansible-lint is not at the version the
requirements file pins. ansible/README.md describes each rule.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import re
import sys
import tarfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# The tools ANS-4 names (ansible-core, ansible-lint, Molecule and its driver
# plugin, mypy, ruff) and yamllint, which the harness runs (ANS-6).
REQUIRED_TOOLS = frozenset(
    {
        "ansible-core",
        "ansible-lint",
        "molecule",
        "molecule-plugins",
        "mypy",
        "ruff",
        "yamllint",
    }
)
# Every pattern is used with fullmatch and in ASCII mode: a trailing newline or a
# digit from another script is not part of a version.
REQUIREMENT_LINE = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9._,-]+\])?==(?P<version>\d+(?:\.\d+)*)",
    re.ASCII,
)

# The vendored artifacts live next to nothing else, so a stray file is noise a
# reviewer must explain. The path is relative to the ansible/ directory, which
# is where ansible-galaxy resolves it from (see ansible/README.md).
VENDOR_DIRECTORY = "vendor/collections"
CHECKSUM_FILE = "SHA256SUMS"
ARTIFACT_NAME = re.compile(
    rf"{VENDOR_DIRECTORY}/(?P<namespace>[a-z0-9_]+)-(?P<name>[a-z0-9_]+)"
    r"-(?P<version>\d+\.\d+\.\d+)\.tar\.gz",
    re.ASCII,
)
EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+", re.ASCII)
CHECKSUM_LINE = re.compile(r"(?P<digest>[0-9a-f]{64}) {2}(?P<file>[^/\s]+)", re.ASCII)
MANIFEST_LIMIT = 1_000_000

# Where ansible.cfg sends Ansible and ansible-lint to find the installed copy.
INSTALL_DIRECTORY = ".ansible/collections"

LINT_REPOSITORY = "https://github.com/ansible/ansible-lint"


def pinned_tools(requirements: Path) -> tuple[dict[str, str], list[str]]:
    """Return the tool pins by normalised name, and a finding for every line not pinned exactly."""
    findings: list[str] = []
    pins: dict[str, str] = {}
    for number, line in enumerate(requirements.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        match = REQUIREMENT_LINE.fullmatch(line)
        if match is None:
            findings.append(f"{requirements.name} line {number} is not name==version: {line!r}")
            continue
        name = re.sub(r"[-_.]+", "-", match["name"]).lower()
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


def version_tuple(version: str) -> tuple[int, ...]:
    """Return the numeric parts of a dotted version."""
    return tuple(int(part) for part in version.split("."))


def meets(version: str, constraint: str) -> bool | None:
    """Say whether ``version`` satisfies a collection dependency constraint, None if unreadable."""
    have = version_tuple(version)
    for clause in constraint.split(","):
        clause = clause.strip()
        if clause == "*":
            continue
        match = re.fullmatch(r"(>=|<=|==|!=|>|<)\s*(\d+(?:\.\d+)*)", clause, re.ASCII)
        if match is None:
            return None
        want = version_tuple(match[2])
        outcomes = {
            ">=": have >= want,
            "<=": have <= want,
            "==": have == want,
            "!=": have != want,
            ">": have > want,
            "<": have < want,
        }
        if not outcomes[match[1]]:
            return False
    return True


def read_checksums(path: Path) -> tuple[dict[str, str], list[str]]:
    """Return the file-to-digest table of the checksum file, and a finding per bad line."""
    findings: list[str] = []
    digests: dict[str, str] = {}
    if not path.is_file():
        return digests, [f"{CHECKSUM_FILE} is missing"]
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            findings.append(f"{CHECKSUM_FILE} line {number} is not '<sha256>  <file>': {line!r}")
        elif match["file"] in digests:
            findings.append(f"{CHECKSUM_FILE} lists {match['file']} a second time")
        else:
            digests[match["file"]] = match["digest"]
    return digests, findings


def artifact_identity(artifact: Path) -> tuple[Mapping[str, object] | None, str | None]:
    """Return the collection_info of the artifact's own MANIFEST.json, or why it is unreadable."""
    try:
        with tarfile.open(artifact, "r:gz") as archive:
            member = archive.getmember("MANIFEST.json")
            if member.size > MANIFEST_LIMIT:
                return None, f"{artifact.name} has an oversized MANIFEST.json"
            handle = archive.extractfile(member)
            if handle is None:
                return None, f"{artifact.name} has no readable MANIFEST.json"
            document: object = json.loads(handle.read())
    except (OSError, KeyError, tarfile.TarError, ValueError) as error:
        return None, f"{artifact.name} has no readable MANIFEST.json ({type(error).__name__})"
    info = document.get("collection_info") if isinstance(document, Mapping) else None
    if not isinstance(info, Mapping):
        return None, f"{artifact.name} MANIFEST.json has no collection_info"
    return info, None


def check_entry(
    entry: object, ansible_dir: Path, digests: Mapping[str, str]
) -> tuple[str | None, str | None, Mapping[str, object], list[str]]:
    """Check one entry; return its collection, version, dependencies and findings."""
    if not isinstance(entry, Mapping):
        return None, None, {}, [f"requirements.yml has an entry that is not a mapping: {entry!r}"]
    label = str(entry.get("name"))
    findings: list[str] = []
    extra = sorted(str(key) for key in entry if key not in ("name", "version"))
    if extra:
        findings.append(f"{label} sets {', '.join(extra)}; an entry has only name and version")
    name, version = entry.get("name"), entry.get("version")
    match = ARTIFACT_NAME.fullmatch(name) if isinstance(name, str) else None
    if match is None:
        return None, None, {}, [*findings, f"{label} is not a path under {VENDOR_DIRECTORY}/"]
    if not isinstance(version, str) or EXACT_VERSION.fullmatch(version) is None:
        return None, None, {}, [*findings, f"{label} version {version!r} is not an exact x.y.z"]
    if version != match["version"]:
        findings.append(f"{label} names version {match['version']} but the pin is {version}")
    artifact = ansible_dir / match.string
    if not artifact.is_file():
        return None, None, {}, [*findings, f"{label} is not vendored: the file is missing"]
    expected = digests.get(artifact.name)
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if expected is None:
        findings.append(f"{artifact.name} has no line in {CHECKSUM_FILE}")
    elif actual != expected:
        findings.append(f"{artifact.name} does not match {CHECKSUM_FILE}: it hashes to {actual}")
    info, problem = artifact_identity(artifact)
    if info is None:
        return None, None, {}, [*findings, problem or f"{artifact.name} is unreadable"]
    own = f"{info.get('namespace')}.{info.get('name')}"
    if own != f"{match['namespace']}.{match['name']}" or info.get("version") != version:
        findings.append(
            f"{artifact.name} holds {own} {info.get('version')}, not "
            f"{match['namespace']}.{match['name']} {version}"
        )
    dependencies = info.get("dependencies")
    return (
        own,
        version,
        dependencies if isinstance(dependencies, Mapping) else {},
        findings,
    )


def check_collections(ansible_dir: Path) -> tuple[list[str], int]:
    """Check requirements.yml against the vendored artifacts; return findings and the count."""
    path = ansible_dir / "requirements.yml"
    document, problem = load_yaml(path)
    if problem is not None:
        return [problem], 0
    if not isinstance(document, Mapping):
        return ["requirements.yml has no collections list"], 0
    entries = document.get("collections")
    if not isinstance(entries, list) or not entries:
        return ["requirements.yml has no collections list"], 0
    findings = [
        f"requirements.yml sets {key}; only collections are pinned here"
        for key in sorted(str(key) for key in document if key != "collections")
    ]
    digests, problems = read_checksums(ansible_dir / VENDOR_DIRECTORY / CHECKSUM_FILE)
    findings.extend(problems)
    pinned: dict[str, str] = {}
    needs: list[tuple[str, str, object]] = []
    for entry in entries:
        own, version, dependencies, entry_findings = check_entry(entry, ansible_dir, digests)
        findings.extend(entry_findings)
        if own is None or version is None:
            continue
        if own in pinned:
            findings.append(f"requirements.yml pins {own} a second time")
        pinned[own] = version
        needs.extend((own, dependency, wanted) for dependency, wanted in dependencies.items())
    findings.extend(check_dependencies(pinned, needs))
    findings.extend(check_vendor_files(ansible_dir, entries, digests))
    return findings, len(pinned)


def check_dependencies(
    pinned: Mapping[str, str], needs: Sequence[tuple[str, str, object]]
) -> list[str]:
    """Check every dependency a vendored collection declares is pinned at a satisfying version."""
    findings: list[str] = []
    for owner, dependency, wanted in needs:
        have = pinned.get(str(dependency))
        if have is None:
            findings.append(f"{owner} depends on {dependency}, which requirements.yml does not pin")
        elif meets(have, str(wanted)) is not True:
            findings.append(f"{owner} needs {dependency} {wanted}, the pin is {have}")
    return findings


def check_vendor_files(
    ansible_dir: Path, entries: Sequence[object], digests: Mapping[str, str]
) -> list[str]:
    """Check the vendor directory and the checksum file hold nothing requirements.yml omits."""
    listed = (entry.get("name") for entry in entries if isinstance(entry, Mapping))
    named = {Path(name).name for name in listed if isinstance(name, str)}
    held = {item.name for item in (ansible_dir / VENDOR_DIRECTORY).glob("*") if item.is_file()}
    return [
        *(
            f"{VENDOR_DIRECTORY}/{name} is not named by requirements.yml"
            for name in sorted(held - named - {CHECKSUM_FILE})
        ),
        *(
            f"{CHECKSUM_FILE} lists {name}, which requirements.yml does not name"
            for name in sorted(set(digests) - named)
        ),
    ]


def check_ansible_cfg(path: Path) -> list[str]:
    """Check ansible.cfg sets the install directory and nothing else."""
    parser = configparser.RawConfigParser(strict=True)
    try:
        parser.read_string(path.read_text(encoding="utf-8"))
    except (OSError, configparser.Error) as error:
        return [f"{path.name} cannot be read: {type(error).__name__}"]
    found = {section: dict(parser.items(section)) for section in parser.sections()}
    if found != {"defaults": {"collections_path": INSTALL_DIRECTORY}}:
        return [
            f"{path.name} must hold only [defaults] collections_path = {INSTALL_DIRECTORY}, "
            f"not {found}"
        ]
    return []


def lint_hook_revs(config: Path) -> tuple[list[str], list[str]]:
    """Return the revs of the ansible-lint hook repositories, and a finding per odd one."""
    document, problem = load_yaml(config)
    if problem is not None:
        return [], [problem]
    repos = document.get("repos") if isinstance(document, Mapping) else None
    if not isinstance(repos, list):
        return [], [f"{config.name} has no repos list"]
    revs: list[str] = []
    findings: list[str] = []
    for repo in repos:
        url = repo.get("repo") if isinstance(repo, Mapping) else None
        if not isinstance(url, str) or url.rstrip("/").rsplit("/", 1)[-1] != "ansible-lint":
            continue
        if url != LINT_REPOSITORY:
            findings.append(f"{config.name} takes ansible-lint from {url}, not {LINT_REPOSITORY}")
        revs.append(str(repo.get("rev")))
    return revs, findings


def check_lint_rev(config: Path, tools: Mapping[str, str]) -> tuple[list[str], int]:
    """Check the ansible-lint hook rev equals the pin; return findings and the hooks compared."""
    revs, findings = lint_hook_revs(config)
    pin = tools.get("ansible-lint")
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
        dependency = document.get("dependency") if isinstance(document, Mapping) else None
        if problem is not None:
            findings.append(f"{name}: {problem}")
        elif not isinstance(dependency, Mapping) or dependency.get("enabled") is not False:
            findings.append(
                f"{name} does not set dependency.enabled to false, so the step could reach Galaxy"
            )
    return findings, len(scenarios)


def run_checks(root: Path) -> tuple[list[str], list[str]]:
    """Run every check under ``root``; return the findings and the notes."""
    ansible_dir = root / "ansible"
    tools, findings = pinned_tools(ansible_dir / "requirements.txt")
    collections, count = check_collections(ansible_dir)
    findings.extend(collections)
    findings.extend(check_ansible_cfg(root / "ansible.cfg"))
    scenario_findings, scenarios = check_scenarios(ansible_dir)
    findings.extend(scenario_findings)
    hooks, compared = check_lint_rev(root / ".pre-commit-config.yaml", tools)
    findings.extend(hooks)
    notes = [
        f"{len(tools)} tool pin(s), {count} vendored collection(s) and {scenarios} scenario(s) read"
    ]
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
