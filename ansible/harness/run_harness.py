"""Run the role test harness: lint, yamllint, interface checks and Molecule.

The steps, their order and the exit status are described in ansible/README.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError

ANSIBLE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = ANSIBLE_DIR.parent
REQUIREMENTS = ANSIBLE_DIR / "requirements.txt"
COLLECTIONS = ANSIBLE_DIR / "requirements.yml"

OK = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

# The role test never targets a host that is not a container on this machine:
# an engine address other than a local socket is refused before any step runs.
LOCAL_ENGINE_PREFIX = "unix://"

# What a scenario file may say (ANS-15). The driver is a container driver, no
# key points the test at an engine or host other than the local one, the
# scenario brings no host of its own, and every image is pre-built and pinned.
SCENARIO_DRIVERS = frozenset({"docker", "podman"})
CONNECTION_KEYS = frozenset(
    {"docker_host", "ansible_host", "ansible_ssh_host", "ansible_connection"}
)
INVENTORY_HOST_KEYS = frozenset({"hosts", "links"})
IMAGE_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
ENGINE_SOCKET = re.compile(r"(docker|podman)\.sock")
PRIVILEGE_KEYS = ("privileged", "capabilities")

# A role has a scenario called default, and may have more (a directory under
# molecule/). One run of the harness runs one scenario, named by --scenario, so
# each scenario can be its own shard with its own time limit. The name is a
# directory name that is passed to Molecule, so it is a plain one.
DEFAULT_SCENARIO = "default"
SCENARIO_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


@dataclass(frozen=True)
class Step:
    """One command the harness runs, and whether it runs after a failure."""

    name: str
    argv: tuple[str, ...]
    cwd: Path
    always: bool = False
    no_changes: bool = False


Runner = Callable[[Sequence[str], Path, Mapping[str, str]], "subprocess.CompletedProcess[str]"]


def run_command(
    argv: Sequence[str], cwd: Path, env: Mapping[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run one command to completion with its output captured."""
    return subprocess.run(  # noqa: S603 - argv is built here from constants and a checked role path
        list(argv),
        cwd=cwd,
        env=dict(env),
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )


def pinned_version(requirements: Path, package: str) -> str | None:
    """Return the exact version ``package`` is pinned to, or None.

    A line may carry hashes after the version, as a hash-locked file does.
    """
    pattern = re.compile(rf"^{re.escape(package)}==([^\s;\\]+)(?:[\s;\\]|$)", re.MULTILINE)
    match = pattern.search(requirements.read_text(encoding="utf-8"))
    return match.group(1) if match else None


def check_min_version(role: Path, pinned: str) -> str | None:
    """Return a problem if the role's min_ansible_version is not the pinned core."""
    meta = role / "meta" / "main.yml"
    if not meta.is_file():
        return "meta/main.yml is missing"
    match = re.search(
        r"^\s+min_ansible_version:\s*[\"']?([^\"'\s]+)[\"']?\s*$",
        meta.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if match is None:
        return "meta/main.yml sets no min_ansible_version"
    if match.group(1) != pinned:
        return f"min_ansible_version is {match.group(1)}, the pinned ansible-core is {pinned}"
    return None


def check_argument_specs(
    role: Path, ansible_doc: str, run: Runner, env: Mapping[str, str]
) -> str | None:
    """Return a problem if the argument specs lack an entry point (ansible-doc exits 0 without)."""
    done = run(
        [ansible_doc, "-t", "role", "--json", "--roles-path", str(role.parent), role.name],
        role,
        env,
    )
    if done.returncode != 0:
        return f"ansible-doc exited {done.returncode}: {done.stderr.strip()}"
    try:
        document = json.loads(done.stdout)
    except json.JSONDecodeError:
        return "ansible-doc output is not JSON"
    entry = document.get(role.name) if isinstance(document, dict) else None
    points = entry.get("entry_points") if isinstance(entry, dict) else None
    if not isinstance(points, dict):
        return "meta/argument_specs.yml is missing or documents no entry point"
    # A tasks file whose name starts with an underscore is internal to the role
    # (included by another file), so it exposes no entry point to document.
    wanted = {path.stem for path in (role / "tasks").glob("*.yml") if not path.name.startswith("_")}
    absent = sorted(wanted - set(points))
    if absent:
        return "meta/argument_specs.yml has no entry point for: " + ", ".join(absent)
    return None


def refuse_remote_engine(env: Mapping[str, str]) -> str | None:
    """Return a refusal if DOCKER_HOST points anywhere but a local socket."""
    host = env.get("DOCKER_HOST", "")
    if host and not host.startswith(LOCAL_ENGINE_PREFIX):
        return f"DOCKER_HOST is set to a non-local engine ({host.split(':')[0]}://): refused"
    return None


def walk_keys(node: object) -> Iterator[tuple[str, object]]:
    """Yield every (key, value) pair in a parsed YAML document, at any depth."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            yield str(key), value
            yield from walk_keys(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk_keys(item)


def platform_problems(platform: Mapping[str, object]) -> list[str]:
    """Return how one scenario platform breaks the limits on what a test may reach."""
    problems: list[str] = []
    if platform.get("pre_build_image") is not True:
        problems.append("sets no pre_build_image: true, so the image would be built and tagged")
    image = platform.get("image")
    if not isinstance(image, str) or IMAGE_DIGEST.search(image) is None:
        problems.append("image is not pinned by digest (@sha256:<64 hex>)")
    volumes = platform.get("volumes")
    if isinstance(volumes, list) and any(
        isinstance(volume, str) and ENGINE_SOCKET.search(volume) for volume in volumes
    ):
        problems.append("mounts a container engine socket into the platform")
    return problems


def asks_for_privilege(platform: Mapping[str, object], key: str) -> bool:
    """Return whether a platform sets ``privileged`` to true or lists any ``capabilities``."""
    value = platform.get(key)
    return value is True if key == "privileged" else bool(value)


def comment_above(lines: Sequence[str], index: int) -> bool:
    """Return whether the nearest non-blank line before ``lines[index]`` is a comment."""
    before = next((prior for prior in reversed(lines[:index]) if prior), "")
    return before.startswith("#")


def unexplained_privileged_platforms(text: str, platforms: Sequence[object]) -> int:
    """Count platforms that ask for privilege with no comment above any of their own keys.

    Each platform is judged by the lines of its own privilege keys, read from the
    round-trip parse of ``text``. A comment above one platform's key never explains
    another platform, so one platform with two commented keys cannot cover a second,
    bare one. A platform whose key positions cannot be read is counted as unexplained.
    """
    lines = [line.strip() for line in text.splitlines()]
    unexplained = 0
    for platform in platforms:
        if not isinstance(platform, Mapping):
            continue
        asked = [key for key in PRIVILEGE_KEYS if asks_for_privilege(platform, key)]
        if not asked:
            continue
        if not isinstance(platform, CommentedMap) or not all(key in platform for key in asked):
            unexplained += 1
            continue
        if not any(comment_above(lines, platform.lc.key(key)[0]) for key in asked):
            unexplained += 1
    return unexplained


def scenario_problems(scenario: Path) -> list[str]:
    """Return how a scenario's molecule.yml breaks the limits of the container-only test."""
    text = scenario.read_text(encoding="utf-8")
    try:
        document: object = YAML(typ="safe").load(text)
    except YAMLError:
        return ["is not valid YAML"]
    if not isinstance(document, Mapping):
        return ["is not a YAML mapping"]
    problems: list[str] = []
    driver = document.get("driver")
    driver_name = driver.get("name") if isinstance(driver, Mapping) else None
    if driver_name not in SCENARIO_DRIVERS:
        problems.append(
            f"driver is {driver_name!r}: only docker or podman are allowed, "
            "never a driver that runs against a host that already exists"
        )
    for key, value in walk_keys(document):
        if key.lower() in CONNECTION_KEYS:
            problems.append(f"sets {key}, which can reach something other than the local engine")
        if key == "inventory":
            for inner, _ in walk_keys(value):
                if inner in INVENTORY_HOST_KEYS:
                    problems.append(
                        f"inventory defines hosts ({inner}): the platforms are the hosts"
                    )
    platforms = document.get("platforms")
    if not isinstance(platforms, list) or not platforms:
        problems.append("defines no platform")
        return sorted(set(problems))
    for platform in platforms:
        if isinstance(platform, Mapping):
            name = platform.get("name", "?")
            problems.extend(f"platform {name}: {found}" for found in platform_problems(platform))
    if unexplained_privileged_platforms(text, YAML().load(text).get("platforms", [])):
        problems.append(
            "a platform asks for privileged or capabilities without a comment above the key "
            "saying why"
        )
    return sorted(set(problems))


def check_scenarios(role: Path, scenario: str = DEFAULT_SCENARIO) -> list[str]:
    """Return every way the role's Molecule scenarios break the limits of ANS-15.

    Every scenario file of the role is read, whichever one this run executes. The
    default scenario and the one being run must exist: a shard for a scenario that
    is not there fails here and is not skipped.
    """
    problems = [
        f"molecule/{name}/molecule.yml is missing"
        for name in dict.fromkeys((DEFAULT_SCENARIO, scenario))
        if not (role / "molecule" / name / "molecule.yml").is_file()
    ]
    for path in sorted((role / "molecule").glob("*/molecule.yml")):
        relative = path.relative_to(role)
        if not path.is_file():
            # A link to nothing: reported, not read, so a broken link cannot crash the run.
            problems.append(f"{relative}: is not a readable file (a link to nothing?)")
            continue
        problems.extend(f"{relative}: {found}" for found in scenario_problems(path))
    return problems


def static_steps(role: Path, tools: Path) -> list[Step]:
    """Return the lint steps; an in-repository role is linted from the repository root."""
    lint_dir = REPO_ROOT if role.is_relative_to(REPO_ROOT) else role.parent
    return [
        Step(
            "ansible-lint",
            (
                str(tools / "ansible-lint"),
                "--strict",
                "--config-file",
                str(REPO_ROOT / ".ansible-lint"),
                str(role),
            ),
            lint_dir,
        ),
        Step(
            "yamllint",
            (
                str(tools / "yamllint"),
                "--strict",
                "-c",
                str(REPO_ROOT / ".yamllint"),
                str(role),
            ),
            role.parent,
        ),
    ]


def molecule_steps(role: Path, tools: Path, scenario: str = DEFAULT_SCENARIO) -> list[Step]:
    """Return the Molecule steps for one scenario of a role, in the order they run.

    Every command names the scenario with ``-s``: Molecule runs ``default`` when it is
    not told, so a second scenario that was not named would never run and its shard
    would pass on the first. ``check-fresh`` precedes any real converge;
    ``molecule-check`` is Molecule's own action; ``destroy`` names the scenario too.
    """
    molecule = str(tools / "molecule")
    named = ("-s", scenario)
    in_check_mode = ("converge", *named, "--", "--check", "--diff")
    commands: list[tuple[str, tuple[str, ...]]] = [
        ("create", ("create", *named)),
        ("prepare", ("prepare", *named)),
        ("check-fresh", in_check_mode),
        ("converge", ("converge", *named)),
        ("idempotence", ("idempotence", *named)),
        ("verify", ("verify", *named)),
        ("check-configured", in_check_mode),
        ("molecule-check", ("check", *named)),
    ]
    steps = [
        Step(name, (molecule, *args), role, no_changes=name == "check-configured")
        for name, args in commands
    ]
    steps.append(Step("destroy", (molecule, "destroy", *named), role, always=True))
    return steps


def role_environment(
    base: Mapping[str, str], work: Path, tools: Path, run_id: str
) -> dict[str, str]:
    """Return one role's environment: caches in the run's own directory, a unique run id."""
    env = dict(base)
    env["PATH"] = f"{tools}{os.pathsep}{base.get('PATH', '')}"
    env["ANSIBLE_HOME"] = str(work / "ansible-home")
    env["ANSIBLE_COLLECTIONS_PATH"] = str(work / "collections")
    env["XDG_CACHE_HOME"] = str(work / "cache")
    env["ROLE_TEST_RUN_ID"] = run_id
    env["ANSIBLE_NOCOLOR"] = "1"
    env["NO_COLOR"] = "1"
    env["PY_COLORS"] = "0"
    return env


def changed_tasks(output: str) -> int:
    """Return the number of changed tasks in the PLAY RECAP lines of ``output``."""
    recap = re.findall(r"^\S+\s*:\s+ok=\d+\s+changed=(\d+)", output, re.MULTILINE)
    return sum(int(count) for count in recap)


def report(step: Step, done: subprocess.CompletedProcess[str]) -> str:
    """Print a step's output and return its status; a no_changes step fails on a change."""
    output = done.stdout + done.stderr
    status = OK if done.returncode == 0 else FAIL
    changed = changed_tasks(output) if step.no_changes else 0
    if status == OK and changed:
        status = FAIL
    print(f"::group::{step.name} {status}")
    print(output, end="")
    if step.no_changes and changed:
        print(f"{step.name}: {changed} task(s) would change an instance that is already configured")
    print("::endgroup::")
    return status


def run_molecule(
    steps: Sequence[Step], run: Runner, env: Mapping[str, str]
) -> list[tuple[str, str]]:
    """Run the Molecule steps in order; an interrupt still runs the always-run steps."""
    outcomes: list[tuple[str, str]] = []
    broken = False
    finished = False
    try:
        for step in steps:
            if broken and not step.always:
                outcomes.append((step.name, SKIP))
                continue
            status = report(step, run(step.argv, step.cwd, env))
            outcomes.append((step.name, status))
            broken = broken or status == FAIL
        finished = True
    finally:
        if not finished:
            for step in steps:
                if step.always:
                    run(step.argv, step.cwd, env)
    return outcomes


def run_role(
    role: Path,
    tools: Path,
    run: Runner,
    env: Mapping[str, str],
    reasons: dict[str, str] | None = None,
    scenario: str = DEFAULT_SCENARIO,
) -> list[tuple[str, str]]:
    """Run every step for one scenario of a role.

    ``reasons`` receives why each failed check failed. The static checks read the whole
    role and run in every scenario's run; the Molecule steps run the one scenario.
    """
    outcomes: list[tuple[str, str]] = []
    reasons = {} if reasons is None else reasons
    pinned = pinned_version(REQUIREMENTS, "ansible-core")
    problem = (
        "ansible-core is not pinned in requirements.txt"
        if pinned is None
        else check_min_version(role, pinned)
    )
    outcomes.append(("min-version", FAIL if problem else OK))
    if problem:
        reasons["min-version"] = problem
    problem = check_argument_specs(role, str(tools / "ansible-doc"), run, env)
    outcomes.append(("argument-specs", FAIL if problem else OK))
    if problem:
        reasons["argument-specs"] = problem
    limits = check_scenarios(role, scenario)
    outcomes.append(("scenario-limits", FAIL if limits else OK))
    if limits:
        reasons["scenario-limits"] = "; ".join(limits)
    for name in ("min-version", "argument-specs", "scenario-limits"):
        if name in reasons:
            print(f"{name} FAIL: {reasons[name]}")
    for step in static_steps(role, tools):
        outcomes.append((step.name, report(step, run(step.argv, step.cwd, env))))
    steps = molecule_steps(role, tools, scenario)
    if limits:
        outcomes.extend((step.name, SKIP) for step in steps)
    else:
        outcomes.extend(run_molecule(steps, run, env))
    return outcomes


def install_collections(
    tools: Path, run: Runner, env: Mapping[str, str]
) -> subprocess.CompletedProcess[str]:
    """Install the pinned collections into the run's own collections path."""
    argv = [
        str(tools / "ansible-galaxy"),
        "collection",
        "install",
        "-r",
        str(COLLECTIONS),
        "-p",
        env["ANSIBLE_COLLECTIONS_PATH"],
    ]
    return run(argv, ANSIBLE_DIR, env)


def main(
    argv: Sequence[str],
    base_env: Mapping[str, str] | None = None,
    run: Runner = run_command,
    tools: Path | None = None,
) -> int:
    """Run the harness over the roles named in argv; return the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument("roles", nargs="+", type=Path, help="role directories to test")
    parser.add_argument(
        "--scenario",
        default=DEFAULT_SCENARIO,
        help="the Molecule scenario to run, a directory under molecule/ (default: %(default)s)",
    )
    args = parser.parse_args(argv)
    if SCENARIO_NAME.fullmatch(args.scenario) is None:
        print(f"refused: {args.scenario!r} is not a scenario name")
        return 2
    environment = dict(os.environ if base_env is None else base_env)
    refusal = refuse_remote_engine(environment)
    if refusal:
        print(f"refused: {refusal}")
        return 2
    roles = [role.resolve() for role in args.roles]
    missing = [str(role) for role in roles if not (role / "tasks").is_dir()]
    if missing:
        print("refused: not a role directory (no tasks/): " + ", ".join(missing))
        return 2
    tools_dir = tools if tools is not None else Path(sys.executable).parent
    work = Path(tempfile.mkdtemp(prefix="role-harness-"))
    failed = False
    try:
        env = role_environment(environment, work, tools_dir, "collections")
        done = install_collections(tools_dir, run, env)
        if report(Step("collections", (), ANSIBLE_DIR), done) == FAIL:
            return 1
        for role in roles:
            run_env = role_environment(environment, work, tools_dir, uuid.uuid4().hex[:12])
            reasons: dict[str, str] = {}
            outcomes = run_role(role, tools_dir, run, run_env, reasons, args.scenario)
            print(f"== {role.name} ({args.scenario}) ==")
            for name, status in outcomes:
                print(f"{status} {name}")
                if status == FAIL and name in reasons:
                    print(f"    {reasons[name]}")
            failed = failed or any(status == FAIL for _, status in outcomes)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
