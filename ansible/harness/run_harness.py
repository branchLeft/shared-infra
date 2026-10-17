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
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

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
    """Return the exact version ``package`` is pinned to, or None."""
    pattern = re.compile(rf"^{re.escape(package)}==(\S+)\s*$", re.MULTILINE)
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
    wanted = {path.stem for path in (role / "tasks").glob("*.yml")}
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


def molecule_steps(role: Path, tools: Path) -> list[Step]:
    """Return the Molecule steps for a role, in the order they run."""
    molecule = str(tools / "molecule")
    commands: list[tuple[str, tuple[str, ...]]] = [
        ("create", ("create",)),
        ("prepare", ("prepare",)),
        ("converge", ("converge",)),
        ("idempotence", ("idempotence",)),
        ("verify", ("verify",)),
        ("check-configured", ("converge", "--", "--check", "--diff")),
        ("check-fresh", ("check",)),
    ]
    steps = [
        Step(name, (molecule, *args), role, no_changes=name == "check-configured")
        for name, args in commands
    ]
    steps.append(Step("destroy", (molecule, "destroy"), role, always=True))
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


def run_role(role: Path, tools: Path, run: Runner, env: Mapping[str, str]) -> list[tuple[str, str]]:
    """Run every step for one role and return (step name, status) pairs."""
    outcomes: list[tuple[str, str]] = []
    pinned = pinned_version(REQUIREMENTS, "ansible-core")
    problem = (
        "ansible-core is not pinned in requirements.txt"
        if pinned is None
        else check_min_version(role, pinned)
    )
    outcomes.append(("min-version", FAIL if problem else OK))
    if problem:
        print(f"min-version FAIL: {problem}")
    problem = check_argument_specs(role, str(tools / "ansible-doc"), run, env)
    outcomes.append(("argument-specs", FAIL if problem else OK))
    if problem:
        print(f"argument-specs FAIL: {problem}")
    for step in static_steps(role, tools):
        outcomes.append((step.name, report(step, run(step.argv, step.cwd, env))))
    broken = False
    for step in molecule_steps(role, tools):
        if broken and not step.always:
            outcomes.append((step.name, SKIP))
            continue
        status = report(step, run(step.argv, step.cwd, env))
        outcomes.append((step.name, status))
        broken = broken or status == FAIL
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
    args = parser.parse_args(argv)
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
            outcomes = run_role(role, tools_dir, run, run_env)
            print(f"== {role.name} ==")
            for name, status in outcomes:
                print(f"{status} {name}")
            failed = failed or any(status == FAIL for _, status in outcomes)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
