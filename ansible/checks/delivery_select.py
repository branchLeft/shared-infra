"""Choose the Molecule shards a delivery run executes, from the commits it delivers.

The delivery used to run every shard on every push to main. This program reads the files
changed since the last commit whose delivery checks passed, hands them to ``ci_select.py`` (the
rules the pull request gate uses), and prints the two job outputs as ``name=value`` lines:
``shards`` (``true`` when any shard must run) and ``directories`` (the role directories to
test, one per line, relative to ``ansible/``, in the form the reusable workflow's
``role-directories`` input takes).

Two rules keep a narrow run honest, and both err towards running more.

The base is not simply the commit before the push. A delivery run is cancelled when the next
push arrives, so the commit before may never have had its shards run: its changes would then
reach the host untested by the push that follows. The base is the nearest first-parent ancestor
of the previous tip whose delivery run finished its lint and every shard green (``tested_base``),
or, with the lint and shards skipped, whose discover job's merge-queue confirm step succeeded.

Any failure of any step prints the full selection: every role and pattern. The shell step that
runs this program does the same when the program itself cannot run. Nothing here may print an
empty selection except for a diff that names no file a shard reads. The rules are in
ansible/checks/README.md, "delivery_select.py".
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import ci_select

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ".github/workflows/ansible-delivery.yml"
BRANCH = "main"
EVENT = "push"
# What the delivery tests when it tests everything: the globs ansible-delivery.yml passed before
# it chose. check_delivery.ROLE_DIRECTORIES is the other home of the same two lines, and
# test_delivery_select.py holds them equal.
FULL_DIRECTORIES = ("roles/*", "patterns/*")
# The shard directories the reusable workflow tests. The fresh-role skeleton is also a shard of
# the pull request gate, but the delivery's globs never matched it, so it is not tested here.
ROLE_PARENTS = ("ansible/roles/", "ansible/patterns/")
# A change to one of these runs every shard, on top of the rules of ci_select.py: the delivery
# caller and this program decide what the delivery tests, so an edit to either is tested in full.
EVERY_SHARD = (WORKFLOW_PATH, "ansible/checks/delivery_select.py")
# How many first-parent commits back from the previous tip are searched for a tested base.
MAX_WALK = 40
SHA_LENGTH = 40
HEX = frozenset("0123456789abcdef")
# A role directory as it is passed on: the shape the reusable workflow accepts, and no more.
DIRECTORY = re.compile(r"(?:roles|patterns)/[A-Za-z0-9._-]+", re.ASCII)
# The job names of the reusable workflow, after the caller's job id and " / ".
DISCOVER_JOB = "Discover the Ansible checks"
LINT_JOB = "Lint the Ansible inputs"
SHARD_JOB_PREFIX = "Molecule: "
# The discover job's step that fails the job unless the merge queue passed the commit. It runs
# only when the caller skips the lint and the shards, so on that path it is the proof.
CONFIRM_STEP = "Confirm the merge queue passed this commit"
JOB_SEPARATOR = " / "
PAGE_SIZE = 100
MAX_PAGES = 10
DELIMITER = "DIRECTORIES_END"

# Asks GitHub for one document: a path below ``repos/OWNER/REPO/`` and its query fields.
Api = Callable[[str, dict[str, str]], object]


class SelectionError(Exception):
    """Something the selection needs could not be read, so the caller runs everything."""


@dataclass(frozen=True)
class Selection:
    """What the delivery runs: whether any shard runs, which directories, and why."""

    run_shards: bool
    directories: tuple[str, ...]
    reason: str


def full(reason: str) -> Selection:
    """Return the selection that tests everything the delivery ever tested."""
    return Selection(run_shards=True, directories=FULL_DIRECTORIES, reason=reason)


def as_mapping(value: object) -> dict[str, object] | None:
    """Return ``value`` with string keys when it is a mapping, else None."""
    if not isinstance(value, dict):
        return None
    return {str(key): item for key, item in value.items()}


def is_commit(value: str) -> bool:
    """Return whether ``value`` is 40 lowercase hex digits and not the all-zero null commit."""
    return len(value) == SHA_LENGTH and set(value) <= HEX and set(value) != {"0"}


def role_directory(shard_path: str) -> str | None:
    """Return the role directory of a shard path, relative to ansible/, or None for no role."""
    if not shard_path.startswith(ROLE_PARENTS):
        return None
    relative = shard_path.removeprefix("ansible/")
    return relative if DIRECTORY.fullmatch(relative) else None


def choose(changed: Sequence[str], shards: list[dict[str, str]], root: Path) -> Selection:
    """Return the selection for the files changed since the tested base.

    The pull request rules of ci_select.py decide, so a delivery and the gate read one rulebook.
    """
    if any(ci_select.inside(path, EVERY_SHARD) for path in changed):
        return full("the delivery caller or its selection changed")
    chosen = ci_select.select(ci_select.PULL_REQUEST, changed, shards, root)
    listed = {role_directory(shard["path"]) for shard in shards} - {None}
    wanted = {role_directory(shard["path"]) for shard in chosen} - {None}
    if wanted == listed:
        return full("every role and pattern is called for")
    if not wanted:
        return Selection(
            run_shards=False,
            directories=FULL_DIRECTORIES,
            reason=f"{len(changed)} changed file(s), and no role or pattern reads any of them",
        )
    directories = tuple(sorted(name for name in wanted if name is not None))
    return Selection(
        run_shards=True,
        directories=directories,
        reason=f"{len(directories)} of {len(listed)} role and pattern directories are called for",
    )


def job_name(job: dict[str, object]) -> str:
    """Return a job's name without the caller's job id in front of it."""
    name = job.get("name")
    if not isinstance(name, str):
        return ""
    return name.split(JOB_SEPARATOR, 1)[1] if JOB_SEPARATOR in name else name


def confirm_succeeded(job: dict[str, object]) -> bool:
    """Return whether the job lists its merge-queue confirm step exactly once, and it succeeded.

    A job with no step list, a step that is not a mapping, a missing step or a repeated one is
    not a proof: the answer is False, never a guess.
    """
    steps = job.get("steps")
    if not isinstance(steps, list):
        return False
    results: list[object] = []
    for entry in steps:
        step = as_mapping(entry)
        if step is None:
            return False
        if step.get("name") == CONFIRM_STEP:
            results.append(step.get("conclusion"))
    return results == ["success"]


def checks_passed(jobs: Sequence[object]) -> bool:
    """Return whether the jobs of one delivery run show its lint and shards finished green.

    The discover job must have succeeded. The lint job must have succeeded, and then at least
    one shard must exist and every shard must have succeeded; or the lint job was skipped, which
    is how a run that the merge queue vouched for shows. Then no shard may be anything but
    skipped or succeeded, and the discover job's confirm step must have concluded success: that
    step is the only proof the queue passed the commit, and it is skipped on a run that tested
    its own tree. A job that is cancelled, failed, still running or missing is not a pass, so a
    run that the next push cancelled is never taken as the base.
    """
    named: dict[str, list[str | None]] = {}
    shard_results: list[str | None] = []
    confirmed = False
    for entry in jobs:
        job = as_mapping(entry)
        if job is None:
            return False
        name = job_name(job)
        conclusion = job.get("conclusion")
        result = conclusion if isinstance(conclusion, str) else None
        if name.startswith(SHARD_JOB_PREFIX):
            shard_results.append(result)
        elif name in (DISCOVER_JOB, LINT_JOB):
            named.setdefault(name, []).append(result)
            if name == DISCOVER_JOB:
                confirmed = confirm_succeeded(job)
    if named.get(DISCOVER_JOB) != ["success"]:
        return False
    lint = named.get(LINT_JOB)
    if lint == ["success"]:
        return bool(shard_results) and all(result == "success" for result in shard_results)
    if lint == ["skipped"]:
        return confirmed and all(result in ("success", "skipped") for result in shard_results)
    return False


def read_jobs(api: Api, run_id: int) -> list[object]:
    """Return every job of the latest attempt of a run, across pages.

    Raises:
        SelectionError: the answer is not the list of jobs GitHub documents, or is too long to read.
    """
    jobs: list[object] = []
    for page in range(1, MAX_PAGES + 1):
        answer = as_mapping(
            api(
                f"actions/runs/{run_id}/jobs",
                {"filter": "latest", "per_page": str(PAGE_SIZE), "page": str(page)},
            )
        )
        listed = answer.get("jobs") if answer is not None else None
        total = answer.get("total_count") if answer is not None else None
        if not isinstance(listed, list) or isinstance(total, bool) or not isinstance(total, int):
            message = f"the jobs of run {run_id} cannot be read"
            raise SelectionError(message)
        jobs.extend(listed)
        if len(jobs) >= total:
            return jobs
        if not listed:
            break
    message = f"the jobs of run {run_id} are too many or truncated"
    raise SelectionError(message)


def run_tested(api: Api, sha: str) -> bool:
    """Return whether a delivery run of ``sha`` finished its lint and shards green.

    Raises:
        SelectionError: a run list or a job list cannot be read.
    """
    answer = as_mapping(
        api("actions/workflows/ansible-delivery.yml/runs", {"head_sha": sha, "per_page": "30"})
    )
    runs = answer.get("workflow_runs") if answer is not None else None
    if not isinstance(runs, list):
        message = f"the delivery runs of {sha} cannot be read"
        raise SelectionError(message)
    for entry in runs:
        run = as_mapping(entry)
        if run is None or run.get("head_sha") != sha or run.get("path") != WORKFLOW_PATH:
            continue
        if run.get("event") != EVENT or run.get("head_branch") != BRANCH:
            continue
        run_id = run.get("id")
        if isinstance(run_id, bool) or not isinstance(run_id, int):
            continue
        if checks_passed(read_jobs(api, run_id)):
            return True
    return False


def tested_base(api: Api, history: Sequence[str]) -> str | None:
    """Return the first commit of ``history`` whose delivery checks passed, else None.

    ``history`` is the previous tip and its first-parent ancestors, newest first. The first
    one that passes is the base: everything after it has had no delivery shard run. A commit
    that is not a commit id is skipped, never taken as a base.

    Raises:
        SelectionError: a run list or a job list cannot be read.
    """
    for sha in history[:MAX_WALK]:
        if is_commit(sha) and run_tested(api, sha):
            return sha
    return None


def git(root: Path, *args: str) -> bytes:
    """Return the standard output of one git command in ``root``.

    Raises:
        SelectionError: git exits with an error.
    """
    done = subprocess.run(  # noqa: S603
        ["git", "-C", str(root), *args],  # noqa: S607
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    if done.returncode != 0:
        message = f"git {args[0]} failed"
        raise SelectionError(message)
    return done.stdout


def gh_api(repo: str) -> Api:
    """Return the function that reads ``repos/<repo>/<path>`` with the ``gh`` program."""

    def call(path: str, fields: dict[str, str]) -> object:
        command = ["gh", "api", "-X", "GET", f"repos/{repo}/{path}"]
        for key, value in fields.items():
            command.extend(["-f", f"{key}={value}"])
        done = subprocess.run(  # noqa: S603
            command,  # noqa: S607
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            text=True,
        )
        if done.returncode != 0:
            message = f"gh api {path} failed"
            raise SelectionError(message)
        try:
            document: object = json.loads(done.stdout)
        except ValueError as error:
            message = f"gh api {path} did not answer JSON"
            raise SelectionError(message) from error
        return document

    return call


def history_of(root: Path, before: str) -> list[str]:
    """Return ``before`` and its first-parent ancestors, newest first, up to the walk limit.

    Raises:
        SelectionError: ``before`` is not a commit this checkout holds.
    """
    if not is_commit(before):
        message = "the previous tip is not a commit id"
        raise SelectionError(message)
    listed = git(root, "rev-list", "--first-parent", "-n", str(MAX_WALK), before)
    return listed.decode("ascii").split()


def changed_since(root: Path, base: str, sha: str) -> list[str]:
    """Return the files that differ between two commits, renames shown as a delete and an add.

    Raises:
        SelectionError: git cannot diff the two commits.
    """
    raw = git(root, "diff", "--name-only", "-z", "--no-renames", base, sha)
    return [name for name in raw.decode("utf-8").split("\0") if name]


def listed_shards(root: Path) -> list[dict[str, str]]:
    """Return the shards of the tree, listed by the program the workflows run.

    Raises:
        SelectionError: the list is empty or malformed.
    """
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(root / "ansible" / "harness" / "list_shards.py")],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    shards = ci_select.parse_matrix(done.stdout) if done.returncode == 0 else None
    if shards is None:
        message = "the shard list is empty or malformed"
        raise SelectionError(message)
    return shards


def select_delivery(root: Path, before: str, sha: str, api: Api) -> Selection:
    """Return the selection for a push of ``sha`` over ``before``; any failure runs everything."""
    try:
        if not is_commit(sha):
            return full("the pushed commit is not a commit id")
        base = tested_base(api, history_of(root, before))
        if base is None:
            return full(f"no delivery of the last {MAX_WALK} commits finished its checks green")
        selection = choose(changed_since(root, base, sha), listed_shards(root), root)
    except Exception as error:  # noqa: BLE001 - whatever goes wrong, the answer is everything
        return full(f"the selection failed ({type(error).__name__}: {error})")
    return Selection(
        run_shards=selection.run_shards,
        directories=selection.directories,
        reason=f"changes since {base[:12]}: {selection.reason}",
    )


def render(selection: Selection) -> str:
    """Return the selection as the ``name=value`` text a step appends to ``$GITHUB_OUTPUT``.

    A selection whose directories are not all in the accepted shape is replaced by the full one.
    """
    if not selection.directories or not all(
        name in FULL_DIRECTORIES or DIRECTORY.fullmatch(name) for name in selection.directories
    ):
        selection = full("a directory is not in the accepted shape")
    lines = [
        f"shards={'true' if selection.run_shards else 'false'}",
        f"directories<<{DELIMITER}",
        *selection.directories,
        DELIMITER,
    ]
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str]) -> int:
    """Print the outputs for a delivery of ``--sha`` over ``--before``; always return 0."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", maxsplit=1)[0])
    parser.add_argument("--before", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--repository", default=os.environ.get("REPO", ""))
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    try:
        args = parser.parse_args(argv)
        selection = select_delivery(args.root, args.before, args.sha, gh_api(args.repository))
    except SystemExit:
        selection = full("the arguments could not be read")
    print(f"delivery selection: {selection.reason}", file=sys.stderr)
    print(
        f"  shards run: {selection.run_shards}; directories: {', '.join(selection.directories)}",
        file=sys.stderr,
    )
    sys.stdout.write(render(selection))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
