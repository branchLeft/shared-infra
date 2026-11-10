"""Choose which container shards a merge queue entry still has to run.

The pull request ran every shard it needed on its own head. A queue entry whose tree is the same
tree as that head has been tested by those runs already, so the shard is skipped. This program
reads the chosen shards (ci_select.py's output) and keeps every shard except one that the
pull request's own Ansible run passed on the same tree. Any doubt keeps the shard: an unreadable
answer, a tree that differs, a pull request that is not open, a check run from another app or
run, a shard with no or a non-passing check run, or a checkout that is not the queued commit.

It prints the two job outputs as ``name=value`` lines, ready for ``$GITHUB_OUTPUT``, and the
reason on standard error. It uses only the standard library: the reads go through ``gh api``
with the run's token in ``GH_TOKEN``, and the tree comes from ``git rev-parse``.
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
from typing import Protocol

import ci_select

MERGE_GROUP = "merge_group"
PULL_REQUEST = "pull_request"
WORKFLOW_PATH = ".github/workflows/ansible.yml"
# The job name of the shard job is "Harness: <matrix name>", and its check run carries that name.
CHECK_PREFIX = "Harness: "
ACTIONS_APP = "github-actions"
PAGE_SIZE = 100
MAX_PAGES = 20
SHA = re.compile(r"^[0-9a-f]{40}$")
QUEUE_REF = re.compile(r"^(?:refs/heads/)?gh-readonly-queue/[^/]+/pr-([1-9][0-9]*)-[0-9a-f]+$")

Entry = dict[str, str]


class ApiError(Exception):
    """A read of GitHub failed or answered something this program cannot read."""


class UnverifiedError(Exception):
    """The evidence is missing or does not match, so the shards run."""


class Reader(Protocol):
    """The four reads the queue check makes."""

    def pull_request(self, number: int) -> dict[str, object]: ...

    def commit_tree(self, sha: str) -> str: ...

    def pull_request_runs(self, sha: str) -> list[dict[str, object]]: ...

    def check_runs(self, sha: str) -> list[dict[str, object]]: ...


def run_gh(endpoint: str) -> object:
    """Return the JSON answer of ``gh api`` for one GET endpoint.

    Raises:
        ApiError: the call failed or did not answer JSON.
    """
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell, the endpoint is built here
        ["gh", "api", endpoint],  # noqa: S607 - the runner's own gh, found on PATH
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if done.returncode != 0:
        message = f"gh api {endpoint} failed: {done.stderr.strip()[:200]}"
        raise ApiError(message)
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError as err:
        message = f"gh api {endpoint} did not answer JSON"
        raise ApiError(message) from err


def mapping(value: object) -> dict[str, object]:
    """Return ``value`` as a mapping with string keys.

    Raises:
        ApiError: the value is not an object.
    """
    if not isinstance(value, dict):
        message = "an answer was not an object"
        raise ApiError(message)
    return {str(key): item for key, item in value.items()}


class GhCli:
    """The reads, through ``gh api`` for one repository."""

    def __init__(self, repo: str, gh: Callable[[str], object] = run_gh) -> None:
        self.repo = repo
        self.gh = gh

    # The reads below raise ApiError when an answer is not the shape they expect.

    def pull_request(self, number: int) -> dict[str, object]:
        return mapping(self.gh(f"repos/{self.repo}/pulls/{number}"))

    def commit_tree(self, sha: str) -> str:
        commit = mapping(self.gh(f"repos/{self.repo}/git/commits/{sha}"))
        tree = mapping(commit.get("tree"))
        value = tree.get("sha")
        if not isinstance(value, str):
            message = "a commit answer had no tree"
            raise ApiError(message)
        return value

    def pull_request_runs(self, sha: str) -> list[dict[str, object]]:
        answer = mapping(
            self.gh(
                f"repos/{self.repo}/actions/workflows/ansible.yml/runs"
                f"?head_sha={sha}&per_page={PAGE_SIZE}"
            )
        )
        runs = answer.get("workflow_runs")
        total = answer.get("total_count")
        if not isinstance(runs, list) or not isinstance(total, int):
            message = "the run list was not readable"
            raise ApiError(message)
        if total > len(runs):
            message = "the run list is truncated"
            raise ApiError(message)
        return [mapping(run) for run in runs]

    def check_runs(self, sha: str) -> list[dict[str, object]]:
        found: list[dict[str, object]] = []
        for page in range(1, MAX_PAGES + 1):
            answer = mapping(
                self.gh(
                    f"repos/{self.repo}/commits/{sha}/check-runs?per_page={PAGE_SIZE}&page={page}"
                )
            )
            runs = answer.get("check_runs")
            if not isinstance(runs, list):
                message = "the check runs were not readable"
                raise ApiError(message)
            found.extend(mapping(run) for run in runs)
            if len(runs) < PAGE_SIZE:
                return found
        message = "there are more check runs than the reader reads"
        raise ApiError(message)


@dataclass(frozen=True)
class Plan:
    """Which chosen shards run, which the pull request already passed, and why."""

    keep: list[Entry]
    skipped: list[Entry]
    reason: str


def pull_request_number(queue_ref: str) -> int:
    """Return the pull request a merge queue branch tests.

    Raises:
        UnverifiedError: the branch name does not name a pull request.
    """
    found = QUEUE_REF.match(queue_ref)
    if found is None:
        message = "the queue branch name does not name a pull request"
        raise UnverifiedError(message)
    return int(found.group(1))


def passed(check: dict[str, object], suites: set[object]) -> bool:
    """Return whether a check run is a finished pass of this workflow on the pull request."""
    app = check.get("app")
    suite = check.get("check_suite")
    return (
        isinstance(app, dict)
        and app.get("slug") == ACTIONS_APP
        and isinstance(suite, dict)
        and suite.get("id") in suites
    )


def head_evidence(
    *,
    number: int,
    queue_sha: str,
    local_head: str,
    local_tree: str,
    api: Reader,
) -> tuple[str, list[dict[str, object]]]:
    """Return the pull request head and its passing check runs of this workflow.

    Raises:
        UnverifiedError: the queued commit, the pull request or the tree does not match.
    """
    if local_head != queue_sha:
        message = "the checkout is not the queued commit"
        raise UnverifiedError(message)
    pull = api.pull_request(number)
    if pull.get("state") != "open":
        message = "the pull request is not open"
        raise UnverifiedError(message)
    head_value = mapping(pull.get("head")).get("sha")
    if not isinstance(head_value, str) or not SHA.match(head_value):
        message = "the pull request head is not a commit"
        raise UnverifiedError(message)
    if api.commit_tree(head_value) != local_tree:
        message = "the queued tree differs from the pull request head's tree"
        raise UnverifiedError(message)
    suites = {
        run.get("check_suite_id")
        for run in api.pull_request_runs(head_value)
        if run.get("event") == PULL_REQUEST
        and run.get("path") == WORKFLOW_PATH
        and run.get("head_sha") == head_value
        and isinstance(run.get("check_suite_id"), int)
    }
    if not suites:
        message = "no pull request run of the Ansible workflow is on the head"
        raise UnverifiedError(message)
    return head_value, [check for check in api.check_runs(head_value) if passed(check, suites)]


def plan(
    *,
    event: str,
    entries: Sequence[Entry],
    queue_ref: str,
    queue_sha: str,
    local_head: str,
    local_tree: str,
    api: Reader,
) -> Plan:
    """Return the shards to run for one queue entry, and the shards the pull request covers.

    A shard is skipped only when every check run of its name, from the pull request's own Ansible
    runs on the pull request head, finished with success, and the head's tree is the queued tree.
    Any doubt keeps every shard, and the reason says which doubt.
    """
    if event != MERGE_GROUP:
        return Plan(list(entries), [], f"the {event} event runs every chosen shard")
    if not entries:
        return Plan([], [], "no shard was chosen")
    try:
        _, checks = head_evidence(
            number=pull_request_number(queue_ref),
            queue_sha=queue_sha,
            local_head=local_head,
            local_tree=local_tree,
            api=api,
        )
    except (UnverifiedError, ApiError, ValueError, KeyError, TypeError) as doubt:
        return Plan(list(entries), [], f"kept every shard: {doubt}")

    keep: list[Entry] = []
    skipped: list[Entry] = []
    for entry in entries:
        matching = [check for check in checks if check.get("name") == CHECK_PREFIX + entry["name"]]
        if matching and all(
            check.get("status") == "completed" and check.get("conclusion") == "success"
            for check in matching
        ):
            skipped.append(entry)
        else:
            keep.append(entry)
    return Plan(keep, skipped, f"skipped {len(skipped)} of {len(entries)} shard(s)")


def read_selection(path: Path) -> list[Entry]:
    """Return the chosen shards from ci_select.py's output file, without its no-shard entry.

    Raises:
        ValueError: the file has no readable matrix line.
    """
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("matrix="):
            answer = json.loads(line[len("matrix=") :])
            include = answer.get("include") if isinstance(answer, dict) else None
            if not isinstance(include, list):
                message = "the selection has no include list"
                raise ValueError(message)
            return [
                {str(key): str(value) for key, value in entry.items()}
                for entry in include
                if entry.get("kind") != ci_select.NO_SHARD["kind"]
            ]
    message = "the selection has no matrix line"
    raise ValueError(message)


def local_head_and_tree() -> tuple[str, str]:
    """Return the checked-out commit and its tree, as git reads them.

    Raises:
        subprocess.CalledProcessError: git could not read the checkout.
    """
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "rev-parse", "HEAD", "HEAD^{tree}"],  # noqa: S607 - git on PATH
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    head, tree = done.stdout.split()
    return head, tree


def main(
    argv: Sequence[str],
    api: Reader | None = None,
    local: tuple[str, str] | None = None,
) -> int:
    """Print the two job outputs for the selection, and the reason on standard error."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--event", required=True)
    parser.add_argument("--selected", required=True, type=Path)
    parser.add_argument("--queue-ref", default="")
    parser.add_argument("--queue-sha", default="")
    args = parser.parse_args(list(argv))

    entries = read_selection(args.selected)
    if args.event == MERGE_GROUP and entries:
        result = queue_plan(entries, args.queue_ref, args.queue_sha, api, local)
    else:
        result = plan(
            event=args.event,
            entries=entries,
            queue_ref="",
            queue_sha="",
            local_head="",
            local_tree="",
            api=_NoReads(),
        )

    keep = result.keep
    print(f"shards={'true' if keep else 'false'}")
    print("matrix=" + json.dumps({"include": keep or [ci_select.NO_SHARD]}, separators=(",", ":")))
    print(result.reason, file=sys.stderr)
    for entry in result.skipped:
        print(
            f"skipped: {entry['name']}, passed by the pull request on the same tree",
            file=sys.stderr,
        )
    return 0


def queue_plan(
    entries: Sequence[Entry],
    queue_ref: str,
    queue_sha: str,
    api: Reader | None,
    local: tuple[str, str] | None,
) -> Plan:
    """Return the plan for a queue entry; a checkout or environment that cannot be read keeps all.

    Raises:
        UnverifiedError: never: an unreadable input is reported as a doubt in the plan.
    """
    try:
        reader: Reader = api if api is not None else GhCli(_repository())
        head, tree = local if local is not None else local_head_and_tree()
    except (UnverifiedError, OSError, subprocess.CalledProcessError, ValueError) as doubt:
        return Plan(list(entries), [], f"kept every shard: {doubt}")
    return plan(
        event=MERGE_GROUP,
        entries=entries,
        queue_ref=queue_ref,
        queue_sha=queue_sha,
        local_head=head,
        local_tree=tree,
        api=reader,
    )


class _NoReads:
    """Stands in for the reads where none may happen: a pull request keeps every shard."""

    def pull_request(self, number: int) -> dict[str, object]:
        message = "no read is made outside the merge queue"
        raise ApiError(message)

    def commit_tree(self, sha: str) -> str:
        message = "no read is made outside the merge queue"
        raise ApiError(message)

    def pull_request_runs(self, sha: str) -> list[dict[str, object]]:
        message = "no read is made outside the merge queue"
        raise ApiError(message)

    def check_runs(self, sha: str) -> list[dict[str, object]]:
        message = "no read is made outside the merge queue"
        raise ApiError(message)


def _repository() -> str:
    """Return the repository the run is in, from the runner's environment.

    Raises:
        UnverifiedError: the environment does not name an owner and a repository.
    """
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repo):
        message = "GITHUB_REPOSITORY is not an owner/name"
        raise UnverifiedError(message)
    return repo


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
