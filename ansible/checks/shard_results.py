"""Read the container test results of an Ansible workflow run from the Actions API.

Three programs share this: the report job (the step summary of every run), the daily summary
job and advisory_passes.py. All of them only read; the token comes from the environment.
A shard's job is named ``Harness: <shard id>`` when the required check waits for it and
``Advisory harness: <shard id>`` when it does not, so a result carries its kind with it.
Standard library only.

    shard_results.py report --run-id N     # prints the step summary as Markdown
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

API = "https://api.github.com"
WORKFLOW_FILE = "ansible.yml"
BLOCKING_PREFIX = "Harness: "
ADVISORY_PREFIX = "Advisory harness: "
PAGE = 100
MAX_PAGES = 20
# A conclusion that is neither a pass nor a failure: the job did not run or is still going.
NOT_A_RESULT = ("", "skipped", "neutral")


class ApiError(Exception):
    """The API did not answer, or answered with something that is not what was asked for."""


@dataclass(frozen=True)
class ShardResult:
    """One shard job of a run: which shard, whether the check waits for it, how it ended."""

    shard: str
    blocking: bool
    conclusion: str
    url: str

    @property
    def passed(self) -> bool:
        """Return whether the shard job ended in success."""
        return self.conclusion == "success"

    @property
    def failed(self) -> bool:
        """Return whether the shard job ended in anything but success, skipped or still running."""
        return self.conclusion not in ("success", *NOT_A_RESULT)


class Source(Protocol):
    """Where run and job documents come from: the live API, or a recorded fixture."""

    def schedule_runs(self, limit: int) -> list[Mapping[str, object]]:
        """Return the newest completed scheduled runs of the workflow on main, newest first."""

    def run_jobs(self, run_id: int) -> list[Mapping[str, object]]:
        """Return every job of the latest attempt of a run."""


def mapping(value: object) -> Mapping[str, object]:
    """Return ``value`` if it is a JSON object, else an empty mapping."""
    return value if isinstance(value, dict) else {}


def sequence(value: object) -> list[object]:
    """Return ``value`` if it is a JSON array, else an empty list."""
    return value if isinstance(value, list) else []


def shard_results(jobs: Iterable[Mapping[str, object]]) -> list[ShardResult]:
    """Return one result for each job that is a shard, in the order given.

    A matrix job that was skipped as a whole keeps the unexpanded name
    (``Harness: ${{ matrix.name }}``); it names no shard and is left out.
    """
    found: list[ShardResult] = []
    for job in jobs:
        name = str(job.get("name") or "")
        for prefix, blocking in ((BLOCKING_PREFIX, True), (ADVISORY_PREFIX, False)):
            if name.startswith(prefix) and "${{" not in name:
                found.append(
                    ShardResult(
                        shard=name.removeprefix(prefix),
                        blocking=blocking,
                        conclusion=str(job.get("conclusion") or ""),
                        url=str(job.get("html_url") or ""),
                    )
                )
    return found


def count(results: Sequence[ShardResult], *, blocking: bool) -> tuple[int, int, int]:
    """Return (passed, failed, other) for the blocking or the advisory shards."""
    kind = [result for result in results if result.blocking == blocking]
    passed = sum(result.passed for result in kind)
    failed = sum(result.failed for result in kind)
    return passed, failed, len(kind) - passed - failed


def summary(results: Sequence[ShardResult]) -> str:
    """Return the step summary: both counts, and every red shard in one table."""
    lines = ["## Container tests", ""]
    lines += ["| Kind | Passed | Failed | Not run or running |", "| --- | --- | --- | --- |"]
    for label, blocking in (
        ("Blocking (the required check fails with these)", True),
        ("Advisory (the required check does not wait for these)", False),
    ):
        passed, failed, other = count(results, blocking=blocking)
        lines.append(f"| {label} | {passed} | {failed} | {other} |")
    red = [result for result in results if result.failed]
    lines.append("")
    if red:
        lines += [
            "### Red shards: the approver records each red advisory shard on the pull request"
        ]
        lines += ["", "| Shard | Kind | Result | Job |", "| --- | --- | --- | --- |"]
        for result in sorted(red, key=lambda item: (item.blocking is False, item.shard)):
            kind = "blocking" if result.blocking else "advisory"
            lines.append(
                f"| `{result.shard}` | {kind} | {result.conclusion} | [job]({result.url}) |"
            )
    else:
        lines.append("No container test is red.")
    return "\n".join(lines) + "\n"


class LiveSource:
    """The Actions API of one repository, read with a token that only needs to read."""

    def __init__(self, repository: str, token: str) -> None:
        self.repository = repository
        self.token = token

    def get(self, path: str, params: Mapping[str, str | int]) -> Mapping[str, object]:
        """Return the JSON object at ``path``.

        Raises:
            ApiError: The request failed or the answer is not a JSON object.
        """
        document = self.fetch(path, params)
        if not isinstance(document, dict):
            message = f"GET {path} did not return a JSON object"
            raise ApiError(message)
        return document

    def fetch(self, path: str, params: Mapping[str, str | int]) -> object:
        """Return the decoded JSON at ``path`` (an object or an array).

        Raises:
            ApiError: The request failed or the answer is not JSON.
        """
        url = f"{API}/repos/{self.repository}/{path}?{urllib.parse.urlencode(params)}"
        request = urllib.request.Request(  # noqa: S310 - the base is the fixed https API host
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as answer:  # noqa: S310
                document: object = json.loads(answer.read())
        except (OSError, ValueError) as error:
            message = f"GET {path} failed: {error}"
            raise ApiError(message) from error
        return document

    def schedule_runs(self, limit: int) -> list[Mapping[str, object]]:
        """Return the newest completed scheduled runs of the workflow on main, newest first."""
        document = self.get(
            f"actions/workflows/{WORKFLOW_FILE}/runs",
            {"event": "schedule", "status": "completed", "branch": "main", "per_page": limit},
        )
        return [mapping(run) for run in sequence(document.get("workflow_runs"))][:limit]

    def run_jobs(self, run_id: int) -> list[Mapping[str, object]]:
        """Return every job of the latest attempt of a run, page by page."""
        found: list[Mapping[str, object]] = []
        for page in range(1, MAX_PAGES + 1):
            document = self.get(
                f"actions/runs/{run_id}/jobs", {"filter": "latest", "per_page": PAGE, "page": page}
            )
            jobs = sequence(document.get("jobs"))
            found += [mapping(job) for job in jobs]
            if len(jobs) < PAGE:
                break
        return found


class FixtureSource:
    """Recorded answers, so a program runs offline: {"runs": [...], "jobs": {"<run id>": [...]}}."""

    def __init__(self, document: Mapping[str, object]) -> None:
        self.runs = [mapping(run) for run in sequence(document.get("runs"))]
        self.jobs = mapping(document.get("jobs"))

    @classmethod
    def from_file(cls, path: Path) -> FixtureSource:
        """Read a fixture file."""
        return cls(mapping(json.loads(path.read_text(encoding="utf-8"))))

    def schedule_runs(self, limit: int) -> list[Mapping[str, object]]:
        """Return the recorded runs, newest first."""
        return self.runs[:limit]

    def run_jobs(self, run_id: int) -> list[Mapping[str, object]]:
        """Return the recorded jobs of a run; none recorded is an empty run."""
        return [mapping(job) for job in sequence(self.jobs.get(str(run_id)))]


def live_source_from_environment() -> LiveSource:
    """Return a source for the repository and token the environment names.

    Raises:
        ApiError: The repository or the token is not in the environment.
    """
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if not repository or not token:
        message = "GITHUB_REPOSITORY and GH_TOKEN (or GITHUB_TOKEN) must be set"
        raise ApiError(message)
    return LiveSource(repository, token)


def main(argv: Sequence[str]) -> int:
    """Print the step summary of one run to standard output."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", maxsplit=1)[0])
    parser.add_argument("command", choices=("report",))
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--fixture", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        source: Source = (
            FixtureSource.from_file(args.fixture)
            if args.fixture
            else live_source_from_environment()
        )
        results = shard_results(source.run_jobs(args.run_id))
    except (ApiError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    sys.stdout.write(summary(results))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
