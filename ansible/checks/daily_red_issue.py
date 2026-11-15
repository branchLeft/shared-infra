"""Say what failed when the daily full run of the container tests is red.

Mechanical on purpose: the run link and the failed shard ids, no mention, no assignee. It
starts, wakes or asks nobody. The workflow runs it with `--summary`, which prints the text
for the run's step summary and writes nothing to any repository, so the job holds read
permissions only. Without `--summary` it opens one plain issue (or comments on the open one)
with the workflow's own token; no workflow runs it that way now, and the issue code
(`report`, `LiveIssues`) is kept with its tests until it is removed on purpose.

    daily_red_issue.py --summary --run-id N
    daily_red_issue.py --run-id N
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Protocol

from shard_results import (
    API,
    ApiError,
    LiveSource,
    ShardResult,
    live_source_from_environment,
    mapping,
    sequence,
    shard_results,
)

TITLE_PREFIX = "Daily container tests red"
LABEL = "ci-red-daily"
LABEL_COLOUR = "b60205"
LABEL_DESCRIPTION = "The daily full run of the container tests failed"
NO_FAILED_SHARD = "None: a job that is not a container test failed. The run link shows which."


class Issues(Protocol):
    """The four calls the program makes on a repository's issues."""

    def ensure_label(self) -> None:
        """Create the label if it does not exist."""

    def open_issues(self) -> list[tuple[int, str]]:
        """Return (number, title) of every open issue that carries the label."""

    def create(self, title: str, body: str) -> int:
        """Open an issue with the label and no one else attached; return its number."""

    def comment(self, number: int, body: str) -> None:
        """Add a comment to an issue."""


def failed_shards(results: Sequence[ShardResult]) -> list[str]:
    """Return the ids of the shards that did not pass, sorted."""
    return sorted({result.shard for result in results if result.failed})


def text(run_url: str, failed: Sequence[str]) -> str:
    """Return the issue or comment body: the run link and the failed shard ids."""
    listed = "\n".join(f"- `{shard}`" for shard in failed) or NO_FAILED_SHARD
    return f"Run: {run_url}\n\nFailed shard ids:\n\n{listed}\n".replace("@", "")


def summary(run_url: str, failed: Sequence[str], today: datetime.date) -> str:
    """Return the step summary of a red daily run: the date, the run link, the failed ids."""
    return f"## Daily container tests red: {today.isoformat()}\n\n{text(run_url, failed)}"


def report(
    api: Issues, run_url: str, failed: Sequence[str], today: datetime.date
) -> tuple[str, int]:
    """Open the day's issue, or comment on the open one; return what was done and the number."""
    api.ensure_label()
    body = text(run_url, failed)
    for number, title in api.open_issues():
        if title.startswith(TITLE_PREFIX):
            api.comment(number, f"Still red on {today.isoformat()}.\n\n{body}")
            return "commented", number
    return "opened", api.create(f"{TITLE_PREFIX}: {today.isoformat()}", body)


class LiveIssues:
    """Issues of one repository, written with the workflow's own token."""

    def __init__(self, source: LiveSource) -> None:
        self.source = source

    def call(self, method: str, path: str, payload: Mapping[str, object]) -> object:
        """Send a JSON request to the repository and return the decoded answer.

        Raises:
            ApiError: The request failed.
        """
        url = f"{API}/repos/{self.source.repository}/{path}"
        request = urllib.request.Request(  # noqa: S310 - the host is the fixed https API host
            url,
            data=json.dumps(payload).encode(),
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.source.token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as answer:  # noqa: S310
                decoded: object = json.loads(answer.read())
        except OSError as error:
            message = f"{method} {path} failed: {error}"
            raise ApiError(message) from error
        return decoded

    def ensure_label(self) -> None:
        """Create the label; a label that already exists (HTTP 422) is the normal case.

        Raises:
            ApiError: The request failed for any reason but the label existing.
        """
        try:
            self.call(
                "POST",
                "labels",
                {"name": LABEL, "color": LABEL_COLOUR, "description": LABEL_DESCRIPTION},
            )
        except ApiError as error:
            if "422" not in str(error):
                raise

    def open_issues(self) -> list[tuple[int, str]]:
        """Return the open issues that carry the label (a pull request is not an issue)."""
        listed = self.source.fetch("issues", {"state": "open", "labels": LABEL, "per_page": 100})
        entries = [mapping(entry) for entry in sequence(listed)]
        return [
            (int(str(entry.get("number") or 0)), str(entry.get("title") or ""))
            for entry in entries
            if "pull_request" not in entry
        ]

    def create(self, title: str, body: str) -> int:
        """Open an issue with the label only."""
        made = mapping(
            self.call("POST", "issues", {"title": title, "body": body, "labels": [LABEL]})
        )
        return int(str(made.get("number") or 0))

    def comment(self, number: int, body: str) -> None:
        """Comment on an issue."""
        self.call("POST", f"issues/{number}/comments", {"body": body})


def main(argv: Sequence[str]) -> int:
    """Print the summary of one red run, or open or extend the day's issue for it."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", maxsplit=1)[0])
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--summary", action="store_true", help="print the summary, write nothing")
    args = parser.parse_args(argv)
    try:
        source = live_source_from_environment()
        failed = failed_shards(shard_results(source.run_jobs(args.run_id)))
        server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        run_url = f"{server}/{source.repository}/actions/runs/{args.run_id}"
        today = datetime.datetime.now(datetime.UTC).date()
        if args.summary:
            print(summary(run_url, failed, today))
            return 0
        done, number = report(LiveIssues(source), run_url, failed, today)
    except (ApiError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"{done} issue #{number} for run {args.run_id}: {len(failed)} failed shard(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
