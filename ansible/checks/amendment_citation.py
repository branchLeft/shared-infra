"""Check that the cited standards pull request is the merged ANS-12 amendment.

Why, and how to cite it: ansible/roles/restart_stamp/README.md, "Composition (ANS-12)".
"""

from __future__ import annotations

import http.client
import json
import re
from collections.abc import Callable, Mapping
from typing import Protocol

CITATION_FORM = re.compile(
    r"https://github\.com/branchLeft/standards/pull/([0-9]+) merged ([0-9a-f]{40})"
)
API_HOST = "api.github.com"
STANDARDS = "branchLeft/standards"
ANSIBLE_DOC = "docs/stacks/ansible.md"
BASE_BRANCH = "main"

# The sentence the amendment replaces, and the words the rule that replaces it carries.
NAMED_LIMIT = "is decided with the first role pattern and recorded here by amendment"
RULE_WORDS = "capability role"
ANS12_SECTION = re.compile(r"^## ANS-12 .*?(?=^## ANS-\d+ )", re.DOTALL | re.MULTILINE)


NOT_JSON = "is not a JSON object"
NOT_TEXT = "is not text"


class StandardsReadError(Exception):
    """The standards repository could not be read: a transport error, a refusal or a bad body."""

    def __init__(self, subject: str, reason: str) -> None:
        super().__init__(f"{subject}: {reason}")


class StandardsApi(Protocol):
    """What the check reads from the standards repository."""

    def pull(self, number: int) -> Mapping[str, object]:
        """Return GitHub's pull request object."""
        ...

    def file_at(self, sha: str, path: str) -> str:
        """Return a file of the repository as it was at a commit."""
        ...


class Response(Protocol):
    """The part of an HTTP response the client reads."""

    status: int

    def read(self) -> bytes:
        """Return the body."""
        ...


class Connection(Protocol):
    """The part of an HTTP connection the client uses."""

    def request(self, method: str, url: str, *, headers: dict[str, str]) -> None:
        """Send a request."""
        ...

    def getresponse(self) -> Response:
        """Return the response."""
        ...

    def close(self) -> None:
        """Close the connection."""
        ...


def https_connection(host: str) -> Connection:
    """Open a connection to the host over HTTPS, with a timeout."""
    return http.client.HTTPSConnection(host, timeout=20)


class HttpStandardsApi:
    """GitHub's REST API over HTTPS. The token, when there is one, goes only in a header."""

    def __init__(
        self,
        token: str | None,
        connect: Callable[[str], Connection] = https_connection,
        attempts: int = 2,
    ) -> None:
        self.token = token
        self.connect = connect
        self.attempts = attempts

    def get(self, path: str, accept: str) -> bytes:
        """Read one path; a transport error or a 5xx is tried again, once, and a 4xx is not.

        Raises:
            StandardsReadError: the path could not be read; the reason never holds the token.
        """
        headers = {
            "Accept": accept,
            "User-Agent": "branchleft-ansible-checks",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        reason = ""
        for _ in range(self.attempts):
            connection = self.connect(API_HOST)
            try:
                connection.request("GET", path, headers=headers)
                response = connection.getresponse()
                body = response.read()
            except (OSError, http.client.HTTPException) as error:
                reason = f"{type(error).__name__}"
                continue
            finally:
                connection.close()
            if response.status == 200:
                return body
            reason = f"HTTP {response.status}"
            if response.status < 500:
                break
        raise StandardsReadError(path, reason)

    def pull(self, number: int) -> Mapping[str, object]:
        """Return the pull request object of the standards repository.

        Raises:
            StandardsReadError: the pull request could not be read or is not a JSON object.
        """
        path = f"/repos/{STANDARDS}/pulls/{number}"
        body = self.get(path, "application/vnd.github+json")
        try:
            loaded = json.loads(body)
        except ValueError as error:
            raise StandardsReadError(path, NOT_JSON) from error
        if not isinstance(loaded, dict):
            raise StandardsReadError(path, NOT_JSON)
        return {str(key): value for key, value in loaded.items()}

    def file_at(self, sha: str, path: str) -> str:
        """Return a file of the standards repository at a commit, as text.

        Raises:
            StandardsReadError: the file could not be read or is not text.
        """
        url = f"/repos/{STANDARDS}/contents/{path}?ref={sha}"
        body = self.get(url, "application/vnd.github.raw+json")
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError as error:
            raise StandardsReadError(url, NOT_TEXT) from error


def amendment_problems(document: str) -> list[str]:
    """Return what is wrong with the ANS-12 section of the document: it must hold the rule."""
    section = ANS12_SECTION.search(document)
    if not section:
        return [f"{ANSIBLE_DOC} at the cited commit has no ANS-12 section"]
    text = " ".join(section.group(0).split())
    found: list[str] = []
    if NAMED_LIMIT in text:
        found.append("ANS-12 at the cited commit still carries the named limit it was to close")
    if RULE_WORDS not in text.lower():
        found.append("ANS-12 at the cited commit does not state the capability-role rule")
    return found


def citation_problems(line: str, api: StandardsApi) -> list[str]:
    """Return why the cited line is not the merged amendment; empty when it is.

    A read of the standards repository that fails raises StandardsReadError: whether that is
    a failure or a skip is for the caller to say.
    """
    cited = CITATION_FORM.fullmatch(line.strip())
    if not cited:
        return ["the citation is malformed"]
    number, sha = int(cited.group(1)), cited.group(2)
    pull = api.pull(number)
    found: list[str] = []
    if pull.get("merged") is not True:
        found.append(f"standards pull request {number} is not merged")
    if pull.get("merge_commit_sha") != sha:
        found.append(f"{sha} is not the merge commit of standards pull request {number}")
    base = pull.get("base")
    if not (isinstance(base, Mapping) and base.get("ref") == BASE_BRANCH):
        found.append(f"standards pull request {number} was not merged into {BASE_BRANCH}")
    if found:
        return found
    return amendment_problems(api.file_at(sha, ANSIBLE_DOC))
