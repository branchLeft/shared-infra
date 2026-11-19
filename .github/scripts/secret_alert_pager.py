#!/usr/bin/env python3
"""Page the owner once for each new open secret-scanning alert on a public repository.

Run by .github/workflows/secret-alert-pager.yml every five minutes. It lists the
organisation's open alerts with hide_secret=true, keeps those on public repositories, and
sends one ntfy page per alert it has not paged before. A page names the repository, the alert
number and the kind of secret, with a link to the alert, and never carries the secret.

The set of paged alerts is a JSON file the workflow keeps in an actions/cache entry. An alert
is identified by "<repository full name>:<number>", because numbers repeat across repositories.
The file being absent is the only cold-start signal: the run then pages alerts created in the
last fifteen minutes and records every older open alert without paging it. A file that is
present but unreadable stops the run, because treating it as cold would re-page.

For each alert the page is sent first and its key is written to the file straight after, so a
failed send is retried next run. The one repeat left is the process dying between a successful
send and that write.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import http.client
import json
import os
import pathlib
import re
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from email.message import Message
from typing import IO, Protocol
from urllib.parse import parse_qs, urlsplit

NTFY_TOPIC = "branchleft-pages"
PAGE_PRIORITY = 5
PAGE_TAGS = ("rotating_light",)
PAGE_TITLE = "ALERT_TITLE_PLACEHOLDER"
PAGE_BODY = "ALERT_BODY_PLACEHOLDER"

GITHUB_HOST = "api.github.com"
GITHUB_API_VERSION = "2022-11-28"
USER_AGENT = "branchleft-secret-alert-pager"
LISTING_PAGE_SIZE = 100
MAXIMUM_LISTING_PAGES = 50
REQUEST_TIMEOUT_SECONDS = 30
COLD_START_WINDOW = datetime.timedelta(minutes=15)
STATE_VERSION = 1
ERROR_MESSAGE_LIMIT = 200

OWNER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")
LINK_ENTRY = re.compile(r"<([^>]+)>([^<]*)")
NEXT_RELATION = re.compile(r'rel="?next"?')


class PagerError(Exception):
    """Base of every failure this program raises on purpose."""


class PagerConfigError(PagerError):
    """A required environment variable is missing or unusable."""


class HttpTransportError(PagerError):
    """The request could not be sent or no response came back."""


class AlertReadError(PagerError):
    """GitHub refused the listing, or the listing could not be read completely."""


class AlertPayloadError(PagerError):
    """The listing is not the shape the API documents."""


class PageDeliveryError(PagerError):
    """ntfy did not accept a page."""


class StateFileError(PagerError):
    """The paged-alert file, or the workflow output file, cannot be read or written."""


class MessageLeakError(PagerError):
    """A page about to be sent contains the secret value the API carried."""


@dataclasses.dataclass(frozen=True)
class HttpRequest:
    url: str
    method: str
    headers: Mapping[str, str] = dataclasses.field(repr=False)
    body: bytes | None


@dataclasses.dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class HttpTransport(Protocol):
    """Sends one request. A non-2xx answer is a returned response; only a failure to get any
    answer raises."""

    def send(self, request: HttpRequest) -> HttpResponse: ...


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Stops urllib forwarding the Authorization header to wherever a redirect points."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


class UrllibTransport:
    """The real transport: urllib, no redirects followed, a fixed timeout."""

    def send(self, request: HttpRequest) -> HttpResponse:
        """Return the response for any status.

        Raises:
            HttpTransportError: no response arrived (connection, TLS or timeout failure).
        """
        outgoing = urllib.request.Request(
            request.url, data=request.body, method=request.method, headers=dict(request.headers)
        )
        opener = urllib.request.build_opener(RefuseRedirects)
        try:
            with opener.open(outgoing, timeout=REQUEST_TIMEOUT_SECONDS) as answer:
                return HttpResponse(answer.status, _lowercase(answer.headers.items()), answer.read())
        except urllib.error.HTTPError as refusal:
            with refusal:
                return HttpResponse(refusal.code, _lowercase(refusal.headers.items()), refusal.read())
        except (OSError, http.client.HTTPException) as failure:
            reason = failure.reason if isinstance(failure, urllib.error.URLError) else failure
            raise HttpTransportError(f"{type(failure).__name__}: {reason}") from failure


def _lowercase(pairs: Sequence[tuple[str, str]]) -> dict[str, str]:
    return {name.lower(): value for name, value in pairs}


@dataclasses.dataclass(frozen=True)
class PagerConfig:
    read_token: str = dataclasses.field(repr=False)
    publish_token: str = dataclasses.field(repr=False)
    owner: str
    ntfy_base_url: str
    state_file: pathlib.Path


def load_config(env: Mapping[str, str], state_file: pathlib.Path) -> PagerConfig:
    """Read and check the environment once, at start.

    Raises:
        PagerConfigError: a variable is missing, empty, or not usable; the message names the
            variable and never shows a value.
    """
    owner = _required(env, "GITHUB_REPOSITORY_OWNER")
    if OWNER_PATTERN.fullmatch(owner) is None:
        raise PagerConfigError("GITHUB_REPOSITORY_OWNER is not a plain organisation name")
    base_url = _required(env, "NTFY_BASE_URL")
    parts = urlsplit(base_url)
    if parts.scheme != "https" or not parts.hostname or parts.username is not None:
        raise PagerConfigError("NTFY_BASE_URL must be an https URL with a host and no credentials")
    return PagerConfig(
        read_token=_required(env, "PAGER_READ_TOKEN"),
        publish_token=_required(env, "NTFY_PAGER_PUBLISH_TOKEN"),
        owner=owner,
        ntfy_base_url=base_url.rstrip("/"),
        state_file=state_file,
    )


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise PagerConfigError(f"required environment variable {name} is missing or empty")
    return value


@dataclasses.dataclass(frozen=True)
class SecretAlert:
    """The only facts about an alert that leave the parser. It has no field for the secret."""

    repository_full_name: str
    number: int
    secret_type: str
    secret_type_display_name: str
    html_url: str
    created_at: datetime.datetime

    @property
    def key(self) -> str:
        return f"{self.repository_full_name}:{self.number}"


@dataclasses.dataclass(frozen=True)
class ListedAlert:
    """An alert plus the raw secret string the API carried, held only for the leak guard."""

    alert: SecretAlert
    secret_to_guard: str = dataclasses.field(repr=False)


@dataclasses.dataclass(frozen=True)
class AlertListing:
    alerts: tuple[ListedAlert, ...]
    skipped_non_public: int


def parse_listing_page(body: bytes) -> tuple[list[ListedAlert], int]:
    """Parse one page of the listing into alerts on public repositories.

    Returns the alerts and the number of items skipped because the repository is not
    confirmed public (private, or visibility missing or not a boolean).

    Raises:
        AlertPayloadError: the body is not a JSON array of well-formed alert objects. The
            message names the field and never shows any value.
    """
    try:
        payload: object = json.loads(body)
    except ValueError as failure:
        raise AlertPayloadError("the listing body is not valid JSON") from failure
    if not isinstance(payload, list):
        raise AlertPayloadError("the listing body is not a JSON array")
    alerts: list[ListedAlert] = []
    skipped = 0
    for entry in payload:
        listed = _parse_item(entry)
        if listed is None:
            skipped += 1
        else:
            alerts.append(listed)
    return alerts, skipped


def _parse_item(entry: object) -> ListedAlert | None:
    if not isinstance(entry, dict):
        raise AlertPayloadError("a listing item is not a JSON object")
    repository = entry.get("repository")
    if not isinstance(repository, dict):
        raise AlertPayloadError("field repository is missing or not an object")
    if repository.get("private") is not False:
        return None
    if _text(entry, "state") != "open":
        return None
    secret = entry.get("secret")
    alert = SecretAlert(
        repository_full_name=_text(repository, "full_name"),
        number=_number(entry),
        secret_type=_text(entry, "secret_type"),
        secret_type_display_name=_display_name(entry),
        html_url=_link(entry),
        created_at=_timestamp(entry),
    )
    return ListedAlert(alert, secret if isinstance(secret, str) else "")


def _text(source: Mapping[str, object], name: str) -> str:
    value = source.get(name)
    if not isinstance(value, str) or not value:
        raise AlertPayloadError(f"field {name} is missing or not a non-empty string")
    return value


def _number(entry: Mapping[str, object]) -> int:
    value = entry.get("number")
    if not isinstance(value, int) or isinstance(value, bool):
        raise AlertPayloadError("field number is missing or not an integer")
    return value


def _display_name(entry: Mapping[str, object]) -> str:
    if entry.get("secret_type_display_name") is None:
        return _text(entry, "secret_type")
    return _text(entry, "secret_type_display_name")


def _link(entry: Mapping[str, object]) -> str:
    value = _text(entry, "html_url")
    if not value.startswith("https://"):
        raise AlertPayloadError("field html_url is not an https URL")
    return value


def _timestamp(entry: Mapping[str, object]) -> datetime.datetime:
    text = _text(entry, "created_at")
    try:
        moment = datetime.datetime.fromisoformat(text)
    except ValueError as failure:
        raise AlertPayloadError("field created_at is not an ISO 8601 timestamp") from failure
    if moment.tzinfo is None:
        raise AlertPayloadError("field created_at has no time zone")
    return moment


def read_open_public_alerts(transport: HttpTransport, config: PagerConfig) -> AlertListing:
    """List every open alert on a public repository of the organisation, newest first.

    Raises:
        AlertReadError: GitHub answered non-2xx (a 403 included), no answer came, a next link
            points anywhere but api.github.com over https or drops hide_secret=true, or the
            listing is longer than MAXIMUM_LISTING_PAGES pages.
        AlertPayloadError: a page is not the documented shape.
    """
    query = f"state=open&hide_secret=true&per_page={LISTING_PAGE_SIZE}&sort=created&direction=desc"
    url = f"https://{GITHUB_HOST}/orgs/{config.owner}/secret-scanning/alerts?{query}"
    alerts: list[ListedAlert] = []
    skipped = 0
    for _ in range(MAXIMUM_LISTING_PAGES):
        response = _get_listing_page(transport, url, config.read_token)
        page_alerts, page_skipped = parse_listing_page(response.body)
        alerts.extend(page_alerts)
        skipped += page_skipped
        next_url = _next_link(response.headers.get("link", ""))
        if next_url is None:
            return AlertListing(tuple(alerts), skipped)
        url = _checked_next_url(next_url)
    raise AlertReadError(f"the listing is longer than {MAXIMUM_LISTING_PAGES} pages")


def _get_listing_page(transport: HttpTransport, url: str, token: str) -> HttpResponse:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": USER_AGENT,
    }
    try:
        response = transport.send(HttpRequest(url, "GET", headers, None))
    except HttpTransportError as failure:
        raise AlertReadError(f"the listing request failed: {failure}") from failure
    if not 200 <= response.status < 300:
        raise AlertReadError(
            f"GitHub refused the listing with status {response.status}: "
            f"{_github_message(response.body)}"
        )
    return response


def _github_message(body: bytes) -> str:
    try:
        document: object = json.loads(body)
    except ValueError:
        return "no message"
    if isinstance(document, dict) and isinstance(document.get("message"), str):
        return " ".join(document["message"].split())[:ERROR_MESSAGE_LIMIT]
    return "no message"


def _next_link(header: str) -> str | None:
    for match in LINK_ENTRY.finditer(header):
        if NEXT_RELATION.search(match.group(2)):
            return match.group(1)
    return None


def _checked_next_url(url: str) -> str:
    parts = urlsplit(url)
    on_github = parts.scheme == "https" and parts.hostname == GITHUB_HOST
    if not on_github or parts.port is not None or parts.username is not None:
        raise AlertReadError("a next link points away from api.github.com over https")
    if parse_qs(parts.query).get("hide_secret") != ["true"]:
        raise AlertReadError("a next link does not request hide_secret=true")
    return url


@dataclasses.dataclass(frozen=True)
class NtfyPage:
    topic: str
    title: str
    message: str
    priority: int
    tags: tuple[str, ...]
    click: str

    def to_json_bytes(self) -> bytes:
        document = {
            "topic": self.topic,
            "title": self.title,
            "message": self.message,
            "priority": self.priority,
            "tags": list(self.tags),
            "click": self.click,
        }
        return json.dumps(document).encode("utf-8")


def build_page(alert: SecretAlert) -> NtfyPage:
    """Build the page from the alert's own fields; the alert cannot hold a secret."""
    lines = (
        PAGE_BODY,
        f"repository: {alert.repository_full_name}",
        f"alert: {alert.number}",
        f"kind: {alert.secret_type_display_name}",
        f"link: {alert.html_url}",
    )
    return NtfyPage(
        topic=NTFY_TOPIC,
        title=PAGE_TITLE,
        message="\n".join(lines),
        priority=PAGE_PRIORITY,
        tags=PAGE_TAGS,
        click=alert.html_url,
    )


def ensure_page_free_of_secret(page: NtfyPage, secret: str) -> None:
    """Refuse a page that contains the secret value, whatever put it there.

    Raises:
        MessageLeakError: the secret appears in the title, message, click link or the
            serialised body. The message never shows the value.
    """
    if not secret:
        return
    serialised = page.to_json_bytes().decode("utf-8")
    if any(secret in text for text in (page.title, page.message, page.click, serialised)):
        raise MessageLeakError("a page would carry the detected secret value, so it was not sent")


def publish_page(
    transport: HttpTransport, config: PagerConfig, page: NtfyPage, alert: SecretAlert
) -> None:
    """Send one page to ntfy with the publish token.

    Raises:
        PageDeliveryError: no answer came, or ntfy answered non-2xx. The message carries the
            status and the alert, never the token or the response body.
    """
    headers = {
        "Authorization": f"Bearer {config.publish_token}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    request = HttpRequest(config.ntfy_base_url + "/", "POST", headers, page.to_json_bytes())
    subject = f"alert {alert.number} in {alert.repository_full_name}"
    try:
        response = transport.send(request)
    except HttpTransportError as failure:
        raise PageDeliveryError(f"the page for {subject} was not sent: {failure}") from failure
    if not 200 <= response.status < 300:
        raise PageDeliveryError(f"ntfy refused the page for {subject} with status {response.status}")


class PagedStateStore:
    """The paged-alert file: absent means cold, present means a JSON set of alert keys."""

    def __init__(self, path: pathlib.Path) -> None:
        self.path = path

    def load(self) -> frozenset[str] | None:
        """Return the paged keys, or None when the file does not exist.

        Raises:
            StateFileError: the file exists but cannot be read, parsed or recognised.
        """
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as failure:
            raise StateFileError(f"the state file cannot be read: {failure.strerror}") from failure
        try:
            document: object = json.loads(text)
        except ValueError as failure:
            raise StateFileError("the state file is not valid JSON") from failure
        keys = self._keys(document)
        if keys is None:
            raise StateFileError("the state file is not a version 1 paged-alert set")
        return keys

    @staticmethod
    def _keys(document: object) -> frozenset[str] | None:
        if not isinstance(document, dict) or document.get("version") != STATE_VERSION:
            return None
        paged = document.get("paged")
        if not isinstance(paged, list) or not all(isinstance(key, str) for key in paged):
            return None
        return frozenset(paged)

    def save(self, keys: frozenset[str]) -> None:
        """Write the set atomically: a temporary file in the same directory, then a rename.

        Raises:
            StateFileError: the directory or file cannot be written.
        """
        document = {"version": STATE_VERSION, "paged": sorted(keys)}
        temporary: str | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".paged-")
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except OSError as failure:
            if temporary is not None:
                pathlib.Path(temporary).unlink(missing_ok=True)
            raise StateFileError(f"the state file cannot be written: {failure.strerror}") from failure


class GithubOutputFile:
    """Tells the workflow that the state file changed, once, through GITHUB_OUTPUT."""

    def __init__(self, path: str | None) -> None:
        self.path = path
        self.announced = False

    def announce_state_changed(self) -> None:
        """Append state_changed=true to the output file when one is set.

        Raises:
            StateFileError: the output file cannot be written.
        """
        if self.path is None or self.announced:
            return
        try:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write("state_changed=true\n")
        except OSError as failure:
            raise StateFileError(f"the workflow output file cannot be written: {failure.strerror}") from failure
        self.announced = True


@dataclasses.dataclass(frozen=True)
class RunSummary:
    open_public: int
    paged: int
    already_paged: int
    backlog_recorded: int
    skipped_non_public: int

    def line(self) -> str:
        return (
            f"secret-alert-pager: open_public={self.open_public} paged={self.paged} "
            f"already_paged={self.already_paged} backlog_recorded={self.backlog_recorded} "
            f"skipped_non_public={self.skipped_non_public}"
        )


def run_pager(
    config: PagerConfig,
    transport: HttpTransport,
    clock: Callable[[], datetime.datetime],
    store: PagedStateStore,
    output: GithubOutputFile,
) -> RunSummary:
    """Page each new alert once and record it.

    Raises:
        PagerError: any subclass; the run stops at the first failure with every page already
            sent recorded in the state file.
    """
    previous = store.load()
    listing = read_open_public_alerts(transport, config)
    candidates = sorted(
        listing.alerts,
        key=lambda listed: (listed.alert.created_at, listed.alert.repository_full_name, listed.alert.number),
    )
    backlog_recorded = 0
    if previous is None:
        cutoff = clock() - COLD_START_WINDOW
        backlog = [listed for listed in candidates if listed.alert.created_at < cutoff]
        candidates = [listed for listed in candidates if listed.alert.created_at >= cutoff]
        paged = frozenset(listed.alert.key for listed in backlog)
        backlog_recorded = len(paged)
        store.save(paged)
        output.announce_state_changed()
    else:
        paged = previous
    sent = 0
    already = 0
    for listed in candidates:
        if listed.alert.key in paged:
            already += 1
            continue
        page = build_page(listed.alert)
        ensure_page_free_of_secret(page, listed.secret_to_guard)
        publish_page(transport, config, page, listed.alert)
        paged = paged | {listed.alert.key}
        store.save(paged)
        output.announce_state_changed()
        sent += 1
    return RunSummary(len(listing.alerts), sent, already, backlog_recorded, listing.skipped_non_public)


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    transport: HttpTransport | None = None,
    clock: Callable[[], datetime.datetime] | None = None,
) -> int:
    """Run once and return the exit status: 0 on success, 1 on any PagerError.

    Raises:
        SystemExit: the command line is wrong (argparse exits 2).
    """
    parser = argparse.ArgumentParser(description="Page the owner for new secret-scanning alerts.")
    parser.add_argument("--state-file", type=pathlib.Path, required=True)
    arguments = parser.parse_args(argv)
    environment = os.environ if env is None else env
    try:
        config = load_config(environment, arguments.state_file)
        summary = run_pager(
            config,
            UrllibTransport() if transport is None else transport,
            _utc_now if clock is None else clock,
            PagedStateStore(config.state_file),
            GithubOutputFile(environment.get("GITHUB_OUTPUT") or None),
        )
    except PagerError as failure:
        print(f"ERROR: {type(failure).__name__}: {failure}", file=sys.stderr)
        return 1
    print(summary.line())
    return 0


if __name__ == "__main__":
    sys.exit(main())
