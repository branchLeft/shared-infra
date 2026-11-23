#!/usr/bin/env python3
"""Pages the owner's phone when a report reaches abuse@ on the mail host.

Run every minute by a systemd timer, as root. It asks Stalwart, on loopback, which messages
abuse@ holds, compares them with the ids it saw last time, and posts one fixed notice to the
pager's abuse topic with the mail host's publish-only token. The notice carries no sender, no
message text and no tenant. `run` does the work; `--check` only proves the file loads.
"""

from __future__ import annotations

import base64
import errno
import json
import os
import re
import secrets
import stat
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from http.client import HTTPMessage
from typing import IO, Final

STALWART_URL: Final = "http://127.0.0.1:8080"
ADMIN_CREDENTIALS_PATH: Final = "/root/.stalwart-admin-credentials"
TOKEN_FILE_PATH: Final = "/etc/branchleft/mx1-abuse-page.env"  # noqa: S105 - a path, no secret
TOKEN_KEY: Final = "NTFY_MX1_TOKEN"  # noqa: S105 - a name, no secret
STATE_DIR: Final = "/var/lib/branchleft/abuse-page"
STATE_NAME: Final = "seen.json"
NTFY_TOPIC_URL: Final = "https://ntfy.branchleft.co.uk/branchleft-abuse"
MAIL_DOMAIN: Final = "branchleft.co.uk"
MAILBOX_NAME: Final = "abuse"

# The page's words are the owner's; these are placeholders until they are written.
PAGE_TITLE: Final = "ABUSE_REPORT_PAGE_TITLE"
PAGE_MESSAGE: Final = "ABUSE_REPORT_PAGE_MESSAGE"

JMAP_CORE: Final = "urn:ietf:params:jmap:core"
JMAP_MAIL: Final = "urn:ietf:params:jmap:mail"
# The newest messages looked at each run. A burst larger than this still pages once.
QUERY_LIMIT: Final = 200
TIMEOUT_SECONDS: Final = 15
FILE_MAX_BYTES: Final = 1 << 16
TOKEN_PATTERN: Final = re.compile(r"tk_[a-z0-9]{29}")
ID_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]{1,64}")

ROOT_UID: Final = 0
EXIT_OK: Final = 0
EXIT_FAILED: Final = 1
EXIT_USAGE: Final = 2
EXIT_PAGED_STATE_LOST: Final = 3

# Every failure is one of these codes, so a message never holds a value, an address or a body.
MESSAGES: Final[dict[str, str]] = {
    "not-object": "an answer was not a JSON object",
    "not-list": "an answer was not a JSON list",
    "file-link": "a private file is a link",
    "file-open": "a private file cannot be opened",
    "file-type": "a private file is not a regular file",
    "file-owner": "a private file is not root's, or is open to others",
    "file-size": "a private file is too large",
    "file-text": "a private file is not text",
    "admin-shape": "the administrator credential file is not user:secret",
    "token-shape": "the token file does not hold exactly one usable token",
    "request": "a request could not be made",
    "http-status": "a request was answered with an error status",
    "stalwart-status": "Stalwart did not answer 200",
    "stalwart-json": "Stalwart's answer was not JSON",
    "stalwart-shape": "Stalwart's answer held no single method response",
    "stalwart-refused": "Stalwart refused a method call",
    "domain": "the mail domain is not exactly one Domain object",
    "account": "abuse@ is not exactly one Account object",
    "message-id": "a message id had an unexpected shape",
    "pager-reply": "the pager's answer was not an ntfy message",
    "pager-refused": "the pager did not accept the notice",
    "state-write": "the state file could not be written",
}


class AbusePageError(Exception):
    """A refusal or failure, by code. The text is fixed and holds no value, address or body."""

    def __init__(self, code: str) -> None:
        super().__init__(MESSAGES.get(code, code))


Json = dict[str, object]


@dataclass(frozen=True)
class Seen:
    """What the last run saw: None when it has never run, else the ids, newest first."""

    ids: tuple[str, ...] | None


def as_mapping(value: object) -> Json:
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return {str(key): item for key, item in value.items()}
    raise AbusePageError("not-object")


def as_list(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    raise AbusePageError("not-list")


def valid_ids(items: list[object]) -> list[str] | None:
    """The items as ids, or None when any is not a string of the shape Stalwart uses."""
    if all(isinstance(item, str) and ID_PATTERN.fullmatch(item) for item in items):
        return [str(item) for item in items]
    return None


def new_ids(current: Sequence[str], seen: Seen) -> list[str]:
    """The ids that are new since the last run. A first run, with nothing seen, has none: the
    mailbox as it stands is the baseline, so deploying this does not page for old mail."""
    if seen.ids is None:
        return []
    known = set(seen.ids)
    return [item for item in current if item not in known]


def read_private_file(path: str, owner_uid: int = ROOT_UID) -> str:
    """The text of a regular file owned by `owner_uid` (root) that no one else can read or write.

    Raises:
        AbusePageError: when it is a link, not regular, not root's, open to others, or unreadable.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as err:
        raise AbusePageError("file-link" if err.errno == errno.ELOOP else "file-open") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise AbusePageError("file-type")
        if info.st_uid != owner_uid or info.st_mode & 0o077:
            raise AbusePageError("file-owner")
        data = os.read(descriptor, FILE_MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > FILE_MAX_BYTES:
        raise AbusePageError("file-size")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise AbusePageError("file-text") from None


def parse_admin_credentials(text: str) -> tuple[str, str]:
    """`user:secret` on one line, as the mail host's reconcilers keep it.

    Raises:
        AbusePageError: when the text is not that.
    """
    user, separator, secret = text.strip().partition(":")
    if not separator or not user or not secret or "\n" in secret:
        raise AbusePageError("admin-shape")
    return user, secret


def parse_token(text: str) -> str:
    """The one NTFY_MX1_TOKEN line of the token file, shaped as ntfy requires.

    Raises:
        AbusePageError: when there is not exactly one well-formed token.
    """
    found = [
        line.partition("=")[2].strip()
        for line in text.splitlines()
        if line.partition("=")[0].strip() == TOKEN_KEY
    ]
    if len(found) != 1 or TOKEN_PATTERN.fullmatch(found[0]) is None:
        raise AbusePageError("token-shape")
    return found[0]


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect would carry a credential somewhere the owner never configured."""

    def redirect_request(  # noqa: PLR0913
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


def open_url(request: urllib.request.Request) -> tuple[int, bytes]:
    """Send a request with no proxy and no redirect. Returns the status and the body.

    Raises:
        AbusePageError: when the request fails or is answered with an error status.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RefuseRedirects)
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            return int(response.status), bytes(response.read(FILE_MAX_BYTES))
    except urllib.error.HTTPError:
        raise AbusePageError("http-status") from None
    except (urllib.error.URLError, OSError, ValueError):
        raise AbusePageError("request") from None


Fetch = Callable[[urllib.request.Request], tuple[int, bytes]]


def jmap_call(
    fetch: Fetch, credentials: tuple[str, str], uses: list[str], method: str, arguments: Json
) -> Json:
    """One JMAP method call against Stalwart as the administrator.

    Raises:
        AbusePageError: when Stalwart does not answer with one successful method response.
    """
    login = base64.b64encode(f"{credentials[0]}:{credentials[1]}".encode()).decode()
    body = json.dumps({"using": uses, "methodCalls": [[method, arguments, "0"]]}).encode()
    request = urllib.request.Request(  # noqa: S310 - a constant loopback URL
        f"{STALWART_URL}/jmap",
        data=body,
        method="POST",
        headers={"Authorization": f"Basic {login}", "Content-Type": "application/json"},
    )
    status, content = fetch(request)
    if status != 200:
        raise AbusePageError("stalwart-status")
    try:
        answer = as_mapping(json.loads(content))
    except ValueError:
        raise AbusePageError("stalwart-json") from None
    responses = as_list(answer.get("methodResponses"))
    if len(responses) != 1:
        raise AbusePageError("stalwart-shape")
    entry = as_list(responses[0])
    if len(entry) != 3 or entry[0] != method:
        raise AbusePageError("stalwart-refused")
    return as_mapping(entry[1])


def abuse_account_id(fetch: Fetch, credentials: tuple[str, str]) -> str:
    """The id of abuse@ on the mail domain, read by name, never guessed.

    Raises:
        AbusePageError: when the domain or the account is not exactly one object.
    """
    domains = as_list(jmap_call(fetch, credentials, [JMAP_CORE], "x:Domain/get", {}).get("list"))
    domain_ids = [
        str(as_mapping(item).get("id"))
        for item in domains
        if as_mapping(item).get("name") == MAIL_DOMAIN
    ]
    if len(domain_ids) != 1:
        raise AbusePageError("domain")
    accounts = as_list(
        jmap_call(
            fetch, credentials, [JMAP_CORE], "x:Account/get", {"properties": ["name", "domainId"]}
        ).get("list")
    )
    found = [
        str(as_mapping(item).get("id"))
        for item in accounts
        if as_mapping(item).get("name") == MAILBOX_NAME
        and as_mapping(item).get("domainId") == domain_ids[0]
    ]
    if len(found) != 1 or ID_PATTERN.fullmatch(found[0]) is None:
        raise AbusePageError("account")
    return found[0]


def message_ids(fetch: Fetch, credentials: tuple[str, str], account_id: str) -> list[str]:
    """The ids of the newest messages abuse@ holds, newest first. Ids only: nothing of a message.

    Raises:
        AbusePageError: when an id has an unexpected shape.
    """
    result = jmap_call(
        fetch,
        credentials,
        [JMAP_CORE, JMAP_MAIL],
        "Email/query",
        {
            "accountId": account_id,
            "sort": [{"property": "receivedAt", "isAscending": False}],
            "limit": QUERY_LIMIT,
        },
    )
    ids = valid_ids(as_list(result.get("ids")))
    if ids is None:
        raise AbusePageError("message-id")
    return ids


def publish_page(fetch: Fetch, token: str) -> None:
    """Post the fixed notice. A 200 that is not an ntfy message does not count as published.

    Raises:
        AbusePageError: when the pager does not return an ntfy message with status 200.
    """
    request = urllib.request.Request(
        NTFY_TOPIC_URL,
        data=PAGE_MESSAGE.encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Title": PAGE_TITLE,
            "Priority": "5",
            "Tags": "rotating_light",
        },
    )
    status, content = fetch(request)
    try:
        answer = as_mapping(json.loads(content))
    except (ValueError, AbusePageError):
        raise AbusePageError("pager-reply") from None
    published = answer.get("id")
    if status != 200 or not isinstance(published, str) or not published:
        raise AbusePageError("pager-refused")


def read_seen(state_dir: str, owner_uid: int = ROOT_UID) -> Seen:
    """The ids of the last run. No file is a first run. A damaged file is not trusted: it reads as
    an empty list, so the next run pages for what the mailbox holds."""
    path = os.path.join(state_dir, STATE_NAME)
    try:
        text = read_private_file(path, owner_uid)
    except AbusePageError:
        return Seen(()) if os.path.lexists(path) else Seen(None)
    try:
        ids = valid_ids(as_list(as_mapping(json.loads(text)).get("ids")))
    except (ValueError, AbusePageError):
        return Seen(())
    return Seen(tuple(ids) if ids is not None else ())


def write_seen(state_dir: str, ids: Sequence[str]) -> None:
    """Replace the state file whole: written closed to root, synced, then renamed into place.

    Raises:
        AbusePageError: when the file cannot be written.
    """
    destination = os.path.join(state_dir, STATE_NAME)
    temporary = os.path.join(state_dir, f".{STATE_NAME}.{os.getpid()}.{secrets.token_hex(4)}")
    data = (json.dumps({"ids": list(ids)}) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(temporary, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, destination)
        directory = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        raise AbusePageError("state-write") from None
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def run_once(
    fetch: Fetch,
    admin_credentials: tuple[str, str],
    token: str,
    state_dir: str,
    log: Callable[[str], None],
    owner_uid: int = ROOT_UID,
) -> int:
    """One poll. Returns the exit code. A failure before the page leaves the state as it was, so
    the next run tries again."""
    account_id = abuse_account_id(fetch, admin_credentials)
    current = message_ids(fetch, admin_credentials, account_id)
    seen = read_seen(state_dir, owner_uid)
    if seen.ids is None:
        write_seen(state_dir, current)
        log("first run: the mailbox as it stands is the baseline, no page")
        return EXIT_OK
    fresh = new_ids(current, seen)
    if not fresh:
        if tuple(current) != seen.ids:
            write_seen(state_dir, current)
        return EXIT_OK
    publish_page(fetch, token)
    log(f"paged once for {len(fresh)} new message(s)")
    try:
        write_seen(state_dir, current)
    except AbusePageError:
        log("the page was sent but the state file was not written; the next run pages again")
        return EXIT_PAGED_STATE_LOST
    return EXIT_OK


def main(argv: Sequence[str] | None = None, fetch: Fetch = open_url) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--check"]:
        return EXIT_OK
    if arguments != ["run"]:
        print("branchleft_abuse_page: usage: run | --check", file=sys.stderr)
        return EXIT_USAGE
    try:
        credentials = parse_admin_credentials(read_private_file(ADMIN_CREDENTIALS_PATH))
        token = parse_token(read_private_file(TOKEN_FILE_PATH))
        return run_once(
            fetch,
            credentials,
            token,
            STATE_DIR,
            lambda text: print(f"branchleft_abuse_page: {text}"),
        )
    except AbusePageError as err:
        print(f"branchleft_abuse_page: failed: {err}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
