#!/usr/bin/env python3
"""Steps of the OVHcloud London probe workflow that are not Pulumi.

Subcommands, run by .github/workflows/ovh-copy2-probe.yml in this order:

    preflight  refuse a stack file or environment the probe may not run against
    backend    make the throwaway Pulumi state location and passphrase
    probe      exercise object lock on the buckets Pulumi made (outputs on stdin)
    cleanup    remove every object version the probe left (outputs on stdin)
    finish     write the lifecycle table and say what to delete by hand

The rules, the checks and the limits are written up in probe_object_lock.md.
Standard library only, except that `preflight` reads the stack file with
PyYAML. No credential is ever printed, written to a file or put in a result:
the S3 pair is read from stdin, masked at once, and scrubbed from every line
this program writes.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import IO, Any

ENDPOINT = "https://s3.uk.io.cloud.ovh.net"
REGION = "uk"
SERVICE = "s3"

PROJECT_NAMESPACE = "branchleft-ovh-copy2"
PROBE_PREFIX = "zz-probe-"
BUCKET_A = "zz-probe-a"
BUCKET_B = "zz-probe-b"
USER_RW = "zz-probe-rw"
SECRET_NAMES = ("OVH_CLIENT_ID", "OVH_CLIENT_SECRET")

# The only lock this program will ever ask for.
ALLOWED_MODE = "GOVERNANCE"
MAX_RETENTION_DAYS = 1

UNSET_MARKER = "UNSET"
PROJECT_ID = re.compile(r"^[0-9a-f]{32}$")
DIGITS = re.compile(r"^[0-9]{1,20}$")

PASS = "PASS"
FAIL = "FAIL"
INCONCLUSIVE = "INCONCLUSIVE"

OBJECT_KEY = "probe/object.txt"
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_LIST_PAGES = 20


class Refusal(Exception):
    """The run is not allowed to go on. Distinct from a probe that ran."""


class ProbeError(Exception):
    """A request could not be carried out, so the question is unanswered."""


# --------------------------------------------------------------------------
# Output helpers


def mask(value: str, out: IO[str]) -> None:
    """Ask the runner to hide `value` from every later log line."""
    if value:
        print(f"::add-mask::{value}", file=out)


def scrub(text: str, hidden: Sequence[str]) -> str:
    for value in hidden:
        if value:
            text = text.replace(value, "***")
    return text


def append_lines(path: str | None, lines: Sequence[str]) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------
# preflight


@dataclass(frozen=True)
class StackFacts:
    project_id: str
    declared_compliance: tuple[str, ...]


def _config(stack: Mapping[str, Any], key: str) -> Any:
    return (stack.get("config") or {}).get(f"{PROJECT_NAMESPACE}:{key}")


def check_project_id(stack: Mapping[str, Any]) -> str:
    project = _config(stack, "allowedProjectId")
    if project is None or project == UNSET_MARKER:
        raise Refusal(
            "allowedProjectId is UNSET in the stack file: nothing is created, "
            "and nothing is destroyed, until the project id is committed there"
        )
    if not isinstance(project, str) or not PROJECT_ID.match(project):
        raise Refusal("allowedProjectId is not a 32-character lower-case hex project id")
    return project


def write_targets(users: Sequence[Mapping[str, Any]]) -> set[str]:
    """Buckets that a user holding an S3 credential is allowed to name."""
    targets: set[str] = set()
    for user in users:
        if not user.get("s3Credential"):
            continue
        for statement in user.get("statements") or []:
            if statement.get("effect") == "Allow":
                targets.update(statement.get("buckets") or [])
    return targets


def check_buckets(stack: Mapping[str, Any]) -> tuple[str, ...]:
    """Refuse a lock this probe may not touch; return declared Compliance buckets."""
    buckets = _config(stack, "buckets") or []
    users = _config(stack, "users") or []
    targets = write_targets(users)
    problems: list[str] = []
    declared: list[str] = []
    names = {bucket.get("name") for bucket in buckets}
    if BUCKET_A not in names:
        problems.append(f"bucket {BUCKET_A} is not declared")
    for bucket in buckets:
        name = str(bucket.get("name"))
        lock = bucket.get("objectLock")
        if bucket.get("region") != "UK":
            problems.append(f"bucket {name}: region must be UK")
        if not name.startswith(PROBE_PREFIX):
            problems.append(f"bucket {name}: not a {PROBE_PREFIX}* bucket")
        if lock is None:
            if name == BUCKET_A:
                problems.append(f"bucket {name}: the write target must declare a lock")
            continue
        mode = lock.get("mode")
        days = lock.get("retentionDays")
        if mode not in ("GOVERNANCE", "COMPLIANCE"):
            problems.append(f"bucket {name}: unknown lock mode")
        if (
            not isinstance(days, int)
            or isinstance(days, bool)
            or not 1 <= days <= MAX_RETENTION_DAYS
        ):
            problems.append(f"bucket {name}: retention must be {MAX_RETENTION_DAYS} day at most")
        if mode == "COMPLIANCE":
            declared.append(name)
            if name in targets:
                problems.append(f"bucket {name}: Compliance on a bucket the probe writes to")
        if name == BUCKET_A and mode != ALLOWED_MODE:
            problems.append(f"bucket {name}: the write target must be {ALLOWED_MODE}")
    if problems:
        raise Refusal("stack file refused:\n- " + "\n- ".join(problems))
    return tuple(declared)


def check_secrets(env: Mapping[str, str]) -> None:
    missing = [name for name in SECRET_NAMES if not env.get(name)]
    if missing:
        raise Refusal(
            "environment secrets missing or empty: "
            + ", ".join(missing)
            + " (set them on the ovh-copy2-probe environment)"
        )


def run_suffix(env: Mapping[str, str]) -> str:
    run_id = env.get("GITHUB_RUN_ID", "")
    attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    if not DIGITS.match(run_id) or not DIGITS.match(attempt):
        raise Refusal("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT must be numbers")
    return f"r{run_id}-{attempt}"


def load_stack(path: Path) -> Mapping[str, Any]:
    try:
        import yaml  # noqa: PLC0415 - only this subcommand needs it
    except ImportError as exc:  # pragma: no cover - the workflow installs it
        raise Refusal("PyYAML is not installed, so the stack file cannot be read") from exc
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise Refusal(f"stack file cannot be read: {path}") from exc
    if not isinstance(loaded, dict):
        raise Refusal("stack file is not a mapping")
    return loaded


def preflight(
    stack_file: Path, env: Mapping[str, str], github_env: str | None, out: IO[str]
) -> StackFacts:
    stack = load_stack(stack_file)
    project = check_project_id(stack)
    declared = check_buckets(stack)
    check_secrets(env)
    suffix = run_suffix(env)
    # Not secret: the project id is committed, the suffix is the run id.
    append_lines(
        github_env,
        [f"OVH_CLOUD_PROJECT_SERVICE={project}", f"PROBE_SUFFIX={suffix}"],
    )
    print(f"preflight passed: suffix {suffix}", file=out)
    if declared:
        print(
            "notice: Compliance is declared, empty and one day, on "
            + ", ".join(declared)
            + "; this workflow never writes to it",
            file=out,
        )
    return StackFacts(project, declared)


def prepare_backend(state_dir: Path, github_env: str | None, out: IO[str]) -> None:
    """A state location and passphrase that live exactly as long as the runner."""
    state_dir.mkdir(parents=True, exist_ok=True)
    passphrase = secrets.token_hex(32)
    mask(passphrase, out)
    append_lines(
        github_env,
        [
            f"PULUMI_BACKEND_URL=file://{state_dir}",
            f"PULUMI_CONFIG_PASSPHRASE={passphrase}",
        ],
    )
    print("ephemeral state backend prepared", file=out)


# --------------------------------------------------------------------------
# SigV4 and the S3 client


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    key = _hmac(f"AWS4{secret}".encode("utf-8"), date_stamp)
    return _hmac(_hmac(_hmac(key, region), service), "aws4_request")


def canonical_query(query: Mapping[str, str] | None) -> str:
    if not query:
        return ""
    return "&".join(
        f"{urllib.parse.quote(name, safe='~')}={urllib.parse.quote(query[name] or '', safe='~')}"
        for name in sorted(query)
    )


def canonical_uri(bucket: str, key: str | None) -> str:
    path = f"/{bucket}" if key is None else f"/{bucket}/{key}"
    return urllib.parse.quote(path, safe="/~")


def sign_headers(
    *,
    method: str,
    path: str,
    query: Mapping[str, str] | None,
    payload: bytes,
    host: str,
    access_key: str,
    secret_key: str,
    now: datetime.datetime,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(payload).hexdigest()
    headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
    for name, value in (extra or {}).items():
        headers[name.lower()] = " ".join(value.split())
    signed = ";".join(sorted(headers))
    canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in sorted(headers))
    request = "\n".join(
        [method, path, canonical_query(query), canonical_headers, signed, payload_hash]
    )
    scope = f"{date_stamp}/{REGION}/{SERVICE}/aws4_request"
    to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(request.encode("utf-8")).hexdigest()]
    )
    signature = hmac.new(
        signing_key(secret_key, date_stamp, REGION, SERVICE),
        to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed}, Signature={signature}"
    )
    return headers


class Response:
    def __init__(self, status: int, body: bytes = b"", headers: Mapping[str, str] | None = None):
        self.status = status
        self.body = body
        self.headers = {name.lower(): value for name, value in (headers or {}).items()}

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def refused(self) -> bool:
        """A positive refusal. A 404 or a 5xx answers nothing, so is not one."""
        return 400 <= self.status < 500 and self.status != 404

    def code(self) -> str:
        try:
            return (_text(ET.fromstring(self.body), "Code") or "").strip()
        except ET.ParseError:
            return ""

    def describe(self) -> str:
        code = self.code()
        return f"HTTP {self.status}" + (f" {code}" if code else "")


Transport = Callable[[str, str, Mapping[str, str], bytes], Response]


def urllib_transport(method: str, url: str, headers: Mapping[str, str], payload: bytes) -> Response:
    if not url.startswith(ENDPOINT + "/"):
        raise ProbeError("refusing to send a request anywhere but the London endpoint")
    request = urllib.request.Request(url, data=payload or None, method=method)
    for name, value in headers.items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as reply:  # noqa: S310 - https, checked above
            return Response(reply.status, reply.read(), dict(reply.headers))
    except urllib.error.HTTPError as exc:
        return Response(exc.code, exc.read(), dict(exc.headers))
    except OSError as exc:
        raise ProbeError(f"{method} request did not complete: {type(exc).__name__}") from exc


class S3:
    def __init__(
        self,
        bucket: str,
        access_key: str,
        secret_key: str,
        transport: Transport,
        clock: Callable[[], datetime.datetime],
    ):
        self.bucket = bucket
        self._access_key = access_key
        self._secret_key = secret_key
        self._transport = transport
        self._clock = clock

    def request(
        self,
        method: str,
        *,
        key: str | None = None,
        query: Mapping[str, str] | None = None,
        payload: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        path = canonical_uri(self.bucket, key)
        host = ENDPOINT.removeprefix("https://")
        signed = sign_headers(
            method=method,
            path=path,
            query=query,
            payload=payload,
            host=host,
            access_key=self._access_key,
            secret_key=self._secret_key,
            now=self._clock(),
            extra=headers,
        )
        url = ENDPOINT + path + (f"?{canonical_query(query)}" if query else "")
        return self._transport(method, url, signed, payload)


# --------------------------------------------------------------------------
# Object lock requests (the only place a lock is ever asked for)


def lock_configuration_xml(mode: str, days: int) -> bytes:
    """The lock default this program may request. Governance, one day at most."""
    if mode != ALLOWED_MODE:
        raise Refusal(f"refusing to request lock mode {mode}: only {ALLOWED_MODE} is allowed")
    if not 1 <= days <= MAX_RETENTION_DAYS:
        raise Refusal(f"refusing a retention of {days} days: {MAX_RETENTION_DAYS} day at most")
    return (
        f'<ObjectLockConfiguration xmlns="{S3_NS}"><ObjectLockEnabled>Enabled</ObjectLockEnabled>'
        f"<Rule><DefaultRetention><Mode>{mode}</Mode><Days>{days}</Days></DefaultRetention></Rule>"
        "</ObjectLockConfiguration>"
    ).encode("utf-8")


def put_lock_configuration(client: S3, mode: str, days: int) -> Response:
    body = lock_configuration_xml(mode, days)
    digest = base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode("ascii")
    return client.request(
        "PUT", query={"object-lock": ""}, payload=body, headers={"content-md5": digest}
    )


def _text(root: ET.Element, name: str) -> str | None:
    for element in root.iter():
        if element.tag.split("}")[-1] == name:
            return element.text
    return None


def _all(root: ET.Element, name: str) -> list[ET.Element]:
    return [element for element in root.iter() if element.tag.split("}")[-1] == name]


def parse_lock(body: bytes) -> tuple[str | None, str | None, str | None]:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None, None, None
    return _text(root, "ObjectLockEnabled"), _text(root, "Mode"), _text(root, "Days")


def parse_versions(body: bytes) -> tuple[list[tuple[str, str]], bool, str, str]:
    """(key, version id) pairs, then truncated flag and the next markers."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise ProbeError("a listing could not be read") from exc
    found = [
        (_text(item, "Key") or "", _text(item, "VersionId") or "")
        for name in ("Version", "DeleteMarker")
        for item in _all(root, name)
    ]
    return (
        found,
        (_text(root, "IsTruncated") or "").lower() == "true",
        _text(root, "NextKeyMarker") or "",
        _text(root, "NextVersionIdMarker") or "",
    )


def list_versions(client: S3) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    query: dict[str, str] = {"versions": ""}
    for _ in range(MAX_LIST_PAGES):
        reply = client.request("GET", query=query)
        if not reply.ok:
            raise ProbeError(f"listing versions failed: {reply.describe()}")
        page, truncated, key_marker, version_marker = parse_versions(reply.body)
        found.extend(page)
        if not truncated:
            return found
        query = {"versions": "", "key-marker": key_marker, "version-id-marker": version_marker}
    raise ProbeError("a listing did not end")


BYPASS = {"x-amz-bypass-governance-retention": "true"}


def purge(client: S3) -> int:
    """Delete every version and marker, bypassing Governance. Returns how many."""
    removed = 0
    for key, version in list_versions(client):
        reply = client.request("DELETE", key=key, query={"versionId": version}, headers=BYPASS)
        if not reply.ok:
            raise ProbeError(f"deleting a version failed: {reply.describe()}")
        removed += 1
    return removed


# --------------------------------------------------------------------------
# The probe


@dataclass
class Check:
    id: str
    title: str
    expected: str
    verdict: str
    detail: str


@dataclass(frozen=True)
class Buckets:
    a: str
    b: str
    c: str
    access_key: str
    secret_key: str


def read_outputs(outputs: Mapping[str, Any], suffix: str) -> Buckets:
    """Pick the probe's own credential and bucket names out of the stack outputs."""
    access = (outputs.get("accessKeyIds") or {}).get(USER_RW, "")
    secret = (outputs.get("secretAccessKeys") or {}).get(USER_RW, "")
    names = {f"{PROBE_PREFIX}{letter}-{suffix}" for letter in "abc"}
    endpoints = outputs.get("s3Endpoints") or {}
    present = set(outputs.get("bucketNames") or [])
    if not names <= present:
        raise Refusal("the stack outputs do not list the three probe buckets")
    if any(endpoints.get(name) != ENDPOINT for name in names):
        raise Refusal("a probe bucket reports an endpoint other than the London endpoint")
    a, b, c = (f"{PROBE_PREFIX}{letter}-{suffix}" for letter in "abc")
    return Buckets(a, b, c, access, secret)


class Probe:
    def __init__(
        self, buckets: Buckets, transport: Transport, clock: Callable[[], datetime.datetime]
    ):
        self.buckets = buckets
        self.clock = clock
        hidden = (buckets.access_key, buckets.secret_key)
        self._hidden = hidden
        self.a = S3(buckets.a, *hidden, transport, clock)
        self.b = S3(buckets.b, *hidden, transport, clock)
        self.checks: list[Check] = []
        self._version = ""

    def record(
        self, id_: str, title: str, expected: str, run: Callable[[], tuple[str, str]]
    ) -> str:
        try:
            verdict, detail = run()
        except ProbeError as exc:
            verdict, detail = INCONCLUSIVE, str(exc)
        self.checks.append(Check(id_, title, expected, verdict, scrub(detail, self._hidden)))
        return verdict

    def run(self) -> list[Check]:
        self.record(
            "P0",
            "Provider created three London buckets, lock set at creation",
            "stack outputs list buckets A, B and C on the London endpoint",
            lambda: (PASS, "A (Governance, 1 day), B (no lock) and C are listed by the stack"),
        )
        put = self.record("P1", "Scoped credential writes to bucket A", "PUT 200", self._put)
        have_object = put == PASS
        self._dependent(
            "P1b", "Bucket A reads back Governance, 1 day", have_object, self._lock_read
        )
        self._dependent(
            "P2",
            "New object carries Governance and a retain-until about a day out",
            have_object,
            self._head,
        )
        self._dependent("P3a", "Listing bucket A shows the version", have_object, self._listing)
        self._dependent(
            "P3b", "Delete inside the window is refused", have_object, self._delete_plain
        )
        self._dependent(
            "P3c", "Delete with Governance bypass succeeds", have_object, self._delete_bypass
        )
        self._dependent("P3d", "Bucket A is empty afterwards", have_object, self._empty_after)
        self.record(
            "P4", "Credential is refused on bucket B", "PUT and list both refused", self._scope
        )
        self.record(
            "P5",
            "Lock cannot be added to bucket B later",
            "PUT object-lock refused",
            self._lock_later,
        )
        return self.checks

    def _dependent(
        self, id_: str, title: str, ready: bool, run: Callable[[], tuple[str, str]]
    ) -> str:
        if not ready:
            self.checks.append(
                Check(
                    id_,
                    title,
                    "needs the object from P1",
                    INCONCLUSIVE,
                    "skipped: no object was written",
                )
            )
            return INCONCLUSIVE
        return self.record(id_, title, "see detail", run)

    def _put(self) -> tuple[str, str]:
        reply = self.a.request("PUT", key=OBJECT_KEY, payload=b"probe")
        self._version = reply.headers.get("x-amz-version-id", "")
        if reply.ok and self._version:
            return PASS, "PUT 200 with a version id"
        if reply.ok:
            return FAIL, "PUT succeeded but returned no version id (versioning off?)"
        return FAIL, f"PUT refused: {reply.describe()}"

    def _lock_read(self) -> tuple[str, str]:
        reply = self.a.request("GET", query={"object-lock": ""})
        if not reply.ok:
            return FAIL, f"read of the lock configuration failed: {reply.describe()}"
        enabled, mode, days = parse_lock(reply.body)
        seen = f"{enabled} {mode} {days} day(s)"
        ok = (enabled, mode, days) == ("Enabled", ALLOWED_MODE, str(MAX_RETENTION_DAYS))
        return (PASS if ok else FAIL), seen

    def _head(self) -> tuple[str, str]:
        reply = self.a.request("HEAD", key=OBJECT_KEY, query={"versionId": self._version})
        if not reply.ok:
            return FAIL, f"HEAD failed: {reply.describe()}"
        mode = reply.headers.get("x-amz-object-lock-mode", "")
        until = reply.headers.get("x-amz-object-lock-retain-until-date", "")
        try:
            when = datetime.datetime.fromisoformat(until.replace("Z", "+00:00"))
        except ValueError:
            return FAIL, f"mode {mode or 'absent'}, retain-until absent or unreadable"
        ahead = when - self.clock()
        in_window = datetime.timedelta(0) < ahead <= datetime.timedelta(days=2)
        hours = round(ahead.total_seconds() / 3600, 1)
        return (
            PASS if mode == ALLOWED_MODE and in_window else FAIL
        ), f"mode {mode}, retain-until {hours} hours ahead"

    def _listing(self) -> tuple[str, str]:
        found = list_versions(self.a)
        return (
            PASS if (OBJECT_KEY, self._version) in found else FAIL
        ), f"{len(found)} version(s) listed"

    def _delete_plain(self) -> tuple[str, str]:
        reply = self.a.request("DELETE", key=OBJECT_KEY, query={"versionId": self._version})
        if reply.ok:
            return FAIL, "the delete was accepted, so the lock did not bite"
        if reply.refused:
            return PASS, f"refused: {reply.describe()}"
        return INCONCLUSIVE, f"no clear answer: {reply.describe()}"

    def _delete_bypass(self) -> tuple[str, str]:
        reply = self.a.request(
            "DELETE", key=OBJECT_KEY, query={"versionId": self._version}, headers=BYPASS
        )
        if reply.ok:
            return PASS, f"accepted: {reply.describe()}"
        return FAIL, f"bypass delete failed: {reply.describe()}"

    def _empty_after(self) -> tuple[str, str]:
        left = list_versions(self.a)
        return (PASS if not left else FAIL), f"{len(left)} version(s) left"

    def _scope(self) -> tuple[str, str]:
        put = self.b.request("PUT", key=OBJECT_KEY, payload=b"probe")
        if put.ok:
            # Leave nothing behind in B even when the scope proof fails.
            version = put.headers.get("x-amz-version-id", "")
            self.b.request(
                "DELETE", key=OBJECT_KEY, query={"versionId": version} if version else None
            )
        listing = self.b.request("GET", query={"versions": ""})
        detail = f"PUT {put.describe()}; list {listing.describe()}"
        if put.ok or listing.ok:
            return FAIL, f"the credential reached bucket B: {detail}"
        if put.refused and listing.refused:
            return PASS, detail
        return INCONCLUSIVE, detail

    def _lock_later(self) -> tuple[str, str]:
        reply = put_lock_configuration(self.b, ALLOWED_MODE, MAX_RETENTION_DAYS)
        if reply.ok:
            return FAIL, "a lock was accepted on a bucket made without one"
        if reply.refused:
            note = (
                " (an access refusal cannot be told from the policy scope)"
                if reply.code() == "AccessDenied"
                else ""
            )
            return PASS, f"refused: {reply.describe()}{note}"
        return INCONCLUSIVE, f"no clear answer: {reply.describe()}"


def overall(checks: Sequence[Check]) -> str:
    if any(check.verdict == FAIL for check in checks):
        return FAIL
    if any(check.verdict == INCONCLUSIVE for check in checks):
        return INCONCLUSIVE
    return PASS


def render_markdown(checks: Sequence[Check], verdict: str, suffix: str) -> str:
    rows = [
        "## OVH London probe",
        "",
        f"Result: **{verdict}**. Endpoint `{ENDPOINT}`, region `{REGION}`, run suffix `{suffix}`.",
        "",
        "| Check | What | Verdict | Detail |",
        "| --- | --- | --- | --- |",
    ]
    rows += [f"| {c.id} | {c.title} | {c.verdict} | {c.detail.replace('|', '/')} |" for c in checks]
    rows += [
        "",
        "Bucket C (Compliance, one day) is never written and is not readable by the probe "
        "credential.",
    ]
    return "\n".join(rows) + "\n"


def write_results(
    directory: Path, checks: Sequence[Check], suffix: str, summary: str | None
) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    verdict = overall(checks)
    document = {
        "endpoint": ENDPOINT,
        "region": REGION,
        "suffix": suffix,
        "overall": verdict,
        "checks": [asdict(check) for check in checks],
    }
    (directory / "result.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    markdown = render_markdown(checks, verdict, suffix)
    (directory / "result.md").write_text(markdown, encoding="utf-8")
    append_lines(summary, [markdown])
    return verdict


# --------------------------------------------------------------------------
# finish


def finish(outcomes: Mapping[str, str], suffix: str, summary: str | None, out: IO[str]) -> int:
    rows = ["## Probe lifecycle", "", "| Step | Outcome |", "| --- | --- |"]
    rows += [f"| {step} | {outcome or 'not run'} |" for step, outcome in outcomes.items()]
    created = outcomes.get("init") == "success"
    destroyed = outcomes.get("destroy") == "success"
    if created and not destroyed:
        names = [f"{PROBE_PREFIX}{letter}-{suffix}" for letter in "abc"]
        rows += [
            "",
            (
                "**The destroy did not succeed and the state is gone with this runner.** "
                f"Delete by hand in the OVHcloud console: buckets {', '.join(names)} "
                "(empty each first; Governance versions need the bypass), "
                "then users `zz-probe-owner` and `zz-probe-rw`."
            ),
        ]
    elif not created:
        rows += ["", "No stack was created, so nothing needed destroying."]
    else:
        rows += ["", "Every probe resource was destroyed in this run."]
    append_lines(summary, rows)
    print("\n".join(rows), file=out)
    return 0 if (destroyed or not created) else 1


# --------------------------------------------------------------------------
# Command line


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    pre = sub.add_parser("preflight")
    pre.add_argument("--stack-file", type=Path, required=True)

    back = sub.add_parser("backend")
    back.add_argument("--state-dir", type=Path, required=True)

    for name in ("probe", "cleanup"):
        item = sub.add_parser(name)
        item.add_argument("--suffix", default=None)
        if name == "probe":
            item.add_argument("--results-dir", type=Path, required=True)

    fin = sub.add_parser("finish")
    fin.add_argument("--suffix", default=None)
    for step in ("init", "up", "probe", "cleanup", "destroy"):
        fin.add_argument(f"--{step}", default="")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    stdin: IO[str] | None = None,
    out: IO[str] | None = None,
    transport: Transport = urllib_transport,
    clock: Callable[[], datetime.datetime] = _now,
) -> int:
    env = os.environ if env is None else env
    stdin = sys.stdin if stdin is None else stdin
    out = sys.stdout if out is None else out
    args = build_parser().parse_args(argv)
    github_env = env.get("GITHUB_ENV")
    summary = env.get("GITHUB_STEP_SUMMARY")
    try:
        if args.command == "preflight":
            preflight(args.stack_file, env, github_env, out)
            return 0
        if args.command == "backend":
            prepare_backend(args.state_dir, github_env, out)
            return 0
        suffix = args.suffix or env.get("PROBE_SUFFIX", "")
        if args.command == "finish":
            outcomes = {
                step: getattr(args, step) for step in ("init", "up", "probe", "cleanup", "destroy")
            }
            return finish(outcomes, suffix, summary, out)
        return _with_outputs(args, suffix, stdin, out, transport, clock, summary)
    except Refusal as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except ProbeError as exc:
        print(f"probe could not run: {exc}", file=sys.stderr)
        return 1


def _with_outputs(
    args: argparse.Namespace,
    suffix: str,
    stdin: IO[str],
    out: IO[str],
    transport: Transport,
    clock: Callable[[], datetime.datetime],
    summary: str | None,
) -> int:
    raw = stdin.read()
    if args.command == "cleanup" and not raw.strip():
        print("no stack outputs: nothing to purge", file=out)
        return 0
    if not re.fullmatch(r"r[0-9]{1,20}-[0-9]{1,20}", suffix):
        raise Refusal("the run suffix is missing or malformed")
    try:
        outputs = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Refusal("stack outputs on stdin are not JSON") from exc
    # Mask the pair before anything else can fail or log.
    for group in ("accessKeyIds", "secretAccessKeys"):
        mask((outputs.get(group) or {}).get(USER_RW, ""), out)
    buckets = read_outputs(outputs, suffix)
    if not buckets.access_key or not buckets.secret_key:
        if args.command == "cleanup":
            print("no probe credential in the outputs: nothing to purge", file=out)
            return 0
        raise Refusal("the stack outputs carry no probe credential")
    hidden = (buckets.access_key, buckets.secret_key)
    if args.command == "cleanup":
        # Only A: the credential is refused on B and C, and P4 removes anything
        # it wrote to B itself.
        client = S3(buckets.a, *hidden, transport, clock)
        try:
            print(f"purged {purge(client)} version(s) from {buckets.a}", file=out)
        except ProbeError as exc:
            print(scrub(f"purge of {buckets.a} failed: {exc}", hidden), file=sys.stderr)
            return 1
        return 0
    checks = Probe(buckets, transport, clock).run()
    verdict = write_results(args.results_dir, checks, suffix, summary)
    print(f"probe result: {verdict}", file=out)
    return 0 if verdict == PASS else 1


if __name__ == "__main__":
    sys.exit(main())
