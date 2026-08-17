#!/usr/bin/env python3
"""Exercise a Hetzner Object Storage bucket and report what it actually does.

Usage:
    export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
    probe-object-storage.py --bucket branchleft-lab-probe \
        --endpoint hel1.your-objectstorage.com --region hel1

Settles the storage properties a state backend depends on -- versioning,
object lifecycle, and whether anonymous read can be granted without also
granting listing -- which only a live bucket can answer. Prints a dated
markdown block to paste into whatever register tracks them. Each probe records
what was observed, including when the observation is a failure -- a probe that
cannot run is reported as UNKNOWN, and UNKNOWN is not a passing exit code.

**This script writes, and one of the things it writes is a policy granting
anonymous reads.** Three properties keep that bounded, and none of them is
advisory:

* It refuses any bucket whose name ends in `-pulumi-state`. That suffix is
  the convention `scripts/assert-no-provisioning-deletes.py` already guards
  on, and it covers the per-tenant state buckets the provisioning flow mints
  as well as the ones that exist today.
* The public-read grant names `<bucket>/_probe/*`, never `<bucket>/*`. It
  proves the same property -- `s3:GetObject` granted, `s3:ListBucket`
  absent -- without making anything else in the bucket anonymously readable.
* It refuses a bucket that already carries a bucket policy or a lifecycle
  configuration, because both are whole-document replacements at the API and
  it cannot put back what it would overwrite.

Run it against a scratch bucket regardless. The state backend and the probe
target are deliberately two different buckets; Object Storage bills per
account rather than per bucket, so the second one costs nothing.

Stdlib only, so it runs on a workstation with no S3 client installed --
deliberate, since the alternative is a `brew install` standing between the
platform owner and a spike everything else is waiting on. SigV4 is
implemented here rather than delegated; a signer that is subtly wrong fails
as an opaque 403, indistinguishable from a wrong key, a wrong region or a
wrong-location endpoint, and would be debugged in entirely the wrong place.
"""

# Keeps the `X | None` annotations legal on Python 3.9, which is what
# `/usr/bin/python3` still is on macOS. Without it the script fails at import
# rather than at a missing argument, which reads as a broken file.
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

# Bucket names ending here hold Pulumi state. `assert-no-provisioning-deletes.py`
# guards on the same suffix; matching it means a bucket minted by the
# provisioning flow is protected the day it appears, without an edit here.
PROTECTED_SUFFIX = "-pulumi-state"

ALGORITHM = "AWS4-HMAC-SHA256"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

PROBE_PREFIX = "_probe/"
PROBE_KEY = f"{PROBE_PREFIX}object-storage-probe.txt"
LIFECYCLE_ID = "object-storage-probe"

VERSIONING_UNKNOWN = "unknown"

S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"


class ProbeError(Exception):
    """A probe could not be carried out. Distinct from a probe that ran and
    observed the platform refusing something, which is a result, not an
    error."""


# --------------------------------------------------------------------------
# SigV4


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    key = _sign(f"AWS4{secret}".encode("utf-8"), date_stamp)
    key = _sign(key, region)
    key = _sign(key, service)
    return _sign(key, "aws4_request")


def canonical_query(query: dict[str, str] | None) -> str:
    """S3 requires sub-resource query parameters in the signature, sorted, with
    valueless parameters (`?versioning`) present as `versioning=`."""
    if not query:
        return ""
    parts = []
    for name in sorted(query):
        key = urllib.parse.quote(name, safe="~")
        value = urllib.parse.quote(query[name] or "", safe="~")
        parts.append(f"{key}={value}")
    return "&".join(parts)


def canonical_uri(bucket: str, key: str | None) -> str:
    """Path-style only. `s3ForcePathStyle` is mandatory against this endpoint
    (a dotted bucket name falls outside its one-label wildcard certificate), so
    virtual-host addressing is not implemented rather than left as a trap."""
    path = f"/{bucket}" if key is None else f"/{bucket}/{key}"
    return urllib.parse.quote(path, safe="/~")


def _canonical_header_value(value: str) -> str:
    """SigV4 trims and collapses internal whitespace runs in header values.
    The same normalisation has to reach the wire, or the signature covers a
    value the server did not receive."""
    return " ".join(value.split())


def sigv4_headers(
    *,
    method: str,
    bucket: str,
    key: str | None,
    query: dict[str, str] | None,
    payload: bytes,
    host: str,
    region: str,
    access_key: str,
    secret_key: str,
    now: datetime.datetime,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, str]:
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(payload).hexdigest() if payload else EMPTY_SHA256

    headers = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    for name, value in (extra_headers or {}).items():
        headers[name.lower()] = _canonical_header_value(value)

    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{n}:{headers[n]}\n" for n in sorted(headers))

    request = "\n".join(
        [
            method,
            canonical_uri(bucket, key),
            canonical_query(query),
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    scope = f"{date_stamp}/{region}/s3/aws4_request"
    to_sign = "\n".join(
        [
            ALGORITHM,
            amz_date,
            scope,
            hashlib.sha256(request.encode("utf-8")).hexdigest(),
        ]
    )
    signature = hmac.new(
        signing_key(secret_key, date_stamp, region, "s3"),
        to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    headers["Authorization"] = (
        f"{ALGORITHM} Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers


# --------------------------------------------------------------------------
# Client


class Response:
    def __init__(self, status: int, body: bytes, headers: dict[str, str] | None = None):
        self.status = status
        self.body = body
        self.headers = headers or {}

    @property
    def ok(self) -> bool:
        return self.status in (200, 204)

    def error_code(self) -> str | None:
        """S3 errors are XML with a `<Code>`; a bare status tells you far less
        than the code does when the status is 403."""
        try:
            return (ET.fromstring(self.body).findtext("Code") or "").strip() or None
        except ET.ParseError:
            return None

    def describe(self) -> str:
        code = self.error_code()
        return f"HTTP {self.status}" + (f" ({code})" if code else "")


def _urllib_transport(method: str, url: str, headers: dict[str, str], payload: bytes) -> Response:
    req = urllib.request.Request(url, data=payload or None, method=method)
    for name, value in headers.items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return Response(resp.status, resp.read(), dict(resp.headers))
    except urllib.error.HTTPError as exc:
        return Response(exc.code, exc.read(), dict(exc.headers))
    except OSError as exc:
        raise ProbeError(f"{method} {url} failed to complete: {exc}") from exc


class Bucket:
    def __init__(
        self,
        bucket: str,
        endpoint: str,
        region: str,
        access_key: str,
        secret_key: str,
        transport=_urllib_transport,
    ):
        self.bucket = bucket
        self.endpoint = endpoint
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.transport = transport

    def request(
        self,
        method: str,
        *,
        key: str | None = None,
        query: dict[str, str] | None = None,
        payload: bytes = b"",
        extra_headers: dict[str, str] | None = None,
        signed: bool = True,
    ) -> Response:
        url = f"https://{self.endpoint}{canonical_uri(self.bucket, key)}"
        if query:
            url += "?" + canonical_query(query)

        if signed:
            headers = sigv4_headers(
                method=method,
                bucket=self.bucket,
                key=key,
                query=query,
                payload=payload,
                host=self.endpoint,
                region=self.region,
                access_key=self.access_key,
                secret_key=self.secret_key,
                now=datetime.datetime.now(datetime.timezone.utc),
                extra_headers=extra_headers,
            )
        else:
            headers = {
                name.lower(): _canonical_header_value(value)
                for name, value in (extra_headers or {}).items()
            }

        return self.transport(method, url, headers, payload)


# --------------------------------------------------------------------------
# Parsing helpers


class Result:
    def __init__(self, name: str, verdict: str, detail: str):
        self.name = name
        self.verdict = verdict
        self.detail = detail


def _versioning_status(body: bytes) -> str | None:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None
    return root.findtext(f"{{{S3_NS}}}Status") or root.findtext("Status")


def _lifecycle_noncurrent_days(body: bytes) -> int | None:
    """Read back `NoncurrentVersionExpiration/NoncurrentDays`. Hetzner
    documents this as the only supported option of that element, so a
    round-trip that drops it is the failure worth catching."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None
    for element in root.iter():
        if element.tag.endswith("NoncurrentDays") and (element.text or "").strip():
            try:
                return int(element.text.strip())
            except ValueError:
                return None
    return None


def _count_versions(body: bytes) -> int:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return 0
    return sum(1 for e in root.iter() if e.tag.endswith("Version"))


def _count_contents(body: bytes) -> int | None:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None
    return sum(1 for e in root.iter() if e.tag.endswith("Contents"))


# --------------------------------------------------------------------------
# Pre-flight


def _is_absent(resp: Response) -> bool:
    """True only when the platform positively said the sub-resource is not
    there. Any other answer -- a 500, a 403, an unparseable body -- means the
    question was not answered, which is not the same thing and must never be
    read as one."""
    if resp.status == 404:
        return True
    return resp.status == 403 and resp.error_code() in (
        "NoSuchBucketPolicy",
        "NoSuchLifecycleConfiguration",
    )


def preflight(bucket: Bucket) -> list[str]:
    """Refusals, not warnings, and it **fails closed**. `PUT ?policy` and
    `PUT ?lifecycle` replace the whole document and teardown then deletes it,
    so a check that cannot be answered has to stop the run: a transient 500 on
    the lifecycle read would otherwise let the script destroy the very
    configuration it promises never to touch."""
    refusals = []

    policy = bucket.request("GET", query={"policy": ""})
    if policy.ok:
        refusals.append(
            "the bucket already has a bucket policy, which PUT ?policy would replace"
            " wholesale and teardown would then delete"
        )
    elif not _is_absent(policy):
        refusals.append(f"could not determine whether a bucket policy exists ({policy.describe()})")

    lifecycle = bucket.request("GET", query={"lifecycle": ""})
    if lifecycle.ok:
        refusals.append(
            "the bucket already has a lifecycle configuration, which PUT ?lifecycle"
            " would replace wholesale"
        )
    elif not _is_absent(lifecycle):
        refusals.append(
            f"could not determine whether a lifecycle configuration exists"
            f" ({lifecycle.describe()})"
        )

    listing = bucket.request("GET", query={"list-type": "2", "max-keys": "1"})
    count = _count_contents(listing.body) if listing.ok else None
    if count is None:
        refusals.append(f"could not determine whether the bucket is empty ({listing.describe()})")
    elif count:
        refusals.append(
            "the bucket is not empty; this script publishes an anonymous-read grant"
            f" over {PROBE_PREFIX} and should only ever run on a scratch bucket"
        )

    return refusals


# --------------------------------------------------------------------------
# Probes


def probe_reachable(bucket: Bucket) -> Result:
    resp = bucket.request("HEAD")
    if resp.ok:
        return Result("Bucket reachable, credentials valid", "PASS", "HTTP 200 on HeadBucket")
    return Result(
        "Bucket reachable, credentials valid",
        "FAIL",
        resp.describe()
        + " -- a 403 here is a wrong key, a wrong region, or a wrong endpoint location,"
        " and this script cannot tell you which",
    )


def read_versioning(bucket: Bucket) -> str | None:
    """`None` means never versioned; `VERSIONING_UNKNOWN` means the read did
    not succeed. Collapsing the two would let teardown "restore" a state it
    never observed -- error bodies parse to no `<Status>` element just as an
    unversioned bucket does."""
    resp = bucket.request("GET", query={"versioning": ""})
    if not resp.ok:
        return VERSIONING_UNKNOWN
    return _versioning_status(resp.body)


def set_versioning(bucket: Bucket, status: str) -> Response:
    body = (
        f'<VersioningConfiguration xmlns="{S3_NS}">'
        f"<Status>{status}</Status></VersioningConfiguration>"
    ).encode("utf-8")
    return bucket.request("PUT", query={"versioning": ""}, payload=body)


def probe_versioning(bucket: Bucket) -> Result:
    put = set_versioning(bucket, "Enabled")
    if not put.ok:
        return Result("Versioning can be enabled", "FAIL", f"PutBucketVersioning {put.describe()}")
    status = read_versioning(bucket)
    if status == "Enabled":
        return Result("Versioning can be enabled", "PASS", "read back as Enabled")
    return Result(
        "Versioning can be enabled", "FAIL", f"accepted the PUT but read back as {status!r}"
    )


def probe_versions_retained(bucket: Bucket) -> Result:
    """Enabling versioning and *retaining* a replaced object are different
    claims; §8's noncurrent lifecycle depends on the second."""
    for content in (b"first", b"second"):
        put = bucket.request("PUT", key=PROBE_KEY, payload=content)
        if not put.ok:
            return Result(
                "A replaced object retains its previous version",
                "FAIL",
                f"PutObject {put.describe()}",
            )
    listing = bucket.request("GET", query={"versions": "", "prefix": PROBE_KEY})
    count = _count_versions(listing.body)
    if count >= 2:
        return Result(
            "A replaced object retains its previous version",
            "PASS",
            f"ListObjectVersions reported {count} versions of the probe object",
        )
    return Result(
        "A replaced object retains its previous version",
        "FAIL",
        f"ListObjectVersions reported {count} versions after two writes",
    )


def lifecycle_document() -> bytes:
    return (
        f'<LifecycleConfiguration xmlns="{S3_NS}">'
        f"<Rule><ID>{LIFECYCLE_ID}</ID><Status>Enabled</Status>"
        "<Filter><Prefix></Prefix></Filter>"
        "<NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays>"
        "</NoncurrentVersionExpiration>"
        "<AbortIncompleteMultipartUpload><DaysAfterInitiation>10</DaysAfterInitiation>"
        "</AbortIncompleteMultipartUpload>"
        "</Rule></LifecycleConfiguration>"
    ).encode("utf-8")


def probe_lifecycle(bucket: Bucket) -> Result:
    """Applies §8's own policy shape, not a minimal one -- the question is
    whether the design is expressible, not whether the API accepts anything."""
    body = lifecycle_document()
    digest = hashlib.md5(body, usedforsecurity=False).digest()
    put = bucket.request(
        "PUT",
        query={"lifecycle": ""},
        payload=body,
        extra_headers={"content-md5": base64.b64encode(digest).decode("ascii")},
    )
    if not put.ok:
        return Result(
            "30-day noncurrent lifecycle is accepted",
            "FAIL",
            f"PutBucketLifecycleConfiguration {put.describe()}",
        )
    days = _lifecycle_noncurrent_days(bucket.request("GET", query={"lifecycle": ""}).body)
    if days == 30:
        return Result(
            "30-day noncurrent lifecycle is accepted",
            "PASS",
            "NoncurrentDays=30 survived the round trip",
        )
    return Result(
        "30-day noncurrent lifecycle is accepted",
        "FAIL",
        f"accepted the PUT but read NoncurrentDays back as {days!r}",
    )


def public_read_policy(bucket_name: str) -> str:
    """GetObject on the probe prefix and nothing on the bucket resource.

    Two deliberate narrowings. The resource is `<bucket>/_probe/*`, not
    `<bucket>/*` -- the property under test is that `s3:GetObject` can be
    granted anonymously while `s3:ListBucket` stays absent, and that is
    provable over one prefix without publishing whatever else is in the
    bucket. And the principal is the bare `"*"` rather than `{"AWS": ["*"]}`;
    both are documented as anonymous access, but a platform that read the
    second as authenticated-principals-only would make this probe report
    "public read failed" and wrongly rule out anonymous-read as an option."""
    return (
        '{"Version":"2012-10-17","Statement":[{'
        '"Sid":"PublicReadProbePrefixOnly","Effect":"Allow","Principal":"*",'
        '"Action":["s3:GetObject"],'
        f'"Resource":["arn:aws:s3:::{bucket_name}/{PROBE_PREFIX}*"]'
        "}]}"
    )


def probe_public_read_not_listable(bucket: Bucket) -> list[Result]:
    put = bucket.request(
        "PUT", query={"policy": ""}, payload=public_read_policy(bucket.bucket).encode("utf-8")
    )
    if not put.ok:
        return [
            Result(
                "Bucket policy accepted",
                "FAIL",
                f"PutBucketPolicy {put.describe()}"
                " -- if policies are unsupported, §6 candidate (b) has no mechanism",
            )
        ]

    results = [Result("Bucket policy accepted", "PASS", put.describe())]

    anon_object = bucket.request("GET", key=PROBE_KEY, signed=False)
    results.append(
        Result(
            "Anonymous object read succeeds",
            "PASS" if anon_object.status == 200 else "FAIL",
            anon_object.describe(),
        )
    )

    anon_list = bucket.request("GET", signed=False)
    listable = anon_list.status not in (401, 403)
    results.append(
        Result(
            "Anonymous bucket listing is refused",
            "FAIL" if listable else "PASS",
            anon_list.describe() + (" -- THE BUCKET IS PUBLICLY LISTABLE" if listable else ""),
        )
    )
    return results


# --------------------------------------------------------------------------
# Teardown


def teardown(bucket: Bucket, original_versioning: str | None) -> tuple[list[str], list[str]]:
    """Returns (failures, advisories). Every step is independent and every
    step reports. A transport failure in one must not skip the rest -- the
    first step removes the anonymous-read grant, and the ones after it would
    otherwise be abandoned with the bucket still published.

    The two lists are kept apart because they mean different things to the
    exit code. "S3 has no way back to never-versioned" is a fact about S3 on a
    run that went perfectly; reporting it as a teardown failure would make
    exit 1 the outcome of every successful run, and an exit code that is
    always 1 is one the operator stops reading."""
    failures: list[str] = []
    advisories: list[str] = []

    def attempt(what: str, call):
        try:
            resp = call()
        except ProbeError as exc:
            failures.append(f"{what} FAILED to complete ({exc}) -- check and undo by hand")
            return None
        if not resp.ok:
            failures.append(f"{what} FAILED ({resp.describe()}) -- undo by hand")
        return resp

    attempt(
        "removing the public-read bucket policy",
        lambda: bucket.request("DELETE", query={"policy": ""}),
    )
    attempt(
        "removing the lifecycle configuration",
        lambda: bucket.request("DELETE", query={"lifecycle": ""}),
    )

    listing = attempt(
        "listing probe object versions",
        lambda: bucket.request("GET", query={"versions": "", "prefix": PROBE_KEY}),
    )
    if listing is not None and listing.ok:
        try:
            root = ET.fromstring(listing.body)
        except ET.ParseError:
            failures.append("probe object versions could not be parsed -- delete them by hand")
            root = None
        if root is not None:
            for element in root.iter():
                if not (element.tag.endswith("Version") or element.tag.endswith("DeleteMarker")):
                    continue
                key = next((c.text for c in element if c.tag.endswith("Key")), None)
                version = next((c.text for c in element if c.tag.endswith("VersionId")), None)
                if not (key and version):
                    continue
                attempt(
                    f"deleting {key} version {version}",
                    lambda k=key, v=version: bucket.request(
                        "DELETE", key=k, query={"versionId": v}
                    ),
                )

    # Restore rather than force: a bucket that arrived with versioning enabled
    # must not leave with it suspended, and S3 has no transition back to the
    # never-versioned state at all.
    if original_versioning == VERSIONING_UNKNOWN:
        # Never write a state that was never read. Suspending here on a bucket
        # that arrived Enabled would remove a recovery property while claiming
        # to have restored one.
        failures.append(
            "the bucket's original versioning state could not be read, so versioning was"
            " left exactly as this run set it (Enabled) -- set it back by hand"
        )
    elif original_versioning in ("Enabled", "Suspended"):
        attempt(
            f"restoring versioning to {original_versioning}",
            lambda: set_versioning(bucket, original_versioning),
        )
    else:
        resp = attempt("suspending versioning", lambda: set_versioning(bucket, "Suspended"))
        if resp is not None and resp.ok:
            advisories.append(
                "versioning was not configured before this run and is now Suspended;"
                " S3 has no transition back to never-versioned"
            )
    return failures, advisories


# --------------------------------------------------------------------------
# Report


def render(
    bucket_name: str,
    endpoint: str,
    region: str,
    results: list[Result],
    failures: list[str],
    advisories: list[str] | None = None,
) -> str:
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    lines = [
        f"### Object Storage probe — {today}",
        "",
        f"Bucket `{bucket_name}` at `{endpoint}`, region `{region}`.",
        "",
        "| Probe | Verdict | Observed |",
        "|---|---|---|",
    ]
    lines += [f"| {r.name} | **{r.verdict}** | {r.detail} |" for r in results]
    if failures:
        lines += ["", "**Teardown did not fully complete:**"] + [f"- {n}" for n in failures]
    if advisories:
        lines += ["", "Notes:"] + [f"- {n}" for n in advisories]
    return "\n".join(lines) + "\n"


def run_probes(bucket: Bucket) -> list[Result]:
    results = [probe_reachable(bucket)]
    if results[0].verdict != "PASS":
        return results
    results.append(probe_versioning(bucket))
    results.append(probe_versions_retained(bucket))
    results.append(probe_lifecycle(bucket))
    results.extend(probe_public_read_not_listable(bucket))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--endpoint", required=True, help="e.g. hel1.your-objectstorage.com")
    parser.add_argument("--region", required=True, help="the bucket's own location, e.g. hel1")
    args = parser.parse_args(argv)

    if args.bucket.endswith(PROTECTED_SUFFIX):
        print(
            f"refusing to probe {args.bucket!r}: this script writes and publishes an"
            f" anonymous-read grant, and a name ending {PROTECTED_SUFFIX!r} is a Pulumi"
            " state bucket. Point it at a scratch bucket instead.",
            file=sys.stderr,
        )
        return 2

    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if not access_key or not secret_key:
        print(
            "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set."
            " They are not accepted as arguments: an argument lands in shell history"
            " and in the process table.",
            file=sys.stderr,
        )
        return 2

    bucket = Bucket(args.bucket, args.endpoint, args.region, access_key, secret_key)

    try:
        refusals = preflight(bucket)
    except ProbeError as exc:
        print(f"pre-flight could not complete: {exc}", file=sys.stderr)
        return 2
    if refusals:
        for refusal in refusals:
            print(f"refusing to probe {args.bucket!r}: {refusal}", file=sys.stderr)
        return 2

    original_versioning = VERSIONING_UNKNOWN
    failures: list[str] = []
    advisories: list[str] = []
    try:
        original_versioning = read_versioning(bucket)
        results = run_probes(bucket)
    except ProbeError as exc:
        results = [Result("Probe run", "UNKNOWN", str(exc))]
    except Exception as exc:  # noqa: BLE001 - the report is the deliverable
        results = [Result("Probe run", "UNKNOWN", f"unexpected {type(exc).__name__}: {exc}")]
    finally:
        try:
            failures, advisories = teardown(bucket, original_versioning)
        except Exception as exc:  # noqa: BLE001
            failures = [f"teardown itself raised {type(exc).__name__}: {exc} -- undo by hand"]

    print(render(args.bucket, args.endpoint, args.region, results, failures, advisories))
    inconclusive = [r for r in results if r.verdict in ("FAIL", "UNKNOWN")]
    return 1 if inconclusive or failures else 0


if __name__ == "__main__":
    sys.exit(main())
