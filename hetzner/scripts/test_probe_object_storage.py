#!/usr/bin/env python3
"""Unit tests for probe-object-storage.

Three properties carry real consequence and get the most attention:

* **Teardown.** It is the only thing that removes the anonymous-read grant the
  script publishes. A teardown that aborts on the first transport error, or
  that ignores a failed delete and reports success, leaves a bucket published
  and says nothing. Every step is driven here through a fake transport,
  including the failure paths.

* **The signer.** A subtly wrong SigV4 implementation fails as HTTP 403, which
  against this endpoint is indistinguishable from a wrong key, a wrong region
  or a wrong-location endpoint. The HMAC chain is checked against AWS's
  published derivation, and `sigv4_headers` itself is driven end-to-end for
  every request shape the script actually issues -- not only the simplest one.

* **The public-read policy and the bucket guard.** The policy is the mechanism
  §6 requires for "public-read but NOT listable", so the tests assert what it
  does *not* grant. The guard is what keeps a writing script away from Pulumi
  state.

No network. No subprocess.
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import hmac
import importlib.util
import io
import os
import pathlib
import unittest


def _load_module():
    """Import by path: the filename has hyphens, so it is not a legal module
    name for a plain import."""
    path = pathlib.Path(__file__).resolve().parent / "probe-object-storage.py"
    spec = importlib.util.spec_from_file_location("probe_object_storage", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = _load_module()

FIXED_NOW = datetime.datetime(2026, 8, 16, 12, 0, 0, tzinfo=datetime.timezone.utc)
ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

NO_VERSIONS = f'<ListVersionsResult xmlns="{probe.S3_NS}"/>'.encode()


class FakeTransport:
    """Records every call and answers from a queue keyed on (method, marker).

    `marker` is the query sub-resource where there is one, otherwise the object
    key, otherwise `''` -- enough to distinguish every request this script
    makes without matching whole URLs.
    """

    def __init__(self, responses=None, raise_on=None):
        self.responses = responses or {}
        self.raise_on = raise_on or set()
        self.calls = []

    SUBRESOURCES = ("versioning", "versions", "lifecycle", "policy", "versionId", "list-type")

    @classmethod
    def marker(cls, url):
        """Name the request the way the script thinks of it. Query parameters
        are sorted into the URL by `canonical_query`, so the first one is not
        reliably the sub-resource -- `?versions&prefix=` sorts to `prefix`
        first."""
        if "?" in url:
            names = {p.split("=", 1)[0] for p in url.split("?", 1)[1].split("&")}
            for candidate in cls.SUBRESOURCES:
                if candidate in names:
                    return candidate
            return sorted(names)[0]
        tail = url.split("/", 4)
        return tail[4] if len(tail) > 4 and tail[4] else ""

    def __call__(self, method, url, headers, payload):
        marker = self.marker(url)
        self.calls.append((method, marker, url, headers, payload))
        if (method, marker) in self.raise_on:
            raise probe.ProbeError(f"{method} {url} failed to complete: simulated")
        status, body = self.responses.get((method, marker), (200, b""))
        return probe.Response(status, body)

    def markers(self, method=None):
        return [m for (meth, m, *_rest) in self.calls if method is None or meth == method]


def _bucket(transport, name="branchleft-lab-probe"):
    return probe.Bucket(name, "hel1.your-objectstorage.com", "hel1", ACCESS_KEY, SECRET_KEY, transport)


# --------------------------------------------------------------------------
# Signer


class SigningKeyTests(unittest.TestCase):
    """Checked against AWS's published worked example rather than against a
    remembered constant: the whole derivation is verified by reproducing a
    signature AWS documents, which no transcription error can accidentally
    satisfy."""

    def test_reproduces_the_published_s3_get_object_signature(self):
        empty = hashlib.sha256(b"").hexdigest()
        canonical_request = "\n".join(
            [
                "GET",
                "/test.txt",
                "",
                "host:examplebucket.s3.amazonaws.com",
                "range:bytes=0-9",
                f"x-amz-content-sha256:{empty}",
                "x-amz-date:20130524T000000Z",
                "",
                "host;range;x-amz-content-sha256;x-amz-date",
                empty,
            ]
        )
        to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                "20130524T000000Z",
                "20130524/us-east-1/s3/aws4_request",
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            ]
        )
        signature = hmac.new(
            probe.signing_key(SECRET_KEY, "20130524", "us-east-1", "s3"),
            to_sign.encode(),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(
            signature, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        )

    def test_region_participates(self):
        """The one that bites on this endpoint: `region` is cosmetic on GCS and
        load-bearing here."""
        self.assertNotEqual(
            probe.signing_key(SECRET_KEY, "20120215", "hel1", "s3"),
            probe.signing_key(SECRET_KEY, "20120215", "fsn1", "s3"),
        )


class CanonicalQueryTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(probe.canonical_query(None), "")
        self.assertEqual(probe.canonical_query({}), "")

    def test_valueless_subresource_keeps_its_equals_sign(self):
        self.assertEqual(probe.canonical_query({"versioning": ""}), "versioning=")

    def test_sorted_by_name(self):
        self.assertEqual(
            probe.canonical_query({"prefix": "a", "list-type": "2"}), "list-type=2&prefix=a"
        )

    def test_values_are_encoded(self):
        self.assertEqual(
            probe.canonical_query({"prefix": probe.PROBE_KEY}),
            "prefix=_probe%2Fobject-storage-probe.txt",
        )


class CanonicalUriTests(unittest.TestCase):
    def test_bucket_only_is_path_style(self):
        self.assertEqual(probe.canonical_uri("lab", None), "/lab")

    def test_key_is_appended_with_slashes_preserved(self):
        self.assertEqual(probe.canonical_uri("lab", "a/b.txt"), "/lab/a/b.txt")

    def test_special_characters_are_encoded(self):
        self.assertEqual(probe.canonical_uri("lab", "a b.txt"), "/lab/a%20b.txt")


class SigV4HeaderTests(unittest.TestCase):
    """`sigv4_headers` is driven directly here, for every request shape the
    script issues. The published-vector test above exercises only the HMAC
    chain, so on its own it would prove nothing about how the canonical
    request is assembled."""

    def _headers(self, **overrides):
        kwargs = dict(
            method="GET",
            bucket="branchleft-lab-probe",
            key=None,
            query={"versioning": ""},
            payload=b"",
            host="hel1.your-objectstorage.com",
            region="hel1",
            access_key=ACCESS_KEY,
            secret_key=SECRET_KEY,
            now=FIXED_NOW,
        )
        kwargs.update(overrides)
        return probe.sigv4_headers(**kwargs)

    def _expected_signature(self, canonical_request: str) -> str:
        to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                "20260816T120000Z",
                "20260816/hel1/s3/aws4_request",
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            ]
        )
        return hmac.new(
            probe.signing_key(SECRET_KEY, "20260816", "hel1", "s3"), to_sign.encode(), hashlib.sha256
        ).hexdigest()

    def test_canonical_request_for_a_bucket_subresource_get(self):
        canonical_request = (
            "GET\n"
            "/branchleft-lab-probe\n"
            "versioning=\n"
            "host:hel1.your-objectstorage.com\n"
            f"x-amz-content-sha256:{probe.EMPTY_SHA256}\n"
            "x-amz-date:20260816T120000Z\n"
            "\n"
            "host;x-amz-content-sha256;x-amz-date\n"
            f"{probe.EMPTY_SHA256}"
        )
        self.assertIn(
            f"Signature={self._expected_signature(canonical_request)}",
            self._headers()["Authorization"],
        )

    def test_canonical_request_for_an_object_put_with_a_payload(self):
        payload = b"second"
        payload_hash = hashlib.sha256(payload).hexdigest()
        canonical_request = (
            "PUT\n"
            "/branchleft-lab-probe/_probe/object-storage-probe.txt\n"
            "\n"
            "host:hel1.your-objectstorage.com\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            "x-amz-date:20260816T120000Z\n"
            "\n"
            "host;x-amz-content-sha256;x-amz-date\n"
            f"{payload_hash}"
        )
        headers = self._headers(
            method="PUT", key=probe.PROBE_KEY, query=None, payload=payload
        )
        self.assertIn(
            f"Signature={self._expected_signature(canonical_request)}", headers["Authorization"]
        )

    def test_canonical_request_with_multiple_query_parameters(self):
        canonical_request = (
            "GET\n"
            "/branchleft-lab-probe\n"
            "prefix=_probe%2Fobject-storage-probe.txt&versions=\n"
            "host:hel1.your-objectstorage.com\n"
            f"x-amz-content-sha256:{probe.EMPTY_SHA256}\n"
            "x-amz-date:20260816T120000Z\n"
            "\n"
            "host;x-amz-content-sha256;x-amz-date\n"
            f"{probe.EMPTY_SHA256}"
        )
        headers = self._headers(query={"versions": "", "prefix": probe.PROBE_KEY})
        self.assertIn(
            f"Signature={self._expected_signature(canonical_request)}", headers["Authorization"]
        )

    def test_canonical_request_with_an_extra_signed_header(self):
        payload = probe.lifecycle_document()
        payload_hash = hashlib.sha256(payload).hexdigest()
        canonical_request = (
            "PUT\n"
            "/branchleft-lab-probe\n"
            "lifecycle=\n"
            "content-md5:abc==\n"
            "host:hel1.your-objectstorage.com\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            "x-amz-date:20260816T120000Z\n"
            "\n"
            "content-md5;host;x-amz-content-sha256;x-amz-date\n"
            f"{payload_hash}"
        )
        headers = self._headers(
            method="PUT",
            query={"lifecycle": ""},
            payload=payload,
            extra_headers={"Content-MD5": "abc=="},
        )
        self.assertIn(
            f"Signature={self._expected_signature(canonical_request)}", headers["Authorization"]
        )

    def test_authorization_carries_the_scope_and_signed_headers(self):
        auth = self._headers()["Authorization"]
        self.assertTrue(auth.startswith("AWS4-HMAC-SHA256 "))
        self.assertIn(f"Credential={ACCESS_KEY}/20260816/hel1/s3/aws4_request", auth)
        self.assertIn("SignedHeaders=host;x-amz-content-sha256;x-amz-date", auth)

    def test_empty_payload_uses_the_empty_sha256(self):
        self.assertEqual(self._headers()["x-amz-content-sha256"], probe.EMPTY_SHA256)

    def test_a_different_payload_changes_the_signature(self):
        self.assertNotEqual(
            self._headers(method="PUT", payload=b"first")["Authorization"],
            self._headers(method="PUT", payload=b"second")["Authorization"],
        )

    def test_a_different_region_changes_the_signature(self):
        self.assertNotEqual(
            self._headers(region="hel1")["Authorization"],
            self._headers(region="fsn1")["Authorization"],
        )

    def test_extra_header_value_is_normalised_the_same_way_on_the_wire(self):
        """SigV4 collapses internal whitespace in the signed value. If the
        outgoing header kept the original spacing the signature would cover a
        value the server never saw."""
        headers = self._headers(extra_headers={"Content-MD5": "a   b"})
        self.assertEqual(headers["content-md5"], "a b")


class TransportWiringTests(unittest.TestCase):
    """Whatever the signer computes has to be what goes on the wire."""

    def test_signed_request_puts_the_authorization_header_on_the_wire(self):
        transport = FakeTransport()
        _bucket(transport).request("GET", query={"versioning": ""})
        _method, _marker, url, headers, _payload = transport.calls[0]
        self.assertTrue(url.endswith("/branchleft-lab-probe?versioning="))
        self.assertIn("Authorization", headers)
        self.assertIn("x-amz-content-sha256", headers)

    def test_extra_headers_reach_the_wire(self):
        transport = FakeTransport()
        _bucket(transport).request(
            "PUT", query={"lifecycle": ""}, payload=b"x", extra_headers={"content-md5": "abc=="}
        )
        self.assertEqual(transport.calls[0][3]["content-md5"], "abc==")

    def test_unsigned_request_carries_no_authorization_header(self):
        transport = FakeTransport()
        _bucket(transport).request("GET", key=probe.PROBE_KEY, signed=False)
        self.assertNotIn("Authorization", transport.calls[0][3])


# --------------------------------------------------------------------------
# Policy and guards


class PublicReadPolicyTests(unittest.TestCase):
    def test_grants_getobject_on_the_probe_prefix_only(self):
        policy = probe.public_read_policy("lab-bucket")
        self.assertIn('"s3:GetObject"', policy)
        self.assertIn('"arn:aws:s3:::lab-bucket/_probe/*"', policy)

    def test_never_grants_the_whole_bucket(self):
        """A grant over `<bucket>/*` would publish anything else the bucket
        holds, including Pulumi checkpoint JSON at a documented key path."""
        self.assertNotIn('"arn:aws:s3:::lab-bucket/*"', probe.public_read_policy("lab-bucket"))

    def test_never_grants_listbucket(self):
        """The tenant-roster control is the absence of this action."""
        self.assertNotIn("ListBucket", probe.public_read_policy("lab-bucket"))

    def test_never_names_the_bucket_resource_itself(self):
        self.assertNotIn('"arn:aws:s3:::lab-bucket"', probe.public_read_policy("lab-bucket"))

    def test_is_valid_json_with_the_expected_shape(self):
        import json

        parsed = json.loads(probe.public_read_policy("lab-bucket"))
        self.assertEqual(len(parsed["Statement"]), 1)
        self.assertEqual(parsed["Statement"][0]["Effect"], "Allow")
        self.assertEqual(parsed["Statement"][0]["Action"], ["s3:GetObject"])
        self.assertEqual(parsed["Statement"][0]["Principal"], "*")


class ProtectedBucketTests(unittest.TestCase):
    """The guard is what keeps a script that publishes an anonymous-read grant
    away from Pulumi state."""

    def _run(self, name):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = probe.main(
                ["--bucket", name, "--endpoint", "hel1.your-objectstorage.com", "--region", "hel1"]
            )
        return code, stderr.getvalue()

    def test_refuses_the_production_state_bucket(self):
        code, err = self._run("branchleft-pulumi-state")
        self.assertEqual(code, 2)
        self.assertIn("refusing to probe", err)

    def test_refuses_the_lab_state_bucket(self):
        """Named to look like a state bucket, so a deny-list of one would have
        let it through."""
        self.assertEqual(self._run("branchleft-lab-pulumi-state")[0], 2)

    def test_refuses_a_tenant_state_bucket_that_does_not_exist_yet(self):
        """The provisioning flow mints `<tenant>-pulumi-state` buckets; the
        suffix guard covers them the day they appear."""
        self.assertEqual(self._run("some-tenant-pulumi-state")[0], 2)

    def test_the_refusal_does_not_depend_on_credentials_being_absent(self):
        for name, value in (("AWS_ACCESS_KEY_ID", "AKIA_TEST"), ("AWS_SECRET_ACCESS_KEY", "s")):
            self.addCleanup(os.environ.pop, name, None)
            os.environ[name] = value
        self.assertEqual(self._run("branchleft-pulumi-state")[0], 2)


class CredentialSourcingTests(unittest.TestCase):
    def test_missing_credentials_exit_without_probing(self):
        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
            original = os.environ.pop(name, None)
            if original is not None:
                self.addCleanup(os.environ.__setitem__, name, original)

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = probe.main(
                [
                    "--bucket",
                    "branchleft-lab-probe",
                    "--endpoint",
                    "hel1.your-objectstorage.com",
                    "--region",
                    "hel1",
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("must be set", stderr.getvalue())


class PreflightTests(unittest.TestCase):
    """`PUT ?policy` and `PUT ?lifecycle` replace the whole document, so the
    script must not run where it would overwrite one."""

    def test_clean_bucket_passes(self):
        transport = FakeTransport(
            responses={
                ("GET", "policy"): (404, b""),
                ("GET", "lifecycle"): (404, b""),
                ("GET", "list-type"): (200, f'<ListBucketResult xmlns="{probe.S3_NS}"/>'.encode()),
            }
        )
        self.assertEqual(probe.preflight(_bucket(transport)), [])

    def test_existing_bucket_policy_is_refused(self):
        transport = FakeTransport(
            responses={
                ("GET", "policy"): (200, b'{"Statement":[]}'),
                ("GET", "lifecycle"): (404, b""),
                ("GET", "list-type"): (200, f'<ListBucketResult xmlns="{probe.S3_NS}"/>'.encode()),
            }
        )
        self.assertIn("already has a bucket policy", " ".join(probe.preflight(_bucket(transport))))

    def test_existing_lifecycle_is_refused(self):
        transport = FakeTransport(
            responses={
                ("GET", "policy"): (404, b""),
                ("GET", "lifecycle"): (200, probe.lifecycle_document()),
                ("GET", "list-type"): (200, f'<ListBucketResult xmlns="{probe.S3_NS}"/>'.encode()),
            }
        )
        self.assertIn("lifecycle configuration", " ".join(probe.preflight(_bucket(transport))))

    def test_an_unanswerable_policy_check_refuses_rather_than_assuming_absent(self):
        """`PUT ?policy` replaces the whole document and teardown deletes it.
        A transient 500 must not be read as "there is no policy"."""
        transport = FakeTransport(
            responses={
                ("GET", "policy"): (500, b""),
                ("GET", "lifecycle"): (404, b""),
                ("GET", "list-type"): (200, f'<ListBucketResult xmlns="{probe.S3_NS}"/>'.encode()),
            }
        )
        self.assertIn("could not determine", " ".join(probe.preflight(_bucket(transport))))

    def test_an_unanswerable_lifecycle_check_refuses(self):
        transport = FakeTransport(
            responses={
                ("GET", "policy"): (404, b""),
                ("GET", "lifecycle"): (503, b""),
                ("GET", "list-type"): (200, f'<ListBucketResult xmlns="{probe.S3_NS}"/>'.encode()),
            }
        )
        self.assertIn("lifecycle configuration exists", " ".join(probe.preflight(_bucket(transport))))

    def test_an_unanswerable_emptiness_check_refuses(self):
        transport = FakeTransport(
            responses={
                ("GET", "policy"): (404, b""),
                ("GET", "lifecycle"): (404, b""),
                ("GET", "list-type"): (403, b""),
            }
        )
        self.assertIn("whether the bucket is empty", " ".join(probe.preflight(_bucket(transport))))

    def test_a_403_naming_the_absent_subresource_is_treated_as_absent(self):
        """S3 implementations answer the "no policy here" case with a 403 and
        an explanatory code as well as with a 404."""
        transport = FakeTransport(
            responses={
                ("GET", "policy"): (403, b"<Error><Code>NoSuchBucketPolicy</Code></Error>"),
                ("GET", "lifecycle"): (
                    403,
                    b"<Error><Code>NoSuchLifecycleConfiguration</Code></Error>",
                ),
                ("GET", "list-type"): (200, f'<ListBucketResult xmlns="{probe.S3_NS}"/>'.encode()),
            }
        )
        self.assertEqual(probe.preflight(_bucket(transport)), [])

    def test_non_empty_bucket_is_refused(self):
        listing = (
            f'<ListBucketResult xmlns="{probe.S3_NS}">'
            "<Contents><Key>.pulumi/stacks/p/s.json</Key></Contents></ListBucketResult>"
        ).encode()
        transport = FakeTransport(
            responses={
                ("GET", "policy"): (404, b""),
                ("GET", "lifecycle"): (404, b""),
                ("GET", "list-type"): (200, listing),
            }
        )
        self.assertIn("not empty", " ".join(probe.preflight(_bucket(transport))))


# --------------------------------------------------------------------------
# Teardown — the security-sensitive path


class TeardownTests(unittest.TestCase):
    def test_removes_the_policy_first(self):
        """The anonymous-read grant is the thing worth removing soonest."""
        transport = FakeTransport(responses={("GET", "versions"): (200, NO_VERSIONS)})
        probe.teardown(_bucket(transport), None)
        self.assertEqual(transport.markers("DELETE")[0], "policy")

    def test_a_transport_failure_does_not_skip_the_remaining_steps(self):
        transport = FakeTransport(
            responses={("GET", "versions"): (200, NO_VERSIONS)},
            raise_on={("DELETE", "policy")},
        )
        notes, _advisories = probe.teardown(_bucket(transport), None)
        self.assertIn("lifecycle", transport.markers("DELETE"))
        self.assertIn("versioning", transport.markers("PUT"))
        self.assertTrue(any("public-read bucket policy" in n for n in notes))

    def test_a_failed_policy_delete_is_reported(self):
        transport = FakeTransport(
            responses={("DELETE", "policy"): (500, b""), ("GET", "versions"): (200, NO_VERSIONS)}
        )
        notes, _advisories = probe.teardown(_bucket(transport), None)
        self.assertTrue(any("public-read bucket policy" in n and "FAILED" in n for n in notes))

    def test_a_failed_version_delete_is_reported_not_swallowed(self):
        versions = (
            f'<ListVersionsResult xmlns="{probe.S3_NS}"><Version>'
            f"<Key>{probe.PROBE_KEY}</Key><VersionId>v1</VersionId>"
            "</Version></ListVersionsResult>"
        ).encode()
        transport = FakeTransport(
            responses={("GET", "versions"): (200, versions), ("DELETE", "versionId"): (403, b"")}
        )
        notes, _advisories = probe.teardown(_bucket(transport), None)
        self.assertTrue(any("version v1" in n for n in notes), notes)

    def test_deletes_every_listed_version_and_delete_marker(self):
        versions = (
            f'<ListVersionsResult xmlns="{probe.S3_NS}">'
            f"<Version><Key>{probe.PROBE_KEY}</Key><VersionId>v1</VersionId></Version>"
            f"<Version><Key>{probe.PROBE_KEY}</Key><VersionId>v2</VersionId></Version>"
            f"<DeleteMarker><Key>{probe.PROBE_KEY}</Key><VersionId>v3</VersionId></DeleteMarker>"
            "</ListVersionsResult>"
        ).encode()
        transport = FakeTransport(responses={("GET", "versions"): (200, versions)})
        probe.teardown(_bucket(transport), None)
        deleted = [c for c in transport.calls if c[0] == "DELETE" and "versionId" in c[2]]
        self.assertEqual(len(deleted), 3)

    def test_restores_versioning_that_was_already_enabled(self):
        """A bucket that arrived versioned must not leave suspended."""
        transport = FakeTransport(responses={("GET", "versions"): (200, NO_VERSIONS)})
        notes, advisories = probe.teardown(_bucket(transport), "Enabled")
        put = [c for c in transport.calls if c[0] == "PUT" and c[1] == "versioning"]
        self.assertIn(b"<Status>Enabled</Status>", put[0][4])
        self.assertEqual(notes, [])
        self.assertEqual(advisories, [])

    def test_never_versioned_is_an_advisory_not_a_teardown_failure(self):
        """It is a fact about S3 on a run that went perfectly. Counting it as a
        failure would make exit 1 the outcome of every successful run, and an
        exit code that is always 1 is one the operator stops reading."""
        transport = FakeTransport(responses={("GET", "versions"): (200, NO_VERSIONS)})
        failures, advisories = probe.teardown(_bucket(transport), None)
        self.assertEqual(failures, [])
        self.assertTrue(any("never-versioned" in n for n in advisories))

    def test_never_writes_a_versioning_state_it_did_not_read(self):
        """An unreadable original state must not become a confident restore:
        suspending a bucket that arrived Enabled would remove a recovery
        property while claiming to have put one back."""
        transport = FakeTransport(responses={("GET", "versions"): (200, NO_VERSIONS)})
        failures, _advisories = probe.teardown(_bucket(transport), probe.VERSIONING_UNKNOWN)
        self.assertEqual([c for c in transport.calls if c[0] == "PUT" and c[1] == "versioning"], [])
        self.assertTrue(any("could not be read" in n for n in failures))

    def test_unparseable_version_listing_is_reported(self):
        transport = FakeTransport(responses={("GET", "versions"): (200, b"<html>oops")})
        failures, _advisories = probe.teardown(_bucket(transport), "Enabled")
        self.assertTrue(any("could not be parsed" in n for n in failures))


# --------------------------------------------------------------------------
# Probes


class ProbeTests(unittest.TestCase):
    def test_versioning_reports_a_put_the_platform_silently_ignored(self):
        transport = FakeTransport(
            responses={("GET", "versioning"): (200, f'<VersioningConfiguration xmlns="{probe.S3_NS}"/>'.encode())}
        )
        result = probe.probe_versioning(_bucket(transport))
        self.assertEqual(result.verdict, "FAIL")
        self.assertIn("read back as None", result.detail)

    def test_lifecycle_reports_noncurrent_days_dropped_on_the_round_trip(self):
        stripped = (
            f'<LifecycleConfiguration xmlns="{probe.S3_NS}"><Rule>'
            "<Expiration><Days>90</Days></Expiration></Rule></LifecycleConfiguration>"
        ).encode()
        transport = FakeTransport(responses={("GET", "lifecycle"): (200, stripped)})
        result = probe.probe_lifecycle(_bucket(transport))
        self.assertEqual(result.verdict, "FAIL")
        self.assertIn("NoncurrentDays back as None", result.detail)

    def test_a_publicly_listable_bucket_is_a_failure(self):
        transport = FakeTransport(
            responses={
                ("PUT", "policy"): (204, b""),
                ("GET", probe.PROBE_KEY): (200, b"second"),
                ("GET", ""): (200, f'<ListBucketResult xmlns="{probe.S3_NS}"/>'.encode()),
            }
        )
        results = probe.probe_public_read_not_listable(_bucket(transport))
        listing = [r for r in results if "listing" in r.name][0]
        self.assertEqual(listing.verdict, "FAIL")
        self.assertIn("PUBLICLY LISTABLE", listing.detail)

    def test_unsupported_bucket_policy_stops_and_says_what_it_means(self):
        transport = FakeTransport(responses={("PUT", "policy"): (501, b"")})
        results = probe.probe_public_read_not_listable(_bucket(transport))
        self.assertEqual(len(results), 1)
        self.assertIn("candidate (b) has no mechanism", results[0].detail)



class VersioningReadTests(unittest.TestCase):
    def test_a_failed_read_is_unknown_not_never_versioned(self):
        """Error bodies parse to no `<Status>` element, exactly as an
        unversioned bucket does. Collapsing the two lets teardown "restore" a
        state nobody observed."""
        transport = FakeTransport(responses={("GET", "versioning"): (500, b"<Error/>")})
        self.assertEqual(probe.read_versioning(_bucket(transport)), probe.VERSIONING_UNKNOWN)

    def test_a_successful_read_of_an_unversioned_bucket_is_none(self):
        body = f'<VersioningConfiguration xmlns="{probe.S3_NS}"/>'.encode()
        transport = FakeTransport(responses={("GET", "versioning"): (200, body)})
        self.assertIsNone(probe.read_versioning(_bucket(transport)))


class EndToEndTests(unittest.TestCase):
    """Drives `main` over the documented case -- a fresh, never-versioned
    scratch bucket -- because every guard being individually correct did not
    stop the assembled run from reporting a teardown failure and exiting 1 on
    a flawless pass."""

    def _happy_transport(self):
        versions = (
            f'<ListVersionsResult xmlns="{probe.S3_NS}">'
            f"<Version><Key>{probe.PROBE_KEY}</Key><VersionId>v1</VersionId></Version>"
            f"<Version><Key>{probe.PROBE_KEY}</Key><VersionId>v2</VersionId></Version>"
            "</ListVersionsResult>"
        ).encode()
        enabled = (
            f'<VersioningConfiguration xmlns="{probe.S3_NS}">'
            "<Status>Enabled</Status></VersioningConfiguration>"
        ).encode()
        unversioned = f'<VersioningConfiguration xmlns="{probe.S3_NS}"/>'.encode()
        lifecycle = (
            f'<LifecycleConfiguration xmlns="{probe.S3_NS}"><Rule>'
            "<NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays>"
            "</NoncurrentVersionExpiration></Rule></LifecycleConfiguration>"
        ).encode()

        class Sequenced(FakeTransport):
            """`GET ?versioning` answers unversioned first (the pre-run read)
            and Enabled thereafter (the probe's read-back)."""

            def __init__(self):
                super().__init__()
                self.versioning_reads = 0

            def __call__(self, method, url, headers, payload):
                marker = self.marker(url)
                if method == "GET" and marker == "versioning":
                    self.versioning_reads += 1
                    self.calls.append((method, marker, url, headers, payload))
                    return probe.Response(
                        200, unversioned if self.versioning_reads == 1 else enabled
                    )
                if method == "GET" and marker in ("policy", "lifecycle"):
                    if marker == "lifecycle" and any(
                        c[0] == "PUT" and c[1] == "lifecycle" for c in self.calls
                    ):
                        self.calls.append((method, marker, url, headers, payload))
                        return probe.Response(200, lifecycle)
                    self.calls.append((method, marker, url, headers, payload))
                    return probe.Response(404, b"")
                if method == "GET" and marker == "list-type":
                    self.calls.append((method, marker, url, headers, payload))
                    return probe.Response(
                        200, f'<ListBucketResult xmlns="{probe.S3_NS}"/>'.encode()
                    )
                if method == "GET" and marker == "versions":
                    self.calls.append((method, marker, url, headers, payload))
                    return probe.Response(200, versions)
                if method == "GET" and marker == probe.PROBE_KEY:
                    self.calls.append((method, marker, url, headers, payload))
                    return probe.Response(200, b"second")
                if method == "GET" and marker == "":
                    self.calls.append((method, marker, url, headers, payload))
                    return probe.Response(403, b"<Error><Code>AccessDenied</Code></Error>")
                return super().__call__(method, url, headers, payload)

        return Sequenced()

    def test_a_flawless_run_exits_zero_and_reports_no_teardown_failure(self):
        transport = self._happy_transport()
        original = probe.Bucket
        probe.Bucket = lambda *a, **k: original(*a, transport=transport)
        self.addCleanup(setattr, probe, "Bucket", original)
        for name, value in (("AWS_ACCESS_KEY_ID", "AKIA_T"), ("AWS_SECRET_ACCESS_KEY", "s")):
            self.addCleanup(os.environ.pop, name, None)
            os.environ[name] = value

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = probe.main(
                [
                    "--bucket",
                    "branchleft-lab-probe",
                    "--endpoint",
                    "hel1.your-objectstorage.com",
                    "--region",
                    "hel1",
                ]
            )
        report = out.getvalue()
        self.assertNotIn("**FAIL**", report)
        self.assertNotIn("Teardown did not fully complete", report)
        self.assertIn("never-versioned", report)
        self.assertEqual(code, 0)


class ResponseTests(unittest.TestCase):
    def test_error_code_is_extracted(self):
        body = b"<?xml version='1.0'?><Error><Code>AccessDenied</Code></Error>"
        self.assertEqual(probe.Response(403, body).error_code(), "AccessDenied")

    def test_error_code_of_a_non_xml_body_is_none(self):
        self.assertIsNone(probe.Response(502, b"<html>bad gateway").error_code())

    def test_describe_includes_the_code_when_there_is_one(self):
        body = b"<Error><Code>NoSuchBucket</Code></Error>"
        self.assertEqual(probe.Response(404, body).describe(), "HTTP 404 (NoSuchBucket)")


class XmlParsingTests(unittest.TestCase):
    def test_versioning_status_with_namespace(self):
        body = (
            f'<VersioningConfiguration xmlns="{probe.S3_NS}">'
            "<Status>Enabled</Status></VersioningConfiguration>"
        ).encode()
        self.assertEqual(probe._versioning_status(body), "Enabled")

    def test_versioning_status_of_a_never_versioned_bucket_is_absent(self):
        body = f'<VersioningConfiguration xmlns="{probe.S3_NS}"/>'.encode()
        self.assertIsNone(probe._versioning_status(body))

    def test_noncurrent_days_round_trip(self):
        body = (
            f'<LifecycleConfiguration xmlns="{probe.S3_NS}"><Rule>'
            "<NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays>"
            "</NoncurrentVersionExpiration></Rule></LifecycleConfiguration>"
        ).encode()
        self.assertEqual(probe._lifecycle_noncurrent_days(body), 30)

    def test_non_numeric_noncurrent_days_does_not_raise(self):
        body = (
            f'<LifecycleConfiguration xmlns="{probe.S3_NS}"><Rule>'
            "<NoncurrentVersionExpiration><NoncurrentDays>soon</NoncurrentDays>"
            "</NoncurrentVersionExpiration></Rule></LifecycleConfiguration>"
        ).encode()
        self.assertIsNone(probe._lifecycle_noncurrent_days(body))

    def test_counts_versions(self):
        body = (
            f'<ListVersionsResult xmlns="{probe.S3_NS}">'
            "<Version><Key>a</Key></Version><Version><Key>a</Key></Version>"
            "</ListVersionsResult>"
        ).encode()
        self.assertEqual(probe._count_versions(body), 2)

    def test_counts_zero_versions_on_unparseable_body(self):
        self.assertEqual(probe._count_versions(b"not xml"), 0)


class RenderTests(unittest.TestCase):
    def test_reports_every_verdict_and_the_teardown_notes(self):
        out = probe.render(
            "lab",
            "hel1.your-objectstorage.com",
            "hel1",
            [
                probe.Result("Versioning can be enabled", "PASS", "read back as Enabled"),
                probe.Result("Bucket policy accepted", "FAIL", "HTTP 501"),
            ],
            ["removing the public-read bucket policy FAILED"],
        )
        self.assertIn("**PASS**", out)
        self.assertIn("**FAIL**", out)
        self.assertIn("Teardown did not fully complete", out)

    def test_omits_the_teardown_section_when_clean(self):
        self.assertNotIn(
            "Teardown", probe.render("lab", "hel1.your-objectstorage.com", "hel1", [], [])
        )


if __name__ == "__main__":
    unittest.main()
