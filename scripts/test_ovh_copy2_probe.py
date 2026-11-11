#!/usr/bin/env python3
"""Tests for ovh/copy2/probe_object_lock.py: its refusals and its probe, against a fake S3.

No OVHcloud endpoint is contacted. The fake enforces what the probe expects the
platform to enforce, and each test that says "sabotaged" turns one of those
behaviours off to show the probe goes red.
"""

from __future__ import annotations

import datetime
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
import urllib.parse
from collections.abc import Mapping
from typing import Any

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ovh" / "copy2" / "probe_object_lock.py"
STACK_FILE = ROOT / "ovh" / "copy2" / "Pulumi.probe.yaml"
NS = "branchleft-ovh-copy2"

spec = importlib.util.spec_from_file_location("probe_object_lock", SCRIPT)
assert spec is not None and spec.loader is not None
probe = importlib.util.module_from_spec(spec)
sys.modules["probe_object_lock"] = probe
spec.loader.exec_module(probe)

PROJECT = "0123456789abcdef0123456789abcdef"
SUFFIX = "r4242-1"
ACCESS = "AKIAEXAMPLEACCESSKEY"
SECRET = "sEcReT/valueFORtests+0123456789"
NOW = datetime.datetime(2026, 11, 11, 12, 0, 0, tzinfo=datetime.timezone.utc)
ENV_OK = {
    "OVH_CLIENT_ID": "client-id-value",
    "OVH_CLIENT_SECRET": "client-secret-value",
    "GITHUB_RUN_ID": "4242",
    "GITHUB_RUN_ATTEMPT": "1",
}


def error_xml(code: str, message: str = "") -> bytes:
    return f"<Error><Code>{code}</Code><Message>{message}</Message></Error>".encode()


class FakeS3:
    """The behaviour the probe expects from a London bucket pair.

    Bucket A is the credential's own, lock-enabled with Governance and one day.
    Bucket B is outside the credential's scope. Each flag turns one expected
    behaviour off.
    """

    def __init__(
        self,
        suffix: str = SUFFIX,
        *,
        bites: bool = True,
        leaks_scope: bool = False,
        reported_mode: str = "GOVERNANCE",
        returns_version_id: bool = True,
        accepts_late_lock: bool = False,
        server_error: bool = False,
    ) -> None:
        self.a = f"zz-probe-a-{suffix}"
        self.b = f"zz-probe-b-{suffix}"
        self.bites = bites
        self.leaks_scope = leaks_scope
        self.reported_mode = reported_mode
        self.returns_version_id = returns_version_id
        self.accepts_late_lock = accepts_late_lock
        self.server_error = server_error
        self.versions: dict[str, dict[str, tuple[str, datetime.datetime]]] = {
            self.a: {},
            self.b: {},
        }
        self.calls: list[tuple[str, str, Mapping[str, str]]] = []
        self.counter = 0

    def __call__(self, method: str, url: str, headers: Mapping[str, str], payload: bytes) -> Any:
        self.calls.append((method, url, headers))
        assert "Authorization" in headers
        assert url.startswith("https://s3.uk.io.cloud.ovh.net/")
        parsed = urllib.parse.urlparse(url)
        bucket, _, key = parsed.path.lstrip("/").partition("/")
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if self.server_error:
            return probe.Response(500, error_xml("InternalError"))
        if method == "PUT" and "object-lock" in query and bucket == self.b:
            if self.accepts_late_lock:
                return probe.Response(200)
            return probe.Response(409, error_xml("InvalidBucketState"))
        if bucket == self.b and not self.leaks_scope:
            message = f"Access Key Id {ACCESS} is not allowed on this bucket"
            return probe.Response(403, error_xml("AccessDenied", message))
        store = self.versions[bucket]
        if method == "PUT" and "object-lock" in query:
            if bucket == self.b and not self.accepts_late_lock:
                return probe.Response(409, error_xml("InvalidBucketState"))
            return probe.Response(200)
        if method == "PUT":
            self.counter += 1
            version = f"v{self.counter}"
            until = NOW + datetime.timedelta(days=1)
            store[version] = (key, until if bucket == self.a else NOW)
            reply = {"x-amz-version-id": version} if self.returns_version_id else {}
            return probe.Response(200, b"", reply)
        if method == "GET" and "object-lock" in query:
            xml = (
                "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>"
                f"<Rule><DefaultRetention><Mode>{self.reported_mode}</Mode><Days>1</Days>"
                "</DefaultRetention></Rule></ObjectLockConfiguration>"
            )
            return probe.Response(200, xml.encode())
        if method == "HEAD":
            _, until = store[query["versionId"][0]]
            return probe.Response(
                200,
                b"",
                {
                    "x-amz-object-lock-mode": "GOVERNANCE",
                    "x-amz-object-lock-retain-until-date": until.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                },
            )
        if method == "GET" and "versions" in query:
            items = "".join(
                f"<Version><Key>{k}</Key><VersionId>{v}</VersionId></Version>"
                for v, (k, _) in store.items()
            )
            return probe.Response(
                200,
                f"<ListVersionsResult><IsTruncated>false</IsTruncated>{items}</ListVersionsResult>".encode(),
            )
        if method == "DELETE":
            version = query["versionId"][0]
            bypass = "x-amz-bypass-governance-retention" in headers
            if bucket == self.a and self.bites and not bypass:
                return probe.Response(403, error_xml("AccessDenied"))
            store.pop(version, None)
            return probe.Response(204)
        return probe.Response(400, error_xml("InvalidRequest"))


def outputs(suffix: str = SUFFIX, *, with_secret: bool = True) -> str:
    names = [f"zz-probe-{letter}-{suffix}" for letter in "abc"]
    return json.dumps(
        {
            "bucketNames": names,
            "s3Endpoints": {name: probe.ENDPOINT for name in names},
            "accessKeyIds": {"zz-probe-rw": ACCESS} if with_secret else {},
            "secretAccessKeys": {"zz-probe-rw": SECRET} if with_secret else {},
        }
    )


class Run:
    """One `main` call with captured output and a scratch directory."""

    def __init__(self, test: unittest.TestCase) -> None:
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="ovh-probe-test-"))
        test.addCleanup(self._remove)
        self.github_env = self.dir / "github_env"
        self.summary = self.dir / "summary.md"
        self.out = io.StringIO()
        self.err = io.StringIO()

    def _remove(self) -> None:
        for path in sorted(self.dir.rglob("*"), reverse=True):
            path.unlink() if path.is_file() else path.rmdir()
        self.dir.rmdir()

    def env(self, **extra: str) -> dict[str, str]:
        return {
            **ENV_OK,
            "GITHUB_ENV": str(self.github_env),
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "PROBE_SUFFIX": SUFFIX,
            **extra,
        }

    def main(self, argv: list[str], stdin: str = "", fake: FakeS3 | None = None, **env: str) -> int:
        old_err, sys.stderr = sys.stderr, self.err
        try:
            return probe.main(
                argv,
                env=self.env(**env),
                stdin=io.StringIO(stdin),
                out=self.out,
                transport=fake if fake is not None else FakeS3(),
                clock=lambda: NOW,
            )
        finally:
            sys.stderr = old_err

    def everything(self) -> str:
        # The mask lines are the point: they tell the runner to hide the value.
        printed = "".join(
            line
            for line in self.out.getvalue().splitlines(keepends=True)
            if not line.startswith("::add-mask::")
        )
        parts = [printed, self.err.getvalue()]
        for path in self.dir.rglob("*"):
            if path.is_file():
                parts.append(path.read_text(encoding="utf-8"))
        return "\n".join(parts)


def stack_file(
    test: unittest.TestCase, run: Run, change: Any = None, project: str = PROJECT
) -> pathlib.Path:
    """The committed probe stack file with a project id, then `change` applied."""
    document = yaml.safe_load(STACK_FILE.read_text(encoding="utf-8"))
    document["config"][f"{NS}:allowedProjectId"] = project
    if change is not None:
        change(document["config"])
    path = run.dir / "Pulumi.probe.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def bucket(config: dict[str, Any], name: str) -> dict[str, Any]:
    return next(b for b in config[f"{NS}:buckets"] if b["name"] == name)


class PreflightTests(unittest.TestCase):
    def preflight(self, run: Run, path: pathlib.Path, **env: str) -> int:
        return run.main(["preflight", "--stack-file", str(path)], **env)

    def test_accepts_the_committed_file_once_a_project_id_is_supplied(self) -> None:
        run = Run(self)
        code = self.preflight(run, stack_file(self, run))
        self.assertEqual(code, 0, run.err.getvalue())
        exported = run.github_env.read_text()
        self.assertIn(f"OVH_CLOUD_PROJECT_SERVICE={PROJECT}", exported)
        self.assertIn(f"PROBE_SUFFIX={SUFFIX}", exported)
        self.assertNotIn(ENV_OK["OVH_CLIENT_SECRET"], run.everything())
        self.assertNotIn(ENV_OK["OVH_CLIENT_ID"], run.everything())

    def test_refuses_an_unset_project_id_and_exports_nothing(self) -> None:
        run = Run(self)
        code = self.preflight(run, stack_file(self, run, project="UNSET"))
        self.assertEqual(code, 2)
        self.assertIn("UNSET", run.err.getvalue())
        self.assertFalse(run.github_env.exists())

    def test_refuses_a_project_id_that_is_not_hex(self) -> None:
        for bad in ("", "short", PROJECT.upper(), PROJECT + "0"):
            with self.subTest(bad=bad):
                run = Run(self)
                self.assertEqual(self.preflight(run, stack_file(self, run, project=bad)), 2)

    def test_refuses_when_the_project_id_key_is_missing(self) -> None:
        run = Run(self)
        path = stack_file(self, run, lambda config: config.pop(f"{NS}:allowedProjectId"))
        self.assertEqual(self.preflight(run, path), 2)

    def test_refuses_a_missing_or_empty_secret_and_names_it_without_a_value(self) -> None:
        for name in ("OVH_CLIENT_ID", "OVH_CLIENT_SECRET"):
            for value in ("", None):
                with self.subTest(name=name, value=value):
                    run = Run(self)
                    path = stack_file(self, run)
                    env = dict(ENV_OK)
                    if value is None:
                        del env[name]
                    else:
                        env[name] = value
                    old_err, sys.stderr = sys.stderr, run.err
                    try:
                        code = probe.main(
                            ["preflight", "--stack-file", str(path)],
                            env={**env, "GITHUB_ENV": str(run.github_env)},
                            out=run.out,
                        )
                    finally:
                        sys.stderr = old_err
                    self.assertIn(name, run.err.getvalue())
                    self.assertNotIn(ENV_OK[name], run.err.getvalue())
                    self.assertEqual(code, 2)
                    self.assertFalse(run.github_env.exists())

    def test_refuses_compliance_on_the_bucket_the_probe_writes_to(self) -> None:
        run = Run(self)

        def sabotage(config: dict[str, Any]) -> None:
            bucket(config, "zz-probe-a")["objectLock"]["mode"] = "COMPLIANCE"

        code = self.preflight(run, stack_file(self, run, sabotage))
        self.assertEqual(code, 2)
        self.assertIn("Compliance", run.err.getvalue())
        self.assertFalse(run.github_env.exists())

    def test_refuses_a_probe_bucket_locked_for_more_than_a_day(self) -> None:
        run = Run(self)

        def sabotage(config: dict[str, Any]) -> None:
            bucket(config, "zz-probe-c")["objectLock"]["retentionDays"] = 14

        self.assertEqual(self.preflight(run, stack_file(self, run, sabotage)), 2)

    def test_refuses_any_region_but_uk(self) -> None:
        for region in ("GRA", "SBG", "uk"):
            with self.subTest(region=region):
                run = Run(self)

                def sabotage(config: dict[str, Any], region: str = region) -> None:
                    bucket(config, "zz-probe-b")["region"] = region

                self.assertEqual(self.preflight(run, stack_file(self, run, sabotage)), 2)
                self.assertIn("region must be UK", run.err.getvalue())

    def test_refuses_a_bucket_that_is_not_a_probe_bucket(self) -> None:
        run = Run(self)

        def sabotage(config: dict[str, Any]) -> None:
            config[f"{NS}:buckets"].append(
                {"name": "branchleft-copy2-uk", "region": "UK", "versioning": "ENABLED"}
            )

        self.assertEqual(self.preflight(run, stack_file(self, run, sabotage)), 2)

    def test_refuses_a_write_target_without_a_governance_lock(self) -> None:
        run = Run(self)

        def sabotage(config: dict[str, Any]) -> None:
            del bucket(config, "zz-probe-a")["objectLock"]

        self.assertEqual(self.preflight(run, stack_file(self, run, sabotage)), 2)

    def test_notes_the_empty_compliance_bucket_the_stack_file_declares(self) -> None:
        run = Run(self)
        self.assertEqual(self.preflight(run, stack_file(self, run)), 0)
        self.assertIn("zz-probe-c", run.out.getvalue())

    def test_refuses_a_run_id_that_is_not_a_number(self) -> None:
        run = Run(self)
        self.assertEqual(self.preflight(run, stack_file(self, run), GITHUB_RUN_ID="12;rm"), 2)


class RefusalTests(unittest.TestCase):
    def test_a_compliance_lock_cannot_be_built(self) -> None:
        with self.assertRaises(probe.Refusal):
            probe.lock_configuration_xml("COMPLIANCE", 1)

    def test_a_long_or_empty_retention_cannot_be_built(self) -> None:
        for days in (0, 2, 14):
            with self.subTest(days=days), self.assertRaises(probe.Refusal):
                probe.lock_configuration_xml("GOVERNANCE", days)

    def test_governance_for_one_day_can_be_built(self) -> None:
        body = probe.lock_configuration_xml("GOVERNANCE", 1)
        self.assertIn(b"<Mode>GOVERNANCE</Mode><Days>1</Days>", body)
        self.assertNotIn(b"COMPLIANCE", body)

    def test_no_request_the_probe_sends_names_compliance(self) -> None:
        run = Run(self)
        fake = FakeS3()
        self.assertEqual(
            run.main(["probe", "--results-dir", str(run.dir / "r")], outputs(), fake), 0
        )
        self.assertEqual(run.main(["cleanup"], outputs(), fake), 0)
        self.assertTrue(fake.calls)
        self.assertNotIn("COMPLIANCE", repr(fake.calls))

    def test_the_transport_refuses_any_other_host(self) -> None:
        with self.assertRaises(probe.ProbeError):
            probe.urllib_transport("GET", "https://example.invalid/zz-probe-a", {}, b"")

    def test_outputs_naming_another_endpoint_are_refused(self) -> None:
        run = Run(self)
        document = json.loads(outputs())
        for name in document["s3Endpoints"]:
            document["s3Endpoints"][name] = "https://s3.gra.io.cloud.ovh.net"
        fake = FakeS3()
        code = run.main(["probe", "--results-dir", str(run.dir / "r")], json.dumps(document), fake)
        self.assertEqual(code, 2)
        self.assertEqual(fake.calls, [])

    def test_outputs_without_a_credential_are_refused_by_the_probe(self) -> None:
        run = Run(self)
        fake = FakeS3()
        code = run.main(
            ["probe", "--results-dir", str(run.dir / "r")], outputs(with_secret=False), fake
        )
        self.assertEqual(code, 2)
        self.assertEqual(fake.calls, [])

    def test_a_malformed_suffix_is_refused(self) -> None:
        run = Run(self)
        code = run.main(
            ["probe", "--results-dir", str(run.dir / "r")], outputs(), PROBE_SUFFIX="../x"
        )
        self.assertEqual(code, 2)


class BackendTests(unittest.TestCase):
    def test_writes_a_fresh_masked_passphrase_and_a_file_backend(self) -> None:
        seen = []
        for _ in range(2):
            run = Run(self)
            self.assertEqual(run.main(["backend", "--state-dir", str(run.dir / "state")]), 0)
            exported = run.github_env.read_text()
            self.assertIn(f"PULUMI_BACKEND_URL=file://{run.dir / 'state'}", exported)
            passphrase = next(
                line.split("=", 1)[1]
                for line in exported.splitlines()
                if line.startswith("PULUMI_CONFIG_PASSPHRASE=")
            )
            self.assertGreaterEqual(len(passphrase), 32)
            self.assertIn(f"::add-mask::{passphrase}", run.out.getvalue())
            seen.append(passphrase)
        self.assertNotEqual(seen[0], seen[1])


class ProbeTests(unittest.TestCase):
    def run_probe(self, fake: FakeS3) -> tuple[Run, int, dict[str, Any]]:
        run = Run(self)
        results = run.dir / "result"
        code = run.main(["probe", "--results-dir", str(results)], outputs(), fake)
        document = json.loads((results / "result.json").read_text())
        return run, code, document

    def verdicts(self, document: dict[str, Any]) -> dict[str, str]:
        return {check["id"]: check["verdict"] for check in document["checks"]}

    def test_every_check_passes_against_the_expected_behaviour(self) -> None:
        run, code, document = self.run_probe(FakeS3())
        self.assertEqual(code, 0, run.out.getvalue())
        self.assertEqual(document["overall"], "PASS")
        self.assertEqual(
            list(self.verdicts(document)),
            ["P0", "P1", "P1b", "P2", "P3a", "P3b", "P3c", "P3d", "P4", "P5"],
        )
        self.assertEqual(set(self.verdicts(document).values()), {"PASS"})
        self.assertIn("OVH London probe", run.summary.read_text())

    def test_sabotaged_delete_that_the_lock_does_not_refuse_goes_red(self) -> None:
        _, code, document = self.run_probe(FakeS3(bites=False))
        self.assertEqual(self.verdicts(document)["P3b"], "FAIL")
        self.assertEqual(code, 1)

    def test_sabotaged_scope_that_reaches_bucket_b_goes_red_and_leaves_b_empty(self) -> None:
        fake = FakeS3(leaks_scope=True)
        _, code, document = self.run_probe(fake)
        self.assertEqual(self.verdicts(document)["P4"], "FAIL")
        self.assertEqual(fake.versions[fake.b], {})
        self.assertEqual(code, 1)

    def test_sabotaged_mode_reported_as_compliance_goes_red(self) -> None:
        _, code, document = self.run_probe(FakeS3(reported_mode="COMPLIANCE"))
        self.assertEqual(self.verdicts(document)["P1b"], "FAIL")
        self.assertEqual(code, 1)

    def test_sabotaged_late_lock_accepted_on_b_goes_red(self) -> None:
        _, _, document = self.run_probe(FakeS3(accepts_late_lock=True))
        self.assertEqual(self.verdicts(document)["P5"], "FAIL")

    def test_a_missing_version_id_fails_the_write_and_skips_what_needs_it(self) -> None:
        _, code, document = self.run_probe(FakeS3(returns_version_id=False))
        verdicts = self.verdicts(document)
        self.assertEqual(verdicts["P1"], "FAIL")
        self.assertEqual(verdicts["P2"], "INCONCLUSIVE")
        self.assertEqual(verdicts["P4"], "PASS")
        self.assertEqual(code, 1)

    def test_a_server_error_is_inconclusive_never_a_pass_or_a_refusal(self) -> None:
        _, code, document = self.run_probe(FakeS3(server_error=True))
        self.assertNotIn("PASS", [v for k, v in self.verdicts(document).items() if k != "P0"])
        self.assertEqual(self.verdicts(document)["P4"], "INCONCLUSIVE")
        self.assertEqual(code, 1)

    def test_a_transport_failure_is_inconclusive(self) -> None:
        def broken(*_: Any) -> Any:
            raise probe.ProbeError("PUT request did not complete: TimeoutError")

        _, code, document = self.run_probe(broken)  # type: ignore[arg-type]
        self.assertEqual(self.verdicts(document)["P1"], "INCONCLUSIVE")
        self.assertEqual(code, 1)

    def test_the_credential_never_reaches_a_result_a_summary_or_a_log(self) -> None:
        run, _, _ = self.run_probe(FakeS3())
        everything = run.everything()
        self.assertNotIn(SECRET, everything)
        self.assertNotIn(ACCESS, everything)
        self.assertIn(f"::add-mask::{SECRET}", run.out.getvalue())
        self.assertIn(f"::add-mask::{ACCESS}", run.out.getvalue())

    def test_a_credential_inside_an_error_is_scrubbed_from_the_result(self) -> None:
        def echoing(*_: Any) -> Any:
            raise probe.ProbeError(f"upstream said {ACCESS} and {SECRET}")

        run, _, document = self.run_probe(echoing)  # type: ignore[arg-type]
        text = json.dumps(document)
        self.assertNotIn(SECRET, text)
        self.assertNotIn(ACCESS, text)
        self.assertIn("***", text)
        self.assertNotIn(SECRET, run.everything())

    def test_the_credential_is_masked_before_a_refusal_can_print_anything(self) -> None:
        run = Run(self)
        document = json.loads(outputs())
        document["bucketNames"] = []
        code = run.main(["probe", "--results-dir", str(run.dir / "r")], json.dumps(document))
        self.assertEqual(code, 2)
        self.assertIn(f"::add-mask::{SECRET}", run.out.getvalue())
        self.assertNotIn(SECRET, run.err.getvalue())


class CleanupTests(unittest.TestCase):
    def test_removes_every_version_with_the_bypass_header(self) -> None:
        run = Run(self)
        fake = FakeS3()
        fake.versions[fake.a] = {"v1": ("probe/object.txt", NOW + datetime.timedelta(days=1))}
        self.assertEqual(run.main(["cleanup"], outputs(), fake), 0)
        self.assertEqual(fake.versions[fake.a], {})
        deletes = [call for call in fake.calls if call[0] == "DELETE"]
        self.assertTrue(deletes)
        for _, _, headers in deletes:
            self.assertIn("x-amz-bypass-governance-retention", headers["Authorization"])

    def test_reports_a_failure_without_the_credential(self) -> None:
        run = Run(self)
        self.assertEqual(run.main(["cleanup"], outputs(), FakeS3(server_error=True)), 1)
        self.assertNotIn(SECRET, run.everything())

    def test_empty_outputs_mean_nothing_to_purge(self) -> None:
        run = Run(self)
        fake = FakeS3()
        self.assertEqual(run.main(["cleanup"], "", fake), 0)
        self.assertEqual(fake.calls, [])


class FinishTests(unittest.TestCase):
    def finish(self, **outcomes: str) -> tuple[int, Run]:
        run = Run(self)
        argv = ["finish", "--suffix", SUFFIX]
        for step in ("init", "up", "probe", "cleanup", "destroy"):
            argv += [f"--{step}", outcomes.get(step, "")]
        return run.main(argv), run

    def test_a_destroy_that_did_not_succeed_fails_and_lists_what_to_delete(self) -> None:
        code, run = self.finish(init="success", up="success", probe="success", destroy="failure")
        self.assertEqual(code, 1)
        for name in (
            "zz-probe-a-r4242-1",
            "zz-probe-b-r4242-1",
            "zz-probe-c-r4242-1",
            "zz-probe-rw",
        ):
            self.assertIn(name, run.summary.read_text())

    def test_a_skipped_destroy_after_a_created_stack_fails(self) -> None:
        code, _ = self.finish(init="success", up="success", destroy="skipped")
        self.assertEqual(code, 1)

    def test_a_clean_run_succeeds(self) -> None:
        code, run = self.finish(
            init="success", up="success", probe="success", cleanup="success", destroy="success"
        )
        self.assertEqual(code, 0)
        self.assertIn("destroyed", run.summary.read_text())

    def test_a_refused_preflight_created_nothing_and_needs_no_destroy(self) -> None:
        code, run = self.finish(init="skipped", up="skipped", destroy="skipped")
        self.assertEqual(code, 0)
        self.assertIn("nothing needed destroying", run.summary.read_text())


class SigningTests(unittest.TestCase):
    def test_the_signing_key_matches_the_published_vector(self) -> None:
        key = probe.signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam"
        )
        self.assertEqual(
            key.hex(), "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        )

    def test_the_bypass_header_is_a_signed_header(self) -> None:
        headers = probe.sign_headers(
            method="DELETE",
            path="/b/k",
            query={"versionId": "v1"},
            payload=b"",
            host="s3.uk.io.cloud.ovh.net",
            access_key=ACCESS,
            secret_key=SECRET,
            now=NOW,
            extra=probe.BYPASS,
        )
        self.assertIn("x-amz-bypass-governance-retention", headers["Authorization"])
        self.assertIn("/uk/s3/aws4_request", headers["Authorization"])


if __name__ == "__main__":
    unittest.main()
