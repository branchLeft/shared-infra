"""The six lock checks, P1 to P6, run against the three probe buckets.

Bucket A is locked at creation (Governance, one day) and is the only bucket the
probe credential reaches. Bucket B has versioning and no lock. Bucket C is the
real configuration at probe size (Compliance, one day).

Two rules protect the account and are pinned by the tests:

- nothing is ever written to bucket C, because an object under Compliance
  retention cannot be deleted by anyone, nor can the bucket that holds it;
- a refusal only counts as one when the server answered with an error. A
  connection fault is an ERROR row, never a pass.
"""

from __future__ import annotations

import datetime
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from probe_report import CheckResult, Status
from probe_s3 import Ops, S3Error

T = TypeVar("T")

ACCESS_CODES = frozenset({"AccessDenied", "Forbidden", "AllAccessDisabled"})
NO_LOCK_CODE = "ObjectLockConfigurationNotFoundError"
LONDON_REGION = "uk"
PROBE_KEY = "probe/object.txt"
PROBE_BODY = b"probe"
RETENTION_TOLERANCE = datetime.timedelta(hours=1)


@dataclass(frozen=True)
class Target:
    endpoint: str
    bucket_a: str
    bucket_b: str
    bucket_c: str


def is_access_refusal(error: S3Error) -> bool:
    return error.status == 403 or error.code in ACCESS_CODES


def is_client_refusal(error: S3Error) -> bool:
    return 400 <= error.status < 500


def _utc(moment: datetime.datetime) -> datetime.datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=datetime.UTC)
    return moment.astimezone(datetime.UTC)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _result(code: str, title: str, status: Status, detail: str) -> CheckResult:
    return CheckResult(code, title, status, detail)


TITLES = {
    "P1": "London bucket reachable with the scoped credential",
    "P2": "Default retention applied to a new object",
    "P3": "Delete refused, then allowed with bypass",
    "P4": "A second bucket refuses the credential",
    "P5": "A lock cannot be added to an existing bucket",
    "P6": "Compliance one day accepted as a default on an empty bucket",
}


class Probe:
    def __init__(
        self,
        rw: Ops,
        admin: Ops,
        target: Target,
        *,
        clock: Callable[[], datetime.datetime] = _now,
        sleep: Callable[[float], None] = time.sleep,
        settle_attempts: int = 6,
        settle_delay: float = 10.0,
    ) -> None:
        self._rw = rw
        self._admin = admin
        self._t = target
        self._clock = clock
        self._sleep = sleep
        self._attempts = settle_attempts
        self._delay = settle_delay
        self._version_id: str | None = None

    def run(self) -> list[CheckResult]:
        steps: list[tuple[str, Callable[[], CheckResult]]] = [
            ("P1", self.p1_london_bucket),
            ("P2", self.p2_default_retention),
            ("P3", self.p3_delete_refused_then_bypassed),
            ("P4", self.p4_second_bucket_refuses),
            ("P5", self.p5_lock_not_added_later),
            ("P6", self.p6_compliance_default),
        ]
        results: list[CheckResult] = []
        for code, step in steps:
            try:
                results.append(step())
            except Exception as exc:  # noqa: BLE001 - a check that blew up proves nothing
                text = f"{type(exc).__name__}: {str(exc)[:160]}"
                results.append(_result(code, TITLES[code], Status.ERROR, text))
        return results

    def _settled(self, call: Callable[[], T]) -> T:
        """Retries an access refusal: a new credential and policy take a moment to apply."""
        for attempt in range(self._attempts):
            try:
                return call()
            except S3Error as error:
                if not is_access_refusal(error) or attempt == self._attempts - 1:
                    raise
                self._sleep(self._delay)
        raise AssertionError("unreachable")

    def p1_london_bucket(self) -> CheckResult:
        code = "P1"
        if f"://s3.{LONDON_REGION}." not in self._t.endpoint:
            return _result(
                code, TITLES[code], Status.ERROR, "the endpoint is not the London one"
            )
        versions = self._settled(lambda: self._rw.list_versions(self._t.bucket_a))
        location = self._rw.bucket_location(self._t.bucket_a)
        shown = "not reported" if not location else location
        if location and location.lower() != LONDON_REGION:
            return _result(
                code, TITLES[code], Status.FAIL, f"bucket A reports location {location}"
            )
        return _result(
            code,
            TITLES[code],
            Status.PASS,
            f"bucket A listed ({len(versions)} versions) at the London endpoint; location {shown}",
        )

    def p2_default_retention(self) -> CheckResult:
        code = "P2"
        version = self._rw.put_object(self._t.bucket_a, PROBE_KEY, PROBE_BODY)
        if not version:
            return _result(
                code, TITLES[code], Status.FAIL, "the write returned no version id"
            )
        self._version_id = version
        held = self._rw.get_object_retention(self._t.bucket_a, PROBE_KEY, version)
        if held is None:
            return _result(
                code, TITLES[code], Status.FAIL, "the new object has no retention"
            )
        expected = self._clock() + datetime.timedelta(days=1)
        drift = abs(_utc(held.until) - expected)
        if held.mode != "GOVERNANCE" or drift > RETENTION_TOLERANCE:
            return _result(
                code,
                TITLES[code],
                Status.FAIL,
                f"mode {held.mode}, retain until {_utc(held.until).isoformat()}, "
                "expected GOVERNANCE for one day",
            )
        return _result(
            code, TITLES[code], Status.PASS, "GOVERNANCE, retained for one day"
        )

    def p3_delete_refused_then_bypassed(self) -> CheckResult:
        code = "P3"
        version = self._version_id
        if version is None:
            return _result(
                code, TITLES[code], Status.ERROR, "no object from P2 to delete"
            )
        bucket = self._t.bucket_a
        try:
            self._rw.delete_version(bucket, PROBE_KEY, version, bypass=False)
        except S3Error as error:
            if not is_client_refusal(error):
                raise
            refusal = error.code
        else:
            return _result(
                code, TITLES[code], Status.FAIL, "the plain delete was NOT refused"
            )
        if not self._holds(bucket, version):
            return _result(
                code,
                TITLES[code],
                Status.FAIL,
                f"refused with {refusal}, but the version is gone",
            )
        try:
            self._rw.delete_version(bucket, PROBE_KEY, version, bypass=True)
        except S3Error as error:
            return _result(
                code,
                TITLES[code],
                Status.FAIL,
                f"the bypass delete was refused: {error.code}",
            )
        if self._holds(bucket, version):
            return _result(
                code, TITLES[code], Status.FAIL, "the bypass delete left the version"
            )
        return _result(
            code,
            TITLES[code],
            Status.PASS,
            f"plain delete refused ({refusal}); bypass deleted it",
        )

    def _holds(self, bucket: str, version: str) -> bool:
        return any(
            item.version_id == version for item in self._rw.list_versions(bucket)
        )

    def p4_second_bucket_refuses(self) -> CheckResult:
        code = "P4"
        problems: list[str] = []
        inconclusive: list[str] = []

        def refused(label: str, call: Callable[[], object]) -> None:
            try:
                call()
            except S3Error as error:
                if not is_access_refusal(error):
                    inconclusive.append(f"{label}: {error.code}")
            else:
                problems.append(f"{label} was ALLOWED")

        refused("list B", lambda: self._rw.list_versions(self._t.bucket_b))
        refused(
            "write B",
            lambda: self._rw.put_object(self._t.bucket_b, PROBE_KEY, PROBE_BODY),
        )
        refused("list C", lambda: self._rw.list_versions(self._t.bucket_c))
        if problems:
            return _result(code, TITLES[code], Status.FAIL, "; ".join(problems))
        if inconclusive:
            text = "answered, but not as a refusal: " + "; ".join(inconclusive)
            return _result(code, TITLES[code], Status.ERROR, text)
        return _result(
            code,
            TITLES[code],
            Status.PASS,
            "list B, write B and list C all refused (403)",
        )

    def p5_lock_not_added_later(self) -> CheckResult:
        code = "P5"
        bucket = self._t.bucket_b
        try:
            before = self._settled(lambda: self._admin.get_lock_config(bucket))
        except S3Error as error:
            if error.code != NO_LOCK_CODE:
                text = f"cannot read bucket B's lock settings: {error.code}"
                return _result(code, TITLES[code], Status.ERROR, text)
        else:
            if before.enabled:
                return _result(
                    code, TITLES[code], Status.ERROR, "bucket B already shows a lock"
                )
        try:
            self._admin.put_lock_config(bucket, "GOVERNANCE", 1)
        except S3Error as error:
            if not is_client_refusal(error):
                raise
            refusal = error.code
        else:
            return _result(
                code,
                TITLES[code],
                Status.FAIL,
                "a lock WAS accepted on the existing bucket B",
            )
        try:
            after = self._admin.get_lock_config(bucket)
        except S3Error as error:
            if error.code != NO_LOCK_CODE:
                raise
        else:
            if after.enabled:
                return _result(
                    code,
                    TITLES[code],
                    Status.FAIL,
                    f"refused ({refusal}) but B now shows a lock",
                )
        return _result(
            code, TITLES[code], Status.PASS, f"refused ({refusal}); B still has no lock"
        )

    def p6_compliance_default(self) -> CheckResult:
        code = "P6"
        bucket = self._t.bucket_c
        config = self._settled(lambda: self._admin.get_lock_config(bucket))
        versions = self._admin.list_versions(bucket)
        shown = f"enabled={config.enabled}, mode={config.mode}, days={config.days}"
        if config.years:
            shown += f", years={config.years}"
        ok = (
            config.enabled
            and config.mode == "COMPLIANCE"
            and config.days == 1
            and not config.years
            and not versions
        )
        if not ok:
            return _result(
                code,
                TITLES[code],
                Status.FAIL,
                f"{shown}, {len(versions)} versions in C",
            )
        return _result(code, TITLES[code], Status.PASS, f"{shown}; C is empty")
