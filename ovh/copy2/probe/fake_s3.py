"""An in-memory stand-in for the three probe buckets, for the offline tests.

The knobs on `World` switch one platform behaviour at a time, so each check can
be shown to notice the behaviour it exists to catch. `World.log` records every
call as (role, operation, bucket), which is how the tests prove that nothing is
ever written to bucket C.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from probe_checks import NO_LOCK_CODE, Target
from probe_s3 import LockConfig, Retention, S3Error, VersionRef

NOW = datetime.datetime(2026, 11, 20, 12, 0, tzinfo=datetime.UTC)


def denied() -> S3Error:
    return S3Error("AccessDenied", "Access Denied", 403)


@dataclass
class Stored:
    key: str
    version_id: str
    retention: Retention | None


@dataclass
class World:
    suffix: str = "r1a1"
    honour_lock: bool = True
    apply_retention: bool = True
    honour_bypass: bool = True
    rw_reaches_b: bool = False
    accept_late_lock: bool = False
    location: str | None = "uk"
    retention_days: int = 1
    c_lock: LockConfig = field(
        default_factory=lambda: LockConfig(True, "COMPLIANCE", 1)
    )
    fault_on: set[str] = field(default_factory=set)
    log: list[tuple[str, str, str]] = field(default_factory=list)
    counter: int = 0

    def __post_init__(self) -> None:
        self.target = Target(
            endpoint="https://s3.uk.io.cloud.ovh.net",
            bucket_a=f"zz-probe-a-{self.suffix}",
            bucket_b=f"zz-probe-b-{self.suffix}",
            bucket_c=f"zz-probe-c-{self.suffix}",
        )
        self.stored: dict[str, list[Stored]] = {
            self.target.bucket_a: [],
            self.target.bucket_b: [],
            self.target.bucket_c: [],
        }
        self.locks: dict[str, LockConfig] = {
            self.target.bucket_a: LockConfig(True, "GOVERNANCE", 1),
            self.target.bucket_b: LockConfig(False),
            self.target.bucket_c: self.c_lock,
        }

    def writes_to(self, bucket: str) -> list[tuple[str, str, str]]:
        return [
            row
            for row in self.log
            if row[2] == bucket and row[1] in ("put_object", "put_lock_config")
        ]


class FakeOps:
    def __init__(self, world: World, role: str) -> None:
        self.world = world
        self.role = role

    def _enter(self, operation: str, bucket: str) -> None:
        self.world.log.append((self.role, operation, bucket))
        if operation in self.world.fault_on:
            raise ConnectionError("connection refused")
        t = self.world.target
        if self.role == "rw":
            allowed = bucket == t.bucket_a or (
                self.world.rw_reaches_b and bucket == t.bucket_b
            )
        else:
            allowed = (
                bucket == t.bucket_b
                and operation in ("list_versions", "get_lock_config", "put_lock_config")
            ) or (
                bucket == t.bucket_c
                and operation in ("list_versions", "get_lock_config")
            )
        if not allowed:
            raise denied()

    def bucket_location(self, bucket: str) -> str | None:
        self._enter("bucket_location", bucket)
        return self.world.location

    def list_versions(self, bucket: str) -> list[VersionRef]:
        self._enter("list_versions", bucket)
        return [
            VersionRef(item.key, item.version_id) for item in self.world.stored[bucket]
        ]

    def put_object(self, bucket: str, key: str, body: bytes) -> str | None:
        self._enter("put_object", bucket)
        self.world.counter += 1
        lock = self.world.locks[bucket]
        retention = None
        if lock.enabled and self.world.apply_retention:
            until = NOW + datetime.timedelta(days=self.world.retention_days)
            retention = Retention(lock.mode or "GOVERNANCE", until)
        version = f"v{self.world.counter}"
        self.world.stored[bucket].append(Stored(key, version, retention))
        return version

    def get_object_retention(
        self, bucket: str, key: str, version_id: str
    ) -> Retention | None:
        self._enter("get_object_retention", bucket)
        for item in self.world.stored[bucket]:
            if item.version_id == version_id:
                return item.retention
        raise S3Error("NoSuchVersion", "", 404)

    def delete_version(
        self, bucket: str, key: str, version_id: str, *, bypass: bool
    ) -> None:
        self._enter("delete_version", bucket)
        for item in self.world.stored[bucket]:
            if item.version_id != version_id:
                continue
            locked = item.retention is not None and self.world.honour_lock
            if locked and (not bypass or not self.world.honour_bypass):
                raise denied()
            self.world.stored[bucket].remove(item)
            return
        raise S3Error("NoSuchVersion", "", 404)

    def get_lock_config(self, bucket: str) -> LockConfig:
        self._enter("get_lock_config", bucket)
        lock = self.world.locks[bucket]
        if not lock.enabled:
            raise S3Error(NO_LOCK_CODE, "not found", 404)
        return lock

    def put_lock_config(self, bucket: str, mode: str, days: int) -> None:
        self._enter("put_lock_config", bucket)
        if not self.world.accept_late_lock:
            raise S3Error("InvalidBucketState", "cannot enable", 409)
        self.world.locks[bucket] = LockConfig(True, mode, days)
