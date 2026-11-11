"""The S3 operations the probe uses, and the boto3 adapter that performs them.

`Ops` is the whole surface the checks see. The checks are tested against a fake
`Ops`; `BotoOps` is the only code that imports boto3, and it does so lazily so
the unit tests need no third-party package.

An answer from the server that is an error becomes an `S3Error`. Anything else
(a refused connection, a timeout) is left to propagate as it is: a check treats
that as "could not be carried out", never as a refusal.
"""

from __future__ import annotations

import contextlib
import datetime
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Protocol


class S3Error(Exception):
    """The server answered with an error."""

    def __init__(self, code: str, message: str = "", status: int = 0) -> None:
        super().__init__(
            f"{code} ({status}): {message}" if message else f"{code} ({status})"
        )
        self.code = code
        self.message = message
        self.status = status


@dataclass(frozen=True)
class VersionRef:
    key: str
    version_id: str
    delete_marker: bool = False


@dataclass(frozen=True)
class Retention:
    mode: str
    until: datetime.datetime


@dataclass(frozen=True)
class LockConfig:
    enabled: bool
    mode: str | None = None
    days: int | None = None
    years: int | None = None


class Ops(Protocol):
    def bucket_location(self, bucket: str) -> str | None: ...

    def list_versions(self, bucket: str) -> list[VersionRef]: ...

    def put_object(self, bucket: str, key: str, body: bytes) -> str | None: ...

    def get_object_retention(
        self, bucket: str, key: str, version_id: str
    ) -> Retention | None: ...

    def delete_version(
        self, bucket: str, key: str, version_id: str, *, bypass: bool
    ) -> None: ...

    def get_lock_config(self, bucket: str) -> LockConfig: ...

    def put_lock_config(self, bucket: str, mode: str, days: int) -> None: ...


@contextlib.contextmanager
def _translated() -> Iterator[None]:
    """Turns a botocore ClientError (anything carrying an error response) into S3Error."""
    try:
        yield
    except Exception as exc:
        response = getattr(exc, "response", None)
        if isinstance(response, dict) and isinstance(response.get("Error"), dict):
            error = response["Error"]
            meta = response.get("ResponseMetadata") or {}
            raise S3Error(
                str(error.get("Code", "")),
                str(error.get("Message", ""))[:200],
                int(meta.get("HTTPStatusCode", 0) or 0),
            ) from None
        raise


class BotoOps:
    """`Ops` over a boto3 S3 client (or anything with the same methods)."""

    def __init__(self, client: Any) -> None:
        self._client = client

    @classmethod
    def connect(
        cls, endpoint: str, region: str, access_key: str, secret_key: str
    ) -> BotoOps:
        import boto3
        from botocore.config import Config

        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path"},
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=10,
                read_timeout=30,
                # Non-AWS endpoints reject the default CRC32 trailer.
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )
        return cls(client)

    def bucket_location(self, bucket: str) -> str | None:
        with _translated():
            answer = self._client.get_bucket_location(Bucket=bucket)
        location = answer.get("LocationConstraint")
        return None if location is None else str(location)

    def list_versions(self, bucket: str) -> list[VersionRef]:
        found: list[VersionRef] = []
        markers: dict[str, str] = {}
        while True:
            with _translated():
                page = self._client.list_object_versions(Bucket=bucket, **markers)
            for item in page.get("Versions", []):
                found.append(VersionRef(item["Key"], item["VersionId"], False))
            for item in page.get("DeleteMarkers", []):
                found.append(VersionRef(item["Key"], item["VersionId"], True))
            if not page.get("IsTruncated"):
                return found
            markers = {
                "KeyMarker": page["NextKeyMarker"],
                "VersionIdMarker": page["NextVersionIdMarker"],
            }

    def put_object(self, bucket: str, key: str, body: bytes) -> str | None:
        with _translated():
            answer = self._client.put_object(Bucket=bucket, Key=key, Body=body)
        version = answer.get("VersionId")
        return None if version is None else str(version)

    def get_object_retention(
        self, bucket: str, key: str, version_id: str
    ) -> Retention | None:
        with _translated():
            answer = self._client.get_object_retention(
                Bucket=bucket, Key=key, VersionId=version_id
            )
        held = answer.get("Retention") or {}
        if not held.get("Mode") or held.get("RetainUntilDate") is None:
            return None
        return Retention(str(held["Mode"]), held["RetainUntilDate"])

    def delete_version(
        self, bucket: str, key: str, version_id: str, *, bypass: bool
    ) -> None:
        extra: dict[str, Any] = {"BypassGovernanceRetention": True} if bypass else {}
        with _translated():
            self._client.delete_object(
                Bucket=bucket, Key=key, VersionId=version_id, **extra
            )

    def get_lock_config(self, bucket: str) -> LockConfig:
        with _translated():
            answer = self._client.get_object_lock_configuration(Bucket=bucket)
        config = answer.get("ObjectLockConfiguration") or {}
        retention = (config.get("Rule") or {}).get("DefaultRetention") or {}
        return LockConfig(
            enabled=config.get("ObjectLockEnabled") == "Enabled",
            mode=retention.get("Mode"),
            days=retention.get("Days"),
            years=retention.get("Years"),
        )

    def put_lock_config(self, bucket: str, mode: str, days: int) -> None:
        with _translated():
            self._client.put_object_lock_configuration(
                Bucket=bucket,
                ObjectLockConfiguration={
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {"DefaultRetention": {"Mode": mode, "Days": days}},
                },
            )
