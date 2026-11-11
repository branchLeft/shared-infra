"""BotoOps against a stand-in client: error translation and request shapes, no boto3."""

from __future__ import annotations

import datetime
import unittest
from typing import Any

from probe_s3 import BotoOps, S3Error


class FakeClientError(Exception):
    def __init__(self, code: str, status: int, message: str = "no") -> None:
        super().__init__(code)
        self.response = {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


class Recorder:
    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        def call(**kwargs: Any) -> Any:
            self.calls.append((name, kwargs))
            answer = self.answers[name]
            if isinstance(answer, Exception):
                raise answer
            return answer(kwargs) if callable(answer) else answer

        return call


class TranslationTests(unittest.TestCase):
    def test_a_server_error_becomes_an_s3_error_with_code_and_status(self) -> None:
        ops = BotoOps(Recorder({"delete_object": FakeClientError("AccessDenied", 403)}))
        with self.assertRaises(S3Error) as caught:
            ops.delete_version("b", "k", "v", bypass=False)
        self.assertEqual(
            ("AccessDenied", 403), (caught.exception.code, caught.exception.status)
        )

    def test_a_connection_fault_is_not_translated(self) -> None:
        ops = BotoOps(Recorder({"get_bucket_location": ConnectionError("down")}))
        with self.assertRaises(ConnectionError):
            ops.bucket_location("b")


class RequestShapeTests(unittest.TestCase):
    def test_bypass_is_sent_only_when_asked_for(self) -> None:
        client = Recorder({"delete_object": {}})
        ops = BotoOps(client)
        ops.delete_version("b", "k", "v", bypass=False)
        ops.delete_version("b", "k", "v", bypass=True)
        self.assertNotIn("BypassGovernanceRetention", client.calls[0][1])
        self.assertTrue(client.calls[1][1]["BypassGovernanceRetention"])

    def test_versions_and_delete_markers_are_both_listed_across_pages(self) -> None:
        pages = iter(
            [
                {
                    "Versions": [{"Key": "a", "VersionId": "1"}],
                    "IsTruncated": True,
                    "NextKeyMarker": "a",
                    "NextVersionIdMarker": "1",
                },
                {
                    "DeleteMarkers": [{"Key": "b", "VersionId": "2"}],
                    "IsTruncated": False,
                },
            ]
        )
        client = Recorder({"list_object_versions": lambda _kw: next(pages)})
        found = BotoOps(client).list_versions("b")
        self.assertEqual(
            [("a", "1", False), ("b", "2", True)],
            [(v.key, v.version_id, v.delete_marker) for v in found],
        )
        self.assertEqual(
            {"KeyMarker": "a", "VersionIdMarker": "1"},
            {k: v for k, v in client.calls[1][1].items() if k != "Bucket"},
        )

    def test_lock_configuration_round_trips_as_governance_days(self) -> None:
        client = Recorder(
            {
                "put_object_lock_configuration": {},
                "get_object_lock_configuration": {
                    "ObjectLockConfiguration": {
                        "ObjectLockEnabled": "Enabled",
                        "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 1}},
                    }
                },
            }
        )
        ops = BotoOps(client)
        ops.put_lock_config("b", "GOVERNANCE", 1)
        sent = client.calls[0][1]["ObjectLockConfiguration"]
        self.assertEqual(
            {"Mode": "GOVERNANCE", "Days": 1}, sent["Rule"]["DefaultRetention"]
        )
        config = ops.get_lock_config("b")
        self.assertEqual(
            (True, "COMPLIANCE", 1), (config.enabled, config.mode, config.days)
        )

    def test_retention_is_read_with_its_date(self) -> None:
        until = datetime.datetime(2026, 11, 21, tzinfo=datetime.UTC)
        client = Recorder(
            {
                "get_object_retention": {
                    "Retention": {"Mode": "GOVERNANCE", "RetainUntilDate": until}
                }
            }
        )
        held = BotoOps(client).get_object_retention("b", "k", "v")
        self.assertIsNotNone(held)
        assert held is not None
        self.assertEqual(("GOVERNANCE", until), (held.mode, held.until))

    def test_no_retention_reads_as_none(self) -> None:
        self.assertIsNone(
            BotoOps(Recorder({"get_object_retention": {}})).get_object_retention(
                "b", "k", "v"
            )
        )


if __name__ == "__main__":
    unittest.main()
