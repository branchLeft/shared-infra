"""P1 to P6 against the in-memory world: each passes, and each notices what it is for."""

from __future__ import annotations

import unittest

from fake_s3 import NOW, FakeOps, World
from probe_checks import Probe
from probe_report import CheckResult, Status
from probe_s3 import LockConfig


def run(world: World) -> dict[str, CheckResult]:
    probe = Probe(
        FakeOps(world, "rw"),
        FakeOps(world, "admin"),
        world.target,
        clock=lambda: NOW,
        sleep=lambda _seconds: None,
        settle_attempts=2,
    )
    return {result.code: result for result in probe.run()}


class HealthyWorldTests(unittest.TestCase):
    def test_every_check_passes(self) -> None:
        results = run(World())
        self.assertEqual(["P1", "P2", "P3", "P4", "P5", "P6"], list(results))
        for code, result in results.items():
            with self.subTest(code=code):
                self.assertEqual(Status.PASS, result.status, result.detail)

    def test_nothing_is_ever_written_to_bucket_c(self) -> None:
        world = World()
        run(world)
        self.assertEqual([], world.writes_to(world.target.bucket_c))

    def test_the_lock_attempt_on_b_is_the_only_lock_write_and_it_is_governance_sized(
        self,
    ) -> None:
        world = World()
        run(world)
        self.assertEqual(
            [("admin", "put_lock_config", world.target.bucket_b)],
            [row for row in world.log if row[1] == "put_lock_config"],
        )

    def test_bucket_a_is_left_empty_by_the_checks(self) -> None:
        world = World()
        run(world)
        self.assertEqual([], world.stored[world.target.bucket_a])


class SabotageTests(unittest.TestCase):
    def status(self, world: World, code: str) -> Status:
        return run(world)[code].status

    def test_p1_notices_a_bucket_outside_london(self) -> None:
        self.assertEqual(Status.FAIL, self.status(World(location="eu-west-par"), "P1"))

    def test_p1_accepts_an_unreported_location_at_the_london_endpoint(self) -> None:
        self.assertEqual(Status.PASS, self.status(World(location=None), "P1"))

    def test_p2_notices_no_default_retention(self) -> None:
        self.assertEqual(Status.FAIL, self.status(World(apply_retention=False), "P2"))

    def test_p2_notices_a_wrong_retention_period(self) -> None:
        self.assertEqual(Status.FAIL, self.status(World(retention_days=14), "P2"))

    def test_p3_notices_a_delete_that_was_not_refused(self) -> None:
        result = run(World(honour_lock=False))["P3"]
        self.assertEqual(Status.FAIL, result.status)
        self.assertIn("NOT refused", result.detail)

    def test_p3_notices_a_bypass_that_is_refused(self) -> None:
        self.assertEqual(Status.FAIL, self.status(World(honour_bypass=False), "P3"))

    def test_p4_notices_a_second_bucket_the_credential_can_reach(self) -> None:
        results = run(World(rw_reaches_b=True))
        self.assertEqual(Status.FAIL, results["P4"].status)
        self.assertIn("ALLOWED", results["P4"].detail)

    def test_p5_notices_a_lock_accepted_on_an_existing_bucket(self) -> None:
        results = run(World(accept_late_lock=True))
        self.assertEqual(Status.FAIL, results["P5"].status)

    def test_p6_notices_the_wrong_mode(self) -> None:
        world = World(c_lock=LockConfig(True, "GOVERNANCE", 1))
        self.assertEqual(Status.FAIL, self.status(world, "P6"))

    def test_p6_notices_the_wrong_period(self) -> None:
        world = World(c_lock=LockConfig(True, "COMPLIANCE", 14))
        self.assertEqual(Status.FAIL, self.status(world, "P6"))

    def test_p6_notices_no_default_at_all(self) -> None:
        world = World(c_lock=LockConfig(False))
        self.assertEqual(Status.ERROR, self.status(world, "P6"))


class FaultTests(unittest.TestCase):
    def test_a_connection_fault_is_an_error_never_a_pass_or_a_refusal(self) -> None:
        results = run(World(fault_on={"list_versions"}))
        self.assertEqual(Status.ERROR, results["P1"].status)
        self.assertEqual(Status.ERROR, results["P4"].status)
        self.assertNotEqual(Status.PASS, results["P3"].status)

    def test_p3_without_an_object_from_p2_is_an_error(self) -> None:
        results = run(World(fault_on={"put_object"}))
        self.assertEqual(Status.ERROR, results["P2"].status)
        self.assertEqual(Status.ERROR, results["P3"].status)

    def test_a_missing_bucket_is_not_counted_as_a_refusal(self) -> None:
        world = World()
        ops = FakeOps(world, "rw")
        original = ops.list_versions

        def missing(bucket: str):  # type: ignore[no-untyped-def]
            if bucket == world.target.bucket_b:
                from probe_s3 import S3Error

                raise S3Error("NoSuchBucket", "", 404)
            return original(bucket)

        ops.list_versions = missing  # type: ignore[method-assign]
        probe = Probe(
            ops,
            FakeOps(world, "admin"),
            world.target,
            clock=lambda: NOW,
            sleep=lambda _s: None,
        )
        result = {r.code: r for r in probe.run()}["P4"]
        self.assertEqual(Status.ERROR, result.status)

    def test_a_credential_that_never_settles_is_retried_then_reported(self) -> None:
        world = World()
        sleeps: list[float] = []

        class Never(FakeOps):
            def list_versions(self, bucket: str):  # type: ignore[no-untyped-def]
                from fake_s3 import denied

                raise denied()

        probe = Probe(
            Never(world, "rw"),
            FakeOps(world, "admin"),
            world.target,
            clock=lambda: NOW,
            sleep=sleeps.append,
            settle_attempts=3,
            settle_delay=7.0,
        )
        first = probe.run()[0]
        self.assertEqual(Status.ERROR, first.status)
        self.assertEqual([7.0, 7.0], sleeps)

    def test_a_wrong_endpoint_is_an_error_before_any_call(self) -> None:
        world = World()
        target = type(world.target)(
            "https://s3.eu-west-par.io.cloud.ovh.net",
            *[world.target.bucket_a, world.target.bucket_b, world.target.bucket_c],
        )
        probe = Probe(
            FakeOps(world, "rw"), FakeOps(world, "admin"), target, clock=lambda: NOW
        )
        self.assertEqual(Status.ERROR, probe.p1_london_bucket().status)
        self.assertEqual([], world.log)


if __name__ == "__main__":
    unittest.main()
