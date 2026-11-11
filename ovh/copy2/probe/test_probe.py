"""The four workflow steps end to end, with a fake Pulumi CLI and the in-memory buckets."""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar

import probe
from fake_s3 import NOW, FakeOps, World
from probe_s3 import Ops
from probe_stack import Completed

RW_ID, RW_SECRET = "AKRWKEY0001", "rw-secret-value-0001"
AD_ID, AD_SECRET = "AKADKEY0002", "admin-secret-value-0002"
SECRETS = (RW_ID, RW_SECRET, AD_ID, AD_SECRET)
RUNNER_ENV = {
    "PATH": "/usr/bin",
    "HOME": "/home/runner",
    "RUNNER_TEMP": "/unused",
    "GITHUB_RUN_ID": "9876543210",
    "GITHUB_RUN_ATTEMPT": "1",
    "OVH_ENDPOINT": "ovh-eu",
    "OVH_CLIENT_ID": "client-id-value",
    "OVH_CLIENT_SECRET": "client-secret-value",
    "OVH_CLOUD_PROJECT_SERVICE": "5dd5eda4165c48fa80428816500bc992",
    "GH_TOKEN": "gh-token-value",
    "NODE_AUTH_TOKEN": "npm-token-value",
}
SUFFIX = "r9876543210a1"


def urn(kind: str, name: str) -> str:
    return f"urn:pulumi:probe::branchleft-ovh-copy2::{kind}::{name}"


class FakePulumi:
    def __init__(self, world: World) -> None:
        self.world = world
        self.calls: list[list[str]] = []
        self.envs: list[dict[str, str]] = []
        self.resources: list[dict[str, Any]] = []
        self.fail_init = False
        self.fail_up = False
        self.fail_export_after_destroy = False
        self.destroy_succeeds_on: int | None = 1
        self.stuck: set[str] = set()
        self.destroys = 0
        self.destroyed = False

    @staticmethod
    def _name(resource: Mapping[str, Any]) -> str:
        return resource["outputs"].get("name") or resource["urn"].rsplit("::", 1)[-1]

    def subcommands(self) -> list[str]:
        return [
            " ".join(call[1:3]) if call[1] == "stack" else call[1]
            for call in self.calls
        ]

    def __call__(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        cwd: Path,
        capture: bool,
        timeout: float,
    ) -> Completed:
        self.calls.append(list(argv))
        self.envs.append(dict(env))
        verb = argv[1]
        if verb == "stack" and argv[2] == "init":
            return Completed(1, "", "boom") if self.fail_init else Completed(0)
        if verb == "config":
            return Completed(0)
        if verb == "up":
            self.resources = [
                {
                    "urn": urn("ovh:CloudStorageObjectBucket", f"bucket-{name}"),
                    "type": "ovh:CloudStorageObjectBucket",
                    "outputs": {"name": name},
                }
                for name in (
                    self.world.target.bucket_a,
                    self.world.target.bucket_b,
                    self.world.target.bucket_c,
                )
            ] + [
                {
                    "urn": urn("ovh:cloudproject:User", f"user-{who}"),
                    "type": "ovh:cloudproject:User",
                    "outputs": {},
                }
                for who in ("zz-probe-owner", "zz-probe-rw", "zz-probe-admin")
            ]
            return Completed(1, "", "up failed") if self.fail_up else Completed(0)
        if verb == "destroy":
            self.destroys += 1
            if (
                self.destroy_succeeds_on is not None
                and self.destroys >= self.destroy_succeeds_on
            ):
                self.resources = [
                    r for r in self.resources if self._name(r) in self.stuck
                ]
                return Completed(0)
            return Completed(1, "", "destroy failed")
        if verb == "stack" and argv[2] == "output":
            t = self.world.target
            body = {
                "bucketNames": [t.bucket_a, t.bucket_b, t.bucket_c],
                "s3Endpoints": {
                    t.bucket_a: t.endpoint,
                    t.bucket_b: t.endpoint,
                    t.bucket_c: t.endpoint,
                },
                "accessKeyIds": {"zz-probe-rw": RW_ID, "zz-probe-admin": AD_ID},
                "secretAccessKeys": {
                    "zz-probe-rw": RW_SECRET,
                    "zz-probe-admin": AD_SECRET,
                },
            }
            return Completed(0, json.dumps(body))
        if verb == "stack" and argv[2] == "export":
            if self.fail_export_after_destroy and self.destroys:
                return Completed(1, "", "export failed")
            stack = {
                "urn": urn("pulumi:pulumi:Stack", "branchleft-ovh-copy2-probe"),
                "type": "pulumi:pulumi:Stack",
            }
            provider = {
                "urn": urn("pulumi:providers:ovh", "default"),
                "type": "pulumi:providers:ovh",
            }
            return Completed(
                0,
                json.dumps(
                    {"deployment": {"resources": [stack, provider, *self.resources]}}
                ),
            )
        return Completed(2, "", f"unexpected {argv}")


class Harness(probe.Context):
    """A Context that records what it prints and writes to the job summary."""

    def __init__(
        self, tmp: Path, world: World, pulumi: FakePulumi, **extra: Any
    ) -> None:
        env = dict(RUNNER_ENV)
        env["RUNNER_TEMP"] = str(tmp)
        env.update(extra.pop("env", {}))
        self.printed: list[str] = []
        self.summaries: list[str] = []
        self.slept: list[float] = []
        self.world = world
        super().__init__(
            environ=env,
            workdir=tmp / "ovh-copy2-probe",
            project_dir=tmp / "project",
            run=pulumi,
            connect=extra.pop("connect", self._connect),
            sleep=self.slept.append,
            clock=lambda: NOW,
        )

    def _connect(self, endpoint: str, region: str, key: str, secret: str) -> Ops:
        return FakeOps(self.world, "rw" if key == RW_ID else "admin")

    def out(self, text: str) -> None:
        self.printed.append(text)

    def summary(self, text: str) -> None:
        self.summaries.append(text)

    def everything(self) -> str:
        return "\n".join(self.printed + self.summaries)


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.world = World(suffix=SUFFIX)
        self.pulumi = FakePulumi(self.world)
        self.ctx = Harness(self.tmp, self.world, self.pulumi)


class GateTests(Base):
    def gate(self, found: Mapping[str, Any] | Exception, **env: str) -> int:
        def fetch(url: str, token: str) -> Mapping[str, Any]:
            self.assertEqual(
                "https://api.github.com/repos/o/r/environments/ovh-copy2-probe", url
            )
            if isinstance(found, Exception):
                raise found
            return found

        self.ctx.environ = {
            "GITHUB_REPOSITORY": "o/r",
            "PROBE_ENVIRONMENT": "ovh-copy2-probe",
            "GH_TOKEN": "t",
            "GITHUB_REF": "refs/heads/main",
            **env,
        }
        self.ctx.fetch = fetch
        return probe.gate(self.ctx)

    GOOD: ClassVar[dict[str, Any]] = {
        "protection_rules": [{"type": "required_reviewers"}, {"type": "branch_policy"}],
        "deployment_branch_policy": {
            "custom_branch_policies": True,
            "protected_branches": False,
        },
    }

    def test_a_reviewer_rule_and_a_branch_policy_pass(self) -> None:
        self.assertEqual(0, self.gate(self.GOOD))

    def test_no_reviewer_rule_fails_closed(self) -> None:
        rules = {**self.GOOD, "protection_rules": [{"type": "branch_policy"}]}
        self.assertEqual(1, self.gate(rules))
        self.assertIn("no required-reviewer rule", self.ctx.everything())

    def test_no_branch_policy_fails_closed(self) -> None:
        self.assertEqual(1, self.gate({**self.GOOD, "deployment_branch_policy": None}))

    def test_an_unreadable_environment_fails_closed(self) -> None:
        self.assertEqual(1, self.gate(OSError("403")))

    def test_a_run_from_another_ref_fails_closed(self) -> None:
        self.assertEqual(1, self.gate(self.GOOD, GITHUB_REF="refs/heads/topic"))

    def test_a_missing_token_fails_closed(self) -> None:
        self.assertEqual(1, self.gate(self.GOOD, GH_TOKEN=""))

    def test_a_hostile_repository_name_is_refused_before_any_request(self) -> None:
        self.assertEqual(1, self.gate(self.GOOD, GITHUB_REPOSITORY="o/r/../../x"))


class UpTests(Base):
    def test_up_creates_the_stack_with_a_private_passphrase_and_the_run_suffix(
        self,
    ) -> None:
        self.assertEqual(0, probe.up(self.ctx))
        self.assertEqual(["stack init", "config", "up"], self.pulumi.subcommands())
        self.assertIn(
            ["config", "set", "branchleft-ovh-copy2:nameSuffix", SUFFIX],
            [c[1:5] for c in self.pulumi.calls if c[1] == "config"],
        )
        phrase = self.ctx.passphrase_file
        self.assertEqual(0o600, stat.S_IMODE(os.stat(phrase).st_mode))
        self.assertEqual(
            {"phase": "stack-ready", "suffix": SUFFIX},
            json.loads(self.ctx.run_file.read_text()),
        )

    def test_the_passphrase_is_masked_before_it_is_used_and_never_printed(self) -> None:
        probe.up(self.ctx)
        value = self.ctx.passphrase_file.read_text()
        self.assertEqual(f"::add-mask::{value}", self.ctx.printed[0])
        self.assertEqual(1, "\n".join(self.ctx.printed).count(value))

    def test_pulumi_gets_a_throwaway_file_backend_and_none_of_the_runner_tokens(
        self,
    ) -> None:
        probe.up(self.ctx)
        for env in self.pulumi.envs:
            self.assertEqual(
                f"file://{self.ctx.backend_dir}", env["PULUMI_BACKEND_URL"]
            )
            self.assertEqual(
                str(self.ctx.passphrase_file), env["PULUMI_CONFIG_PASSPHRASE_FILE"]
            )
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("NODE_AUTH_TOKEN", env)
            self.assertNotIn("PULUMI_CONFIG_PASSPHRASE", env)
            self.assertEqual("client-secret-value", env["OVH_CLIENT_SECRET"])
            self.assertTrue(env["PULUMI_BACKEND_URL"].startswith("file://"))

    def test_a_failed_up_is_red_and_leaves_the_marker_destroy_needs(self) -> None:
        self.pulumi.fail_up = True
        self.assertEqual(1, probe.up(self.ctx))
        self.assertEqual(
            "stack-ready", json.loads(self.ctx.run_file.read_text())["phase"]
        )

    def test_a_failed_stack_init_leaves_the_not_yet_created_marker(self) -> None:
        self.pulumi.fail_init = True
        self.assertEqual(1, probe.up(self.ctx))
        self.assertEqual("started", json.loads(self.ctx.run_file.read_text())["phase"])

    def test_a_malformed_run_id_creates_nothing(self) -> None:
        self.ctx.environ = {**self.ctx.environ, "GITHUB_RUN_ID": "1; rm -rf /"}
        self.assertEqual(1, probe.up(self.ctx))
        self.assertEqual([], self.pulumi.calls)
        self.assertFalse(self.ctx.run_file.exists())


class CheckTests(Base):
    def up(self) -> None:
        self.assertEqual(0, probe.up(self.ctx))
        self.ctx.printed.clear()

    def test_all_six_pass_and_the_credentials_are_masked_first(self) -> None:
        self.up()
        self.assertEqual(0, probe.check(self.ctx))
        masks = [line for line in self.ctx.printed if line.startswith("::add-mask::")]
        self.assertEqual(sorted(f"::add-mask::{s}" for s in SECRETS), sorted(masks))
        self.assertTrue(self.ctx.printed[0].startswith("::add-mask::"))
        self.assertEqual(6, self.ctx.summaries[0].count("**PASS**"))

    def test_no_credential_value_reaches_the_log_or_summary_except_as_a_mask_line(
        self,
    ) -> None:
        self.up()
        probe.check(self.ctx)
        text = "\n".join(
            line for line in self.ctx.printed if not line.startswith("::add-mask::")
        )
        text += "\n".join(self.ctx.summaries)
        for value in SECRETS:
            self.assertNotIn(value, text)

    def test_a_failing_check_makes_the_step_red_and_the_table_says_why(self) -> None:
        self.up()
        self.world.honour_lock = False
        self.assertEqual(1, probe.check(self.ctx))
        self.assertIn("| P3 |", self.ctx.summaries[0])
        self.assertIn("**FAIL**", self.ctx.summaries[0])

    def test_unreadable_stack_outputs_make_all_six_errors(self) -> None:
        self.up()
        original = self.pulumi.__call__
        self.pulumi.fail_up = False

        def broken(argv, **kw):  # type: ignore[no-untyped-def]
            if argv[1:3] == ["stack", "output"]:
                return Completed(1, "", "no outputs")
            return original(argv, **kw)

        self.ctx.run = broken
        self.assertEqual(1, probe.check(self.ctx))
        self.assertEqual(6, self.ctx.summaries[0].count("**ERROR**"))

    def test_a_credential_inside_an_exception_message_is_scrubbed_from_the_table(
        self,
    ) -> None:
        self.up()

        class Leaky:
            def list_versions(self, bucket: str):  # type: ignore[no-untyped-def]
                raise RuntimeError(f"signing failed for {RW_SECRET}")

            def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
                raise RuntimeError(f"unused {name}")

        self.ctx.connect = lambda e, r, key, s: (
            Leaky() if key == RW_ID else FakeOps(self.world, "admin")
        )  # type: ignore[assignment,return-value]
        probe.check(self.ctx)
        self.assertNotIn(RW_SECRET, self.ctx.summaries[0])
        self.assertIn("***", self.ctx.summaries[0])


class DestroyTests(Base):
    def up_and_check(self) -> None:
        probe.up(self.ctx)
        probe.check(self.ctx)
        self.ctx.printed.clear()
        self.ctx.summaries.clear()

    def test_nothing_started_means_nothing_to_destroy(self) -> None:
        self.assertEqual(0, probe.destroy(self.ctx))
        self.assertIn("Nothing was created", self.ctx.summaries[0])
        self.assertEqual([], self.pulumi.calls)

    def test_a_run_that_stopped_before_the_stack_existed_creates_nothing_to_destroy(
        self,
    ) -> None:
        self.pulumi.fail_init = True
        probe.up(self.ctx)
        self.pulumi.calls.clear()
        self.assertEqual(0, probe.destroy(self.ctx))
        self.assertEqual([], self.pulumi.calls)

    def test_destroy_removes_everything_and_says_so(self) -> None:
        self.up_and_check()
        self.assertEqual(0, probe.destroy(self.ctx))
        self.assertIn(
            "Everything was destroyed: 6 resource(s) removed, none remain.",
            self.ctx.summaries[0],
        )
        self.assertEqual(1, self.pulumi.destroys)

    def test_bucket_a_is_emptied_with_bypass_before_pulumi_destroys_it(self) -> None:
        self.up_and_check()
        # Something a failed check left behind: a locked version in bucket A.
        FakeOps(self.world, "rw").put_object(
            self.world.target.bucket_a, "left/over.txt", b"x"
        )
        self.assertEqual(1, len(self.world.stored[self.world.target.bucket_a]))
        order: list[str] = []
        original = self.pulumi.__call__

        def spy(argv, **kw):  # type: ignore[no-untyped-def]
            if argv[1] == "destroy":
                order.append(
                    f"destroy sees {len(self.world.stored[self.world.target.bucket_a])} versions"
                )
            return original(argv, **kw)

        self.ctx.run = spy
        self.assertEqual(0, probe.destroy(self.ctx))
        self.assertEqual(["destroy sees 0 versions"], order)
        self.assertIn(
            ("rw", "delete_version", self.world.target.bucket_a), self.world.log
        )

    def test_a_resource_that_will_not_go_is_a_red_run_that_names_it(self) -> None:
        self.up_and_check()
        self.pulumi.stuck = {self.world.target.bucket_a}
        self.assertEqual(1, probe.destroy(self.ctx))
        text = self.ctx.everything()
        self.assertIn("NOT EVERYTHING WAS DESTROYED: 1 resource(s) remain.", text)
        self.assertIn(self.world.target.bucket_a, text)
        self.assertIn(
            "::error::probe resources remain and must be deleted by hand", text
        )
        self.assertNotIn("Everything was destroyed", text)

    def test_destroy_is_retried_and_a_later_success_is_green(self) -> None:
        self.up_and_check()
        self.pulumi.destroy_succeeds_on = 2
        self.assertEqual(0, probe.destroy(self.ctx))
        self.assertEqual(2, self.pulumi.destroys)
        self.assertEqual([probe.DESTROY_PAUSE], self.ctx.slept)

    def test_destroy_that_never_succeeds_stops_after_three_attempts_and_is_red(
        self,
    ) -> None:
        self.up_and_check()
        self.pulumi.destroy_succeeds_on = None
        self.assertEqual(1, probe.destroy(self.ctx))
        self.assertEqual(probe.DESTROY_ATTEMPTS, self.pulumi.destroys)

    def test_a_state_that_cannot_be_read_afterwards_is_not_reported_as_empty(
        self,
    ) -> None:
        self.up_and_check()
        self.pulumi.fail_export_after_destroy = True
        self.assertEqual(1, probe.destroy(self.ctx))
        self.assertIn("state unreadable", self.ctx.everything())

    def test_a_failed_purge_does_not_stop_the_destroy_and_is_reported(self) -> None:
        self.up_and_check()

        def broken(*_args: str) -> Ops:
            raise ConnectionError("down")

        self.ctx.connect = broken
        self.assertEqual(0, probe.destroy(self.ctx))
        self.assertIn("bucket A was not emptied first", self.ctx.summaries[0])
        self.assertEqual(1, self.pulumi.destroys)

    def test_an_unreadable_run_state_is_red_not_green(self) -> None:
        self.up_and_check()
        self.ctx.run_file.write_text("{not json", encoding="utf-8")
        self.assertEqual(1, probe.destroy(self.ctx))

    def test_a_missing_passphrase_is_red_not_green(self) -> None:
        self.up_and_check()
        self.ctx.passphrase_file.unlink()
        self.assertEqual(1, probe.destroy(self.ctx))

    def test_pending_operations_count_as_leftovers(self) -> None:
        self.up_and_check()
        original = self.pulumi.__call__

        def with_pending(argv, **kw):  # type: ignore[no-untyped-def]
            done = original(argv, **kw)
            if argv[1:3] == ["stack", "export"] and self.pulumi.destroys:
                body = json.loads(done.stdout)
                body["deployment"]["pending_operations"] = [
                    {
                        "type": "creating",
                        "resource": {
                            "urn": urn("ovh:CloudStorageObjectBucket", "bucket-x"),
                            "type": "ovh:CloudStorageObjectBucket",
                        },
                    }
                ]
                return Completed(0, json.dumps(body))
            return done

        self.ctx.run = with_pending
        self.assertEqual(1, probe.destroy(self.ctx))
        self.assertIn("bucket-x", self.ctx.everything())


class MainTests(unittest.TestCase):
    def test_a_step_with_no_scratch_directory_stops(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(1, probe.main(["up"], {}))
        self.assertIn("::error::", printed.getvalue())


if __name__ == "__main__":
    unittest.main()
