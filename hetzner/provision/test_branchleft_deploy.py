#!/usr/bin/env python3
"""Unit tests for branchleft_deploy.

This script is the entire privilege of the CI deploy account, so its input
validation and its rollback path are security-relevant rather than
convenience behaviour, and both are covered here rather than left to a live
deploy to discover.
"""

import contextlib
import fcntl
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

import branchleft_deploy as bd


DIGEST = "a" * 64
VALID_IMAGE = f"ghcr.io/branchleft/example@sha256:{DIGEST}"


def exempt_example_image(case: unittest.TestCase) -> None:
    """Exempt VALID_IMAGE's name for the stacks the mechanics tests deploy to.

    Those tests are about the lock, the pin file, the rollback and the health
    signal, not about which image is allowed, so they borrow a reviewed
    exemption for the duration of one test. The real table is restored after.
    """
    patcher = mock.patch.dict(
        bd.UNATTESTED_STACK_IMAGES,
        {
            stack: frozenset({"ghcr.io/branchleft/example"})
            for stack in ("edge", "missing", "monitoring", "website")
        },
    )
    patcher.start()
    case.addCleanup(patcher.stop)


class FakeRun:
    """Stands in for subprocess.run, recording calls and returning a queue of
    canned responses.

    Each queued response is either a bare int (an exit code, empty stdout --
    what every call except the `docker ps` discriminator check needs), a
    `(code, stdout)` pair for the one call that reads its output rather than
    only its exit code, or a `(code, stdout, stderr)` triple for the verifier,
    whose refusal is named on stderr.

    Every call's keyword arguments are recorded in `kwargs`, so a test can pin
    the environment and stdin a subprocess was started with.
    """

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.kwargs = []

    def __call__(self, argv, check=False, capture_output=False, text=False, **kwargs):
        self.calls.append(list(argv))
        self.kwargs.append(kwargs)
        response = self.responses.pop(0) if self.responses else 0
        if not isinstance(response, tuple):
            response = (response, "")
        code, stdout = response[0], response[1]
        stderr = response[2] if len(response) > 2 else None
        return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr=stderr)


class StackNameTests(unittest.TestCase):
    def test_accepts_plain_names(self):
        for name in ("edge", "ghost-tenant-one", "mon1", "publicpress-website"):
            self.assertEqual(bd.validate_stack_name(name), name)

    def test_rejects_path_traversal(self):
        for name in ("../etc", "a/b", "./x"):
            with self.assertRaises(bd.DeployError):
                bd.validate_stack_name(name)

    def test_rejects_shell_and_systemd_metacharacters(self):
        for name in ("edge;reboot", "edge x", "edge@2", "edge$(id)", "Edge"):
            with self.assertRaises(bd.DeployError):
                bd.validate_stack_name(name)

    def test_rejects_a_trailing_newline(self):
        with self.assertRaises(bd.DeployError):
            bd.validate_stack_name("edge\n")

    def test_rejects_empty_and_overlong(self):
        with self.assertRaises(bd.DeployError):
            bd.validate_stack_name("")
        with self.assertRaises(bd.DeployError):
            bd.validate_stack_name("a" * 33)


class ImageRefTests(unittest.TestCase):
    def test_accepts_digest_pinned_reference(self):
        self.assertEqual(bd.validate_image_ref(VALID_IMAGE), VALID_IMAGE)

    def test_accepts_tag_alongside_digest(self):
        ref = f"ghcr.io/branchleft/example:v1.2.3@sha256:{DIGEST}"
        self.assertEqual(bd.validate_image_ref(ref), ref)

    def test_accepts_registry_port(self):
        ref = f"registry.example:5000/team/app@sha256:{DIGEST}"
        self.assertEqual(bd.validate_image_ref(ref), ref)

    def test_rejects_tag_only_reference(self):
        for ref in ("ghcr.io/branchleft/example:latest", "nginx"):
            with self.assertRaises(bd.DeployError):
                bd.validate_image_ref(ref)

    def test_rejects_an_uppercase_repository_path(self):
        for ref in (
            f"ghcr.io/branchLeft/example@sha256:{DIGEST}",
            f"GHCR.io/branchleft/example@sha256:{DIGEST}",
        ):
            with self.assertRaises(bd.DeployError):
                bd.validate_image_ref(ref)

    def test_rejects_short_or_non_hex_digest(self):
        for digest in ("a" * 63, "g" * 64, "A" * 64):
            with self.assertRaises(bd.DeployError):
                bd.validate_image_ref(f"ghcr.io/x/y@sha256:{digest}")

    def test_rejects_a_trailing_newline(self):
        with self.assertRaises(bd.DeployError):
            bd.validate_image_ref(VALID_IMAGE + "\n")

    def test_rejects_injected_argument(self):
        with self.assertRaises(bd.DeployError):
            bd.validate_image_ref(f"ghcr.io/x/y@sha256:{DIGEST} --privileged")


class WriteImageEnvTests(unittest.TestCase):
    def test_writes_single_key_with_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "edge.image.env")
            bd.write_image_env(path, VALID_IMAGE)
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), f"IMAGE={VALID_IMAGE}\n")
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)

    def test_replaces_rather_than_appends(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "edge.image.env")
            bd.write_image_env(path, VALID_IMAGE)
            other = f"ghcr.io/branchleft/example@sha256:{'b' * 64}"
            bd.write_image_env(path, other)
            self.assertEqual(bd.read_current_image(path), other)

    def test_leaves_no_temporary_files_behind(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "edge.image.env")
            bd.write_image_env(path, VALID_IMAGE)
            self.assertEqual(os.listdir(directory), ["edge.image.env"])


class ReadCurrentImageTests(unittest.TestCase):
    def test_missing_file_reads_as_none(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsNone(
                bd.read_current_image(os.path.join(directory, "absent.env"))
            )

    def test_an_empty_assignment_is_not_a_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "edge.image.env")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("IMAGE=\n")
            self.assertIsNone(bd.read_current_image(path))

    def test_ignores_unrelated_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "edge.image.env")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(f"OTHER=1\nIMAGE={VALID_IMAGE}\n")
            self.assertEqual(bd.read_current_image(path), VALID_IMAGE)


class PinnedImageIsUpTests(unittest.TestCase):
    """The discriminator that decides whether a restart failure implicates

    See test_branchleft_deploy.md, "PinnedImageIsUpTests".
    """

    def test_a_healthy_container_reads_as_up(self):
        run = FakeRun([(0, "Up 5 seconds (healthy)")])
        self.assertTrue(bd.pinned_image_is_up("edge", VALID_IMAGE, run=run))

    def test_a_container_with_no_healthcheck_reads_as_up(self):
        run = FakeRun([(0, "Up 12 seconds")])
        self.assertTrue(bd.pinned_image_is_up("edge", VALID_IMAGE, run=run))

    def test_an_unhealthy_container_reads_as_not_up(self):
        run = FakeRun([(0, "Up 5 seconds (unhealthy)")])
        self.assertFalse(bd.pinned_image_is_up("edge", VALID_IMAGE, run=run))

    def test_an_exited_container_reads_as_not_up(self):
        run = FakeRun([(0, "Exited (1) 3 seconds ago")])
        self.assertFalse(bd.pinned_image_is_up("edge", VALID_IMAGE, run=run))

    def test_a_restart_looping_container_reads_as_not_up(self):
        run = FakeRun([(0, "Restarting (1) 2 seconds ago")])
        self.assertFalse(bd.pinned_image_is_up("edge", VALID_IMAGE, run=run))

    def test_no_matching_container_reads_as_not_up(self):
        run = FakeRun([(0, "")])
        self.assertFalse(bd.pinned_image_is_up("edge", VALID_IMAGE, run=run))

    def test_a_failing_docker_ps_is_unknown_not_not_up(self):
        # `None`, distinct from `False`: an inconclusive check must not read
        # as evidence the image is at fault, or a caller could roll back on
        # a guess exactly when it has the least information to do so safely.
        run = FakeRun([(1, "")])
        self.assertIsNone(bd.pinned_image_is_up("edge", VALID_IMAGE, run=run))

    def test_one_bad_container_among_several_reads_as_not_up(self):
        run = FakeRun([(0, "Up 5 seconds (healthy)\nExited (1) 1 second ago")])
        self.assertFalse(bd.pinned_image_is_up("edge", VALID_IMAGE, run=run))

    def test_filters_by_project_label_and_the_exact_image_reference(self):
        run = FakeRun([(0, "Up 1 second")])
        bd.pinned_image_is_up("edge", VALID_IMAGE, run=run)
        self.assertEqual(
            run.calls,
            [
                [
                    "docker",
                    "ps",
                    "--all",
                    "--filter",
                    "label=com.docker.compose.project=edge",
                    "--filter",
                    f"ancestor={VALID_IMAGE}",
                    "--format",
                    "{{.Status}}",
                ]
            ],
        )


class DeployLockTests(unittest.TestCase):
    """The concurrency guard itself, exercised without a real second process.

    A second `flock` attempt against a *different* open file description on
    the same path genuinely contends, even from within a single test process
    -- the lock is attached to the open file description, not to the process
    or to the file's bytes, so opening the lock path a second time here and
    holding it is a faithful stand-in for a second `branchleft-deploy`
    invocation, with no subprocess needed.
    """

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def hold(self, stack):
        """Open and exclusively lock `stack`'s lock file, as a second holder would."""
        path = bd.deploy_lock_path(stack, self.directory.name)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def test_a_second_deploy_polls_then_fails_while_the_first_still_holds_it(self):
        holder_fd = self.hold("edge")
        self.addCleanup(os.close, holder_fd)

        clock = [0.0]
        sleeps = []

        def fake_now():
            return clock[0]

        def fake_sleep(interval):
            sleeps.append(interval)
            clock[0] += interval

        entered = False
        with self.assertRaises(bd.DeployError) as caught:
            with bd.stack_deploy_lock(
                "edge",
                self.directory.name,
                timeout=1.0,
                poll_interval=0.25,
                now=fake_now,
                sleep=fake_sleep,
            ):
                entered = True  # pragma: no cover -- must never run

        self.assertFalse(entered)
        message = str(caught.exception)
        self.assertIn("edge", message)
        self.assertIn("could not acquire", message)
        # Polled rather than failing on the very first attempt or blocking
        # forever: several bounded waits, not zero and not open-ended.
        self.assertGreaterEqual(len(sleeps), 3)
        self.assertAlmostEqual(sum(sleeps), 1.0, delta=0.25)

    def test_a_free_lock_is_acquired_on_the_first_attempt_with_no_wait(self):
        sleeps = []
        with bd.stack_deploy_lock(
            "edge", self.directory.name, sleep=lambda interval: sleeps.append(interval)
        ):
            pass
        self.assertEqual(sleeps, [])

    def test_the_lock_releases_the_instant_the_holder_process_exits(self):
        holder_fd = self.hold("edge")
        # Closing every fd on an open file description is exactly what
        # process exit does to a flock it holds -- clean exit, an uncaught
        # exception, or SIGKILL all close the process's file descriptors the
        # same way, and the kernel drops the lock the moment that happens.
        # Nothing here writes to or reads from the lock file's contents to
        # simulate that: the guarantee is that flock is not the file.
        os.close(holder_fd)

        sleeps = []
        with bd.stack_deploy_lock(
            "edge",
            self.directory.name,
            timeout=1.0,
            sleep=lambda interval: sleeps.append(interval),
        ):
            pass
        self.assertEqual(sleeps, [])

    def test_two_different_stacks_on_the_same_host_never_contend(self):
        holder_fd = self.hold("edge")
        self.addCleanup(os.close, holder_fd)

        sleeps = []
        # "monitoring" is a different lock file under the same config_dir --
        # scoped per stack, not per host, so holding edge's lock must not
        # block a deploy of an unrelated stack on the same box.
        with bd.stack_deploy_lock(
            "monitoring",
            self.directory.name,
            sleep=lambda interval: sleeps.append(interval),
        ):
            pass
        self.assertEqual(sleeps, [])


class DeployTests(unittest.TestCase):
    def setUp(self):
        exempt_example_image(self)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config_dir = os.path.join(self.directory.name, "etc")
        self.stack_dir = os.path.join(self.directory.name, "opt")
        os.makedirs(self.config_dir)
        os.makedirs(os.path.join(self.stack_dir, "edge"))
        with open(
            os.path.join(self.stack_dir, "edge", "compose.yml"), "w", encoding="utf-8"
        ) as handle:
            handle.write(
                "services:\n"
                "  app:\n"
                "    image: ${IMAGE}\n"
                "    healthcheck:\n"
                "      test: ['CMD', 'true']\n"
            )

    def deploy(self, image, run):
        bd.deploy(
            "edge",
            image,
            config_dir=self.config_dir,
            stack_dir=self.stack_dir,
            run=run,
        )

    def env_path(self):
        return bd.image_env_path("edge", self.config_dir)

    def test_successful_deploy_pins_and_restarts_once(self):
        run = FakeRun([0])
        self.deploy(VALID_IMAGE, run)
        self.assertEqual(run.calls, [["systemctl", "restart", "branchleft-compose@edge"]])
        self.assertEqual(bd.read_current_image(self.env_path()), VALID_IMAGE)

    def test_refuses_a_stack_with_no_compose_file(self):
        run = FakeRun([0])
        with self.assertRaises(bd.DeployError):
            bd.deploy(
                "missing",
                VALID_IMAGE,
                config_dir=self.config_dir,
                stack_dir=self.stack_dir,
                run=run,
            )
        self.assertEqual(run.calls, [])

    def test_refuses_a_compose_file_that_ignores_the_pin(self):
        with open(
            os.path.join(self.stack_dir, "edge", "compose.yml"), "w", encoding="utf-8"
        ) as handle:
            handle.write("services:\n  app:\n    image: ghcr.io/branchleft/x:latest\n")
        run = FakeRun([0])
        with self.assertRaises(bd.DeployError):
            self.deploy(VALID_IMAGE, run)
        self.assertFalse(os.path.exists(self.env_path()))
        self.assertEqual(run.calls, [])

    def test_failed_rollback_names_the_docker_ps_check_instead_of_asserting_an_outage(
        self,
    ):
        previous = f"ghcr.io/branchleft/example@sha256:{'c' * 64}"
        self.deploy(previous, FakeRun([0]))

        # [restart, discriminator docker ps, logger, rollback restart]. The
        # discriminator reports the pinned image itself down, so the
        # rollback proceeds -- and then that rollback restart also fails.
        run = FakeRun([1, (0, "Exited (1) 2 seconds ago"), 0, 1])
        with self.assertRaises(bd.DeployError) as caught:
            self.deploy(VALID_IMAGE, run)

        message = str(caught.exception)
        self.assertIn("also failed", message)
        # States the unit's state and the container state as separate facts
        # rather than asserting an outage.
        self.assertIn("branchleft-compose@edge", message)
        self.assertIn("`failed` on both pins", message)
        self.assertIn(
            "docker ps --filter label=com.docker.compose.project=edge", message
        )
        self.assertNotIn("the stack is down", message)
        self.assertNotIn("needs an operator", message)
        self.assertEqual(len(run.calls), 4)
        self.assertEqual(run.calls[3], ["systemctl", "restart", "branchleft-compose@edge"])

    def test_failed_restart_rolls_back_to_previous_image_when_the_pinned_image_is_down(
        self,
    ):
        previous = f"ghcr.io/branchleft/example@sha256:{'c' * 64}"
        self.deploy(previous, FakeRun([0]))

        run = FakeRun([1, (0, "Exited (1) 2 seconds ago"), 0, 0])
        with self.assertRaises(bd.DeployError):
            self.deploy(VALID_IMAGE, run)

        self.assertEqual(bd.read_current_image(self.env_path()), previous)
        self.assertEqual(len(run.calls), 4)
        # Recorded to the host's own journal, independent of whoever is
        # watching this process's stdout/stderr.
        logger_calls = [call for call in run.calls if call[:2] == ["logger", "-t"]]
        self.assertEqual(len(logger_calls), 1)
        self.assertIn("edge", logger_calls[0][3])
        self.assertIn(previous, logger_calls[0][3])

    def test_failed_restart_leaves_the_pin_in_place_when_the_pinned_image_is_up(self):
        previous = f"ghcr.io/branchleft/example@sha256:{'c' * 64}"
        self.deploy(previous, FakeRun([0]))

        # The stack-wide restart/wait failed, but a container running the
        # image this call just pinned is up and not unhealthy -- the classic
        # "MySQL came up fine, the exporter's healthcheck did not" case. The
        # image is not what failed, so nothing here may rewrite the pin.
        run = FakeRun([1, (0, "Up 5 seconds (healthy)")])
        with self.assertRaises(bd.DeployError) as caught:
            self.deploy(VALID_IMAGE, run)

        message = str(caught.exception)
        self.assertIn("left in place", message)
        self.assertIn(VALID_IMAGE, message)
        # No rollback: the pin this call wrote is still what is on disk, and
        # there is no third (rollback restart) or `logger` call.
        self.assertEqual(bd.read_current_image(self.env_path()), VALID_IMAGE)
        self.assertEqual(len(run.calls), 2)
        self.assertEqual(
            run.calls[1],
            [
                "docker",
                "ps",
                "--all",
                "--filter",
                "label=com.docker.compose.project=edge",
                "--filter",
                f"ancestor={VALID_IMAGE}",
                "--format",
                "{{.Status}}",
            ],
        )

    def test_failed_restart_leaves_the_pin_in_place_when_the_discriminator_is_inconclusive(
        self,
    ):
        previous = f"ghcr.io/branchleft/example@sha256:{'c' * 64}"
        self.deploy(previous, FakeRun([0]))

        # `docker ps` itself errors (docker missing, daemon unreachable). No
        # positive evidence the image is fine, but also none that it is at
        # fault -- the safe default is to leave the pin and fail loud, not
        # to guess by rolling back anyway.
        run = FakeRun([1, 2])
        with self.assertRaises(bd.DeployError) as caught:
            self.deploy(VALID_IMAGE, run)

        self.assertIn("could not be", str(caught.exception))
        self.assertEqual(bd.read_current_image(self.env_path()), VALID_IMAGE)
        self.assertEqual(len(run.calls), 2)

    def test_failed_first_ever_deploy_removes_the_file_and_does_not_restart_again(self):
        run = FakeRun([1, 0])
        with self.assertRaises(bd.DeployError) as caught:
            self.deploy(VALID_IMAGE, run)
        self.assertFalse(os.path.exists(self.env_path()))
        # A second restart would fail by construction with no pin file, so
        # the failure must be reported rather than dressed up as a rollback.
        # The discriminator check does not run here either: there is no
        # previous pin for it to protect.
        self.assertEqual(len(run.calls), 1)
        message = str(caught.exception)
        self.assertIn("does not mean the stack has never run", message)
        self.assertIn(
            "docker ps --filter label=com.docker.compose.project=edge", message
        )

    def test_a_comment_mentioning_the_variable_does_not_satisfy_the_check(self):
        with open(
            os.path.join(self.stack_dir, "edge", "compose.yml"), "w", encoding="utf-8"
        ) as handle:
            handle.write(
                "# the image comes from ${IMAGE}\n"
                "services:\n  app:\n    image: ghcr.io/branchleft/x:latest\n"
            )
        run = FakeRun([0])
        with self.assertRaises(bd.DeployError):
            self.deploy(VALID_IMAGE, run)
        self.assertEqual(run.calls, [])

    def test_validation_runs_before_any_filesystem_change(self):
        run = FakeRun([0])
        with self.assertRaises(bd.DeployError):
            self.deploy("ghcr.io/branchleft/example:latest", run)
        self.assertFalse(os.path.exists(self.env_path()))
        self.assertEqual(run.calls, [])

    def test_refuses_to_proceed_while_another_deploy_holds_this_stacks_lock(self):
        # A real second holder, exclusively locking the exact path deploy()
        # itself will try to lock -- not a mock of the locking call, so this
        # proves the wiring into deploy(), not just the context manager in
        # isolation (DeployLockTests covers that half).
        lock_path = bd.deploy_lock_path("edge", self.config_dir)
        holder_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        self.addCleanup(os.close, holder_fd)

        run = FakeRun([0])
        with self.assertRaises(bd.DeployError) as caught:
            bd.deploy(
                "edge",
                VALID_IMAGE,
                config_dir=self.config_dir,
                stack_dir=self.stack_dir,
                run=run,
                lock_timeout=0.2,
                lock_poll_interval=0.05,
            )
        self.assertIn("could not acquire", str(caught.exception))
        # Neither half of the guarded sequence ran: the pin is untouched and
        # systemctl was never invoked -- a second deploy that cannot get the
        # lock must not have interleaved any part of it.
        self.assertFalse(os.path.exists(self.env_path()))
        self.assertEqual(run.calls, [])

    def test_a_deploy_to_a_different_stack_is_unaffected_by_this_stacks_lock(self):
        os.makedirs(os.path.join(self.stack_dir, "monitoring"))
        with open(
            os.path.join(self.stack_dir, "monitoring", "compose.yml"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                "services:\n"
                "  app:\n"
                "    image: ${IMAGE}\n"
                "    healthcheck:\n"
                "      test: ['CMD', 'true']\n"
            )
        lock_path = bd.deploy_lock_path("edge", self.config_dir)
        holder_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        self.addCleanup(os.close, holder_fd)

        run = FakeRun([0])
        bd.deploy(
            "monitoring",
            VALID_IMAGE,
            config_dir=self.config_dir,
            stack_dir=self.stack_dir,
            run=run,
        )
        self.assertEqual(
            bd.read_current_image(bd.image_env_path("monitoring", self.config_dir)),
            VALID_IMAGE,
        )


TENANT_DIGEST = "b" * 64
TENANT = f"ghcr.io/branchleft/ghost-tenant@sha256:{TENANT_DIGEST}"
TENANT_SIGNER = "branchLeft/ghost-platform/.github/workflows/registry-push.yml"
PERCONA_SIGNER = "branchLeft/ghost-platform/.github/workflows/percona-image.yml"
# The digest the Percona image workflow pushed, scanned (blocking=0) and attested on
# ghost-platform main, run 43331723453 at commit 1289eb507b95. The db_t1 role pins the same one.
PERCONA_DIGEST = "20e400e5558480067f8d72610b27064efa97d260d51f9e86af60afb69fd93696"
PERCONA = f"ghcr.io/branchleft/percona-server@sha256:{PERCONA_DIGEST}"

# sha256 of the program the deploy_verifier role installs, the Python port of
# ghost-platform's scripts/verify-image-attestation.sh. Change the program and this
# constant in the same change, and carry the change to ghost-platform's script.
VERIFIER_SHA256 = "e4ea42757d48571146645a42523bad2eef4d502dd7c802920a758ba771d8b59a"

# The verifier's whole environment, exactly. Nothing is inherited from the host.
# No GitHub API credential is in it; the one credential path is DOCKER_CONFIG,
# the registry read key's directory. A change to any value here is a change to
# what gh is allowed to read, and is reviewed as one.
EXPECTED_VERIFIER_ENV = {
    "PATH": "/usr/local/libexec/branchleft-verifier:/usr/bin:/bin",
    "HOME": "/var/lib/branchleft/verifier-home",
    "GH_CONFIG_DIR": "/var/lib/branchleft/verifier-home",
    "XDG_CONFIG_HOME": "/var/lib/branchleft/verifier-home",
    "DOCKER_CONFIG": "/etc/branchleft/registry/docker",
    "GH_PROMPT_DISABLED": "1",
    "GH_NO_UPDATE_NOTIFIER": "1",
    "LC_ALL": "C",
    "VERIFY_PLAIN_ERRORS": "1",
}

# What a registry says to a client it will not serve, as gh prints it. The
# wording is the registry's, so each spelling a registry uses is listed.
REGISTRY_REFUSALS = [
    "Error: failed to fetch OCI image descriptor: GET https://ghcr.io/v2/x: UNAUTHORIZED: authentication required",
    "GET https://ghcr.io/v2/x: DENIED: requested access to the resource is denied",
    "unexpected status code 401 Unauthorized",
    "request unauthorised",
]


class AttestationTests(unittest.TestCase):
    """The host verifies a registered image's attestation before it deploys it.

    deploy() calls verify_attestation() before the lock, the pin write and any
    restart. Every refusal here must leave the pin file absent and run no
    restart, which is what "fails before up" means on this host.
    """

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config_dir = os.path.join(self.directory.name, "etc")
        self.stack_dir = os.path.join(self.directory.name, "opt")
        os.makedirs(self.config_dir)
        os.makedirs(os.path.join(self.stack_dir, "edge"))
        with open(
            os.path.join(self.stack_dir, "edge", "compose.yml"), "w", encoding="utf-8"
        ) as handle:
            handle.write(
                "services:\n"
                "  app:\n"
                "    image: ${IMAGE}\n"
                "    healthcheck:\n"
                "      test: ['CMD', 'true']\n"
            )

    def deploy(self, image, run):
        bd.deploy(
            "edge",
            image,
            config_dir=self.config_dir,
            stack_dir=self.stack_dir,
            run=run,
        )

    def env_path(self):
        return bd.image_env_path("edge", self.config_dir)

    def assert_refused_before_any_host_change(self, run):
        self.assertFalse(os.path.exists(self.env_path()))
        self.assertEqual([call[0] for call in run.calls], [bd.VERIFIER])

    def test_the_register_names_exactly_the_attested_images_and_their_workflows(self):
        self.assertEqual(
            bd.ATTESTED_IMAGES,
            {
                "ghcr.io/branchleft/ghost-tenant": TENANT_SIGNER,
                "ghcr.io/branchleft/portal-apps": (
                    "branchLeft/ghost-platform/.github/workflows/portal-apps-image.yml"
                ),
                "ghcr.io/branchleft/percona-server": PERCONA_SIGNER,
            },
        )

    def test_the_scanned_percona_digest_is_verified_against_its_own_workflow_and_pinned(self):
        run = FakeRun([0, 0])
        self.deploy(PERCONA, run)
        self.assertEqual(
            run.calls[0],
            [bd.VERIFIER, PERCONA, bd.ATTESTED_REPO, PERCONA_SIGNER, "--bundle-from-oci"],
        )
        self.assertEqual(bd.read_current_image(self.env_path()), PERCONA)

    def test_a_percona_digest_that_is_not_the_attested_one_is_refused_before_any_host_change(self):
        other = f"ghcr.io/branchleft/percona-server@sha256:{'e' * 64}"
        run = FakeRun([1])
        with self.assertRaises(bd.DeployError):
            self.deploy(other, run)
        self.assertEqual(
            run.calls[0],
            [bd.VERIFIER, other, bd.ATTESTED_REPO, PERCONA_SIGNER, "--bundle-from-oci"],
        )
        self.assert_refused_before_any_host_change(run)

    def test_an_unsigned_or_wrong_signer_image_is_refused_before_any_host_change(self):
        run = FakeRun([1])
        with self.assertRaises(bd.DeployError):
            self.deploy(TENANT, run)
        self.assertEqual(
            run.calls[0],
            [bd.VERIFIER, TENANT, bd.ATTESTED_REPO, TENANT_SIGNER, "--bundle-from-oci"],
        )
        self.assert_refused_before_any_host_change(run)

    def test_an_unknown_digest_is_refused_the_same_way(self):
        unknown = f"ghcr.io/branchleft/ghost-tenant@sha256:{'c' * 64}"
        run = FakeRun([1])
        with self.assertRaises(bd.DeployError):
            self.deploy(unknown, run)
        self.assertEqual(run.calls[0][1], unknown)
        self.assert_refused_before_any_host_change(run)

    def test_a_missing_verifier_is_refused_before_any_host_change(self):
        def missing(argv, **kwargs):
            raise FileNotFoundError(argv[0])

        with self.assertRaises(bd.DeployError):
            self.deploy(TENANT, missing)
        self.assertFalse(os.path.exists(self.env_path()))

    def test_the_real_signer_and_a_registered_name_are_accepted_and_pinned(self):
        run = FakeRun([0, 0])
        self.deploy(TENANT, run)
        self.assertEqual(
            run.calls[0],
            [bd.VERIFIER, TENANT, bd.ATTESTED_REPO, TENANT_SIGNER, "--bundle-from-oci"],
        )
        self.assertEqual(
            run.calls[1], ["systemctl", "restart", "branchleft-compose@edge"]
        )
        self.assertEqual(bd.read_current_image(self.env_path()), TENANT)

    def test_a_tag_or_port_spelling_of_a_registered_image_is_still_verified(self):
        spellings = [
            f"ghcr.io/branchleft/ghost-tenant:v1@sha256:{TENANT_DIGEST}",
            f"ghcr.io/branchleft/ghost-tenant:latest@sha256:{TENANT_DIGEST}",
            f"ghcr.io:443/branchleft/ghost-tenant@sha256:{TENANT_DIGEST}",
            f"ghcr.io:443/branchleft/ghost-tenant:v1@sha256:{TENANT_DIGEST}",
        ]
        for image in spellings:
            with self.subTest(image=image):
                run = FakeRun([1])
                with self.assertRaises(bd.DeployError):
                    self.deploy(image, run)
                self.assert_refused_before_any_host_change(run)

    def test_a_tag_or_port_spelling_is_verified_by_its_register_name_and_digest(self):
        image = f"ghcr.io:443/branchleft/ghost-tenant:v1@sha256:{TENANT_DIGEST}"
        run = FakeRun([0, 0])
        self.deploy(image, run)
        self.assertEqual(
            run.calls[0],
            [bd.VERIFIER, TENANT, bd.ATTESTED_REPO, TENANT_SIGNER, "--bundle-from-oci"],
        )
        self.assertEqual(bd.read_current_image(self.env_path()), image)

    def deploy_to(self, stack, image, run):
        directory = os.path.join(self.stack_dir, stack)
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "compose.yml"), "w", encoding="utf-8") as handle:
            handle.write(
                "services:\n"
                "  app:\n"
                "    image: ${IMAGE}\n"
                "    healthcheck:\n"
                "      test: ['CMD', 'true']\n"
            )
        bd.deploy(
            stack, image, config_dir=self.config_dir, stack_dir=self.stack_dir, run=run
        )

    def assert_refused_with_nothing_run(self, stack, image):
        run = FakeRun([0, 0])
        with self.assertRaises(bd.DeployError) as caught:
            self.deploy_to(stack, image, run)
        self.assertIn("no reviewed exemption", str(caught.exception))
        self.assertEqual(run.calls, [])
        self.assertFalse(os.path.exists(bd.image_env_path(stack, self.config_dir)))

    def test_an_image_from_any_other_registry_is_refused_before_any_host_change(self):
        attacker = f"attacker.example/evil@sha256:{'d' * 64}"
        self.assert_refused_with_nothing_run("edge", attacker)

    def test_an_unregistered_image_with_a_tag_or_port_is_refused_too(self):
        for image in (
            f"registry.example:5000/library/mysql:8@sha256:{'d' * 64}",
            f"docker.io/library/mysql@sha256:{'d' * 64}",
            f"ghcr.io:443/attacker/evil:v1@sha256:{'d' * 64}",
        ):
            with self.subTest(image=image):
                self.assert_refused_with_nothing_run("edge", image)

    def test_an_unregistered_image_is_refused_on_a_tenant_slot_stack(self):
        self.assert_refused_with_nothing_run(
            "blog", f"attacker.example/evil@sha256:{'d' * 64}"
        )

    def test_a_branchleft_image_is_not_exempt_just_for_its_registry(self):
        self.assert_refused_with_nothing_run(
            "blog", f"ghcr.io/branchleft/anything-else@sha256:{'d' * 64}"
        )

    def test_an_exemption_is_for_its_own_stack_only(self):
        # edge-caddy is exempt for the edge stack; a slot key for another stack
        # cannot pin it there, and edge cannot pin another stack's image.
        edge_caddy = f"ghcr.io/branchleft/edge-caddy@sha256:{'d' * 64}"
        self.assert_refused_with_nothing_run("blog", edge_caddy)
        self.assert_refused_with_nothing_run(
            "edge", f"ghcr.io/branchleft/website@sha256:{'d' * 64}"
        )

    def test_every_stack_pinned_through_the_wrapper_today_still_deploys_its_image(self):
        today = {
            "website": "ghcr.io/branchleft/website",
            "publicpress-website": "ghcr.io/branchleft/publicpress-website",
            "edge": "ghcr.io/branchleft/edge-caddy",
            "db": "mysql:8.4",
            "mail-spool": "ghcr.io/branchleft/mailgun-shim",
        }
        for stack, name in today.items():
            image = f"{name}@sha256:{'d' * 64}"
            with self.subTest(stack=stack):
                run = FakeRun([0])
                self.deploy_to(stack, image, run)
                # An exempt image is not sent to the verifier.
                self.assertEqual(
                    run.calls, [["systemctl", "restart", f"branchleft-compose@{stack}"]]
                )
                self.assertEqual(
                    bd.read_current_image(bd.image_env_path(stack, self.config_dir)), image
                )

    def test_the_spool_stack_may_bump_the_mailgun_shim_without_the_verifier(self):
        image = f"ghcr.io/branchleft/mailgun-shim@sha256:{'d' * 64}"
        run = FakeRun([0])
        self.deploy_to("mail-spool", image, run)
        self.assertEqual(run.calls, [["systemctl", "restart", "branchleft-compose@mail-spool"]])
        self.assertEqual(
            bd.read_current_image(bd.image_env_path("mail-spool", self.config_dir)), image
        )

    def test_an_unknown_image_on_the_spool_stack_is_still_refused(self):
        self.assert_refused_with_nothing_run(
            "mail-spool", f"attacker.example/evil@sha256:{'d' * 64}"
        )
        self.assert_refused_with_nothing_run(
            "mail-spool", f"ghcr.io/branchleft/anything-else@sha256:{'d' * 64}"
        )

    def test_the_mailgun_shim_exemption_is_for_the_spool_stack_only(self):
        self.assert_refused_with_nothing_run(
            "edge", f"ghcr.io/branchleft/mailgun-shim@sha256:{'d' * 64}"
        )

    def test_the_registered_images_still_deploy_on_any_stack_through_the_verifier(self):
        # control-plane pins portal-apps; tenant slots pin ghost-tenant.
        for stack, name in (
            ("blog", "ghcr.io/branchleft/ghost-tenant"),
            ("control-plane", "ghcr.io/branchleft/portal-apps"),
            ("dbt1", "ghcr.io/branchleft/percona-server"),
        ):
            image = f"{name}@sha256:{'e' * 64}"
            with self.subTest(stack=stack):
                run = FakeRun([0, 0])
                self.deploy_to(stack, image, run)
                self.assertEqual(run.calls[0][0], bd.VERIFIER)
                self.assertEqual(bd.read_current_image(bd.image_env_path(stack, self.config_dir)), image)

    def test_the_exemption_list_is_reviewed_and_disjoint_from_the_register(self):
        self.assertEqual(
            bd.UNATTESTED_STACK_IMAGES,
            {
                "website": frozenset({"ghcr.io/branchleft/website"}),
                "publicpress-website": frozenset({"ghcr.io/branchleft/publicpress-website"}),
                "edge": frozenset(
                    {"ghcr.io/branchleft/edge-caddy", "docker.io/crowdsecurity/crowdsec"}
                ),
                "db": frozenset({"mysql", "prom/mysqld-exporter"}),
                "control-plane": frozenset(
                    {"docker.io/library/postgres", "ghcr.io/zitadel/zitadel"}
                ),
                "mail-spool": frozenset({"ghcr.io/branchleft/mailgun-shim"}),
            },
        )
        for names in bd.UNATTESTED_STACK_IMAGES.values():
            self.assertFalse(names & set(bd.ATTESTED_IMAGES))

    def test_no_environment_variable_switches_verification_off(self):
        run = FakeRun([1])
        switches = {
            "BRANCHLEFT_SKIP_VERIFY": "1",
            "BRANCHLEFT_VERIFY": "0",
            "BRANCHLEFT_DEPLOY_VERIFY": "off",
        }
        with mock.patch.dict(os.environ, switches):
            with self.assertRaises(bd.DeployError):
                self.deploy(TENANT, run)
        self.assert_refused_before_any_host_change(run)

    def test_the_verifier_runs_with_exactly_the_fixed_environment_and_no_stdin(self):
        run = FakeRun([0, 0])
        self.deploy(TENANT, run)
        self.assertEqual(run.kwargs[0]["env"], EXPECTED_VERIFIER_ENV)
        self.assertEqual(run.kwargs[0]["stdin"], subprocess.DEVNULL)

    def test_no_github_credential_reaches_the_verifier_even_when_the_host_holds_one(self):
        run = FakeRun([0, 0])
        held = {"GH_TOKEN": "ghs_" + "x" * 36, "GITHUB_TOKEN": "ghs_" + "y" * 36}
        with mock.patch.dict(os.environ, held):
            self.deploy(TENANT, run)
        env = run.kwargs[0]["env"]
        self.assertNotIn("GH_TOKEN", env)
        self.assertNotIn("GITHUB_TOKEN", env)
        for value in held.values():
            self.assertNotIn(value, env.values())

    def test_the_verifier_path_is_fixed_and_not_inherited_from_the_host(self):
        run = FakeRun([0, 0])
        with mock.patch.dict(os.environ, {"PATH": "/home/attacker/bin:/usr/bin"}):
            self.deploy(TENANT, run)
        self.assertEqual(run.kwargs[0]["env"]["PATH"], EXPECTED_VERIFIER_ENV["PATH"])
        self.assertEqual(
            EXPECTED_VERIFIER_ENV["PATH"],
            "/usr/local/libexec/branchleft-verifier:/usr/bin:/bin",
        )

    def test_a_missing_credential_is_named_as_its_own_refusal(self):
        run = FakeRun([(1, "", "To get started with GitHub CLI, please run:  gh auth login")])
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(TENANT, run)
        self.assertIn("the host verifier needs GitHub credentials this host does not hold", str(raised.exception))
        self.assertIn("the deploy is refused", str(raised.exception))
        self.assertNotIn("is not attested by", str(raised.exception))
        self.assertFalse(os.path.exists(self.env_path()))

    def test_any_other_verifier_failure_keeps_the_not_attested_message(self):
        run = FakeRun([(1, "", "::error::no valid attestation for " + TENANT)])
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(TENANT, run)
        self.assertIn("is not attested by", str(raised.exception))
        self.assertNotIn("needs GitHub credentials", str(raised.exception))

    def test_the_verifier_is_pointed_at_the_registry_read_key_directory(self):
        self.assertEqual(bd.REGISTRY_DOCKER_CONFIG, "/etc/branchleft/registry/docker")
        self.assertEqual(bd.verifier_env()["DOCKER_CONFIG"], bd.REGISTRY_DOCKER_CONFIG)

    def test_the_registry_key_directory_is_one_path_in_wrapper_unit_and_role(self):
        provision = os.path.dirname(os.path.abspath(__file__))
        with open(
            os.path.join(provision, "branchleft-compose@.service"), encoding="utf-8"
        ) as handle:
            unit = handle.read()
        self.assertIn(f"\nEnvironment=DOCKER_CONFIG={bd.REGISTRY_DOCKER_CONFIG}\n", unit)
        role_vars = os.path.join(
            provision, "..", "..", "ansible", "roles", "deploy_verifier", "vars", "main.yml"
        )
        with open(role_vars, encoding="utf-8") as handle:
            self.assertIn(f"deploy_verifier_registry_docker_dir: {bd.REGISTRY_DOCKER_CONFIG}\n", handle.read())

    def test_an_unauthorised_registry_names_the_read_key_and_pins_nothing(self):
        for stderr in REGISTRY_REFUSALS:
            with self.subTest(stderr=stderr):
                run = FakeRun([(1, "", stderr)])
                with self.assertRaises(bd.DeployError) as raised:
                    self.deploy(TENANT, run)
                message = str(raised.exception)
                self.assertIn("registry read key", message)
                self.assertIn(bd.REGISTRY_DOCKER_CONFIG, message)
                self.assertNotIn("is not attested by", message)
                self.assert_refused_before_any_host_change(run)

    def test_a_private_image_is_refused_without_the_key_and_verifies_with_it(self):
        class Registry:
            """A registry that serves the attestation only to a client holding the key."""

            def __init__(self, key_placed):
                self.key_placed = key_placed
                self.calls = []

            def __call__(self, argv, check=False, capture_output=False, text=False, **kwargs):
                self.calls.append(list(argv))
                if argv[0] != bd.VERIFIER:
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
                reads_key = kwargs["env"].get("DOCKER_CONFIG") == bd.REGISTRY_DOCKER_CONFIG
                if self.key_placed and reads_key:
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
                stderr = "GET https://ghcr.io/v2/x: UNAUTHORIZED: authentication required"
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr=stderr)

        without_key = Registry(key_placed=False)
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(TENANT, without_key)
        self.assertIn("registry read key", str(raised.exception))
        self.assertFalse(os.path.exists(self.env_path()))

        with_key = Registry(key_placed=True)
        self.deploy(TENANT, with_key)
        self.assertEqual(bd.read_current_image(self.env_path()), TENANT)

    def test_no_key_on_the_host_leaves_an_image_that_needs_none_deploying(self):
        # The verifier is handed the key directory whether or not the host has
        # one; an absent directory is anonymous access, which a public image's
        # attestation accepts. Nothing in the wrapper checks for the directory.
        run = FakeRun([0, 0])
        self.deploy(TENANT, run)
        self.assertEqual(run.kwargs[0]["env"]["DOCKER_CONFIG"], bd.REGISTRY_DOCKER_CONFIG)
        self.assertEqual(bd.read_current_image(self.env_path()), TENANT)

    def test_the_login_refusal_still_wins_over_the_registry_refusal(self):
        run = FakeRun([(1, "", "gh auth login ... UNAUTHORIZED")])
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(TENANT, run)
        self.assertIn("needs GitHub credentials", str(raised.exception))

    def test_the_registry_refusal_is_not_matched_inside_a_digest(self):
        run = FakeRun([(1, "", "::error::no valid attestation for " + TENANT + " 401 403")])
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(TENANT, run)
        self.assertIn("is not attested by", str(raised.exception))
        self.assertNotIn("registry read key", str(raised.exception))

    def test_the_vendored_verifier_is_pinned_to_its_digest(self):
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            os.pardir,
            os.pardir,
            "ansible",
            "roles",
            "deploy_verifier",
            "files",
            "branchleft-verify-image.py",
        )
        with open(path, "rb") as handle:
            self.assertEqual(hashlib.sha256(handle.read()).hexdigest(), VERIFIER_SHA256)


class SlotStdinTests(unittest.TestCase):
    """The only value a slot key supplies.

    In slot mode the stack name comes from the forced command in
    authorized_keys, which only root writes, so everything a tenant controls
    arrives through this one function.
    """

    def test_accepts_one_digest_pinned_reference(self):
        self.assertEqual(bd.read_slot_image(io.StringIO(f"{VALID_IMAGE}\n")), VALID_IMAGE)

    def test_accepts_a_reference_with_no_trailing_newline(self):
        self.assertEqual(bd.read_slot_image(io.StringIO(VALID_IMAGE)), VALID_IMAGE)

    def test_rejects_empty_input(self):
        for text in ("", "\n"):
            with self.assertRaises(bd.DeployError):
                bd.read_slot_image(io.StringIO(text))

    def test_rejects_a_second_line(self):
        # The shape an attacker reaches for first: a second reference, or a
        # second stack name, smuggled behind a newline.
        for text in (
            f"{VALID_IMAGE}\nother-tenant\n",
            f"{VALID_IMAGE}\n{VALID_IMAGE}\n",
            f"{VALID_IMAGE}\n\n",
        ):
            with self.assertRaises(bd.DeployError):
                bd.read_slot_image(io.StringIO(text))

    def test_rejects_a_line_break_python_splits_on_but_a_newline_scan_would_not(self):
        for separator in ("\x0b", "\x0c", "\x1c", " "):
            with self.assertRaises(bd.DeployError):
                bd.read_slot_image(io.StringIO(f"{VALID_IMAGE}{separator}other-tenant"))

    def test_rejects_a_tag_only_reference(self):
        with self.assertRaises(bd.DeployError):
            bd.read_slot_image(io.StringIO("ghcr.io/branchleft/example:latest\n"))

    def test_rejects_a_reference_with_an_appended_argument(self):
        with self.assertRaises(bd.DeployError):
            bd.read_slot_image(io.StringIO(f"{VALID_IMAGE} other-tenant\n"))

    def test_rejects_input_beyond_the_read_limit(self):
        with self.assertRaises(bd.DeployError):
            bd.read_slot_image(io.StringIO("x" * (bd.SLOT_STDIN_LIMIT + 1)))


class MainTests(unittest.TestCase):
    def test_wrong_argument_count_is_a_usage_error(self):
        self.assertEqual(bd.main(["branchleft-deploy"]), 2)
        self.assertEqual(bd.main(["branchleft-deploy", "edge"]), 2)
        self.assertEqual(
            bd.main(["branchleft-deploy", "edge", VALID_IMAGE, "extra"]), 2
        )

    def test_invalid_input_exits_one_without_touching_the_host(self):
        self.assertEqual(
            bd.main(["branchleft-deploy", "../edge", VALID_IMAGE], log=lambda *args: None), 1
        )

    def test_slot_mode_deploys_the_slots_stack_with_the_image_from_stdin(self):
        # The binding itself, asserted positively. Every other slot test here
        # asserts a refusal, and a refusal is also what broken wiring produces
        # -- so without this one, deleting slot mode outright leaves the suite
        # green.
        calls = []
        code = bd.main(
            ["branchleft-deploy", "--slot", "blog"],
            stdin=io.StringIO(f"{VALID_IMAGE}\n"),
            deploy=lambda stack, image: calls.append((stack, image)),
        )
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("blog", VALID_IMAGE)])

    def test_positional_mode_deploys_the_named_stack_with_the_argument_image(self):
        calls = []
        code = bd.main(
            ["branchleft-deploy", "edge", VALID_IMAGE],
            deploy=lambda stack, image: calls.append((stack, image)),
        )
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("edge", VALID_IMAGE)])

    def test_a_slot_key_cannot_reach_another_stack_through_stdin(self):
        # The whole point of the slot: whatever arrives on stdin, the stack
        # deployed is the one the forced command named.
        calls = []
        bd.main(
            ["branchleft-deploy", "--slot", "blog"],
            stdin=io.StringIO(f"{VALID_IMAGE}\n"),
            deploy=lambda stack, image: calls.append((stack, image)),
        )
        self.assertEqual([stack for stack, _ in calls], ["blog"])

    def test_slot_mode_takes_no_second_positional_argument(self):
        # `--slot blog other-tenant` is the direct attempt to name a stack the
        # key was not issued for. There is no argument position for it.
        self.assertEqual(
            bd.main(["branchleft-deploy", "--slot", "blog", "other-tenant"]), 2
        )

    def test_slot_mode_refuses_a_hostile_stack_name_without_reading_stdin(self):
        # The name reaches this only from a root-written forced command, so a
        # bad one is a corrupted host rather than a caller's argument -- and
        # blocking on a read it will never use is the wrong way to say so.
        stdin = io.StringIO(f"{VALID_IMAGE}\n")
        self.assertEqual(
            bd.main(["branchleft-deploy", "--slot", "../edge"], stdin=stdin, log=lambda *args: None),
            1,
        )
        self.assertEqual(stdin.tell(), 0)

    def test_slot_mode_rejects_an_image_that_names_another_stack(self):
        self.assertEqual(
            bd.main(
                ["branchleft-deploy", "--slot", "blog"],
                stdin=io.StringIO(f"other-tenant {VALID_IMAGE}\n"),
                log=lambda *args: None,
            ),
            1,
        )

    def test_positional_mode_ignores_stdin_entirely(self):
        stdin = io.StringIO("ghcr.io/branchleft/hostile@sha256:" + "b" * 64 + "\n")
        # No compose file exists for this stack, so the failure is the expected
        # one; what matters is that stdin was never consulted to produce it.
        self.assertEqual(
            bd.main(
                ["branchleft-deploy", "no-such-stack", VALID_IMAGE],
                stdin=stdin,
                log=lambda *args: None,
            ),
            1,
        )
        self.assertEqual(stdin.tell(), 0)

    def _with_lock_timeout_env(self, value, argv, **kwargs):
        old = os.environ.get(bd.LOCK_TIMEOUT_ENV_VAR)
        os.environ[bd.LOCK_TIMEOUT_ENV_VAR] = value
        try:
            return bd.main(argv, **kwargs)
        finally:
            if old is None:
                del os.environ[bd.LOCK_TIMEOUT_ENV_VAR]
            else:
                os.environ[bd.LOCK_TIMEOUT_ENV_VAR] = old

    def test_lock_timeout_env_var_reaches_deploy_as_a_keyword(self):
        # Not argv -- a new flag would widen the exact-length shape the
        # sudoers grant depends on (see the constant's own comment). An
        # operator invoking this binary directly can still reach the knob.
        received = {}
        code = self._with_lock_timeout_env(
            "5",
            ["branchleft-deploy", "edge", VALID_IMAGE],
            deploy=lambda stack, image, **kw: received.update(kw),
        )
        self.assertEqual(code, 0)
        self.assertEqual(received, {"lock_timeout": 5.0})

    def test_an_invalid_lock_timeout_env_var_is_reported_and_ignored(self):
        calls = []
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = self._with_lock_timeout_env(
                "not-a-number",
                ["branchleft-deploy", "edge", VALID_IMAGE],
                deploy=lambda stack, image, **kw: calls.append(kw),
            )
        self.assertEqual(code, 0)
        # Falls back to the default rather than crashing or silently using a
        # nonsense value -- the deploy proceeds with no override at all.
        self.assertEqual(calls, [{}])
        self.assertIn(bd.LOCK_TIMEOUT_ENV_VAR, stderr.getvalue())
        self.assertIn("not-a-number", stderr.getvalue())


class JournalLineTests(unittest.TestCase):
    """A refused deploy leaves one line in the host journal, whoever hid the caller's stderr."""

    def _refuse(self):
        def refusing(stack_name, image, **kwargs):
            raise bd.DeployError(f"{image} is not attested by the signing workflow")

        return refusing

    def test_a_refusal_writes_one_journal_line_naming_the_stack_and_the_reason(self):
        calls = []

        def recorded(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0)

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = bd.main(
                ["branchleft-deploy", "tenant-x", VALID_IMAGE],
                deploy=self._refuse(),
                log=lambda stack, error: bd.log_refusal(stack, error, run=recorded),
            )
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:3], ["logger", "-t", bd.JOURNAL_TAG])
        self.assertIn("tenant-x", calls[0][3])
        self.assertIn("refused", calls[0][3])
        self.assertIn("is not attested by", calls[0][3])
        self.assertIn("is not attested by", stderr.getvalue())

    def test_a_deploy_that_succeeds_writes_no_journal_line(self):
        logged = []
        code = bd.main(
            ["branchleft-deploy", "tenant-x", VALID_IMAGE],
            deploy=lambda stack, image, **kwargs: None,
            log=lambda *args: logged.append(args),
        )
        self.assertEqual(code, 0)
        self.assertEqual(logged, [])

    def test_a_usage_error_writes_no_journal_line(self):
        logged = []
        self.assertEqual(bd.main(["branchleft-deploy"], log=lambda *args: logged.append(args)), 2)
        self.assertEqual(logged, [])

    def test_a_host_with_no_logger_still_refuses_the_same_way(self):
        def missing(command, **kwargs):
            raise FileNotFoundError(command[0])

        with contextlib.redirect_stderr(io.StringIO()):
            code = bd.main(
                ["branchleft-deploy", "tenant-x", VALID_IMAGE],
                deploy=self._refuse(),
                log=lambda stack, error: bd.log_refusal(stack, error, run=missing),
            )
        self.assertEqual(code, 1)


class ResolvesImageFromEnvTests(unittest.TestCase):
    """The predicate is the sole arbiter of whether a stack's pin is enforced.

    It decides two things at once: whether `deploy` will write a pin at all, and
    whether `test_compose_unit_contract` demands the drop-in reset that drops the
    pin. A misclassification therefore does not merely mis-report -- it either
    exempts a stack from the guard or instructs its author to disable the pin.
    Its input classes are covered directly rather than through `deploy()`.
    """

    def test_a_live_bare_reference_resolves(self):
        self.assertTrue(bd.resolves_image_from_env("services:\n  a:\n    image: ${IMAGE}\n"))

    def test_a_fail_closed_default_resolves(self):
        """`${IMAGE:?msg}` aborts by name on an empty pin, so it is a real pin."""
        self.assertTrue(
            bd.resolves_image_from_env(
                "services:\n  a:\n    image: ${IMAGE:?set by branchleft-deploy}\n"
            )
        )

    def test_a_whole_line_comment_does_not_resolve(self):
        self.assertFalse(
            bd.resolves_image_from_env("services:\n  a:\n    # image: ${IMAGE}\n")
        )

    def test_a_trailing_comment_does_not_resolve(self):
        """The line runs a hardcoded digest; the reference is commentary."""
        self.assertFalse(
            bd.resolves_image_from_env(
                "services:\n  a:\n    image: prom/prometheus@sha256:aa  # was ${IMAGE}\n"
            )
        )

    def test_a_fail_open_default_does_not_resolve(self):
        """`${IMAGE:-x}` silently becomes `x` the moment the pin is empty."""
        self.assertFalse(
            bd.resolves_image_from_env(
                "services:\n  a:\n    image: ${IMAGE:-ghcr.io/x/y:latest}\n"
            )
        )

    def test_an_unbraced_reference_does_not_resolve(self):
        self.assertFalse(bd.resolves_image_from_env("services:\n  a:\n    image: $IMAGE\n"))

    def test_a_longer_variable_name_is_not_mistaken_for_the_pin(self):
        self.assertFalse(
            bd.resolves_image_from_env("services:\n  a:\n    image: ${IMAGE_TAG}\n")
        )

    def test_a_hash_in_a_digest_is_not_treated_as_a_comment(self):
        """`sha256:` digests carry no `#`, but the cut must be whitespace-anchored
        so an inline `#` cannot truncate a live reference that follows it."""
        self.assertTrue(
            bd.resolves_image_from_env("services:\n  a:\n    image: ${IMAGE}#notacomment\n")
        )


class FailOpenImageReferenceTests(unittest.TestCase):
    def test_the_fail_open_forms_are_named(self):
        for compose in (
            "    image: ${IMAGE:-ghcr.io/x/y:latest}\n",
            "    image: ${IMAGE:+override}\n",
            "    image: $IMAGE\n",
        ):
            with self.subTest(compose=compose):
                self.assertTrue(bd.has_fail_open_image_reference(compose))

    def test_the_fail_closed_forms_are_not(self):
        for compose in ("    image: ${IMAGE}\n", "    image: ${IMAGE:?set it}\n"):
            with self.subTest(compose=compose):
                self.assertFalse(bd.has_fail_open_image_reference(compose))

    def test_commentary_is_not_named(self):
        self.assertFalse(bd.has_fail_open_image_reference("    # image: ${IMAGE:-x}\n"))

    def test_deploy_names_the_fail_open_form_specifically(self):
        exempt_example_image(self)
        with tempfile.TemporaryDirectory() as stack_dir:
            os.makedirs(os.path.join(stack_dir, "edge"))
            with open(os.path.join(stack_dir, "edge", "compose.yml"), "w", encoding="utf-8") as f:
                f.write("services:\n  a:\n    image: ${IMAGE:-ghcr.io/x/y:latest}\n")
            with tempfile.TemporaryDirectory() as config_dir:
                with self.assertRaises(bd.DeployError) as raised:
                    bd.deploy(
                        "edge",
                        VALID_IMAGE,
                        config_dir=config_dir,
                        stack_dir=stack_dir,
                        run=FakeRun([0]),
                    )
                self.assertIn("survives an empty pin", str(raised.exception))
                self.assertEqual(os.listdir(config_dir), [])


class HealthSignalGapsTests(unittest.TestCase):
    """`deploy()`'s judgement call: refuse a gap nobody has reviewed, warn on
    one that has (`KNOWN_UNHEALTHCHECKED_SERVICES`), and leave an
    image-provided probe alone."""

    def test_a_fully_probed_stack_has_no_gaps(self):
        text = (
            "services:\n"
            "  app:\n"
            "    image: ${IMAGE}\n"
            "    healthcheck:\n"
            "      test: ['CMD', 'true']\n"
        )
        self.assertEqual(bd.health_signal_gaps("edge", text), ([], []))

    def test_an_unreviewed_absent_healthcheck_is_refused(self):
        text = "services:\n  app:\n    image: ${IMAGE}\n"
        self.assertEqual(bd.health_signal_gaps("edge", text), (["app (absent)"], []))

    def test_a_disabled_healthcheck_is_refused_the_same_as_absent(self):
        text = (
            "services:\n"
            "  app:\n"
            "    image: ${IMAGE}\n"
            "    healthcheck:\n"
            "      disable: true\n"
        )
        self.assertEqual(bd.health_signal_gaps("edge", text), (["app (disabled)"], []))

    def test_a_reviewed_gap_warns_rather_than_refuses(self):
        text = "services:\n  website-metrics:\n    image: ${IMAGE}\n"
        self.assertEqual(
            bd.health_signal_gaps("website", text), ([], ["website-metrics (absent)"])
        )

    def test_the_db_exporter_is_no_longer_a_reviewed_gap(self):
        """The exporter declares its own healthcheck now, so it is no longer reviewed."""
        text = "services:\n  mysqld-exporter:\n    image: ${IMAGE}\n"
        self.assertEqual(
            bd.health_signal_gaps("db", text), (["mysqld-exporter (absent)"], [])
        )

    def test_the_reviewed_gap_list_is_exactly_this_and_growing_it_means_editing_here(self):
        # A deliberate edit here is the point: a new exemption must change this test in the same diff.
        self.assertEqual(
            bd.KNOWN_UNHEALTHCHECKED_SERVICES, frozenset({("website", "website-metrics")})
        )

    def test_an_image_provided_healthcheck_is_neither_refused_nor_warned(self):
        text = "services:\n  cadvisor:\n    image: ${IMAGE}\n"
        self.assertEqual(bd.health_signal_gaps("monitoring", text), ([], []))

    def test_the_exemption_is_a_stack_service_pair_not_a_bare_service_name(self):
        """`website-metrics` is only reviewed for the `website` stack -- the
        same service name under a different stack is an unreviewed gap."""
        text = "services:\n  website-metrics:\n    image: ${IMAGE}\n"
        self.assertEqual(
            bd.health_signal_gaps("blog", text), (["website-metrics (absent)"], [])
        )

    def test_one_unprobed_service_among_several_probed_ones_is_still_caught(self):
        text = (
            "services:\n"
            "  probed:\n"
            f"    image: {VALID_IMAGE}\n"
            "    healthcheck:\n"
            "      test: ['CMD', 'true']\n"
            "  bare:\n"
            "    image: b\n"
        )
        self.assertEqual(bd.health_signal_gaps("edge", text), (["bare (absent)"], []))

    def test_a_shape_the_parser_cannot_read_raises_rather_than_reporting_no_gaps(self):
        """An anchored service header is invalid input to `healthcheck_states`,
        not a stack with a clean bill of health -- `deploy()` is the layer that
        decides what an unreadable file means for the check as a whole."""
        text = "services:\n  app: &app\n    image: ${IMAGE}\n"
        with self.assertRaises(bd.ComposeParseError):
            bd.health_signal_gaps("edge", text)


class DeployHealthSignalTests(unittest.TestCase):
    """The behaviour `deploy()` wraps `health_signal_gaps` in: refuse before
    any filesystem or systemd change, warn to stderr and proceed for a
    reviewed gap, and never crash on a file the parser cannot read."""

    def setUp(self):
        exempt_example_image(self)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config_dir = os.path.join(self.directory.name, "etc")
        self.stack_dir = os.path.join(self.directory.name, "opt")
        os.makedirs(self.config_dir)

    def write_compose(self, stack, text):
        directory = os.path.join(self.stack_dir, stack)
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "compose.yml"), "w", encoding="utf-8") as handle:
            handle.write(text)

    def deploy(self, stack, run):
        bd.deploy(
            stack, VALID_IMAGE, config_dir=self.config_dir, stack_dir=self.stack_dir, run=run
        )

    def test_refuses_an_unreviewed_gap_before_writing_the_pin_or_restarting(self):
        self.write_compose("edge", "services:\n  app:\n    image: ${IMAGE}\n")
        run = FakeRun([0])
        with self.assertRaises(bd.DeployError) as caught:
            self.deploy("edge", run)
        self.assertIn("app (absent)", str(caught.exception))
        self.assertFalse(os.path.exists(bd.image_env_path("edge", self.config_dir)))
        self.assertEqual(run.calls, [])

    def test_refuses_when_only_one_of_several_services_lacks_a_probe(self):
        self.write_compose(
            "edge",
            "services:\n"
            "  probed:\n"
            f"    image: {VALID_IMAGE}\n"
            "    healthcheck:\n"
            "      test: ['CMD', 'true']\n"
            "  bare:\n"
            "    image: ${IMAGE}\n",
        )
        run = FakeRun([0])
        with self.assertRaises(bd.DeployError) as caught:
            self.deploy("edge", run)
        self.assertIn("bare (absent)", str(caught.exception))
        self.assertNotIn("probed", str(caught.exception))
        self.assertEqual(run.calls, [])

    def test_a_reviewed_gap_warns_and_still_deploys(self):
        self.write_compose("website", "services:\n  website-metrics:\n    image: ${IMAGE}\n")
        run = FakeRun([0])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.deploy("website", run)
        self.assertEqual(len(run.calls), 1)
        self.assertEqual(
            bd.read_current_image(bd.image_env_path("website", self.config_dir)), VALID_IMAGE
        )
        message = stderr.getvalue()
        self.assertIn("website-metrics", message)
        self.assertIn("KNOWN_UNHEALTHCHECKED_SERVICES", message)

    def test_an_image_provided_healthcheck_deploys_with_no_warning_at_all(self):
        self.write_compose("monitoring", "services:\n  cadvisor:\n    image: ${IMAGE}\n")
        run = FakeRun([0])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.deploy("monitoring", run)
        self.assertEqual(len(run.calls), 1)
        self.assertEqual(stderr.getvalue(), "")

    def test_a_stack_with_every_service_probed_deploys_with_no_warning_at_all(self):
        self.write_compose(
            "edge",
            "services:\n"
            "  app:\n"
            "    image: ${IMAGE}\n"
            "    healthcheck:\n"
            "      test: ['CMD', 'true']\n",
        )
        run = FakeRun([0])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.deploy("edge", run)
        self.assertEqual(len(run.calls), 1)
        self.assertEqual(stderr.getvalue(), "")

    def test_a_shape_the_parser_cannot_read_warns_and_still_deploys(self):
        """A parser limitation is not a property of the stack: refusing a
        deploy over a shape this regex-based reader cannot classify would be
        an outage the Compose file itself never had."""
        self.write_compose("edge", "services:\n  app: &app\n    image: ${IMAGE}\n")
        run = FakeRun([0])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.deploy("edge", run)
        self.assertEqual(len(run.calls), 1)
        self.assertIn("could not determine", stderr.getvalue())

    def test_an_absent_compose_file_is_still_the_pre_existing_refusal(self):
        """No health-signal check should ever run against a file that is not
        there -- the existing `no compose file` refusal must still be first."""
        run = FakeRun([0])
        with self.assertRaises(bd.DeployError) as caught:
            self.deploy("missing", run)
        self.assertIn("no compose file", str(caught.exception))
        self.assertEqual(run.calls, [])


# The real renderer, taken before setUpModule replaces it for the deploy() tests.
REAL_RENDER = bd.render_compose

EDGE_PIN = f"ghcr.io/branchleft/edge-caddy@sha256:{DIGEST}"
PORTAL = f"ghcr.io/branchleft/portal-apps@sha256:{'e' * 64}"
PORTAL_SIGNER = "branchLeft/ghost-platform/.github/workflows/portal-apps-image.yml"
STRAY = f"ghcr.io/branchleft/stray@sha256:{'d' * 64}"
EVIL = f"evil.example/x@sha256:{'f' * 64}"
EXPORTER = f"prom/mysqld-exporter:v0.20.0@sha256:{'c' * 64}"
CROWDSEC = f"docker.io/crowdsecurity/crowdsec:v1.7.8@sha256:{'c' * 64}"
PROBE = "    healthcheck:\n      test: ['CMD', 'true']\n"
OVERRIDE = "compose.override.yml"

# The third-party sidecars the committed stacks run beside their pin, by stack. Each is named
# for its stack in UNATTESTED_STACK_IMAGES: none has a signing workflow that registers it. The
# db exporter's entry is temporary, until the exporter image is signed and registered.
SIDECARS = {
    "db": frozenset({"prom/mysqld-exporter"}),
    "edge": frozenset({"docker.io/crowdsecurity/crowdsec"}),
    "control-plane": frozenset({"docker.io/library/postgres", "ghcr.io/zitadel/zitadel"}),
}


def service_block(name, image, extra=""):
    return f"  {name}:\n    image: {image}\n{extra}{PROBE}"


def compose_of(*blocks):
    return "services:\n" + service_block("app", "${IMAGE}") + "".join(blocks)


def yaml_render(directory):
    """A stand-in for Compose's render, used by every deploy() test in this module.

    PyYAML reads compose.yml and merges compose.override.yml service by service,
    resolving anchors and merge keys as Compose does. It does not resolve
    `include`, which is why the hostile shapes are also run through the real
    `docker compose` in RealComposeTests, where it is available.
    """

    def load(name):
        path = os.path.join(directory, name)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    model = load("compose.yml") or {}
    override = load(OVERRIDE)
    if override:
        services = model.setdefault("services", {})
        for name, service in (override.get("services") or {}).items():
            merged = dict(services.get(name) or {})
            merged.update(service or {})
            services[name] = merged
        for key, value in override.items():
            if key != "services":
                model[key] = value
    return model


def setUpModule():
    """No deploy() test in this module starts `docker`: the renderer is the
    PyYAML stand-in unless a test passes another."""
    patcher = mock.patch.object(bd, "render_compose", yaml_render)
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)


def model_of(*services):
    """A rendered model: the pin service plus `(name, image, extra)` services."""
    built = {"app": {"image": "${IMAGE}"}}
    for name, image, extra in services:
        built[name] = {"image": image, **extra}
    return {"services": built}


class SidecarVerificationTests(unittest.TestCase):
    """deploy() holds every image the stack's Compose model names to the same
    rule as the pin, not only the one passed on the command line.

    The attestation step is real here (never patched). Each refusal must leave
    the pin file absent and run no restart.
    """

    STACK = "edge"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config_dir = os.path.join(self.directory.name, "etc")
        self.stack_dir = os.path.join(self.directory.name, "opt")
        os.makedirs(self.config_dir)
        os.makedirs(os.path.join(self.stack_dir, self.STACK))

    def write(self, text, name="compose.yml", stack=None):
        directory = os.path.join(self.stack_dir, stack or self.STACK)
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
            handle.write(text)

    def deploy(self, image, run, render=None, stack=None):
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr):
                bd.deploy(
                    stack or self.STACK,
                    image,
                    config_dir=self.config_dir,
                    stack_dir=self.stack_dir,
                    run=run,
                    render=render,
                )
        finally:
            self.log = stderr.getvalue()

    def env_path(self, stack=None):
        return bd.image_env_path(stack or self.STACK, self.config_dir)

    def assert_refused(self, text, run=None, image=EDGE_PIN, override=None):
        """Refused with no restart and no pin; returns the message."""
        self.write(text)
        override_path = os.path.join(self.stack_dir, self.STACK, OVERRIDE)
        if os.path.exists(override_path):
            os.unlink(override_path)
        if override is not None:
            self.write(override, OVERRIDE)
        run = run or FakeRun([0])
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(image, run)
        self.assertFalse(os.path.exists(self.env_path()))
        self.assertNotIn(["systemctl", "restart", f"branchleft-compose@{self.STACK}"], run.calls)
        return str(raised.exception)

    def test_a_sidecar_on_neither_list_is_refused_before_any_host_change(self):
        run = FakeRun([0])
        message = self.assert_refused(compose_of(service_block("side", STRAY)), run)
        self.assertEqual(run.calls, [])
        self.assertIn("service 'side'", message)
        self.assertIn("ghcr.io/branchleft/stray", message)
        self.assertIn("no reviewed exemption", message)

    def test_each_committed_sidecar_is_named_for_its_own_stack_only(self):
        for stack, names in SIDECARS.items():
            for name in names:
                with self.subTest(stack=stack, name=name):
                    self.assertIn(name, bd.UNATTESTED_STACK_IMAGES[stack])
                    for other, listed in bd.UNATTESTED_STACK_IMAGES.items():
                        if other != stack:
                            self.assertNotIn(name, listed)

    def test_a_sidecar_the_stack_exempts_deploys_and_the_log_says_so(self):
        run = FakeRun([0])
        self.write(compose_of(service_block("side", CROWDSEC)))
        self.deploy(EDGE_PIN, run)
        self.assertEqual(run.calls, [["systemctl", "restart", "branchleft-compose@edge"]])
        self.assertEqual(bd.read_current_image(self.env_path()), EDGE_PIN)
        self.assertIn(
            "service 'side' runs docker.io/crowdsecurity/crowdsec, which is unattested by exemption",
            self.log,
        )

    def test_one_stacks_exemption_does_not_open_another_stack(self):
        website_pin = f"ghcr.io/branchleft/website@sha256:{DIGEST}"
        self.write(compose_of(service_block("side", CROWDSEC)), stack="website")
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(website_pin, FakeRun([0]), stack="website")
        self.assertFalse(os.path.exists(self.env_path("website")))
        self.assertIn("service 'side'", str(raised.exception))
        self.assertIn("stack 'website' has no reviewed exemption", str(raised.exception))

    def test_a_registered_sidecar_goes_through_the_verifier(self):
        run = FakeRun([0, 0, 0])
        self.write(compose_of(service_block("side", PORTAL)))
        self.deploy(TENANT, run)
        self.assertEqual(
            run.calls,
            [
                [bd.VERIFIER, TENANT, bd.ATTESTED_REPO, TENANT_SIGNER, "--bundle-from-oci"],
                [bd.VERIFIER, PORTAL, bd.ATTESTED_REPO, PORTAL_SIGNER, "--bundle-from-oci"],
                ["systemctl", "restart", "branchleft-compose@edge"],
            ],
        )
        self.assertEqual(run.kwargs[1]["env"], EXPECTED_VERIFIER_ENV)
        self.assertIn(f"verified {PORTAL} attested by {PORTAL_SIGNER}", self.log)

    def test_a_registered_sidecar_the_verifier_refuses_stops_the_deploy(self):
        run = FakeRun([0, 1])
        message = self.assert_refused(
            compose_of(service_block("side", PORTAL)), run, image=TENANT
        )
        self.assertEqual([call[0] for call in run.calls], [bd.VERIFIER, bd.VERIFIER])
        self.assertIn("is not attested by", message)
        self.assertIn("service 'side'", message)

    def test_a_missing_verifier_for_a_sidecar_stops_the_deploy(self):
        calls = []

        def verifier_gone_after_the_pin(argv, **kwargs):
            calls.append(argv)
            if len(calls) == 2:
                raise FileNotFoundError(argv[0])
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        self.write(compose_of(service_block("side", PORTAL)))
        with self.assertRaises(bd.DeployError):
            self.deploy(TENANT, verifier_gone_after_the_pin)
        self.assertFalse(os.path.exists(self.env_path()))
        self.assertEqual(len(calls), 2)

    def test_a_sidecar_without_a_digest_is_refused(self):
        for reference in (
            "docker.io/library/postgres:17-alpine",
            "prom/mysqld-exporter",
            f"'prom/mysqld-exporter:v1@sha256:{'c' * 63}'",
        ):
            with self.subTest(reference=reference):
                run = FakeRun([0])
                message = self.assert_refused(compose_of(service_block("side", reference)), run)
                self.assertEqual(run.calls, [])
                self.assertIn("digest-pinned", message)
                self.assertIn("'side'", message)

    def test_an_interpolated_sidecar_is_refused_not_resolved(self):
        for reference in (
            "${SIDECAR_IMAGE}",
            "${SIDECAR_IMAGE:?set it in /etc/branchleft/edge.env}",
            "${IMAGE:-prom/mysqld-exporter}",
            "${IMAGE}-extra",
            "prom/mysqld-exporter@sha256:${DIGEST}",
        ):
            with self.subTest(reference=reference):
                message = self.assert_refused(compose_of(service_block("side", reference)))
                self.assertIn("interpolated", message)

    def test_a_digest_shape_error_is_found_before_any_verifier_runs(self):
        run = FakeRun([0, 0])
        self.assert_refused(
            compose_of(service_block("good", PORTAL), service_block("bad", "redis")),
            run,
            image=TENANT,
        )
        self.assertEqual([call[0] for call in run.calls], [bd.VERIFIER])

    def test_a_sidecar_named_twice_is_verified_once(self):
        run = FakeRun([0, 0, 0, 0])
        self.write(compose_of(service_block("one", PORTAL), service_block("two", PORTAL)))
        self.deploy(TENANT, run)
        self.assertEqual([call[0] for call in run.calls], [bd.VERIFIER, bd.VERIFIER, "systemctl"])

    def test_a_sidecar_in_the_override_file_is_held_to_the_same_rule(self):
        message = self.assert_refused(
            compose_of(), override="services:\n" + service_block("extra", STRAY)
        )
        self.assertIn("ghcr.io/branchleft/stray", message)

    def test_a_service_with_no_image_is_refused(self):
        message = self.assert_refused(compose_of("  bare:\n" + PROBE))
        self.assertIn("names no `image:`", message)

    def test_a_stack_whose_services_never_take_the_pin_is_refused(self):
        text = "services:\n" + service_block("side", CROWDSEC, "    environment:\n      A: ${IMAGE}\n")
        message = self.assert_refused(text)
        self.assertIn("takes its image from the pin", message)

    def test_the_pin_in_either_spelling_or_quoted_is_the_pin(self):
        for reference in ("${IMAGE}", "${IMAGE:?pin the image}", "'${IMAGE}'", '"${IMAGE}"'):
            with self.subTest(reference=reference):
                run = FakeRun([0])
                self.write(compose_of(service_block("second", reference)))
                self.deploy(EDGE_PIN, run)
                self.assertEqual(run.calls, [["systemctl", "restart", "branchleft-compose@edge"]])
                os.unlink(self.env_path())

    def test_a_same_path_on_another_registry_is_another_image(self):
        self.assert_refused(
            compose_of(service_block("side", f"evil.example/crowdsecurity/crowdsec@sha256:{'d' * 64}"))
        )

    def test_an_image_mount_is_refused(self):
        extra = "    volumes:\n      - type: image\n        source: " + EVIL + "\n        target: /x\n"
        run = FakeRun([0])
        message = self.assert_refused(compose_of(service_block("side", PORTAL, extra)), run, image=TENANT)
        self.assertIn("mounts an image", message)

    def test_the_ordinary_mount_types_are_not_refused(self):
        extra = (
            "    volumes:\n      - type: bind\n        source: /a\n        target: /b\n"
            "      - {type: volume, source: v, target: /c}\n"
        )
        self.write(compose_of(service_block("side", CROWDSEC, extra)))
        self.deploy(EDGE_PIN, FakeRun([0]))
        self.assertEqual(bd.read_current_image(self.env_path()), EDGE_PIN)

    def test_a_render_that_fails_refuses_the_deploy_before_any_host_change(self):
        def broken(directory):
            raise bd.DeployError("`docker compose config` failed in somewhere (exit 1)")

        run = FakeRun([0])
        self.write(compose_of())
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(EDGE_PIN, run, render=broken)
        self.assertIn("docker compose config", str(raised.exception))
        self.assertFalse(os.path.exists(self.env_path()))
        self.assertEqual(run.calls, [])

    def test_the_render_is_asked_for_the_stack_directory(self):
        seen = []

        def record(directory):
            seen.append(directory)
            return model_of()

        self.write(compose_of())
        self.deploy(EDGE_PIN, FakeRun([0]), render=record)
        self.assertEqual(seen, [os.path.join(self.stack_dir, "edge")])

    def test_a_port_on_a_dockerhub_namespace_is_another_registry(self):
        other = f"prom:5000/mysqld-exporter:v0.20.0@sha256:{'c' * 64}"
        self.assert_refused(compose_of(service_block("side", other)))

    def test_a_port_is_a_spelling_only_on_a_registry_host(self):
        for image, name in {
            f"ghcr.io:443/branchleft/ghost-tenant:v1@sha256:{DIGEST}": "ghcr.io/branchleft/ghost-tenant",
            f"localhost:5000/x/y@sha256:{DIGEST}": "localhost/x/y",
            f"prom:5000/mysqld-exporter@sha256:{DIGEST}": "prom:5000/mysqld-exporter",
            f"prom/mysqld-exporter:v1@sha256:{DIGEST}": "prom/mysqld-exporter",
            f"mysql:8.0.43@sha256:{DIGEST}": "mysql",
        }.items():
            with self.subTest(image=image):
                self.assertEqual(bd.attested_name(image), name)


class ModelImagesTests(unittest.TestCase):
    """The walker over a rendered Compose model, with models written out whole."""

    def refused(self, model, fragment):
        with self.assertRaises(bd.DeployError) as raised:
            bd.model_images(model, EDGE_PIN)
        self.assertIn(fragment, str(raised.exception))

    def test_it_reports_the_pin_and_each_literal_reference(self):
        pin_seen, literals = bd.model_images(
            model_of(("side", EXPORTER, {}), ("two", STRAY, {})), EDGE_PIN
        )
        self.assertTrue(pin_seen)
        self.assertEqual(literals, [("side", EXPORTER), ("two", STRAY)])

    def test_a_service_naming_the_pin_literally_is_the_pin(self):
        pin_seen, literals = bd.model_images({"services": {"app": {"image": EDGE_PIN}}}, EDGE_PIN)
        self.assertTrue(pin_seen)
        self.assertEqual(literals, [])

    def test_a_model_with_no_pin_service_reports_it_unseen(self):
        pin_seen, _ = bd.model_images({"services": {"s": {"image": EXPORTER}}}, EDGE_PIN)
        self.assertFalse(pin_seen)

    def test_the_top_level_keys_compose_documents_are_accepted(self):
        model = model_of()
        model.update({"name": "x", "networks": {}, "volumes": {}, "secrets": {}, "configs": {}})
        model["x-anything"] = {"type": "image"}
        bd.model_images(model, EDGE_PIN)

    def test_an_unknown_top_level_key_is_refused(self):
        for key in ("include", "models", "version", "extra"):
            with self.subTest(key):
                self.refused({**model_of(), key: {}}, "top-level")

    def test_a_model_without_services_is_refused(self):
        for model in ({}, {"services": None}, {"services": []}, {"services": "x"}):
            with self.subTest(model=model):
                self.refused(model, "no services")

    def test_a_service_that_is_not_a_mapping_is_refused(self):
        for service in (None, "x", [], 3):
            with self.subTest(service=service):
                self.refused({"services": {"app": service}}, "not a mapping")

    def test_a_service_key_that_runs_something_no_image_names_is_refused(self):
        for key in ("build", "extends", "provider", "models"):
            with self.subTest(key):
                self.refused(model_of(("s", EXPORTER, {key: {}})), f"`{key}`")

    def test_an_image_mount_is_refused_wherever_it_sits_in_a_service(self):
        for extra in (
            {"volumes": [{"type": "image", "source": EVIL, "target": "/x"}]},
            {"volumes": [{"type": " Image ", "source": EVIL}]},
            {"deploy": {"x": [[{"type": "image"}]]}},
        ):
            with self.subTest(extra=extra):
                self.refused(model_of(("s", EXPORTER, extra)), "mounts an image")

    def test_the_other_mount_types_are_not_image_mounts(self):
        extra = {
            "volumes": [
                {"type": "bind", "source": "/a", "target": "/b"},
                {"type": "volume", "source": "v", "target": "/c"},
                {"type": "tmpfs", "target": "/d"},
            ],
            "environment": {"type": "image-ish", "n": 3},
        }
        bd.model_images(model_of(("s", EXPORTER, extra)), EDGE_PIN)

    def test_a_service_without_a_usable_image_is_refused(self):
        for image in (None, "", "  ", 3, ["x"], {"a": "b"}):
            with self.subTest(image=image):
                self.refused({"services": {"s": {"image": image}}}, "names no `image:`")
        self.refused({"services": {"s": {}}}, "names no `image:`")

    def test_an_interpolated_reference_other_than_the_pin_is_refused(self):
        for image in ("${OTHER}", "$IMAGE", "${IMAGE:-x}", "a/b@sha256:${D}", "${IMAGE}x"):
            with self.subTest(image=image):
                self.refused(model_of(("s", image, {})), "interpolated")

    def test_a_literal_that_is_not_digest_pinned_names_its_service(self):
        for image in ("redis", "redis:7", f"redis@sha256:{'1' * 63}", "A/B@sha256:" + "1" * 64):
            with self.subTest(image=image):
                self.refused(model_of(("cache", image, {})), "service 'cache'")


class RenderComposeTests(unittest.TestCase):
    """The one subprocess this part of the program starts."""

    GOOD = '{"name": "edge", "services": {"app": {"image": "${IMAGE}"}}}'

    def render(self, response, **kwargs):
        run = FakeRun([response])
        return run, REAL_RENDER("/opt/branchleft/edge", run=run, **kwargs)

    def test_it_asks_compose_for_the_json_model_without_interpolating(self):
        run, model = self.render((0, self.GOOD))
        self.assertEqual(model["services"]["app"]["image"], "${IMAGE}")
        self.assertEqual(
            run.calls,
            [["/usr/bin/docker", "compose", "--profile", "*", "config", "--format", "json", "--no-interpolate"]],
        )

    def test_it_runs_in_the_stack_directory_with_no_stdin_and_a_timeout(self):
        run, _ = self.render((0, self.GOOD))
        kwargs = run.kwargs[0]
        self.assertEqual(kwargs["cwd"], "/opt/branchleft/edge")
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["timeout"], bd.COMPOSE_RENDER_TIMEOUT)

    def test_it_inherits_nothing_from_the_callers_environment(self):
        with mock.patch.dict(
            os.environ, {"COMPOSE_FILE": "/elsewhere.yml", "COMPOSE_PROFILES": "p", "TOKEN": "t"}
        ):
            run, _ = self.render((0, self.GOOD))
        self.assertEqual(run.kwargs[0]["env"], bd.COMPOSE_RENDER_ENV)
        self.assertEqual(set(bd.COMPOSE_RENDER_ENV), {"PATH", "HOME", "LC_ALL"})

    def test_a_failed_render_refuses_and_leaks_no_output(self):
        for response in ((1, "", "secret-in-stderr"), (15, "secret-in-stdout", "")):
            with self.subTest(response=response):
                with self.assertRaises(bd.DeployError) as raised:
                    self.render(response)
                self.assertIn("exit", str(raised.exception))
                self.assertNotIn("secret", str(raised.exception))

    def test_a_docker_that_cannot_start_or_times_out_refuses(self):
        for error in (
            FileNotFoundError("/usr/bin/docker"),
            PermissionError("x"),
            subprocess.TimeoutExpired(["docker"], 60.0),
        ):
            with self.subTest(error=type(error).__name__):

                def broken(argv, **kwargs):
                    raise error

                with self.assertRaises(bd.DeployError) as raised:
                    REAL_RENDER("/d", run=broken)
                self.assertIn(type(error).__name__, str(raised.exception))

    def test_output_that_is_not_a_json_object_refuses(self):
        for stdout in ("", "services:\n  a: {}\n", "[1]", '"x"', "null", "{", "3"):
            with self.subTest(stdout=stdout):
                with self.assertRaises(bd.DeployError) as raised:
                    self.render((0, stdout))
                self.assertIn("JSON object", str(raised.exception))

    def test_the_output_is_never_written_to_disk_or_logged(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.render((0, self.GOOD))
        self.assertEqual(stderr.getvalue(), "")


def _usable_docker_compose():
    docker = shutil.which("docker")
    if docker is None:
        return None
    try:
        result = subprocess.run(
            [docker, "compose", "version"],
            env=REAL_COMPOSE_ENV,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return docker if result.returncode == 0 else None


# A real HOME is kept (Compose finds its CLI plugin there when the package puts it
# in the user's directory). A daemon that cannot be reached shows that rendering
# does not need one.
REAL_COMPOSE_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": os.environ.get("HOME", "/root"),
    "LC_ALL": "C",
    "DOCKER_HOST": "unix:///nonexistent.sock",
}
REAL_DOCKER = _usable_docker_compose()
EVIL_YML = "services:\n  evilsvc:\n    image: " + EVIL + "\n"
EVIL_HOST = "evil.example"


def real_render(directory):
    return REAL_RENDER(directory, docker=REAL_DOCKER, env=REAL_COMPOSE_ENV)


@unittest.skipUnless(REAL_DOCKER, "needs `docker compose` on PATH")
class RealComposeTests(unittest.TestCase):
    """Hostile shapes run through the real `docker compose config`.

    The property: whatever Compose renders, if an image the verifier never saw is
    in the model, verify_compose_images refuses; or Compose itself rejects the
    file. Neither outcome may be an acceptance with the evil image in it.
    """

    def stack(self, files):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        files = {"evil.yml": EVIL_YML, **files}
        for name, text in files.items():
            with open(os.path.join(directory.name, name), "w", encoding="utf-8") as handle:
                handle.write(text)
        return directory.name

    def verify(self, files, stack="edge"):
        directory = self.stack(files)
        bd.verify_compose_images(stack, directory, EDGE_PIN, run=FakeRun([0]), render=real_render)
        return directory

    def outcome(self, files):
        """`rejected` (Compose or the walker refuses), or `accepted`; asserts an
        accepted model holds no evil reference or image mount."""
        try:
            directory = self.verify(files)
        except bd.DeployError as error:
            return "rejected", str(error)
        services = real_render(directory)["services"]
        self.assertNotIn(EVIL_HOST, json.dumps(services), files)
        self.assertFalse(bd._holds_image_mount(services), files)
        return "accepted", ""

    def test_the_real_compose_lists_the_pin_and_the_sidecar(self):
        directory = self.stack({"compose.yml": compose_of(service_block("side", EXPORTER))})
        model = real_render(directory)
        self.assertEqual(model["services"]["app"]["image"], "${IMAGE}")
        self.assertEqual(model["services"]["side"]["image"], EXPORTER)

    def test_a_service_behind_a_profile_is_in_the_model_and_refused(self):
        text = compose_of(service_block("gated", STRAY, "    profiles: [debug]\n"))
        directory = self.stack({"compose.yml": text})
        self.assertEqual(real_render(directory)["services"]["gated"]["image"], STRAY)
        with self.assertRaises(bd.DeployError) as raised:
            self.verify({"compose.yml": text})
        self.assertIn("ghcr.io/branchleft/stray", str(raised.exception))

    def test_an_unset_variable_does_not_stop_the_render_or_get_resolved(self):
        text = compose_of(
            service_block("side", EXPORTER, "    environment:\n      A: ${NEVER_SET:?must be set}\n")
        )
        model = real_render(self.stack({"compose.yml": text}))
        self.assertEqual(model["services"]["side"]["environment"]["A"], "${NEVER_SET:?must be set}")

    def test_an_include_is_followed_and_its_image_is_refused(self):
        with self.assertRaises(bd.DeployError) as raised:
            self.verify({"compose.yml": "include:\n  - evil.yml\n" + compose_of()})
        self.assertIn("evil.example/x", str(raised.exception))

    def test_an_override_file_sidecar_is_refused(self):
        with self.assertRaises(bd.DeployError) as raised:
            self.verify(
                {"compose.yml": compose_of(), OVERRIDE: "services:\n" + service_block("x", STRAY)}
            )
        self.assertIn("ghcr.io/branchleft/stray", str(raised.exception))

    def test_an_image_mount_is_refused_in_the_base_file_and_the_override(self):
        mount = "    volumes:\n      - type: image\n        source: " + EVIL + "\n        target: /x\n"
        flow = "    volumes:\n      - {type: image, source: " + EVIL + ", target: /x}\n"
        anchored = (
            "x-m: &m {type: image, source: " + EVIL + ", target: /x}\n",
            "    volumes:\n      - *m\n",
        )
        cases = {
            "block": ({"compose.yml": compose_of(service_block("s", PORTAL, mount))}),
            "flow": ({"compose.yml": compose_of(service_block("s", PORTAL, flow))}),
            "anchored": (
                {"compose.yml": anchored[0] + compose_of(service_block("s", PORTAL, anchored[1]))}
            ),
            "override": (
                {
                    "compose.yml": compose_of(service_block("s", PORTAL)),
                    OVERRIDE: "services:\n  s:\n" + mount,
                }
            ),
        }
        for label, files in cases.items():
            with self.subTest(label):
                self.assertEqual(self.outcome(files)[0], "rejected")

    def test_a_service_that_builds_on_the_host_is_rejected(self):
        files = {"compose.yml": compose_of(service_block("side", PORTAL, "    build: ./side\n"))}
        self.assertEqual(self.outcome(files)[0], "rejected")

    def test_an_extended_service_leaves_no_foreign_image_in_the_model(self):
        """Compose resolves `extends` into the service's own fields, so the extended
        image is replaced by the service's own `image:`, which is what is checked."""
        fields = "    extends:\n      file: evil.yml\n      service: evilsvc\n"
        self.outcome({"compose.yml": compose_of(service_block("side", PORTAL, fields))})

    def test_a_top_level_key_this_program_cannot_read_is_rejected(self):
        for text in ("models:\n  m:\n    model: evil\n", "extra:\n  a: b\n"):
            with self.subTest(text.partition("\n")[0]):
                self.assertEqual(self.outcome({"compose.yml": text + compose_of()})[0], "rejected")

    def test_an_x_extension_holding_an_image_mount_is_data_and_is_not_run(self):
        text = "x-m:\n  type: image\n  source: " + EVIL + "\n" + compose_of()
        self.assertEqual(self.outcome({"compose.yml": text})[0], "accepted")

    def test_an_env_file_in_the_stack_directory_cannot_hide_an_image(self):
        files = {"compose.yml": compose_of(), ".env": "COMPOSE_FILE=compose.yml:evil.yml\n"}
        self.outcome(files)

    def test_a_file_that_is_not_compose_at_all_is_rejected(self):
        for text in ("{", "- a\n", "services: 3\n"):
            with self.subTest(text):
                self.assertEqual(self.outcome({"compose.yml": text})[0], "rejected")


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# The Compose file each stack that pins through this wrapper ships in this repository.
# The tenant stacks live in ghost-platform and are not here.
COMMITTED_STACKS = {
    "edge": "hetzner/edge/stack/compose.yml",
    "control-plane": "hetzner/control-plane/stack/compose.yml",
    "website": "ansible/roles/website_app1/files/compose.yml",
    "publicpress-website": "ansible/roles/publicpress_website_app1/files/compose.yml",
    "db": "ansible/roles/db1_stack/templates/compose.yml.j2",
}

# Stacks whose Compose file has no `${IMAGE}`: the wrapper refuses to deploy them, so
# no sidecar of theirs reaches it.
NOT_DEPLOYED_BY_THE_WRAPPER = {
    "monitoring": "hetzner/monitoring/stack/compose.yml",
    "nextcloud1": "hetzner/nextcloud1/stack/compose.yml",
}


def committed_compose_text(relative):
    text = (REPO_ROOT / relative).read_text(encoding="utf-8")
    if relative.endswith(".j2"):
        vars_text = (REPO_ROOT / "ansible/roles/db1_stack/vars/main.yml").read_text(encoding="utf-8")
        exporter = re.search(r"^db1_stack_exporter_image: (\S+)$", vars_text, re.MULTILINE)
        assert exporter, "db1_stack_exporter_image is no longer a one-line value"
        text = text.replace("{{ db1_stack_exporter_image }}", exporter.group(1))
    return text


class CommittedStackTests(unittest.TestCase):
    """Every stack this repository ships through the wrapper, rendered whole.

    Proves the program refuses nothing the committed stacks need once their
    sidecars are accounted for, and that no sidecar is added without being
    counted here. The render is the stand-in; RealCommittedStackTests runs the
    same checks through the real Compose.
    """

    render = staticmethod(yaml_render)

    def stack_directory(self, relative):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        with open(os.path.join(directory.name, "compose.yml"), "w", encoding="utf-8") as handle:
            handle.write(committed_compose_text(relative))
        return directory.name

    def sidecars_of(self, stack):
        directory = self.stack_directory(COMMITTED_STACKS[stack])
        _pin_seen, literals = bd.model_images(self.render(directory), "x@sha256:" + "0" * 64)
        return {bd.attested_name(reference) for _service, reference in literals}

    def test_each_committed_stack_runs_exactly_the_sidecars_the_tests_count(self):
        for stack in COMMITTED_STACKS:
            with self.subTest(stack):
                self.assertEqual(self.sidecars_of(stack), set(SIDECARS.get(stack, ())))

    def test_each_sidecar_is_registered_or_named_for_its_stack(self):
        for stack in COMMITTED_STACKS:
            for name in self.sidecars_of(stack):
                with self.subTest(stack=stack, name=name):
                    self.assertTrue(
                        name in bd.ATTESTED_IMAGES
                        or name in bd.UNATTESTED_STACK_IMAGES.get(stack, frozenset())
                    )

    def test_each_committed_stack_verifies_with_the_shipped_lists(self):
        for stack, relative in COMMITTED_STACKS.items():
            with self.subTest(stack):
                directory = self.stack_directory(relative)
                bd.verify_compose_images(
                    stack, directory, EDGE_PIN, run=FakeRun([0] * 4), render=self.render
                )

    def test_a_stack_that_runs_a_sidecar_its_list_does_not_name_is_refused(self):
        for stack, names in SIDECARS.items():
            with self.subTest(stack):
                directory = self.stack_directory(COMMITTED_STACKS[stack])
                trimmed = {
                    key: listed - names for key, listed in bd.UNATTESTED_STACK_IMAGES.items()
                }
                with mock.patch.dict(bd.UNATTESTED_STACK_IMAGES, trimmed):
                    with self.assertRaises(bd.DeployError) as raised:
                        bd.verify_compose_images(
                            stack, directory, EDGE_PIN, run=FakeRun([0] * 4), render=self.render
                        )
                self.assertTrue(any(name in str(raised.exception) for name in names))

    def test_the_stacks_the_wrapper_cannot_deploy_have_no_image_pin(self):
        for stack, relative in NOT_DEPLOYED_BY_THE_WRAPPER.items():
            with self.subTest(stack):
                self.assertFalse(bd.resolves_image_from_env((REPO_ROOT / relative).read_text()))


@unittest.skipUnless(REAL_DOCKER, "needs `docker compose` on PATH")
class RealCommittedStackTests(CommittedStackTests):
    render = staticmethod(real_render)


if __name__ == "__main__":
    unittest.main()
