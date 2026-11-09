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
import os
import pathlib
import random
import re
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

import branchleft_deploy as bd


DIGEST = "a" * 64
VALID_IMAGE = f"ghcr.io/branchleft/example@sha256:{DIGEST}"


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


def attestation_passes(case):
    """Stand in for a passed attestation for the rest of one test case.

    deploy() refuses every image name off the register, and these cases test
    what deploy() does after the attestation step (the compose check, the
    health signal, the lock, the pin and the rollback) with a stand-in image.
    AttestationTests holds the attestation step itself, unpatched.
    """
    patcher = mock.patch.object(bd, "verify_attestation", return_value=None)
    patcher.start()
    case.addCleanup(patcher.stop)


class StackNameTests(unittest.TestCase):
    def test_accepts_plain_names(self):
        for name in ("edge", "ghost-tenant-one", "mon1"):
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
        attestation_passes(self)
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

# sha256 of hetzner/provision/branchleft-verify-image, the host copy of
# ghost-platform's scripts/verify-image-attestation.sh. Change the copy and this
# constant in the same change, and carry the change to ghost-platform's script.
VERIFIER_SHA256 = "2342896f33a659a85697a586223b5d970d92082b02f6f3bd7ea2c7637a71cd0d"

# The verifier's whole environment, exactly. Nothing is inherited from the host,
# and no GitHub credential is in it: the host holds none. A change to any value
# here is a change to what gh is allowed to read, and is reviewed as one.
EXPECTED_VERIFIER_ENV = {
    "PATH": "/usr/local/libexec/branchleft-verifier:/usr/bin:/bin",
    "HOME": "/var/lib/branchleft/verifier-home",
    "GH_CONFIG_DIR": "/var/lib/branchleft/verifier-home",
    "XDG_CONFIG_HOME": "/var/lib/branchleft/verifier-home",
    "GH_PROMPT_DISABLED": "1",
    "GH_NO_UPDATE_NOTIFIER": "1",
    "LC_ALL": "C",
    "VERIFY_PLAIN_ERRORS": "1",
}


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
            },
        )

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

    def assert_refused_unregistered(self, image):
        """Refused by name, with nothing run: no verifier, no restart, no pin."""
        run = FakeRun([0, 0])
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(image, run)
        self.assertEqual(run.calls, [])
        self.assertFalse(os.path.exists(self.env_path()))
        return str(raised.exception)

    def test_an_image_name_on_neither_table_is_refused_and_never_deployed(self):
        for image in (
            f"registry.example:5000/library/mysql:8@sha256:{'d' * 64}",
            f"docker.io/library/mysql@sha256:{'d' * 64}",
            f"ghcr.io/branchleft/new-image@sha256:{DIGEST}",
            VALID_IMAGE,
        ):
            with self.subTest(image=image):
                self.assert_refused_unregistered(image)

    def test_the_refusal_names_the_image_and_both_tables(self):
        image = f"docker.io/library/mysql@sha256:{'d' * 64}"
        message = self.assert_refused_unregistered(image)
        self.assertIn(image, message)
        self.assertIn("register", message)
        self.assertIn("allowance", message)
        for name in (*bd.ATTESTED_IMAGES, *bd.UNATTESTED_ALLOWED):
            self.assertIn(name, message)

    def test_verify_attestation_itself_refuses_an_unknown_name(self):
        def boom(argv, **kwargs):
            raise AssertionError("the verifier must not run for an unknown name")

        with self.assertRaises(bd.DeployError):
            bd.verify_attestation(f"ghcr.io/branchleft/example@sha256:{DIGEST}", run=boom)

    def test_the_allowance_table_is_exactly_the_live_unattested_names(self):
        self.assertEqual(
            sorted(bd.UNATTESTED_ALLOWED),
            [
                "docker.io/crowdsecurity/crowdsec",
                "docker.io/library/postgres",
                "ghcr.io/branchleft/edge-caddy",
                "ghcr.io/branchleft/mailgun-shim",
                "ghcr.io/branchleft/website",
                "ghcr.io/zitadel/zitadel",
                "mysql",
                "prom/mysqld-exporter",
            ],
        )
        for name, reason in bd.UNATTESTED_ALLOWED.items():
            with self.subTest(name=name):
                self.assertTrue(reason.strip())
                self.assertNotIn("\n", reason)

    def test_no_name_is_on_both_tables(self):
        self.assertEqual(set(bd.ATTESTED_IMAGES) & set(bd.UNATTESTED_ALLOWED), set())

    def deploy_allowed(self, image):
        run = FakeRun([0])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.deploy(image, run)
        return run, stderr.getvalue()

    def test_each_allowed_name_deploys_without_the_verifier_and_says_so(self):
        spellings = {
            "ghcr.io/branchleft/edge-caddy": f"ghcr.io/branchleft/edge-caddy@sha256:{DIGEST}",
            "ghcr.io/branchleft/website": f"ghcr.io/branchleft/website@sha256:{DIGEST}",
            "ghcr.io/branchleft/mailgun-shim": (
                f"ghcr.io/branchleft/mailgun-shim@sha256:{DIGEST}"
            ),
            "mysql": f"mysql:8.0.43@sha256:{DIGEST}",
            "prom/mysqld-exporter": f"prom/mysqld-exporter:v0.20.0@sha256:{DIGEST}",
            "docker.io/crowdsecurity/crowdsec": (
                f"docker.io/crowdsecurity/crowdsec:v1.7.8@sha256:{DIGEST}"
            ),
            "docker.io/library/postgres": (
                f"docker.io/library/postgres:17-alpine@sha256:{DIGEST}"
            ),
            "ghcr.io/zitadel/zitadel": f"ghcr.io/zitadel/zitadel@sha256:{DIGEST}",
        }
        self.assertEqual(sorted(spellings), sorted(bd.UNATTESTED_ALLOWED))
        for name, image in spellings.items():
            with self.subTest(name=name):
                run, log = self.deploy_allowed(image)
                self.assertEqual(
                    run.calls, [["systemctl", "restart", "branchleft-compose@edge"]]
                )
                self.assertEqual(bd.read_current_image(self.env_path()), image)
                self.assertIn(
                    f"unattested by allowance: {name} ({bd.UNATTESTED_ALLOWED[name]})",
                    log,
                )

    def test_an_allowed_name_with_a_tag_or_port_is_still_that_name(self):
        image = f"ghcr.io:443/branchleft/website:v1@sha256:{DIGEST}"
        run, log = self.deploy_allowed(image)
        self.assertEqual(run.calls, [["systemctl", "restart", "branchleft-compose@edge"]])
        self.assertIn("unattested by allowance: ghcr.io/branchleft/website (", log)

    def test_a_registered_name_is_not_reported_as_allowed(self):
        run = FakeRun([0, 0])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.deploy(TENANT, run)
        self.assertNotIn("unattested by allowance", stderr.getvalue())
        self.assertEqual(run.calls[0][0], bd.VERIFIER)

    def test_a_name_that_only_starts_with_an_allowed_name_is_refused(self):
        for image in (
            f"ghcr.io/branchleft/edge-caddy-evil@sha256:{DIGEST}",
            f"ghcr.io/branchleft/website/extra@sha256:{DIGEST}",
            f"ghcr.io/branchleft/mailgun-shim2:v1@sha256:{DIGEST}",
            f"mysql-evil:8@sha256:{DIGEST}",
            f"docker.io/branchleft/edge-caddy@sha256:{DIGEST}",
            f"docker.io/library/mysql:8@sha256:{DIGEST}",
            f"evil.example/mysql:8@sha256:{DIGEST}",
        ):
            with self.subTest(image=image):
                self.assert_refused_unregistered(image)

    def test_a_name_that_only_starts_with_a_registered_name_is_refused(self):
        for image in (
            f"ghcr.io/branchleft/ghost-tenant-evil@sha256:{DIGEST}",
            f"ghcr.io/branchleft/ghost-tenantx:v1@sha256:{DIGEST}",
            f"ghcr.io/branchleft/portal-apps2@sha256:{DIGEST}",
            f"ghcr.io/branchleft/ghost-tenant/extra@sha256:{DIGEST}",
            f"ghcr.io/branchleft/ghost-tenant/ghost-tenant@sha256:{DIGEST}",
            f"ghcr.io/branchleft/portal-apps/app:v1@sha256:{DIGEST}",
            f"ghcr.io/evil/branchleft/ghost-tenant@sha256:{DIGEST}",
            f"evil.example/ghcr.io/branchleft/ghost-tenant@sha256:{DIGEST}",
        ):
            with self.subTest(image=image):
                self.assert_refused_unregistered(image)

    def test_a_registry_alias_of_a_registered_name_is_refused(self):
        for image in (
            f"docker.io/branchleft/ghost-tenant@sha256:{DIGEST}",
            f"index.docker.io/branchleft/ghost-tenant@sha256:{DIGEST}",
            f"quay.io/branchleft/portal-apps@sha256:{DIGEST}",
            f"ghcr.io.evil.example/branchleft/ghost-tenant@sha256:{DIGEST}",
            f"branchleft/ghost-tenant@sha256:{DIGEST}",
            f"ghost-tenant@sha256:{DIGEST}",
        ):
            with self.subTest(image=image):
                self.assert_refused_unregistered(image)

    def test_a_case_variant_or_nameless_reference_is_refused_before_any_host_change(self):
        for image in (
            f"GHCR.IO/branchleft/ghost-tenant@sha256:{DIGEST}",
            f"ghcr.io/BranchLeft/ghost-tenant@sha256:{DIGEST}",
            f"ghcr.io/branchleft/Ghost-Tenant@sha256:{DIGEST}",
            f"@sha256:{DIGEST}",
            f"sha256:{DIGEST}",
            "",
        ):
            with self.subTest(image=image):
                self.assert_refused_unregistered(image)

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

    def test_the_vendored_verifier_is_pinned_to_its_digest(self):
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "branchleft-verify-image"
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
        self.assertEqual(bd.main(["branchleft-deploy", "../edge", VALID_IMAGE]), 1)

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
            bd.main(["branchleft-deploy", "--slot", "../edge"], stdin=stdin), 1
        )
        self.assertEqual(stdin.tell(), 0)

    def test_slot_mode_rejects_an_image_that_names_another_stack(self):
        self.assertEqual(
            bd.main(
                ["branchleft-deploy", "--slot", "blog"],
                stdin=io.StringIO(f"other-tenant {VALID_IMAGE}\n"),
            ),
            1,
        )

    def test_an_unregistered_image_exits_one_and_says_so_on_stderr(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = bd.main(["branchleft-deploy", "edge", VALID_IMAGE])
        self.assertEqual(code, 1)
        self.assertIn(VALID_IMAGE, stderr.getvalue())
        self.assertIn("register", stderr.getvalue())

    def test_positional_mode_ignores_stdin_entirely(self):
        attestation_passes(self)
        stdin = io.StringIO("ghcr.io/branchleft/hostile@sha256:" + "b" * 64 + "\n")
        # No compose file exists for this stack, so the failure is the expected
        # one; what matters is that stdin was never consulted to produce it.
        self.assertEqual(
            bd.main(["branchleft-deploy", "no-such-stack", VALID_IMAGE], stdin=stdin), 1
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
        attestation_passes(self)
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
            f"    image: ghcr.io/branchleft/probed@sha256:{'b' * 64}\n"
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
        attestation_passes(self)
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
            f"    image: ghcr.io/branchleft/probed@sha256:{'b' * 64}\n"
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

    def test_a_shape_the_health_parser_cannot_read_warns_and_still_deploys(self):
        """A parser limitation is not a property of the stack: refusing a
        deploy over a shape the health reader cannot classify would be an
        outage the Compose file itself never had. The image reader refuses
        such a shape first (ImageVerificationTests), so this drives the health
        branch with a stand-in that raises."""
        self.write_compose("edge", "services:\n  app:\n    image: ${IMAGE}\n")
        run = FakeRun([0])
        stderr = io.StringIO()
        unreadable = mock.patch.object(
            bd, "health_signal_gaps", side_effect=bd.ComposeParseError("unreadable")
        )
        with unreadable, contextlib.redirect_stderr(stderr):
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


ALLOWED_PIN = f"ghcr.io/branchleft/website@sha256:{DIGEST}"
EXPORTER = f"prom/mysqld-exporter:v0.20.0@sha256:{'c' * 64}"
STRAY = f"ghcr.io/branchleft/stray@sha256:{'d' * 64}"
PORTAL = f"ghcr.io/branchleft/portal-apps@sha256:{'e' * 64}"
PORTAL_SIGNER = "branchLeft/ghost-platform/.github/workflows/portal-apps-image.yml"
PROBE = "    healthcheck:\n      test: ['CMD', 'true']\n"


def service_block(name, image, extra=""):
    return f"  {name}:\n    image: {image}\n{extra}{PROBE}"


def compose_of(*blocks):
    return "services:\n" + service_block("app", "${IMAGE}") + "".join(blocks)


EVIL = f"evil.example/x@sha256:{'f' * 64}"
INCLUDE_EVIL = "  - evil.yml\n"

# Shapes for a compose.yml that put an image on the host no verifier sees,
# through something other than a block `image:` line the reader inspects. Each
# keeps an ordinary pin service, so only the hidden part can be refused.
HIDDEN_AT_COLUMN_ZERO = {
    "an escaped include key": '"inc\\x6cude":\n' + INCLUDE_EVIL + compose_of(),
    "a complex include key": "? include\n: [evil.yml]\n" + compose_of(),
    "a byte order mark before include": "\ufeffinclude:\n" + INCLUDE_EVIL + compose_of(),
    "a byte order mark before services": "\ufeff" + compose_of(),
    "a root merge key": "x-a: &a\n  include: [evil.yml]\n<<: *a\n" + compose_of(),
    "a plain include": "include:\n" + INCLUDE_EVIL + compose_of(),
    "an include after services": compose_of() + "include:\n" + INCLUDE_EVIL,
    "a top level models key": "models:\n  m:\n    model: evil\n" + compose_of(),
    "an unknown top level key": "extra:\n  a: b\n" + compose_of(),
    "a stray list item": "- a\n" + compose_of(),
    "an anchor on the services line": "services: &s\n" + compose_of().partition("\n")[2],
    "a JSON document": '{"services": {"web": {"image": "${IMAGE}"}}, "include": ["evil.yml"]}\n',
    "services twice": compose_of() + compose_of(),
    "name twice": "name: a\nname: b\n" + compose_of(),
    "a second document": compose_of() + "---\ninclude: [evil.yml]\n",
    "a control character": "x-n: a\x0cb\n" + compose_of(),
    "a next line separator": "x-n: a\x85include: [evil.yml]\n" + compose_of(),
}

# The same idea for the services themselves: a `services:` line that is not
# alone, and service fields the reader could not classify.
FLOW_SERVICES = (
    "services: {evil: {image: \"" + EVIL + "\"}, web: {image: \"${IMAGE}\"}}\n"
)
HIDDEN_IN_SERVICES = {
    "flow services": FLOW_SERVICES,
    "flow services with a tail": "services: {}\n",
    "an escaped image key at indent 6": 'services:\n  app:\n      "im\\x61ge": ' + EVIL + "\n",
    "extends at indent 6": (
        "services:\n  app:\n      extends:\n        file: evil.yml\n        service: e\n"
    ),
    "build at indent 6": "services:\n  app:\n      build: .\n",
    "first key at indent 3": "services:\n  app:\n   restart: always\n",
    "first key at indent 5": "services:\n  app:\n     restart: always\n",
    "first key at indent 8": "services:\n  app:\n        restart: always\n",
    "an escaped image key at indent 4": 'services:\n  app:\n    "im\\x61ge": ' + EVIL + "\n",
    "a complex image key": "services:\n  app:\n    ? image\n    : " + EVIL + "\n",
    "provider": "services:\n  app:\n    provider:\n      type: x\n",
    "extends": "services:\n  app:\n    extends:\n      service: web\n",
    "build": "services:\n  app:\n    build: .\n",
}


class ImageVerificationTests(unittest.TestCase):
    """deploy() holds every image the stack's Compose files name to the same
    rule as the pin, not only the one passed on the command line.

    The attestation step is real here (never patched). Each refusal must leave
    the pin file absent and run no restart.
    """

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config_dir = os.path.join(self.directory.name, "etc")
        self.stack_dir = os.path.join(self.directory.name, "opt")
        os.makedirs(self.config_dir)
        os.makedirs(os.path.join(self.stack_dir, "edge"))

    def write(self, text, name="compose.yml"):
        with open(
            os.path.join(self.stack_dir, "edge", name), "w", encoding="utf-8"
        ) as handle:
            handle.write(text)

    def deploy(self, image, run):
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr):
                bd.deploy(
                    "edge",
                    image,
                    config_dir=self.config_dir,
                    stack_dir=self.stack_dir,
                    run=run,
                )
        finally:
            self.log = stderr.getvalue()

    def env_path(self):
        return bd.image_env_path("edge", self.config_dir)

    def assert_refused(
        self, text, run=None, image=ALLOWED_PIN, name="compose.yml", override=None
    ):
        """Refused with no restart and no pin; returns the message."""
        self.write(text, name)
        override_path = os.path.join(self.stack_dir, "edge", bd.COMPOSE_OVERRIDE)
        if os.path.exists(override_path):
            os.unlink(override_path)
        if override is not None:
            self.write(override, bd.COMPOSE_OVERRIDE)
        run = run or FakeRun([0])
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(image, run)
        self.assertFalse(os.path.exists(self.env_path()))
        self.assertNotIn(["systemctl", "restart", "branchleft-compose@edge"], run.calls)
        return str(raised.exception)

    def test_a_sidecar_on_neither_table_is_refused_before_any_host_change(self):
        run = FakeRun([0])
        message = self.assert_refused(compose_of(service_block("side", STRAY)), run)
        self.assertEqual(run.calls, [])
        self.assertIn(STRAY, message)
        self.assertIn("'side'", message)
        self.assertIn("allowance", message)

    def test_a_sidecar_on_the_allowance_deploys_and_logs_as_the_pin_does(self):
        run = FakeRun([0])
        self.write(compose_of(service_block("side", EXPORTER)))
        self.deploy(ALLOWED_PIN, run)
        self.assertEqual(run.calls, [["systemctl", "restart", "branchleft-compose@edge"]])
        self.assertEqual(bd.read_current_image(self.env_path()), ALLOWED_PIN)
        self.assertIn("unattested by allowance: ghcr.io/branchleft/website (", self.log)
        self.assertIn(
            "unattested by allowance: prom/mysqld-exporter "
            f"({bd.UNATTESTED_ALLOWED['prom/mysqld-exporter']})",
            self.log,
        )

    def test_a_stack_of_only_attested_images_deploys_through_the_verifier(self):
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

    def test_an_attested_sidecar_the_verifier_refuses_stops_the_deploy(self):
        run = FakeRun([0, 1])
        message = self.assert_refused(
            compose_of(service_block("side", PORTAL)), run, image=TENANT
        )
        self.assertEqual([call[0] for call in run.calls], [bd.VERIFIER, bd.VERIFIER])
        self.assertIn("is not attested by", message)
        self.assertIn(PORTAL, message)

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
            "prom/mysqld-exporter:latest",
            f"'prom/mysqld-exporter:v1@sha256:{'c' * 63}'",
            "",
        ):
            with self.subTest(reference=reference):
                run = FakeRun([0])
                message = self.assert_refused(
                    compose_of(service_block("side", reference)), run
                )
                self.assertEqual(run.calls, [])
                self.assertIn("digest-pinned", message)
                self.assertIn("'side'", message)

    def test_a_digest_shape_error_is_found_before_any_verifier_runs(self):
        run = FakeRun([0, 0])
        self.assert_refused(
            compose_of(service_block("good", PORTAL), service_block("bad", "redis")),
            run,
            image=TENANT,
        )
        self.assertEqual([call[0] for call in run.calls], [bd.VERIFIER])

    def test_an_interpolated_sidecar_is_refused_not_resolved(self):
        for reference in (
            "${SIDECAR_IMAGE}",
            "$SIDECAR_IMAGE",
            "${SIDECAR_IMAGE:?set it in /etc/branchleft/edge.env}",
            "${IMAGE:-prom/mysqld-exporter}",
            "${IMAGE}-extra",
            "'${IMAGE}x'",
            "prom/mysqld-exporter@sha256:${DIGEST}",
        ):
            with self.subTest(reference=reference):
                message = self.assert_refused(compose_of(service_block("side", reference)))
                self.assertIn("interpolated", message)

    def test_the_pin_in_any_of_its_two_spellings_or_quoted_is_the_pin(self):
        for reference in ("${IMAGE}", "${IMAGE:?pin the image}", "'${IMAGE}'", '"${IMAGE}"'):
            with self.subTest(reference=reference):
                run = FakeRun([0])
                self.write(compose_of(service_block("second", reference)))
                self.deploy(ALLOWED_PIN, run)
                self.assertEqual(
                    run.calls, [["systemctl", "restart", "branchleft-compose@edge"]]
                )
                os.unlink(self.env_path())

    def test_a_quoted_sidecar_is_read_as_the_reference_inside_the_quotes(self):
        for reference in (f"'{EXPORTER}'", f'"{EXPORTER}"'):
            with self.subTest(reference=reference):
                self.write(compose_of(service_block("side", reference)))
                self.deploy(ALLOWED_PIN, FakeRun([0]))
                self.assertIn("unattested by allowance: prom/mysqld-exporter", self.log)
                os.unlink(self.env_path())

    def test_a_sidecar_named_twice_is_verified_once(self):
        run = FakeRun([0, 0, 0, 0])
        self.write(
            compose_of(service_block("one", PORTAL), service_block("two", PORTAL))
        )
        self.deploy(TENANT, run)
        self.assertEqual([call[0] for call in run.calls], [bd.VERIFIER, bd.VERIFIER, "systemctl"])

    def test_a_sidecar_in_the_override_file_is_held_to_the_same_rule(self):
        self.write(compose_of())
        self.write("services:\n" + service_block("extra", STRAY), "compose.override.yml")
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(ALLOWED_PIN, FakeRun([0]))
        self.assertIn(STRAY, str(raised.exception))
        self.assertIn("compose.override.yml", str(raised.exception))
        self.assertFalse(os.path.exists(self.env_path()))

    def test_an_override_that_adds_an_allowed_sidecar_deploys(self):
        self.write(compose_of())
        self.write("services:\n" + service_block("extra", EXPORTER), "compose.override.yml")
        self.deploy(ALLOWED_PIN, FakeRun([0]))
        self.assertIn("unattested by allowance: prom/mysqld-exporter", self.log)

    def test_an_override_service_may_omit_an_image_but_a_base_service_may_not(self):
        self.write(compose_of())
        self.write("services:\n  app:\n    restart: always\n", "compose.override.yml")
        self.deploy(ALLOWED_PIN, FakeRun([0]))
        os.unlink(self.env_path())
        message = self.assert_refused(compose_of("  bare:\n" + PROBE))
        self.assertIn("names no `image:`", message)

    def test_an_unreadable_override_file_is_refused(self):
        self.write(compose_of())
        os.makedirs(os.path.join(self.stack_dir, "edge", "compose.override.yml"))
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(ALLOWED_PIN, FakeRun([0]))
        self.assertIn("could not read", str(raised.exception))
        self.assertFalse(os.path.exists(self.env_path()))

    def test_a_compose_file_this_program_would_not_read_is_refused(self):
        for name in bd.UNREAD_COMPOSE_FILES:
            with self.subTest(name=name):
                self.write(compose_of())
                self.write("services: {}\n", name)
                with self.assertRaises(bd.DeployError) as raised:
                    self.deploy(ALLOWED_PIN, FakeRun([0]))
                self.assertIn(name, str(raised.exception))
                self.assertFalse(os.path.exists(self.env_path()))
                os.unlink(os.path.join(self.stack_dir, "edge", name))

    def test_a_shape_that_could_hide_an_image_is_refused_not_skipped(self):
        shapes = {
            "an anchor on a service header": "services:\n  app: &app\n    image: ${IMAGE}\n"
            + PROBE,
            "a build context": compose_of("  side:\n    build: ./side\n" + PROBE),
            "a build context with an image": compose_of(
                service_block("side", EXPORTER, "    build: ./side\n")
            ),
            "an extends": compose_of("  side:\n    extends:\n      service: app\n" + PROBE),
            "a top level include": "include:\n  - other.yml\n" + compose_of(),
            "a merge key": compose_of(
                "  side:\n    <<: *common\n    image: " + EXPORTER + "\n" + PROBE
            ),
            "an image below a service key": compose_of(
                service_block("side", EXPORTER, "    deploy:\n      image: x\n")
            ),
            "a second image key": compose_of(
                service_block("side", EXPORTER, "    image: " + EXPORTER + "\n")
            ),
            "a repeated service": compose_of(service_block("app", EXPORTER)),
            "a second document": compose_of() + "---\nservices: {}\n",
            "an odd indent": compose_of("  side:\n   image: " + EXPORTER + "\n" + PROBE),
            "a block scalar image": compose_of(
                service_block("side", ">\n      " + EXPORTER)
            ),
            "an alias image": compose_of(service_block("side", "*common")),
            "services nested too deep": "services:\n    app:\n        image: ${IMAGE}\n",
        }
        reads_but_not_a_digest = ("an alias image",)
        for label, text in shapes.items():
            with self.subTest(label):
                run = FakeRun([0])
                message = self.assert_refused(text, run)
                self.assertEqual(run.calls, [])
                self.assertIn(
                    "digest-pinned"
                    if label in reads_but_not_a_digest
                    else "cannot account for every image",
                    message,
                )

    def test_unreadable_compose_text_is_the_refusal_the_message_names(self):
        message = self.assert_refused("services:\n  app: &app\n    image: ${IMAGE}\n" + PROBE)
        self.assertIn("cannot account for every image", message)
        self.assertIn("refusing to deploy", message)

    def test_a_stack_whose_services_never_take_the_pin_is_refused(self):
        text = (
            "services:\n"
            + service_block("side", EXPORTER, "    environment:\n      A: ${IMAGE}\n")
        )
        message = self.assert_refused(text)
        self.assertIn("no service whose `image:` is the pin", message)

    def test_a_commented_out_image_is_not_read_and_a_trailing_comment_is_cut(self):
        text = compose_of(
            "  side:\n    # image: ghcr.io/branchleft/stray:latest\n"
            f"    image: {EXPORTER} # pinned\n" + PROBE
        )
        self.write(text)
        self.deploy(ALLOWED_PIN, FakeRun([0]))
        self.assertIn("unattested by allowance: prom/mysqld-exporter", self.log)

    def test_a_same_path_on_another_registry_is_another_image(self):
        self.assert_refused(
            compose_of(service_block("side", f"docker.io/library/mysql@sha256:{'d' * 64}"))
        )

    def test_a_hidden_top_level_key_is_refused_not_skipped(self):
        """compose.yml alone, ordinary pin service: only the hidden line is wrong."""
        for label, text in HIDDEN_AT_COLUMN_ZERO.items():
            with self.subTest(label):
                run = FakeRun([0])
                message = self.assert_refused(text, run)
                self.assertEqual(run.calls, [])
                self.assertIn("cannot account for every image", message)

    def test_a_services_line_that_is_not_alone_is_refused_whatever_the_override_holds(self):
        """The pin is read from compose.yml itself; a block pin in the override
        cannot vouch for a flow-style compose.yml."""
        for label, text in {
            "flow services": FLOW_SERVICES,
            "whole JSON": HIDDEN_AT_COLUMN_ZERO["a JSON document"],
            "a flow tail with a live pin elsewhere": "services: {}\nx-pin: ${IMAGE}\n",
        }.items():
            with self.subTest(label):
                run = FakeRun([0])
                message = self.assert_refused(text, run, override=compose_of())
                self.assertEqual(run.calls, [])
                self.assertIn("cannot account for every image", message)

    def test_a_pin_found_only_in_the_override_is_not_a_pin(self):
        message = self.assert_refused(
            "services:\n"
            + service_block("side", EXPORTER, "    environment:\n      A: ${IMAGE}\n"),
            override=compose_of(),
        )
        self.assertIn("no service whose `image:` is the pin", message)

    def test_an_override_service_with_an_unclassifiable_field_is_refused(self):
        """The override may omit an image, so it is the path that reaches the pin
        service's own image."""
        for label, text in HIDDEN_IN_SERVICES.items():
            with self.subTest(label):
                run = FakeRun([0])
                message = self.assert_refused(compose_of(), run, override=text)
                self.assertEqual(run.calls, [])
                self.assertIn("cannot account for every image", message)

    def test_a_base_service_with_an_unclassifiable_field_is_refused(self):
        for label, text in HIDDEN_IN_SERVICES.items():
            with self.subTest(label):
                run = FakeRun([0])
                if text.startswith("services: "):
                    # Keep ${IMAGE} on a live line so the wiring check passes first.
                    text += "x-pin: ${IMAGE}\n"
                else:
                    shape = text.partition("\n")[2].replace("  app:", "  extra:", 1)
                    text = "services:\n" + service_block("app", "${IMAGE}") + shape
                message = self.assert_refused(text, run)
                self.assertEqual(run.calls, [])
                self.assertIn("cannot account for every image", message)

    def test_the_allowed_top_level_keys_are_read_and_do_not_refuse(self):
        text = (
            "name: edge\nversion: '3'\nx-shared: &shared\n  a: b\n"
            "networks:\n  n: {}\nvolumes:\n  v: {}\nsecrets:\n  s:\n    file: /x\n"
            "configs:\n  c:\n    file: /x\n" + compose_of()
        )
        self.write(text)
        self.deploy(ALLOWED_PIN, FakeRun([0]))
        self.assertEqual(bd.read_current_image(self.env_path()), ALLOWED_PIN)

    def test_a_dot_env_file_beside_the_compose_file_is_refused(self):
        self.write(compose_of())
        self.write("COMPOSE_FILE=evil.yml\n", ".env")
        with self.assertRaises(bd.DeployError) as raised:
            self.deploy(ALLOWED_PIN, FakeRun([0]))
        self.assertIn(".env", str(raised.exception))
        self.assertFalse(os.path.exists(self.env_path()))

    def test_a_port_on_a_dockerhub_namespace_is_another_registry(self):
        other = f"prom:5000/mysqld-exporter:v0.20.0@sha256:{'c' * 64}"
        message = self.assert_refused(compose_of(service_block("side", other)))
        self.assertIn("allowance", message)
        run = FakeRun([0])
        self.write(compose_of())
        with self.assertRaises(bd.DeployError):
            self.deploy(other, run)
        self.assertEqual(run.calls, [])
        self.assertFalse(os.path.exists(self.env_path()))

    def test_a_port_is_a_spelling_only_on_a_registry_host(self):
        for image, name in {
            f"ghcr.io:443/branchleft/ghost-tenant:v1@sha256:{DIGEST}": (
                "ghcr.io/branchleft/ghost-tenant"
            ),
            f"localhost:5000/x/y@sha256:{DIGEST}": "localhost/x/y",
            f"prom:5000/mysqld-exporter@sha256:{DIGEST}": "prom:5000/mysqld-exporter",
            f"prom/mysqld-exporter:v1@sha256:{DIGEST}": "prom/mysqld-exporter",
            f"mysql:8.0.43@sha256:{DIGEST}": "mysql",
        }.items():
            with self.subTest(image=image):
                self.assertEqual(bd.attested_name(image), name)

    def test_service_images_maps_each_service_to_its_raw_value(self):
        text = compose_of(
            "  bare:\n    restart: always\n",
            service_block("side", f"'{EXPORTER}'"),
        )
        self.assertEqual(
            bd.service_images(text),
            {"app": "${IMAGE}", "bare": None, "side": f"'{EXPORTER}'"},
        )


YAML_ALLOWED_TOP_LEVEL = frozenset(
    {"services", "networks", "volumes", "secrets", "configs", "name", "version"}
)
YAML_UNREAD_SERVICE_KEYS = frozenset({"build", "extends", "provider"})


def reader_outcome(text):
    try:
        return bd.service_images(text)
    except bd.ComposeParseError:
        return None


def yaml_disagreement(text):
    """Why this reader and PyYAML read `text` differently, or None.

    PyYAML stands in for Compose's own parser (YAML 1.1 anchors, merge keys,
    escapes). The reader may refuse anything. What it may not do is accept text
    from which PyYAML reads an image, an include, or a service the reader did
    not report. Text PyYAML cannot parse is skipped: Compose would not start.
    """
    seen = reader_outcome(text)
    if seen is None:
        return None
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        return f"PyYAML reads a {type(loaded).__name__} at the top level"
    for key in loaded:
        if key not in YAML_ALLOWED_TOP_LEVEL and not str(key).startswith("x-"):
            return f"PyYAML reads the top-level key {key!r}"
    services = loaded.get("services") or {}
    if not isinstance(services, dict):
        return f"PyYAML reads services as a {type(services).__name__}"
    if set(services) != set(seen):
        return f"services differ: PyYAML {sorted(map(str, services))}, reader {sorted(seen)}"
    for name, service in services.items():
        if service is None:
            service = {}
        if not isinstance(service, dict):
            return f"PyYAML reads service {name!r} as a {type(service).__name__}"
        if YAML_UNREAD_SERVICE_KEYS & set(service):
            return f"PyYAML reads {sorted(YAML_UNREAD_SERVICE_KEYS & set(service))} on {name!r}"
        if "image" in service:
            wanted = "" if service["image"] is None else str(service["image"])
        else:
            wanted = None
        got = None if seen[name] is None else bd._unquoted(seen[name])
        if wanted != got:
            return f"image of {name!r}: PyYAML {wanted!r}, reader {got!r}"
    return None


# Lines a hostile compose file might carry, tried at random positions and
# indents. Most make the file unparsable or are refused; the property under test
# is only that the reader never accepts what PyYAML reads differently.
HOSTILE_LINES = (
    "include: [evil.yml]",
    '"inc\\x6cude": [evil.yml]',
    "? include",
    ": [evil.yml]",
    "<<: *a",
    "x-a: &a",
    f"image: {EVIL}",
    f'"im\\x61ge": {EVIL}',
    f"'image': {EVIL}",
    "extends:",
    "  file: evil.yml",
    "build: .",
    "provider:",
    "models:",
    "services: {web: {image: x}}",
    "- a",
    "---",
    f"{{image: {EVIL}}}",
    "web: {image: x}",
    "web:",
    "image:",
    f"  {EVIL}",
    "restart: always",
    "name: x",
    "x-b: 1",
    "﻿include: [evil.yml]",
)


class ReaderAgainstYamlTests(unittest.TestCase):
    """The hand-written reader is held to a real YAML parser in CI.

    The deploy program itself stays stdlib-only: nothing installs PyYAML for the
    host's system python3 (ansible-core's copy lives in its own environment), and
    a deploy gate that failed to import would stop every deploy.
    """

    def test_the_hidden_shapes_are_real_and_the_reader_refuses_each(self):
        every = {**HIDDEN_AT_COLUMN_ZERO, **HIDDEN_IN_SERVICES}
        for label, text in every.items():
            with self.subTest(label):
                self.assertIsNone(reader_outcome(text))
                self.assertIsNone(yaml_disagreement(text))

    def test_pyyaml_really_reads_an_include_or_an_unverified_image_in_those_shapes(self):
        """Guards the corpus: a typo that made a shape harmless would pass above."""
        for label in (
            "an escaped include key",
            "a complex include key",
            "a byte order mark before include",
            "a root merge key",
            "a plain include",
        ):
            with self.subTest(label):
                loaded = yaml.safe_load(HIDDEN_AT_COLUMN_ZERO[label])
                self.assertEqual(list(loaded["include"]), ["evil.yml"])
        flow = yaml.safe_load(FLOW_SERVICES)
        self.assertEqual(flow["services"]["evil"]["image"], EVIL)
        for label, key in (
            ("an escaped image key at indent 6", "image"),
            ("extends at indent 6", "extends"),
            ("build at indent 6", "build"),
        ):
            with self.subTest(label):
                loaded = yaml.safe_load(HIDDEN_IN_SERVICES[label])
                self.assertIn(key, loaded["services"]["app"])

    def test_a_generated_sample_never_splits_the_reader_from_pyyaml(self):
        rng = random.Random(702)
        base = compose_of(service_block("side", EXPORTER)).splitlines()
        parsed_and_accepted = parsed_and_refused = 0
        for _ in range(4000):
            lines = list(base)
            for _ in range(rng.randint(1, 3)):
                snippet = rng.choice(HOSTILE_LINES)
                indent = " " * rng.choice((0, 0, 1, 2, 2, 3, 4, 4, 5, 6, 8))
                lines.insert(rng.randrange(len(lines) + 1), indent + snippet)
            text = "\n".join(lines) + "\n"
            self.assertIsNone(yaml_disagreement(text), text)
            try:
                yaml.safe_load(text)
            except yaml.YAMLError:
                continue
            if reader_outcome(text) is None:
                parsed_and_refused += 1
            else:
                parsed_and_accepted += 1
        # Both sides are exercised, so the property is not vacuously true.
        self.assertGreater(parsed_and_refused, 100)
        self.assertGreater(parsed_and_accepted, 100)


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Each committed stack that is deployed through this program, with the sidecar
# names it runs today. A stack that gains a sidecar changes this table, and so
# a reviewer sees the new image beside the allowance it needs.
COMMITTED_SIDECARS = {
    "edge": ("hetzner/edge/stack/compose.yml", {"docker.io/crowdsecurity/crowdsec"}),
    "control-plane": (
        "hetzner/control-plane/stack/compose.yml",
        {"docker.io/library/postgres", "ghcr.io/zitadel/zitadel"},
    ),
    "website": ("ansible/roles/website_app1/files/compose.yml", set()),
    "db": ("ansible/roles/db1_stack/templates/compose.yml.j2", {"prom/mysqld-exporter"}),
}


def committed_compose_text(relative):
    text = (REPO_ROOT / relative).read_text(encoding="utf-8")
    if relative.endswith(".j2"):
        vars_text = (REPO_ROOT / "ansible/roles/db1_stack/vars/main.yml").read_text(
            encoding="utf-8"
        )
        exporter = re.search(r"^db1_stack_exporter_image: (\S+)$", vars_text, re.MULTILINE)
        assert exporter, "db1_stack_exporter_image is no longer a one-line value"
        text = text.replace("{{ db1_stack_exporter_image }}", exporter.group(1))
        text = re.sub(r"\{\{[^}]*\}\}", "x", text)
    return text


class CommittedStackTests(unittest.TestCase):
    """The stacks this repository commits pass the check as they stand, so the
    sidecar rule does not refuse a deploy that works today."""

    def test_each_committed_stack_deploys_with_only_its_known_sidecars(self):
        for stack, (relative, expected) in COMMITTED_SIDECARS.items():
            with self.subTest(stack=stack):
                with tempfile.TemporaryDirectory() as directory:
                    compose = os.path.join(directory, "compose.yml")
                    text = committed_compose_text(relative)
                    with open(compose, "w", encoding="utf-8") as handle:
                        handle.write(text)
                    stderr = io.StringIO()
                    run = FakeRun([0])
                    with contextlib.redirect_stderr(stderr):
                        bd.verify_compose_images(compose, text, ALLOWED_PIN, run=run)
                    logged = set(
                        re.findall(r"unattested by allowance: (\S+) \(", stderr.getvalue())
                    )
                self.assertEqual(logged, expected)
                self.assertEqual(run.calls, [])

    def test_the_committed_stacks_actually_contain_the_sidecars_listed(self):
        for stack, (relative, expected) in COMMITTED_SIDECARS.items():
            with self.subTest(stack=stack):
                images = bd.service_images(committed_compose_text(relative))
                found = {
                    bd.attested_name(value)
                    for value in images.values()
                    if value and not bd.IMAGE_PIN_REFERENCE.fullmatch(value)
                }
                self.assertEqual(found, expected)


if __name__ == "__main__":
    unittest.main()
