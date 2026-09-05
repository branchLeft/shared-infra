#!/usr/bin/env python3
"""Unit tests for branchleft_deploy.

This script is the entire privilege of the CI deploy account, so its input
validation and its rollback path are security-relevant rather than
convenience behaviour, and both are covered here rather than left to a live
deploy to discover.
"""

import contextlib
import fcntl
import io
import os
import stat
import subprocess
import tempfile
import unittest

import branchleft_deploy as bd


DIGEST = "a" * 64
VALID_IMAGE = f"ghcr.io/branchleft/example@sha256:{DIGEST}"


class FakeRun:
    """Stands in for subprocess.run, recording calls and returning a queue of
    canned responses.

    Each queued response is either a bare int (an exit code, empty stdout --
    what every call except the `docker ps` discriminator check needs) or a
    `(code, stdout)` pair, for the one call that reads its output rather than
    only its exit code.
    """

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv, check=False, capture_output=False, text=False):
        self.calls.append(list(argv))
        response = self.responses.pop(0) if self.responses else 0
        code, stdout = response if isinstance(response, tuple) else (response, "")
        return subprocess.CompletedProcess(argv, code, stdout=stdout)


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
    the image this call just pinned, as opposed to some other service in the
    same stack. This is the fact the MySQL data-dictionary-downgrade case
    turns on: mysqld starting cleanly on the new image while an unrelated
    exporter fails its healthcheck must read as "the image is fine.\""""

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

    def test_positional_mode_ignores_stdin_entirely(self):
        stdin = io.StringIO("ghcr.io/branchleft/hostile@sha256:" + "b" * 64 + "\n")
        # No compose file exists for this stack, so the failure is the expected
        # one; what matters is that stdin was never consulted to produce it.
        self.assertEqual(
            bd.main(["branchleft-deploy", "no-such-stack", VALID_IMAGE], stdin=stdin), 1
        )
        self.assertEqual(stdin.tell(), 0)


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

    def test_the_db_stack_gap_is_also_reviewed(self):
        text = "services:\n  mysqld-exporter:\n    image: ${IMAGE}\n"
        self.assertEqual(
            bd.health_signal_gaps("db", text), ([], ["mysqld-exporter (absent)"])
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
            "    image: a\n"
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
            "    image: a\n"
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


if __name__ == "__main__":
    unittest.main()
