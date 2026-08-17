#!/usr/bin/env python3
"""Unit tests for branchleft_deploy.

This script is the entire privilege of the CI deploy account, so its input
validation and its rollback path are security-relevant rather than
convenience behaviour, and both are covered here rather than left to a live
deploy to discover.
"""

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
    exit codes."""

    def __init__(self, return_codes):
        self.return_codes = list(return_codes)
        self.calls = []

    def __call__(self, argv, check=False):
        self.calls.append(list(argv))
        code = self.return_codes.pop(0) if self.return_codes else 0
        return subprocess.CompletedProcess(argv, code)


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
            handle.write("services:\n  app:\n    image: ${IMAGE}\n")

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

    def test_failed_rollback_is_reported_as_a_host_that_is_down(self):
        previous = f"ghcr.io/branchleft/example@sha256:{'c' * 64}"
        self.deploy(previous, FakeRun([0]))

        run = FakeRun([1, 1])
        with self.assertRaises(bd.DeployError) as caught:
            self.deploy(VALID_IMAGE, run)

        message = str(caught.exception)
        self.assertIn("also failed", message)
        self.assertIn("needs an operator", message)
        self.assertEqual(len(run.calls), 2)

    def test_failed_restart_rolls_back_to_previous_image(self):
        previous = f"ghcr.io/branchleft/example@sha256:{'c' * 64}"
        self.deploy(previous, FakeRun([0]))

        run = FakeRun([1, 0])
        with self.assertRaises(bd.DeployError):
            self.deploy(VALID_IMAGE, run)

        self.assertEqual(bd.read_current_image(self.env_path()), previous)
        self.assertEqual(len(run.calls), 2)

    def test_failed_first_ever_deploy_removes_the_file_and_does_not_restart_again(self):
        run = FakeRun([1, 0])
        with self.assertRaises(bd.DeployError) as caught:
            self.deploy(VALID_IMAGE, run)
        self.assertFalse(os.path.exists(self.env_path()))
        # A second restart would fail by construction with no pin file, so
        # the failure must be reported rather than dressed up as a rollback.
        self.assertEqual(len(run.calls), 1)
        self.assertIn("has never run", str(caught.exception))

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


class MainTests(unittest.TestCase):
    def test_wrong_argument_count_is_a_usage_error(self):
        self.assertEqual(bd.main(["branchleft-deploy"]), 2)
        self.assertEqual(bd.main(["branchleft-deploy", "edge"]), 2)
        self.assertEqual(
            bd.main(["branchleft-deploy", "edge", VALID_IMAGE, "extra"]), 2
        )

    def test_invalid_input_exits_one_without_touching_the_host(self):
        self.assertEqual(bd.main(["branchleft-deploy", "../edge", VALID_IMAGE]), 1)


if __name__ == "__main__":
    unittest.main()
