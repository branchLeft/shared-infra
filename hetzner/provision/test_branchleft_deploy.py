#!/usr/bin/env python3
"""Unit tests for branchleft_deploy.

This script is the entire privilege of the CI deploy account, so its input
validation and its rollback path are security-relevant rather than
convenience behaviour, and both are covered here rather than left to a live
deploy to discover.
"""

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


if __name__ == "__main__":
    unittest.main()
