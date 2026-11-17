#!/usr/bin/env python3
"""Tests for UNATTESTED_STACK_DIGESTS, the temporary exemption of single digests.

See branchleft_deploy.md, "UNATTESTED_STACK_DIGESTS". The exemption lets one stack
redeploy one exact image digest with no attestation check, and nothing else. The
last class is the guard that ends it: once ops1's control plane pin names any
other digest, the entry must go in the same change.
"""

import io
import os
import pathlib
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr

import yaml

import branchleft_deploy as bd

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
OPS1_OWNER_VARS = REPO_ROOT / "ansible" / "owner_vars" / "ops1.yml"

PORTAL_NAME = "ghcr.io/branchleft/portal-apps"
EXEMPT_DIGEST = "2231a370a0d7e7746778e502ad70963e5c322bfae0de427e3ed2021d80ac0f7b"
EXEMPT = f"{PORTAL_NAME}@sha256:{EXEMPT_DIGEST}"
OTHER = f"{PORTAL_NAME}@sha256:{'e' * 64}"
PORTAL_SIGNER = "branchLeft/ghost-platform/.github/workflows/portal-apps-image.yml"
REFUSAL = "no valid attestation"

COMPOSE = "services:\n  app:\n    image: ${IMAGE}\n    healthcheck:\n      test: ['CMD', 'true']\n"


def pin_only_model(_directory):
    """The rendered Compose model of COMPOSE, so no test here starts `docker`."""
    return {"services": {"app": {"image": "${IMAGE}"}}}


class Run:
    """Stands in for subprocess.run: records each argv and answers from a queue.

    A queued answer is an exit code, or a (code, stderr) pair for the verifier.
    """

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, argv, check=False, capture_output=False, text=False, **kwargs):
        self.calls.append(list(argv))
        answer = self.answers.pop(0) if self.answers else 0
        code, stderr = answer if isinstance(answer, tuple) else (answer, "")
        return subprocess.CompletedProcess(argv, code, stdout="", stderr=stderr)


class DigestExemptionTests(unittest.TestCase):
    """The exempt digest skips the verifier on its own stack, and only there."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config_dir = os.path.join(self.directory.name, "etc")
        self.stack_dir = os.path.join(self.directory.name, "opt")
        os.makedirs(self.config_dir)

    def deploy(self, stack, image, run):
        directory = os.path.join(self.stack_dir, stack)
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "compose.yml"), "w", encoding="utf-8") as handle:
            handle.write(COMPOSE)
        log = io.StringIO()
        with redirect_stderr(log):
            bd.deploy(
                stack,
                image,
                config_dir=self.config_dir,
                stack_dir=self.stack_dir,
                run=run,
                render=pin_only_model,
            )
        return log.getvalue()

    def pin(self, stack):
        return bd.read_current_image(bd.image_env_path(stack, self.config_dir))

    def assert_verified_and_refused(self, stack, image):
        run = Run([(1, REFUSAL)])
        with self.assertRaises(bd.DeployError) as caught:
            self.deploy(stack, image, run)
        self.assertIn("is not attested by", str(caught.exception))
        self.assertEqual(
            run.calls,
            [[bd.VERIFIER, f"{PORTAL_NAME}@{image.partition('@')[2]}", bd.ATTESTED_REPO,
              PORTAL_SIGNER, "--bundle-from-oci"]],
        )
        self.assertIsNone(self.pin(stack))

    def test_the_exempt_digest_deploys_on_control_plane_without_the_verifier(self):
        run = Run([0])
        log = self.deploy("control-plane", EXEMPT, run)
        self.assertEqual(run.calls, [["systemctl", "restart", "branchleft-compose@control-plane"]])
        self.assertEqual(self.pin("control-plane"), EXEMPT)
        self.assertIn("UNATTESTED_STACK_DIGESTS", log)

    def test_a_tag_or_port_spelling_of_the_exempt_digest_is_exempt_too(self):
        for image in (
            f"{PORTAL_NAME}:v1@sha256:{EXEMPT_DIGEST}",
            f"ghcr.io:443/branchleft/portal-apps@sha256:{EXEMPT_DIGEST}",
        ):
            with self.subTest(image=image):
                run = Run([0])
                self.deploy("control-plane", image, run)
                self.assertEqual(
                    run.calls, [["systemctl", "restart", "branchleft-compose@control-plane"]]
                )

    def test_any_other_portal_digest_on_control_plane_is_still_verified(self):
        self.assert_verified_and_refused("control-plane", OTHER)

    def test_a_digest_that_differs_in_one_character_is_still_verified(self):
        self.assert_verified_and_refused(
            "control-plane", f"{PORTAL_NAME}@sha256:{EXEMPT_DIGEST[:-1]}c"
        )

    def test_the_exempt_digest_on_any_other_stack_is_verified_and_refused(self):
        for stack in ("blog", "edge", "dbt1", "website", "db"):
            with self.subTest(stack=stack):
                self.assert_verified_and_refused(stack, EXEMPT)

    def test_the_table_holds_exactly_the_one_reviewed_entry(self):
        self.assertEqual(bd.UNATTESTED_STACK_DIGESTS, {"control-plane": frozenset({EXEMPT})})

    def test_every_entry_is_a_registered_image_pinned_by_digest(self):
        for references in bd.UNATTESTED_STACK_DIGESTS.values():
            for reference in references:
                with self.subTest(reference=reference):
                    bd.validate_image_ref(reference)
                    self.assertIn(bd.attested_name(reference), bd.ATTESTED_IMAGES)


def stale_digest_exemptions(owner_vars_text, table):
    """The control-plane entries a moved ops1 pin has made stale.

    An entry is stale once owner_vars pins control_plane_app_image to anything that
    is not that entry: the host no longer redeploys the exempt digest.
    """
    data = yaml.safe_load(owner_vars_text) or {}
    pin = data.get("control_plane_app_image")
    entries = table.get("control-plane", frozenset())
    if not pin or pin in entries:
        return []
    return sorted(entries)


class DigestExemptionEndsWithThePinTests(unittest.TestCase):
    """The guard: the exemption cannot outlive ops1's move to an attested digest."""

    def test_ops1_has_not_moved_its_pin_off_an_exempt_digest(self):
        stale = stale_digest_exemptions(
            OPS1_OWNER_VARS.read_text(encoding="utf-8"), bd.UNATTESTED_STACK_DIGESTS
        )
        self.assertEqual(
            stale,
            [],
            "ansible/owner_vars/ops1.yml pins control_plane_app_image to another digest, so "
            "remove these entries from UNATTESTED_STACK_DIGESTS in branchleft_deploy.py in "
            "the same change",
        )

    def test_the_guard_passes_with_no_pin_or_the_exempt_pin(self):
        table = {"control-plane": frozenset({EXEMPT})}
        for text in ("---\nother_key: 1\n", "---\ncontrol_plane_app_image: ''\n",
                     f"---\ncontrol_plane_app_image: '{EXEMPT}'\n"):
            with self.subTest(text=text):
                self.assertEqual(stale_digest_exemptions(text, table), [])

    def test_the_guard_fails_once_the_pin_names_another_digest(self):
        table = {"control-plane": frozenset({EXEMPT})}
        text = f"---\ncontrol_plane_app_image: '{OTHER}'\n"
        self.assertEqual(stale_digest_exemptions(text, table), [EXEMPT])

    def test_the_guard_is_quiet_once_the_entry_is_removed(self):
        text = f"---\ncontrol_plane_app_image: '{OTHER}'\n"
        self.assertEqual(stale_digest_exemptions(text, {}), [])


if __name__ == "__main__":
    unittest.main()
