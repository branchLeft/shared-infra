#!/usr/bin/env python3
"""The promote route reaches the real wrapper's attestation check before any pin moves.

The applier builds the wrapper's argv; here that argv drives the real
branchleft_deploy.main, with only the verifier and systemctl faked. A ledger
entry the verifier refuses must leave the pin file untouched and never reach
systemctl, and the same route with an accepted image must advance.
"""

import contextlib
import functools
import io
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import branchleft_deploy as bd
import branchleft_promote as bp

DIGEST = "d" * 64
REGISTERED = f"ghcr.io/branchleft/ghost-tenant@sha256:{DIGEST}"
PREVIOUS = f"ghcr.io/branchleft/ghost-tenant@sha256:{'e' * 64}"
ACTION = bp.Action(30001, "blog", REGISTERED, "6.55.1")


class ScriptedRun:
    """Stands in for subprocess.run inside the wrapper: verifier first, then systemctl."""

    def __init__(self, verifier_code: int, verifier_stderr: str = ""):
        self.verifier_code = verifier_code
        self.verifier_stderr = verifier_stderr
        self.calls: list[list[str]] = []

    def __call__(self, argv, check=False, capture_output=False, text=False, **kwargs):
        self.calls.append(list(argv))
        if argv[0] == bd.VERIFIER:
            return subprocess.CompletedProcess(argv, self.verifier_code, "", self.verifier_stderr)
        return subprocess.CompletedProcess(argv, 0, "", "")


class WrapperContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config_dir = os.path.join(self.directory.name, "etc")
        self.stack_dir = os.path.join(self.directory.name, "opt")
        os.makedirs(self.config_dir)
        os.makedirs(os.path.join(self.stack_dir, "blog"))
        with open(os.path.join(self.stack_dir, "blog", "compose.yml"), "w", encoding="utf-8") as h:
            h.write("services:\n  app:\n    image: ${IMAGE}\n    healthcheck:\n      test: ['CMD', 'true']\n")
        self.env_path = bd.image_env_path("blog", self.config_dir)
        bd.write_image_env(self.env_path, PREVIOUS)

    def route(self, wrapper_run: ScriptedRun) -> tuple[bool, list[list[str]]]:
        """Run the applier with the real wrapper as the thing it calls."""
        argvs: list[list[str]] = []
        deploy = functools.partial(
            bd.deploy,
            config_dir=self.config_dir,
            stack_dir=self.stack_dir,
            run=wrapper_run,
        )

        def as_the_wrapper(argv, **kwargs):
            argvs.append(list(argv))
            sink = io.StringIO()
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                code = bd.main(["branchleft-deploy", *argv[1:]], deploy=deploy)
            return subprocess.CompletedProcess(argv, code)

        return bp.apply_action(ACTION, run=as_the_wrapper), argvs

    def test_the_applier_builds_exactly_the_wrappers_two_argument_form(self):
        _, argvs = self.route(ScriptedRun(0))
        self.assertEqual(argvs, [[bp.WRAPPER, "blog", REGISTERED]])

    def test_an_image_the_verifier_refuses_never_moves_the_pin_or_reaches_systemctl(self):
        run = ScriptedRun(1, "verification failed")
        with mock.patch.object(bd, "verify_attestation", wraps=bd.verify_attestation) as spy:
            advanced, _ = self.route(run)
        self.assertFalse(advanced)
        spy.assert_called_once()
        self.assertEqual(bd.read_current_image(self.env_path), PREVIOUS)
        self.assertEqual([call[0] for call in run.calls], [bd.VERIFIER])
        self.assertFalse([c for c in run.calls if c[0] == "systemctl"])

    def test_the_verifier_is_given_the_digest_the_ledger_named(self):
        run = ScriptedRun(1)
        self.route(run)
        self.assertEqual(run.calls[0][1], REGISTERED)

    def test_an_image_the_verifier_accepts_advances_through_the_same_route(self):
        run = ScriptedRun(0)
        advanced, _ = self.route(run)
        self.assertTrue(advanced)
        self.assertEqual(bd.read_current_image(self.env_path), REGISTERED)
        self.assertEqual(
            [call[0] for call in run.calls],
            [bd.VERIFIER, "systemctl"],
            "the verifier must run before anything restarts",
        )

    def test_a_host_that_cannot_run_the_verifier_refuses_the_move(self):
        def cannot(argv, **kwargs):
            raise FileNotFoundError(argv[0])

        advanced, _ = self.route(cannot)
        self.assertFalse(advanced)
        self.assertEqual(bd.read_current_image(self.env_path), PREVIOUS)


if __name__ == "__main__":
    unittest.main()
