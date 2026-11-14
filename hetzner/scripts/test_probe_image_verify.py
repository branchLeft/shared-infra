"""Tests for probe-image-verify against the real wrapper code and a model of the host's verifier.

A check that cannot fail is not a check, so SabotageTests runs the probe against hosts whose
verifier is broken in each way that matters and expects red.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import subprocess
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SCRIPT = HERE / "probe-image-verify.py"
WRAPPER_SOURCE = ROOT / "hetzner" / "provision" / "branchleft_deploy.py"


def load(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


probe = load(SCRIPT, "probe_image_verify")
wrapper = load(WRAPPER_SOURCE, "branchleft_deploy_under_test")

REAL = "ghcr.io/branchleft/ghost-tenant@sha256:" + "ab" * 32
OTHER_REGISTERED = "ghcr.io/branchleft/portal-apps"


class FakeVerifier:
    """The host's branchleft-verify-image: accepts one digest from one signer, as the real one does."""

    def __init__(self, mode: str = "correct") -> None:
        self.mode = mode
        self.calls: list[list[str]] = []

    def __call__(self, argv, **_kwargs):
        self.calls.append(list(argv))
        if self.mode == "missing":
            raise FileNotFoundError(argv[0])
        if self.mode == "login":
            return subprocess.CompletedProcess(argv, 1, "", "error: run gh auth login")
        if self.mode == "accept-all":
            return subprocess.CompletedProcess(argv, 0, "", "")
        if self.mode == "refuse-all":
            return subprocess.CompletedProcess(argv, 1, "", "error: no attestation")
        _verifier, image, _repo, signer, flag = argv
        right = wrapper.ATTESTED_IMAGES["ghcr.io/branchleft/ghost-tenant"]
        if image == REAL and signer == right and flag == "--bundle-from-oci":
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 1, "", "error: no valid attestation")


def results(mode: str) -> dict[str, object]:
    out = probe.run_probe(wrapper, REAL, run=FakeVerifier(mode))
    return {r.name: r for r in out}


class CorrectHostTests(unittest.TestCase):
    def test_a_correct_host_passes_all_three(self):
        out = results("correct")
        self.assertEqual(
            set(out),
            {"real-image-accepted", "unsigned-image-refused", "wrong-identity-refused"},
        )
        self.assertTrue(
            all(r.passed for r in out.values()), [r.line() for r in out.values()]
        )

    def test_the_unsigned_digest_is_not_the_real_one_and_keeps_the_name(self):
        fake = FakeVerifier("correct")
        probe.run_probe(wrapper, REAL, run=fake)
        images = [call[1] for call in fake.calls]
        self.assertIn(
            f"ghcr.io/branchleft/ghost-tenant@sha256:{probe.UNSIGNED_DIGEST}", images
        )
        self.assertNotEqual(probe.UNSIGNED_DIGEST, "ab" * 32)

    def test_the_wrong_identity_is_another_registered_workflow(self):
        fake = FakeVerifier("correct")
        probe.run_probe(wrapper, REAL, run=fake)
        signers = {call[3] for call in fake.calls}
        self.assertEqual(
            signers,
            set(wrapper.ATTESTED_IMAGES.values()),
            "the probe asks with the right signer and with the other registered one",
        )

    def test_a_tagged_spelling_is_probed_as_the_register_name(self):
        tagged = "ghcr.io/branchleft/ghost-tenant:latest@sha256:" + "ab" * 32
        out = probe.run_probe(wrapper, tagged, run=FakeVerifier("correct"))
        self.assertTrue(all(r.passed for r in out), [r.line() for r in out])


class SabotageTests(unittest.TestCase):
    """Each broken host must turn the probe red, and for the stated reason."""

    def test_a_verifier_that_accepts_everything_fails_both_refusal_checks(self):
        out = results("accept-all")
        self.assertTrue(out["real-image-accepted"].passed)
        self.assertFalse(out["unsigned-image-refused"].passed)
        self.assertIn("ACCEPTED", out["unsigned-image-refused"].detail)
        self.assertFalse(out["wrong-identity-refused"].passed)
        self.assertIn("ACCEPTED", out["wrong-identity-refused"].detail)

    def test_a_verifier_that_refuses_everything_fails_the_control_and_stops(self):
        out = results("refuse-all")
        self.assertEqual(list(out), ["real-image-accepted"])
        self.assertFalse(out["real-image-accepted"].passed)

    def test_a_missing_verifier_fails_the_control(self):
        out = results("missing")
        self.assertEqual(list(out), ["real-image-accepted"])
        self.assertFalse(out["real-image-accepted"].passed)

    def test_a_host_asking_for_a_credential_fails_the_control(self):
        out = results("login")
        self.assertEqual(list(out), ["real-image-accepted"])
        self.assertIn("credentials", out["real-image-accepted"].detail)

    def test_a_refusal_for_a_host_fault_is_not_counted_as_a_refusal(self):
        correct = FakeVerifier("correct")

        def login_after_control(argv, **kwargs):
            if not correct.calls:
                return correct(argv, **kwargs)
            return subprocess.CompletedProcess(argv, 1, "", "error: run gh auth login")

        out = {
            r.name: r for r in probe.run_probe(wrapper, REAL, run=login_after_control)
        }
        self.assertTrue(out["real-image-accepted"].passed)
        self.assertFalse(out["unsigned-image-refused"].passed)
        self.assertFalse(out["wrong-identity-refused"].passed)

    def test_an_image_outside_the_register_is_not_a_control(self):
        out = probe.run_probe(
            wrapper,
            "ghcr.io/branchleft/website@sha256:" + "ab" * 32,
            run=FakeVerifier("correct"),
        )
        self.assertEqual(len(out), 1)
        self.assertFalse(out[0].passed)


class ExitCodeTests(unittest.TestCase):
    def run_main(self, mode: str, euid: int = 0) -> int:
        original = (probe.load_wrapper, probe.os.geteuid, probe.subprocess.run)
        probe.load_wrapper = lambda _path: wrapper
        probe.os.geteuid = lambda: euid
        fake = FakeVerifier(mode)
        # run_probe's default is bound at definition, so route main through the fake.
        real_run_probe = probe.run_probe
        probe.run_probe = lambda w, image: real_run_probe(w, image, run=fake)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                return probe.main(["probe", "--accepted-image", REAL])
        finally:
            probe.load_wrapper, probe.os.geteuid, probe.subprocess.run = original
            probe.run_probe = real_run_probe

    def test_exit_zero_only_when_all_three_pass(self):
        self.assertEqual(self.run_main("correct"), 0)

    def test_exit_one_when_a_host_accepts_everything(self):
        self.assertEqual(self.run_main("accept-all"), 1)

    def test_exit_one_when_the_control_fails(self):
        self.assertEqual(self.run_main("refuse-all"), 1)

    def test_a_non_root_run_is_refused_before_any_check(self):
        self.assertEqual(self.run_main("correct", euid=1000), 2)


class WrapperContractTests(unittest.TestCase):
    """The probe leans on the wrapper's names; if they move, this fails before a host does."""

    def test_the_wrapper_names_the_probe_uses_exist(self):
        for attribute in (
            "verify_attestation",
            "attested_name",
            "verifier_env",
            "VERIFIER",
            "ATTESTED_REPO",
            "ATTESTED_IMAGES",
            "DeployError",
        ):
            self.assertTrue(hasattr(wrapper, attribute), attribute)

    def test_the_refusal_words_are_the_wrappers_own(self):
        text = WRAPPER_SOURCE.read_text(encoding="utf-8")
        self.assertIn(probe.REFUSAL_MARKER, text)
        self.assertIn(probe.LOGIN_MARKER, text)

    def test_two_signers_are_registered_so_a_wrong_identity_exists(self):
        self.assertGreaterEqual(len(set(wrapper.ATTESTED_IMAGES.values())), 2)
        self.assertIn(OTHER_REGISTERED, wrapper.ATTESTED_IMAGES)


if __name__ == "__main__":
    unittest.main()
