#!/usr/bin/env python3
"""Offline attestation verification in branchleft_deploy (branchLeft/workspace#3133).

A host with no outbound access cannot read an attestation from the registry. On such a host
the image's attestation bundle and manifest travel with the delivery, are staged under
OFFLINE_STAGING_DIR by digest, and are verified against a trusted root pinned on the host. These
tests show the three halves of that:

  * the offline path is chosen by the host's trusted root and never falls back to the registry;
  * a missing, tampered, mis-hashed or untrustworthy staged file is refused before any host change;
  * a real gh, with every network call made to fail, verifies a real attestation of a real image
    and refuses the same bundle once it is altered.

The real-gh tests need a gh with `attestation verify --bundle` and are skipped without one. CI's
runner has gh.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

import branchleft_deploy as bd

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures" / "offline-attestation"
# The trusted root the deploy_verifier role installs. The one copy: the test reads the role's file,
# so the root the host is given is the root these tests prove can verify a real attestation.
ROLE_TRUSTED_ROOT = HERE.parent.parent / "ansible" / "roles" / "deploy_verifier" / "files" / "trusted_root.jsonl"

# A real, public tenant image, attested by registry-push.yml on refs/heads/main. The manifest
# fixture is the image's manifest, so its sha256 is the digest. The bundle is its attestation.
REAL_DIGEST = "0d8ddc21a9e51237e1d709614973f7b418d9a0c69e0933e4301281ee90481ae4"
REAL_IMAGE = f"ghcr.io/branchleft/ghost-tenant@sha256:{REAL_DIGEST}"
REAL_SIGNER = "branchLeft/ghost-platform/.github/workflows/registry-push.yml"

GH = shutil.which("gh")

Run = Callable[..., "subprocess.CompletedProcess[str]"]


class Recorder:
    """A stand-in for subprocess.run that records each call and returns a canned exit code."""

    def __init__(self, code: int = 0, stderr: str = "") -> None:
        self.code = code
        self.stderr = stderr
        self.calls: list[list[str]] = []
        self.kwargs: list[dict[str, Any]] = []
        self.staged: list[dict[str, bytes]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> "subprocess.CompletedProcess[str]":
        self.calls.append(list(argv))
        self.kwargs.append(kwargs)
        # What gh would be given to read, captured now because the copies are removed afterwards.
        seen: dict[str, bytes] = {}
        if argv[0] == bd.GH_BIN:
            for flag in ("--bundle", "--custom-trusted-root"):
                seen[flag] = Path(argv[argv.index(flag) + 1]).read_bytes()
            seen["artifact"] = Path(argv[3]).read_bytes()
        self.staged.append(seen)
        return subprocess.CompletedProcess(argv, self.code, stdout="", stderr=self.stderr)


class OfflineCase(unittest.TestCase):
    """A host with a trusted root, a staging directory and the real fixtures staged by digest."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.trusted_root = self.root / "attestation" / "trusted_root.jsonl"
        self.staging = self.root / "attestations"
        self.trusted_root.parent.mkdir()
        self.staging.mkdir()
        shutil.copyfile(ROLE_TRUSTED_ROOT, self.trusted_root)
        self.stage(REAL_DIGEST)

        for name, value in (
            ("OFFLINE_TRUSTED_ROOT", str(self.trusted_root)),
            ("OFFLINE_STAGING_DIR", str(self.staging)),
            ("OFFLINE_OWNER_UID", os.getuid()),
        ):
            patcher = mock.patch.object(bd, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def stage(self, digest: str) -> Path:
        directory = self.staging / digest
        directory.mkdir(exist_ok=True)
        shutil.copyfile(FIXTURES / "manifest.json", directory / "manifest.json")
        shutil.copyfile(FIXTURES / "bundle.jsonl", directory / "bundle.jsonl")
        return directory

    def staged(self, name: str = "bundle.jsonl") -> Path:
        return self.staging / REAL_DIGEST / name

    def refused(self, run: Run, image: str = REAL_IMAGE) -> str:
        with self.assertRaises(bd.DeployError) as caught:
            bd.verify_attestation(image, run=run)
        return str(caught.exception)


class SelectionTests(OfflineCase):
    def test_a_host_with_a_trusted_root_verifies_offline_with_gh_and_never_the_registry_verifier(
        self,
    ) -> None:
        run = Recorder()
        self.assertTrue(bd.verify_attestation(REAL_IMAGE, run=run))
        self.assertEqual(len(run.calls), 1)
        argv = run.calls[0]
        self.assertEqual(argv[0], bd.GH_BIN)
        self.assertEqual(argv[1:3], ["attestation", "verify"])
        self.assertNotIn("--bundle-from-oci", argv)
        self.assertNotIn(bd.VERIFIER, argv)
        self.assertFalse(any(arg.startswith("oci://") for arg in argv))

    def test_gh_is_given_the_staged_bundle_and_manifest_and_the_hosts_own_trusted_root(self) -> None:
        run = Recorder()
        bd.verify_attestation(REAL_IMAGE, run=run)
        seen = run.staged[0]
        self.assertEqual(seen["--bundle"], (FIXTURES / "bundle.jsonl").read_bytes())
        self.assertEqual(seen["artifact"], (FIXTURES / "manifest.json").read_bytes())
        self.assertEqual(seen["--custom-trusted-root"], ROLE_TRUSTED_ROOT.read_bytes())

    def test_the_identity_checks_are_the_online_verifiers_checks(self) -> None:
        run = Recorder()
        bd.verify_attestation(REAL_IMAGE, run=run)
        argv = run.calls[0]

        def after(flag: str) -> str:
            return argv[argv.index(flag) + 1]

        self.assertEqual(after("--repo"), bd.ATTESTED_REPO)
        self.assertEqual(after("--signer-workflow"), REAL_SIGNER)
        self.assertEqual(after("--source-ref"), "refs/heads/main")
        self.assertEqual(after("--cert-oidc-issuer"), "https://token.actions.githubusercontent.com")
        self.assertIn("--deny-self-hosted-runners", argv)

    def test_the_environment_holds_no_credential_and_no_registry_key(self) -> None:
        run = Recorder()
        bd.verify_attestation(REAL_IMAGE, run=run)
        self.assertEqual(
            run.kwargs[0]["env"],
            {
                "PATH": "/usr/local/libexec/branchleft-verifier:/usr/bin:/bin",
                "HOME": "/var/lib/branchleft/verifier-home",
                "GH_CONFIG_DIR": "/var/lib/branchleft/verifier-home",
                "XDG_CONFIG_HOME": "/var/lib/branchleft/verifier-home",
                "GH_PROMPT_DISABLED": "1",
                "GH_NO_UPDATE_NOTIFIER": "1",
                "LC_ALL": "C",
            },
        )
        self.assertEqual(run.kwargs[0]["stdin"], subprocess.DEVNULL)

    def test_an_image_outside_the_register_is_not_verified_here_and_runs_nothing(self) -> None:
        run = Recorder()
        self.assertFalse(bd.verify_attestation(f"ghcr.io/branchleft/other@sha256:{'a' * 64}", run=run))
        self.assertEqual(run.calls, [])

    def test_a_host_without_a_trusted_root_still_uses_the_registry_verifier(self) -> None:
        self.trusted_root.unlink()
        run = Recorder()
        self.assertTrue(bd.verify_attestation(REAL_IMAGE, run=run))
        self.assertEqual(run.calls[0][0], bd.VERIFIER)
        self.assertIn("--bundle-from-oci", run.calls[0])


class RefusalTests(OfflineCase):
    """Each refusal leaves gh unrun, so nothing a host holds can make a bad bundle pass."""

    def assert_refused_without_running_gh(self, run: Recorder, *needles: str) -> None:
        message = self.refused(run)
        self.assertEqual(run.calls, [], "gh must not run on a file that failed a check")
        for needle in needles:
            self.assertIn(needle, message)

    def test_a_missing_bundle_is_refused_and_never_falls_back_to_the_registry(self) -> None:
        self.staged().unlink()
        run = Recorder()
        self.assert_refused_without_running_gh(run, "bundle.jsonl", "not staged")

    def test_a_missing_manifest_is_refused(self) -> None:
        self.staged("manifest.json").unlink()
        run = Recorder()
        self.assert_refused_without_running_gh(run, "manifest.json", "not staged")

    def test_an_image_nothing_was_staged_for_is_refused(self) -> None:
        run = Recorder()
        other = f"ghcr.io/branchleft/ghost-tenant@sha256:{'c' * 64}"
        message = self.refused(run, other)
        self.assertEqual(run.calls, [])
        self.assertIn("not staged", message)

    def test_a_manifest_that_does_not_hash_to_the_digest_is_refused(self) -> None:
        wrong = "e" * 64
        directory = self.stage(wrong)
        self.assertTrue((directory / "manifest.json").exists())
        run = Recorder()
        message = self.refused(run, f"ghcr.io/branchleft/ghost-tenant@sha256:{wrong}")
        self.assertEqual(run.calls, [])
        self.assertIn("does not hash to", message)

    def test_a_manifest_altered_after_staging_is_refused(self) -> None:
        with self.staged("manifest.json").open("ab") as handle:
            handle.write(b" ")
        run = Recorder()
        self.assert_refused_without_running_gh(run, "does not hash to")

    def test_an_empty_bundle_is_refused(self) -> None:
        self.staged().write_bytes(b"")
        run = Recorder()
        self.assert_refused_without_running_gh(run, "bundle.jsonl", "empty")

    def test_an_oversized_file_is_refused(self) -> None:
        self.staged().write_bytes(b"x" * (bd.OFFLINE_FILE_LIMIT + 1))
        run = Recorder()
        self.assert_refused_without_running_gh(run, "bundle.jsonl", "larger than")

    def test_a_symlinked_bundle_is_refused(self) -> None:
        target = self.root / "elsewhere.jsonl"
        shutil.copyfile(FIXTURES / "bundle.jsonl", target)
        self.staged().unlink()
        self.staged().symlink_to(target)
        run = Recorder()
        self.assert_refused_without_running_gh(run, "bundle.jsonl")

    def test_a_hard_linked_bundle_is_refused(self) -> None:
        os.link(self.staged(), self.root / "second-name")
        run = Recorder()
        self.assert_refused_without_running_gh(run, "bundle.jsonl", "linked")

    def test_a_fifo_for_a_bundle_is_refused_without_blocking(self) -> None:
        self.staged().unlink()
        os.mkfifo(self.staged())
        run = Recorder()
        self.assert_refused_without_running_gh(run, "bundle.jsonl", "regular")

    def test_a_group_or_world_writable_bundle_is_refused(self) -> None:
        os.chmod(self.staged(), 0o666)
        run = Recorder()
        self.assert_refused_without_running_gh(run, "bundle.jsonl", "writable")

    def test_a_bundle_not_owned_by_the_trusted_account_is_refused(self) -> None:
        with mock.patch.object(bd, "OFFLINE_OWNER_UID", os.getuid() + 1):
            run = Recorder()
            self.assert_refused_without_running_gh(run, "owned by")

    def test_a_writable_staging_directory_is_refused(self) -> None:
        os.chmod(self.staging / REAL_DIGEST, 0o777)
        run = Recorder()
        self.assert_refused_without_running_gh(run, "writable")

    def test_a_symlinked_digest_directory_is_refused(self) -> None:
        real = self.root / "real"
        (self.staging / REAL_DIGEST).rename(real)
        (self.staging / REAL_DIGEST).symlink_to(real)
        run = Recorder()
        self.assert_refused_without_running_gh(run, "directory")

    def test_a_trusted_root_that_is_a_symlink_is_refused(self) -> None:
        target = self.root / "root-elsewhere.jsonl"
        shutil.copyfile(ROLE_TRUSTED_ROOT, target)
        self.trusted_root.unlink()
        self.trusted_root.symlink_to(target)
        run = Recorder()
        self.assert_refused_without_running_gh(run, "trusted_root.jsonl")

    def test_gh_refusing_the_bundle_refuses_the_deploy(self) -> None:
        run = Recorder(code=1, stderr="Error: verifying with issuer \"sigstore.dev\"")
        message = self.refused(run)
        self.assertEqual(len(run.calls), 1)
        self.assertIn(REAL_SIGNER, message)
        self.assertIn("refs/heads/main", message)

    def test_a_gh_that_asks_for_a_login_is_refused_with_the_credential_message(self) -> None:
        run = Recorder(code=4, stderr="To get started with GitHub CLI, please run:  gh auth login")
        self.assertIn("credentials this host does not hold", self.refused(run))

    def test_a_missing_gh_is_refused(self) -> None:
        def missing(argv: list[str], **kwargs: Any) -> "subprocess.CompletedProcess[str]":
            raise FileNotFoundError(argv[0])

        self.assertIn("without verifying", self.refused(missing))

    def test_refusals_never_print_the_bundle(self) -> None:
        run = Recorder(code=1)
        message = self.refused(run)
        self.assertNotIn("dsseEnvelope", message)


class DeployWiringTests(OfflineCase):
    """deploy() verifies offline before the lock, the pin write and any restart."""

    def setUp(self) -> None:
        super().setUp()
        self.config_dir = str(self.root / "etc")
        self.stack_dir = str(self.root / "opt")
        os.makedirs(self.config_dir)
        os.makedirs(os.path.join(self.stack_dir, "edge"))
        with open(os.path.join(self.stack_dir, "edge", "compose.yml"), "w", encoding="utf-8") as handle:
            handle.write("services:\n  app:\n    image: ${IMAGE}\n    healthcheck:\n      test: ['CMD', 'true']\n")

    def test_a_refused_bundle_leaves_no_pin_and_runs_no_restart(self) -> None:
        self.staged().unlink()
        run = Recorder()
        with self.assertRaises(bd.DeployError):
            bd.deploy("edge", REAL_IMAGE, config_dir=self.config_dir, stack_dir=self.stack_dir, run=run)
        self.assertFalse(os.path.exists(bd.image_env_path("edge", self.config_dir)))
        self.assertEqual(run.calls, [])


@unittest.skipUnless(GH, "gh is not installed")
class RealGhTests(OfflineCase):
    """A real gh, with every network call made to fail, against a real attestation.

    The proxy variables point at a port nothing listens on, so a request to the registry, the TUF
    mirrors or the GitHub API would fail the verification. The sabotage cases alter one thing at a
    time and show the same verifier refusing, so the green case is not green by accident.
    """

    def setUp(self) -> None:
        super().setUp()
        home = self.root / "home"
        home.mkdir()
        patcher = mock.patch.object(bd, "GH_BIN", GH)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.run_real = self.make_run(home)

    @staticmethod
    def make_run(home: Path) -> Run:
        def run(argv: list[str], **kwargs: Any) -> "subprocess.CompletedProcess[str]":
            env = dict(kwargs.pop("env"))
            for name in ("HOME", "GH_CONFIG_DIR", "XDG_CONFIG_HOME"):
                env[name] = str(home)
            env["PATH"] = f"{Path(str(GH)).parent}:/usr/bin:/bin"
            for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
                env[name] = "http://127.0.0.1:9"
            env["NO_PROXY"] = ""
            return subprocess.run(argv, env=env, **kwargs)

        return run

    def test_a_real_attestation_verifies_with_no_network(self) -> None:
        self.assertTrue(bd.verify_attestation(REAL_IMAGE, run=self.run_real))

    def test_a_tampered_bundle_is_refused(self) -> None:
        lines = self.staged().read_text(encoding="utf-8").splitlines()
        bundle = json.loads(lines[0])
        signature = bundle["dsseEnvelope"]["signatures"][0]["sig"]
        bundle["dsseEnvelope"]["signatures"][0]["sig"] = ("A" if signature[0] != "A" else "B") + signature[1:]
        self.staged().write_text(json.dumps(bundle) + "\n", encoding="utf-8")
        self.assertIn("is not attested", self.refused(self.run_real))

    def test_a_bundle_for_another_artifact_is_refused(self) -> None:
        # The manifest is altered and the digest re-derived from it, so the host's own hash check
        # passes and it is gh, on the bundle's subject digest, that refuses.
        altered = (FIXTURES / "manifest.json").read_bytes() + b" "
        digest = hashlib.sha256(altered).hexdigest()
        directory = self.stage(digest)
        (directory / "manifest.json").write_bytes(altered)
        image = f"ghcr.io/branchleft/ghost-tenant@sha256:{digest}"
        self.assertIn("is not attested", self.refused(self.run_real, image))

    def test_a_bundle_signed_by_another_workflow_is_refused(self) -> None:
        other = {"ghcr.io/branchleft/ghost-tenant": "branchLeft/ghost-platform/.github/workflows/portal-apps-image.yml"}
        with mock.patch.object(bd, "ATTESTED_IMAGES", other):
            self.assertIn("is not attested", self.refused(self.run_real))

    def test_a_missing_bundle_is_refused(self) -> None:
        self.staged().unlink()
        self.assertIn("not staged", self.refused(self.run_real))

    def test_a_truncated_trusted_root_is_refused(self) -> None:
        self.trusted_root.write_bytes(b'{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}\n')
        self.assertIn("is not attested", self.refused(self.run_real))


class FixtureTests(unittest.TestCase):
    def test_the_manifest_fixture_hashes_to_the_image_digest(self) -> None:
        self.assertEqual(hashlib.sha256((FIXTURES / "manifest.json").read_bytes()).hexdigest(), REAL_DIGEST)

    def test_the_fixture_files_are_ordinary_files(self) -> None:
        for path in (FIXTURES / "manifest.json", FIXTURES / "bundle.jsonl", ROLE_TRUSTED_ROOT):
            self.assertTrue(stat.S_ISREG(os.lstat(path).st_mode), path)


if __name__ == "__main__":
    unittest.main()
