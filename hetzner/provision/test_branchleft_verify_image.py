"""The host verifier's gh token gate, run for real against a stub gh.

branchleft-verify-image is run by the host with no GitHub token. gh refuses to
start without a non-empty one, so on the --bundle-from-oci path (no API call) the
script gives gh a fixed constant that is not a credential. These tests run the
script itself, with a stub gh first on PATH that records the token it was given.
"""

import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFIER = os.path.join(HERE, "branchleft-verify-image")

IMAGE = "ghcr.io/branchleft/ghost-tenant@sha256:" + "a" * 64
REPO = "branchLeft/ghost-platform"
SIGNER = "branchLeft/ghost-platform/.github/workflows/registry-push.yml"
FLAG = "--bundle-from-oci"

PLACEHOLDER = "placeholder-not-a-credential"
REAL_LOOKING = "ghs_" + "k" * 36

# Records what the gh process saw, one line per variable, "UNSET" when absent.
STUB_GH = """#!/bin/sh
{
  echo "GH_TOKEN=${GH_TOKEN-UNSET}"
  echo "GITHUB_TOKEN=${GITHUB_TOKEN-UNSET}"
  echo "ARGS=$*"
} > "$STUB_RECORD"
exit "${STUB_EXIT:-0}"
"""


class VerifierTokenGateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.record = os.path.join(self.dir, "record")
        stub = os.path.join(self.dir, "gh")
        with open(stub, "w") as handle:
            handle.write(STUB_GH)
        os.chmod(stub, 0o755)

    def run_verifier(self, *args, env=None, stub_exit=0):
        base = {
            "PATH": f"{self.dir}:/usr/bin:/bin",
            "STUB_RECORD": self.record,
            "STUB_EXIT": str(stub_exit),
            "VERIFY_PLAIN_ERRORS": "1",
        }
        base.update(env or {})
        result = subprocess.run(
            ["sh", VERIFIER, *args],
            env=base,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        return result

    def seen(self):
        with open(self.record) as handle:
            return dict(line.rstrip("\n").split("=", 1) for line in handle)

    def assert_never_printed(self, result, value):
        for line in (result.stdout + result.stderr).splitlines():
            self.assertNotIn(value, line)

    def test_flag_and_no_token_gives_gh_the_placeholder(self):
        result = self.run_verifier(IMAGE, REPO, SIGNER, FLAG)
        self.assertEqual(result.returncode, 0, result.stderr)
        seen = self.seen()
        self.assertEqual(seen["GH_TOKEN"], PLACEHOLDER)
        self.assertIn(FLAG, seen["ARGS"])

    def test_flag_and_empty_tokens_gives_gh_the_placeholder(self):
        result = self.run_verifier(
            IMAGE, REPO, SIGNER, FLAG, env={"GH_TOKEN": "", "GITHUB_TOKEN": ""}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.seen()["GH_TOKEN"], PLACEHOLDER)

    def test_flag_and_a_real_gh_token_leaves_it_unchanged(self):
        result = self.run_verifier(
            IMAGE, REPO, SIGNER, FLAG, env={"GH_TOKEN": REAL_LOOKING}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.seen()["GH_TOKEN"], REAL_LOOKING)
        self.assert_never_printed(result, REAL_LOOKING)

    def test_flag_and_a_real_github_token_sets_no_placeholder(self):
        result = self.run_verifier(
            IMAGE, REPO, SIGNER, FLAG, env={"GITHUB_TOKEN": REAL_LOOKING}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        seen = self.seen()
        self.assertEqual(seen["GITHUB_TOKEN"], REAL_LOOKING)
        self.assertEqual(seen["GH_TOKEN"], "UNSET")

    def test_no_flag_and_no_token_refuses_without_a_placeholder(self):
        result = self.run_verifier(IMAGE, REPO, SIGNER)
        self.assertEqual(result.returncode, 1)
        self.assertIn("without --bundle-from-oci", result.stderr)
        self.assertIn("GH_TOKEN or GITHUB_TOKEN", result.stderr)
        self.assertFalse(os.path.exists(self.record), "gh must not have been run")
        self.assert_never_printed(result, PLACEHOLDER)

    def test_no_flag_and_a_real_token_runs_gh_with_that_token(self):
        result = self.run_verifier(
            IMAGE, REPO, SIGNER, env={"GH_TOKEN": REAL_LOOKING}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        seen = self.seen()
        self.assertEqual(seen["GH_TOKEN"], REAL_LOOKING)
        self.assertNotIn(FLAG, seen["ARGS"])

    def test_the_placeholder_is_never_printed_on_success_or_refusal(self):
        for stub_exit in (0, 1):
            result = self.run_verifier(IMAGE, REPO, SIGNER, FLAG, stub_exit=stub_exit)
            self.assertEqual(result.returncode, stub_exit)
            self.assertTrue(result.stdout + result.stderr)
            self.assert_never_printed(result, PLACEHOLDER)

    def test_a_gh_refusal_still_fails_closed_with_the_placeholder_set(self):
        result = self.run_verifier(IMAGE, REPO, SIGNER, FLAG, stub_exit=1)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no valid attestation", result.stderr)
        self.assertNotIn("verified:", result.stdout)


if __name__ == "__main__":
    unittest.main()
