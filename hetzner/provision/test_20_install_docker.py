#!/usr/bin/env python3
"""Unit tests for 20-install-docker.sh signing-key verification.

Real-GnuPG rows use Docker's public key (a fixture) and a throwaway key; stub
GnuPG rows feed a chosen colon listing. System commands are logging stubs.
The positive row is judged by what the script writes, not its exit code:
macOS has no /etc/os-release, read after the keyring step.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(__file__)
SCRIPT = os.path.join(HERE, "20-install-docker.sh")
DOCKER_KEY_FIXTURE = os.path.join(HERE, "fixtures", "docker-apt-key.asc")

with open(SCRIPT, encoding="utf-8") as _fh:
    PINNED_FPR = re.search(r'^EXPECTED_FPR="([0-9A-F]{40})"', _fh.read(), re.MULTILINE).group(1)

FAKE_CURL = """#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
cp "$FAKE_KEY_PATH" "$out"
"""

LOGGING_STUB = """#!/usr/bin/env bash
echo "$(basename "$0") $*" >> "$FAKE_CALL_LOG"
exit 0
"""

STUB_GPG = """#!/usr/bin/env bash
printf '%s\\n' "$FAKE_GPG_LISTING"
"""


def _stub(path, body):
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o755)


def _listing(*fprs):
    """A colon listing with one pub record per fingerprint, as gpg prints it."""
    lines = []
    for fpr in fprs:
        lines.append("pub:-:4096:1:0000000000000000:1487788586:::-:::scESC::::::23::0:")
        lines.append(f"fpr:::::::::{fpr}:")
    return "\n".join(lines)


def _one_digit_changed(fpr):
    last = fpr[-1]
    return fpr[:-1] + ("0" if last != "0" else "1")


@unittest.skipUnless(shutil.which("gpg"), "gpg is required to build a test key")
class DockerSigningKeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.bin = os.path.join(root, "bin")
        self.stub_bin = os.path.join(root, "stubgpg")
        os.mkdir(self.bin)
        os.mkdir(self.stub_bin)
        self.call_log = os.path.join(root, "calls.log")
        open(self.call_log, "w").close()

        gnupg = os.path.join(root, "gnupg")
        os.mkdir(gnupg, 0o700)
        subprocess.run(
            [
                "gpg", "--homedir", gnupg, "--batch", "--passphrase", "",
                "--quick-gen-key", "not-docker <test@example.invalid>", "ed25519",
                "default", "never",
            ],
            check=True,
            capture_output=True,
        )
        self.foreign_key = os.path.join(root, "foreign.asc")
        exported = subprocess.run(
            ["gpg", "--homedir", gnupg, "--batch", "--armor", "--export"],
            check=True,
            capture_output=True,
        )
        with open(self.foreign_key, "wb") as fh:
            fh.write(exported.stdout)

        self.docker_then_foreign = os.path.join(root, "two-keys.asc")
        with open(self.docker_then_foreign, "wb") as out:
            with open(DOCKER_KEY_FIXTURE, "rb") as fh:
                out.write(fh.read())
            out.write(exported.stdout)

        self.junk_key = os.path.join(root, "junk.asc")
        with open(self.junk_key, "w") as fh:
            fh.write("<html>not a key</html>\n")

        _stub(os.path.join(self.bin, "curl"), FAKE_CURL)
        for name in ("install", "apt-get", "systemctl", "dpkg", "chmod", "docker"):
            _stub(os.path.join(self.bin, name), LOGGING_STUB)
        _stub(os.path.join(self.stub_bin, "gpg"), STUB_GPG)

    def run_script(self, key, listing=None):
        env = {
            "PATH": self.bin + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_KEY_PATH": key,
            "FAKE_CALL_LOG": self.call_log,
            "HOME": self.tmp.name,
        }
        if listing is not None:
            env["PATH"] = self.stub_bin + os.pathsep + env["PATH"]
            env["FAKE_GPG_LISTING"] = listing
        result = subprocess.run(
            ["bash", SCRIPT], env=env, capture_output=True, text=True, timeout=60
        )
        with open(self.call_log) as fh:
            calls = fh.read()
        return result, calls

    def assert_refused(self, result, calls):
        self.assertNotIn("docker.asc", calls, "keyring must not be written for a refused key")
        self.assertNotIn("docker-ce", calls, "no package may be installed for a refused key")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("refusing to install it", result.stderr)

    def assert_accepted(self, result, calls):
        self.assertIn("docker.asc", calls, "the keyring step must be reached for a pinned key")
        self.assertNotIn("refusing to install it", result.stderr, result.stderr)

    def test_accepts_dockers_pinned_key(self):
        result, calls = self.run_script(DOCKER_KEY_FIXTURE)
        self.assert_accepted(result, calls)

    def test_refuses_a_valid_key_that_is_not_dockers(self):
        result, calls = self.run_script(self.foreign_key)
        self.assert_refused(result, calls)

    def test_refuses_a_file_holding_docker_key_and_a_second_key(self):
        result, calls = self.run_script(self.docker_then_foreign)
        self.assert_refused(result, calls)

    def test_refuses_a_file_gpg_cannot_read(self):
        result, calls = self.run_script(self.junk_key)
        self.assert_refused(result, calls)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_refuses_a_fingerprint_with_one_changed_digit(self):
        result, calls = self.run_script(DOCKER_KEY_FIXTURE, _listing(_one_digit_changed(PINNED_FPR)))
        self.assert_refused(result, calls)

    def test_refuses_a_fingerprint_sharing_only_the_first_eight_characters(self):
        other = PINNED_FPR[:8] + ("0" * 32 if PINNED_FPR[8:] != "0" * 32 else "1" * 32)
        result, calls = self.run_script(DOCKER_KEY_FIXTURE, _listing(other))
        self.assert_refused(result, calls)

    def test_accepts_the_pinned_fingerprint_written_in_lower_case(self):
        result, calls = self.run_script(DOCKER_KEY_FIXTURE, _listing(PINNED_FPR.lower()))
        self.assert_accepted(result, calls)


if __name__ == "__main__":
    unittest.main()
