#!/usr/bin/env python3
"""Unit tests for 20-install-docker.sh signing-key verification.

The script fetches Docker's apt key over HTTPS and must refuse any key whose
primary fingerprint is not the pinned one. The test serves a valid key that
is not Docker's (generated here, in a throwaway GnuPG home) through a stub
`curl`, and substitutes every system-changing command with a logging stub, so
nothing touches a real keyring, apt or systemd.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "20-install-docker.sh")

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


def _stub(path, body):
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o755)


@unittest.skipUnless(shutil.which("gpg"), "gpg is required to build a test key")
class DockerSigningKeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.bin = os.path.join(root, "bin")
        os.mkdir(self.bin)
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

        _stub(os.path.join(self.bin, "curl"), FAKE_CURL)
        for name in ("install", "apt-get", "systemctl", "dpkg", "chmod", "docker"):
            _stub(os.path.join(self.bin, name), LOGGING_STUB)

    def run_script(self):
        env = {
            "PATH": self.bin + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_KEY_PATH": self.foreign_key,
            "FAKE_CALL_LOG": self.call_log,
            "HOME": self.tmp.name,
        }
        return subprocess.run(
            ["bash", SCRIPT], env=env, capture_output=True, text=True, timeout=60
        )

    def test_refuses_a_valid_key_that_is_not_dockers(self):
        result = self.run_script()
        with open(self.call_log) as fh:
            calls = fh.read()
        self.assertNotIn("docker.asc", calls, "keyring must not be written for a foreign key")
        self.assertNotIn("docker-ce", calls, "no package may be installed for a foreign key")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fingerprint", result.stderr)


if __name__ == "__main__":
    unittest.main()
