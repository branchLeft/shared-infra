#!/usr/bin/env python3
"""Runs the real smoke-test function of 65-install-local-resolver.sh under
/bin/bash with PATH set to a stub directory alone. The package list is checked
statically: installing needs real dpkg and apt-get.
"""
from __future__ import annotations

import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parent / "65-install-local-resolver.sh"
BASH = "/bin/bash"
SMOKE_TEST_NAME = "deb.debian.org"
SLEEP_STUB = "#!/bin/sh\nexit 0\n"
ANSWERING_DIG_STUB = "#!/bin/sh\necho 192.0.2.10\n"
SILENT_DIG_STUB = "#!/bin/sh\nexit 0\n"
RUN_TIMEOUT_SECONDS = 30


def extract_smoke_test_function(script_text: str) -> str:
    """Returns the function text up to the first line that is exactly `}`.

    Raises:
        AssertionError: the function is absent or never closes."""
    lines = script_text.split("\n")
    try:
        start = lines.index("smoke_test_recursion() {")
    except ValueError:
        raise AssertionError(
            f"{SCRIPT_PATH.name} has no line 'smoke_test_recursion() {{'; "
            "the smoke test must be a function the test can extract"
        ) from None
    try:
        end = lines.index("}", start)
    except ValueError:
        raise AssertionError(
            f"smoke_test_recursion in {SCRIPT_PATH.name} has no closing line '}}'"
        ) from None
    return "\n".join(lines[start : end + 1])


def write_stub(directory: Path, name: str, content: str) -> None:
    stub = directory / name
    stub.write_text(content)
    stub.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


class SmokeTestRecursionTests(unittest.TestCase):
    def run_smoke_test(self, dig_stub: str | None) -> subprocess.CompletedProcess[str]:
        function_text = extract_smoke_test_function(SCRIPT_PATH.read_text())
        with tempfile.TemporaryDirectory() as stub_directory:
            write_stub(Path(stub_directory), "sleep", SLEEP_STUB)
            if dig_stub is not None:
                write_stub(Path(stub_directory), "dig", dig_stub)
            program = (
                f"set -euo pipefail; SMOKE_TEST_NAME={SMOKE_TEST_NAME}; "
                f"{function_text}\nsmoke_test_recursion"
            )
            return subprocess.run(
                [BASH, "-c", program],
                env={"PATH": stub_directory},
                capture_output=True,
                text=True,
                timeout=RUN_TIMEOUT_SECONDS,
                check=False,
            )

    def test_missing_dig_fails_instead_of_skipping(self) -> None:
        result = self.run_smoke_test(dig_stub=None)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("dig", result.stderr)
        self.assertNotIn("recursion works", result.stdout)

    def test_dig_that_answers_reports_recursion_works(self) -> None:
        result = self.run_smoke_test(dig_stub=ANSWERING_DIG_STUB)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"65-install-local-resolver: 127.0.0.1 resolved {SMOKE_TEST_NAME}, recursion works",
            result.stdout,
        )

    def test_dig_that_never_answers_fails(self) -> None:
        result = self.run_smoke_test(dig_stub=SILENT_DIG_STUB)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"did not resolve {SMOKE_TEST_NAME}", result.stderr)
        self.assertNotIn("recursion works", result.stdout)

    def test_the_package_list_installs_dig_when_absent(self) -> None:
        loop_lines = [
            line
            for line in SCRIPT_PATH.read_text().split("\n")
            if re.match(r"^for pkg in .*; do$", line)
        ]
        self.assertEqual(len(loop_lines), 1, loop_lines)
        packages = loop_lines[0].removeprefix("for pkg in ").removesuffix("; do").split()
        self.assertIn("bind9-dnsutils", packages)


if __name__ == "__main__":
    unittest.main()
