"""The whole-directory type check of ansible/patterns, run the way the workflow's tests run it.

mypy reads its configuration from the directory it is started in, so the check names the
typed_module pattern's pyproject.toml with --config-file: that file holds the exclude for
the symbolic link in molecule/, which would otherwise register the same module twice. The
first test runs the check over the shipped tree and must pass. The second copies the tree,
seeds a second file with the module's name, and must fail with mypy's named error, so the
gate cannot pass in silence.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATTERNS = ROOT / "ansible" / "patterns"
CONFIG = PATTERNS / "typed_module" / "pyproject.toml"


def run_mypy(target: Path, cache: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [
            sys.executable,
            "-m",
            "mypy",
            "--config-file",
            str(CONFIG),
            "--cache-dir",
            str(cache),
            str(target),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


class PatternsTypeCheckTest(unittest.TestCase):
    def test_the_whole_patterns_directory_passes(self) -> None:
        with tempfile.TemporaryDirectory() as cache:
            result = run_mypy(PATTERNS, Path(cache))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_seeded_duplicate_module_name_fails_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "patterns"
            shutil.copytree(PATTERNS, copy)
            extra = copy / "typed_module" / "extra"
            extra.mkdir()
            shutil.copy(
                copy / "typed_module" / "library" / "typed_module_record.py",
                extra / "typed_module_record.py",
            )
            result = run_mypy(copy, Path(tmp) / "cache")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Duplicate module named "typed_module_record"', result.stdout)


if __name__ == "__main__":
    unittest.main()
