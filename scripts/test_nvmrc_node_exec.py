"""Tests for scripts/nvmrc-node-exec.sh, run against fakes in a temp directory.

The selector must run its command under the Node named by .nvmrc, not the
Node first on PATH. Fake `node` binaries stand in for the nvm install and
for whatever the shell would otherwise find, so the tests never depend on
the Node this machine happens to have.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SELECTOR = SCRIPTS / "nvmrc-node-exec.sh"


def write_exec(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class NvmrcNodeExecTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.repo = base / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        shutil.copy2(SELECTOR, self.repo / "scripts" / "nvmrc-node-exec.sh")
        self.home = base / "home"
        self.path_dir = base / "path-bin"
        write_exec(self.path_dir / "node", 'echo "PATH-NODE $*"')
        self.set_nvmrc("v26.5.0")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def set_nvmrc(self, text: str) -> None:
        (self.repo / ".nvmrc").write_text(text)

    def install_nvm_node(self, version: str) -> None:
        bin_dir = self.home / ".nvm" / "versions" / "node" / f"v{version}" / "bin"
        write_exec(bin_dir / "node", f'echo "NVM-NODE-{version} $*"')

    def run_selector(self, *args: str) -> subprocess.CompletedProcess:
        env = {
            "HOME": str(self.home),
            "PATH": f"{self.path_dir}:/usr/bin:/bin",
        }
        return subprocess.run(
            [str(self.repo / "scripts" / "nvmrc-node-exec.sh"), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_runs_under_the_nvmrc_node_when_it_is_installed(self) -> None:
        self.install_nvm_node("26.5.0")
        result = self.run_selector("node", "--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "NVM-NODE-26.5.0 --version")

    def test_ignores_the_path_node_even_when_it_comes_first(self) -> None:
        self.install_nvm_node("26.5.0")
        result = self.run_selector("node")
        self.assertNotIn("PATH-NODE", result.stdout)

    def test_missing_version_prints_one_line_naming_it_and_exits_1(self) -> None:
        self.set_nvmrc("v99.1.0\n")
        result = self.run_selector("node", "--version")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        lines = result.stderr.strip().splitlines()
        self.assertEqual(len(lines), 1, result.stderr)
        self.assertIn("v99.1.0", lines[0])
        self.assertIn("nvm install 99.1.0", lines[0])

    def test_missing_nvmrc_exits_1_with_one_line(self) -> None:
        (self.repo / ".nvmrc").unlink()
        result = self.run_selector("node")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(result.stderr.strip().splitlines()), 1, result.stderr)

    def test_non_exact_version_is_refused(self) -> None:
        self.set_nvmrc("lts/*\n")
        result = self.run_selector("node")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(result.stderr.strip().splitlines()), 1, result.stderr)


if __name__ == "__main__":
    unittest.main()
