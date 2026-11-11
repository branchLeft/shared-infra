#!/usr/bin/env python3
"""Pin tests for scripts/trace_reads.py: it must fail on a read outside the map, and only then.

Each case runs the tracer as a subprocess in a throwaway "repository" directory,
because an audit hook cannot be removed from a running interpreter. The fixture
scripts live outside that directory so that running them is not itself a read.
The control case (a clean fixture exits 0) sits beside every red one.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

import ci_skip
import trace_reads

SCRIPTS = pathlib.Path(__file__).resolve().parent
TRACE = SCRIPTS / "trace_reads.py"
UNIT = "mail-typecheck"  # reads mail/ and nothing else


class TraceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = pathlib.Path(self.tmp.name).resolve()
        self.repo = base / "repo"
        self.fixtures = base / "fixtures"
        self.outside = base / "outside.txt"
        self.outside.write_text("elsewhere")
        for path in ("mail/a.txt", "ansible/x", "hetzner/monitoring/m.txt", "README.md"):
            full = self.repo / path
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text("content")
        self.fixtures.mkdir()

    def fixture(self, name: str, body: str) -> pathlib.Path:
        path = self.fixtures / name
        path.write_text(textwrap.dedent(body))
        return path

    def trace(self, script: pathlib.Path, unit: str = UNIT) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        return subprocess.run(
            [sys.executable, str(TRACE), "--unit", unit, "--", str(script)],
            cwd=self.repo,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_a_clean_fixture_exits_zero(self):
        script = self.fixture(
            "clean.py",
            f"""
            import os
            open("mail/a.txt").read()
            os.listdir("mail")
            open({str(self.outside)!r}).read()
            """,
        )
        result = self.trace(script)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)

    def test_a_read_of_an_unmapped_file_exits_nonzero_and_names_it(self):
        script = self.fixture("reads_ansible.py", 'open("ansible/x").read()\n')
        result = self.trace(script)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("ansible/x", result.stderr)

    def test_the_clean_control_case_does_not_flag_the_same_unit_on_its_own_file(self):
        script = self.fixture("reads_mail.py", 'open("mail/a.txt").read()\n')
        self.assertEqual(0, self.trace(script).returncode)

    def test_a_listing_of_the_repository_root_or_a_parent_directory_is_a_read(self):
        for name, call in (("root", 'os.listdir(".")'), ("scandir", 'list(os.scandir("ansible"))')):
            with self.subTest(case=name):
                script = self.fixture(f"list_{name}.py", f"import os\n{call}\n")
                result = self.trace(script)
                self.assertNotEqual(0, result.returncode)

    def test_a_read_inside_another_unit_is_still_a_violation(self):
        script = self.fixture("reads_monitoring.py", 'open("hetzner/monitoring/m.txt").read()\n')
        self.assertNotEqual(0, self.trace(script).returncode)
        self.assertEqual(0, self.trace(script, unit="monitoring-config-validate").returncode)

    def test_git_ls_files_is_a_whole_tree_read(self):
        script = self.fixture(
            "ls_files.py",
            """
            import subprocess
            try:
                subprocess.run(["git", "ls-files"], capture_output=True)
            except OSError:
                pass
            """,
        )
        result = self.trace(script)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("git ls-files", result.stderr)

    def test_other_git_commands_are_not_a_tree_read(self):
        script = self.fixture(
            "git_version.py",
            """
            import subprocess
            try:
                subprocess.run(["git", "--version"], capture_output=True)
            except OSError:
                pass
            """,
        )
        self.assertEqual(0, self.trace(script).returncode)

    def test_the_command_exit_status_passes_through_when_nothing_was_misread(self):
        script = self.fixture("exit3.py", 'import sys\nopen("mail/a.txt").read()\nsys.exit(3)\n')
        self.assertEqual(3, self.trace(script).returncode)

    def test_a_violation_fails_even_when_the_command_succeeds(self):
        script = self.fixture("succeeds.py", 'open("README.md").read()\nraise SystemExit(0)\n')
        self.assertNotEqual(0, self.trace(script).returncode)

    def test_a_relative_read_after_a_chdir_is_attributed_to_where_it_landed(self):
        script = self.fixture("chdir.py", 'import os\nos.chdir("ansible")\nopen("x").read()\n')
        self.assertNotEqual(0, self.trace(script).returncode)

    def test_a_module_run_with_dash_m_is_traced(self):
        tests = self.repo / "mail" / "provision"
        tests.mkdir()
        (tests / "test_ok.py").write_text("import unittest\nclass T(unittest.TestCase):\n    def test_a(self):\n        open('ansible/x').read()\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        result = subprocess.run(
            [sys.executable, str(TRACE), "--unit", UNIT, "--", "-m", "unittest", "discover", "-s", "mail/provision"],
            cwd=self.repo,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("ansible/x", result.stderr)

    def test_an_unknown_unit_or_a_missing_command_is_refused(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        for args in (["--unit", "scripts-tests", "--", "-m", "unittest"], ["--unit", UNIT]):
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, str(TRACE), *args], cwd=self.repo, env=env, capture_output=True, text=True, timeout=60)
                self.assertNotEqual(0, result.returncode)


class PathTests(unittest.TestCase):
    def test_is_allowed_matches_the_map_and_nothing_above_it(self):
        reads = ci_skip.UNITS["monitoring-config-validate"]
        for allowed in ("hetzner/monitoring", "hetzner/monitoring/x.py", "hetzner/RUNBOOK-monitoring.md"):
            with self.subTest(allowed=allowed):
                self.assertTrue(trace_reads.is_allowed(allowed, reads))
        for denied in ("", "hetzner", "hetzner/edge/x", "hetzner/monitoring2/x", "hetzner/RUNBOOK-monitoring.md.bak", "ansible"):
            with self.subTest(denied=denied):
                self.assertFalse(trace_reads.is_allowed(denied, reads))

    def test_paths_outside_the_repository_are_not_repository_paths(self):
        repo = os.path.realpath(os.getcwd())
        self.assertIsNone(trace_reads.relative_to_repo("/usr/lib/python3", repo))
        self.assertIsNone(trace_reads.relative_to_repo(3, repo))
        self.assertIsNone(trace_reads.relative_to_repo("<unknown>", repo))
        self.assertIsNone(trace_reads.relative_to_repo("", repo))
        self.assertEqual("scripts/ci_skip.py", trace_reads.relative_to_repo(os.path.join(repo, "scripts", "ci_skip.py"), repo))


if __name__ == "__main__":
    unittest.main()
