"""Tests for the role test harness, with the commands it runs replaced by a fake."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

import run_harness

TOOLS = Path("/tools")
ENV = {"PATH": "/usr/bin"}


def completed(code: int = 0, out: str = "") -> subprocess.CompletedProcess[str]:
    """Return a finished command with the given exit status and output."""
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=out, stderr="")


def spec_document(role: str, entries: Sequence[str]) -> str:
    """Return the JSON ansible-doc prints for a role with the given entry points."""
    return json.dumps({role: {"entry_points": {entry: {"options": {}} for entry in entries}}})


def step_name(argv: Sequence[str]) -> str:
    """Name a command the way the harness names its step."""
    tool = Path(argv[0]).name
    if tool != "molecule":
        return tool
    if argv[1] == "converge" and "--check" in argv:
        return "check-configured"
    return "check-fresh" if argv[1] == "check" else argv[1]


def fake_runner(
    failing: Sequence[str] = (), specs: str | None = None, changing: Sequence[str] = ()
) -> tuple[run_harness.Runner, list[tuple[str, ...]]]:
    """Return a runner that fails or reports changes for the named steps, and its call list."""
    calls: list[tuple[str, ...]] = []

    def run(
        argv: Sequence[str], cwd: Path, env: Mapping[str, str]
    ) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(argv))
        if Path(argv[0]).name == "ansible-doc":
            return completed(0, specs or spec_document(cwd.name, ["main"]))
        name = step_name(argv)
        recap = f"host : ok=3 changed={1 if name in changing else 0} unreachable=0 failed=0\n"
        return completed(1 if name in failing else 0, f"output of {name}\n{recap}")

    return run, calls


class RunHarnessTests(unittest.TestCase):
    """The harness runs every step, in order, and fails when a step fails."""

    def make_role(self, min_version: str = "2.21.5", with_tasks: bool = True) -> Path:
        """Create a minimal role directory and return its path."""
        base = Path(tempfile.mkdtemp(prefix="harness-test-"))
        self.addCleanup(shutil.rmtree, base, True)
        role = base / "demo_role"
        (role / "meta").mkdir(parents=True)
        (role / "meta" / "main.yml").write_text(
            f'galaxy_info:\n  min_ansible_version: "{min_version}"\n', encoding="utf-8"
        )
        if with_tasks:
            (role / "tasks").mkdir()
            (role / "tasks" / "main.yml").write_text("---\n", encoding="utf-8")
        return role

    def outcomes(self, failing: Sequence[str] = (), specs: str | None = None) -> dict[str, str]:
        """Run one role's steps with the fake runner and return step -> status."""
        run, _ = fake_runner(failing, specs)
        return dict(run_harness.run_role(self.make_role(), TOOLS, run, ENV))

    def test_pinned_version_reads_the_exact_pin(self) -> None:
        self.assertIsNotNone(run_harness.pinned_version(run_harness.REQUIREMENTS, "ansible-core"))
        self.assertIsNone(run_harness.pinned_version(run_harness.REQUIREMENTS, "not-a-package"))

    def test_every_step_runs_in_order_and_destroy_is_last(self) -> None:
        run, _ = fake_runner()
        outcomes = run_harness.run_role(self.make_role(), TOOLS, run, ENV)
        self.assertEqual(
            [name for name, _ in outcomes],
            [
                "min-version",
                "argument-specs",
                "ansible-lint",
                "yamllint",
                "create",
                "prepare",
                "converge",
                "idempotence",
                "verify",
                "check-configured",
                "check-fresh",
                "destroy",
            ],
        )
        self.assertTrue(all(status == run_harness.OK for _, status in outcomes))

    def test_a_failed_idempotence_step_skips_the_rest_but_destroy_still_runs(self) -> None:
        run, calls = fake_runner(failing=["idempotence"])
        outcomes = dict(run_harness.run_role(self.make_role(), TOOLS, run, ENV))
        self.assertEqual(outcomes["idempotence"], run_harness.FAIL)
        for later in ("verify", "check-configured", "check-fresh"):
            self.assertEqual(outcomes[later], run_harness.SKIP)
        self.assertEqual(outcomes["destroy"], run_harness.OK)
        self.assertIn(("/tools/molecule", "destroy"), calls)

    def test_a_failed_lint_does_not_stop_the_container_steps(self) -> None:
        outcomes = self.outcomes(failing=["ansible-lint"])
        self.assertEqual(outcomes["ansible-lint"], run_harness.FAIL)
        self.assertEqual(outcomes["converge"], run_harness.OK)
        self.assertEqual(outcomes["idempotence"], run_harness.OK)

    def test_a_check_mode_failure_is_reported_against_its_own_step(self) -> None:
        outcomes = self.outcomes(failing=["check-configured"])
        self.assertEqual(outcomes["check-configured"], run_harness.FAIL)
        self.assertEqual(outcomes["check-fresh"], run_harness.SKIP)

    def test_changes_reported_by_the_configured_check_fail_it(self) -> None:
        run, _ = fake_runner(changing=["check-configured"])
        outcomes = dict(run_harness.run_role(self.make_role(), TOOLS, run, ENV))
        self.assertEqual(outcomes["check-configured"], run_harness.FAIL)
        self.assertEqual(outcomes["check-fresh"], run_harness.SKIP)

    def test_changes_in_the_converge_step_are_expected_and_pass(self) -> None:
        run, _ = fake_runner(changing=["converge", "check-fresh"])
        outcomes = dict(run_harness.run_role(self.make_role(), TOOLS, run, ENV))
        self.assertEqual(outcomes["converge"], run_harness.OK)
        self.assertEqual(outcomes["check-fresh"], run_harness.OK)

    def test_changed_tasks_sums_the_recap_lines_only(self) -> None:
        output = "TASK changed=9\nhost-a : ok=2 changed=1 unreachable=0\nhost-b : ok=1 changed=2\n"
        self.assertEqual(run_harness.changed_tasks(output), 3)

    def test_the_configured_check_runs_the_converge_playbook_with_check_and_diff(self) -> None:
        run, calls = fake_runner()
        run_harness.run_role(self.make_role(), TOOLS, run, ENV)
        self.assertIn(("/tools/molecule", "converge", "--", "--check", "--diff"), calls)

    def test_missing_argument_specs_fails_the_interface_check(self) -> None:
        self.assertEqual(self.outcomes(specs="{}")["argument-specs"], run_harness.FAIL)

    def test_a_tasks_file_without_an_entry_point_fails(self) -> None:
        role = self.make_role()
        (role / "tasks" / "extra.yml").write_text("---\n", encoding="utf-8")
        run, _ = fake_runner(specs=spec_document("demo_role", ["main"]))
        outcomes = dict(run_harness.run_role(role, TOOLS, run, ENV))
        self.assertEqual(outcomes["argument-specs"], run_harness.FAIL)

    def test_a_role_in_the_repository_is_linted_from_the_repository_root(self) -> None:
        inside = run_harness.REPO_ROOT / "ansible" / "roles" / "demo_role"
        outside = Path("/elsewhere/demo_role")
        self.assertEqual(run_harness.static_steps(inside, TOOLS)[0].cwd, run_harness.REPO_ROOT)
        self.assertEqual(run_harness.static_steps(outside, TOOLS)[0].cwd, outside.parent)

    def test_min_version_must_equal_the_pinned_core(self) -> None:
        pinned = run_harness.pinned_version(run_harness.REQUIREMENTS, "ansible-core") or ""
        self.assertIsNone(run_harness.check_min_version(self.make_role(pinned), pinned))
        self.assertIsNotNone(run_harness.check_min_version(self.make_role("0.0.1"), pinned))

    def test_a_non_local_docker_host_is_refused(self) -> None:
        refuse = run_harness.refuse_remote_engine
        self.assertIsNotNone(refuse({"DOCKER_HOST": "tcp://203.0.113.1:2375"}))
        self.assertIsNotNone(refuse({"DOCKER_HOST": "ssh://203.0.113.1"}))
        self.assertIsNone(refuse({"DOCKER_HOST": "unix:///var/run/docker.sock"}))
        self.assertIsNone(refuse({}))

    def test_each_run_gets_a_unique_instance_id_in_its_environment(self) -> None:
        first = run_harness.role_environment({}, Path("/work"), TOOLS, "aaaa")
        second = run_harness.role_environment({}, Path("/work"), TOOLS, "bbbb")
        self.assertEqual(first["ROLE_TEST_RUN_ID"], "aaaa")
        self.assertNotEqual(first["ROLE_TEST_RUN_ID"], second["ROLE_TEST_RUN_ID"])
        self.assertTrue(first["PATH"].startswith(str(TOOLS)))

    def test_main_returns_non_zero_when_a_step_fails(self) -> None:
        run, _ = fake_runner(failing=["verify"])
        self.assertEqual(run_harness.main([str(self.make_role())], ENV, run, TOOLS), 1)

    def test_main_returns_zero_when_every_step_passes(self) -> None:
        run, _ = fake_runner()
        self.assertEqual(run_harness.main([str(self.make_role())], ENV, run, TOOLS), 0)

    def test_main_refuses_a_directory_that_is_not_a_role(self) -> None:
        run, _ = fake_runner()
        role = self.make_role(with_tasks=False)
        self.assertEqual(run_harness.main([str(role)], ENV, run, TOOLS), 2)

    def test_main_refuses_a_remote_engine_before_running_anything(self) -> None:
        run, calls = fake_runner()
        env = {"PATH": "/usr/bin", "DOCKER_HOST": "tcp://203.0.113.1:2375"}
        self.assertEqual(run_harness.main([str(self.make_role())], env, run, TOOLS), 2)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
