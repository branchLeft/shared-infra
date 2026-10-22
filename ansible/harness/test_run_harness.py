"""Tests for the role test harness, with the commands it runs replaced by a fake."""

from __future__ import annotations

import contextlib
import io
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
DIGEST = "sha256:" + "a" * 64


def scenario(platform: str = "", provisioner: str = "") -> str:
    """Return a valid scenario file with extra lines inside its platform and provisioner."""
    return (
        "---\ndriver:\n  name: docker\nplatforms:\n  - name: instance\n"
        f"    image: python:3.12-slim@{DIGEST}\n    pre_build_image: true\n{platform}"
        f"provisioner:\n  name: ansible\n{provisioner}"
    )


SCENARIO = scenario()
MOLECULE_STEPS = [
    "create",
    "prepare",
    "check-fresh",
    "converge",
    "idempotence",
    "verify",
    "check-configured",
    "molecule-check",
    "destroy",
]


def completed(code: int = 0, out: str = "") -> subprocess.CompletedProcess[str]:
    """Return a finished command with the given exit status and output."""
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=out, stderr="")


def spec_document(role: str, entries: Sequence[str]) -> str:
    """Return the JSON ansible-doc prints for a role with the given entry points."""
    return json.dumps({role: {"entry_points": {entry: {"options": {}} for entry in entries}}})


def fake_runner(
    failing: Sequence[str] = (),
    specs: str | None = None,
    changing: Sequence[str] = (),
    interrupt_at: str | None = None,
) -> tuple[run_harness.Runner, list[tuple[str, ...]]]:
    """Return a runner that fails, reports changes or is interrupted at the named steps."""
    calls: list[tuple[str, ...]] = []
    converged = [False]

    def name_of(argv: Sequence[str]) -> str:
        tool = Path(argv[0]).name
        if tool != "molecule":
            return tool
        if argv[1] == "converge":
            if "--check" in argv:
                return "check-configured" if converged[0] else "check-fresh"
            return "converge"
        return "molecule-check" if argv[1] == "check" else argv[1]

    def run(
        argv: Sequence[str], cwd: Path, env: Mapping[str, str]
    ) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(argv))
        if Path(argv[0]).name == "ansible-doc":
            return completed(0, specs or spec_document(cwd.name, ["main"]))
        name = name_of(argv)
        if name == interrupt_at:
            raise KeyboardInterrupt
        if name == "converge":
            converged[0] = True
        recap = f"host : ok=3 changed={1 if name in changing else 0} unreachable=0 failed=0\n"
        return completed(1 if name in failing else 0, f"output of {name}\n{recap}")

    return run, calls


class RoleCase(unittest.TestCase):
    """A test case that can make a throwaway role directory."""

    def make_role(
        self,
        min_version: str = "2.21.5",
        with_tasks: bool = True,
        scenario: str | None = SCENARIO,
        also: Sequence[str] = (),
    ) -> Path:
        """Create a minimal role directory and return its path.

        ``also`` names more scenarios, each with a valid scenario file.
        """
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
        if scenario is not None:
            (role / "molecule" / "default").mkdir(parents=True)
            (role / "molecule" / "default" / "molecule.yml").write_text(scenario, encoding="utf-8")
        for name in also:
            (role / "molecule" / name).mkdir(parents=True)
            (role / "molecule" / name / "molecule.yml").write_text(SCENARIO, encoding="utf-8")
        return role


class RunHarnessTests(RoleCase):
    """The harness runs every step, in order, and fails when a step fails."""

    def outcomes(self, failing: Sequence[str] = (), specs: str | None = None) -> dict[str, str]:
        """Run one role's steps with the fake runner and return step -> status."""
        run, _ = fake_runner(failing, specs)
        return dict(run_harness.run_role(self.make_role(), TOOLS, run, ENV))

    def test_pinned_version_reads_the_exact_pin(self) -> None:
        self.assertIsNotNone(run_harness.pinned_version(run_harness.REQUIREMENTS, "ansible-core"))
        self.assertIsNone(run_harness.pinned_version(run_harness.REQUIREMENTS, "not-a-package"))

    def test_pinned_version_reads_a_hash_locked_line(self) -> None:
        base = Path(tempfile.mkdtemp(prefix="harness-lock-"))
        self.addCleanup(shutil.rmtree, base, True)
        lock = base / "requirements.txt"
        lock.write_text(
            "ansible-core==2.21.5 \\\n    --hash=sha256:" + "b" * 64 + "\n"
            "ansible-core-extra==9.9.9 --hash=sha256:" + "c" * 64 + "\n"
            "ruff==0.17.0\n",
            encoding="utf-8",
        )
        self.assertEqual(run_harness.pinned_version(lock, "ansible-core"), "2.21.5")
        self.assertEqual(run_harness.pinned_version(lock, "ruff"), "0.17.0")
        self.assertIsNone(run_harness.pinned_version(lock, "ansible"))

    def test_every_step_runs_in_order_and_destroy_is_last(self) -> None:
        run, _ = fake_runner()
        outcomes = run_harness.run_role(self.make_role(), TOOLS, run, ENV)
        self.assertEqual(
            [name for name, _ in outcomes],
            ["min-version", "argument-specs", "scenario-limits", "ansible-lint", "yamllint"]
            + MOLECULE_STEPS,
        )
        self.assertTrue(all(status == run_harness.OK for _, status in outcomes))

    def test_a_failed_idempotence_step_skips_the_rest_but_destroy_still_runs(self) -> None:
        run, calls = fake_runner(failing=["idempotence"])
        outcomes = dict(run_harness.run_role(self.make_role(), TOOLS, run, ENV))
        self.assertEqual(outcomes["idempotence"], run_harness.FAIL)
        for later in ("verify", "check-configured", "molecule-check"):
            self.assertEqual(outcomes[later], run_harness.SKIP)
        self.assertEqual(outcomes["destroy"], run_harness.OK)
        self.assertIn(("/tools/molecule", "destroy", "-s", "default"), calls)

    def test_a_failed_lint_does_not_stop_the_container_steps(self) -> None:
        outcomes = self.outcomes(failing=["ansible-lint"])
        self.assertEqual(outcomes["ansible-lint"], run_harness.FAIL)
        self.assertEqual(outcomes["converge"], run_harness.OK)
        self.assertEqual(outcomes["idempotence"], run_harness.OK)

    def test_the_fresh_check_runs_before_any_real_converge(self) -> None:
        run, calls = fake_runner()
        run_harness.run_role(self.make_role(), TOOLS, run, ENV)
        check = ("/tools/molecule", "converge", "-s", "default", "--", "--check", "--diff")
        real = ("/tools/molecule", "converge", "-s", "default")
        self.assertLess(calls.index(check), calls.index(real))
        self.assertGreater(calls.index(check, calls.index(real)), calls.index(real))

    def test_a_fresh_check_failure_stops_before_the_real_converge(self) -> None:
        run, calls = fake_runner(failing=["check-fresh"])
        outcomes = dict(run_harness.run_role(self.make_role(), TOOLS, run, ENV))
        self.assertEqual(outcomes["check-fresh"], run_harness.FAIL)
        for later in ("converge", "idempotence", "verify", "check-configured", "molecule-check"):
            self.assertEqual(outcomes[later], run_harness.SKIP)
        self.assertNotIn(("/tools/molecule", "converge", "-s", "default"), calls)
        self.assertEqual(outcomes["destroy"], run_harness.OK)

    def test_changes_reported_by_the_fresh_check_are_expected_and_pass(self) -> None:
        run, _ = fake_runner(changing=["check-fresh", "converge", "molecule-check"])
        outcomes = dict(run_harness.run_role(self.make_role(), TOOLS, run, ENV))
        for name in ("check-fresh", "converge", "molecule-check"):
            self.assertEqual(outcomes[name], run_harness.OK)

    def test_a_check_mode_failure_is_reported_against_its_own_step(self) -> None:
        outcomes = self.outcomes(failing=["check-configured"])
        self.assertEqual(outcomes["check-configured"], run_harness.FAIL)
        self.assertEqual(outcomes["molecule-check"], run_harness.SKIP)

    def test_changes_reported_by_the_configured_check_fail_it(self) -> None:
        run, _ = fake_runner(changing=["check-configured"])
        outcomes = dict(run_harness.run_role(self.make_role(), TOOLS, run, ENV))
        self.assertEqual(outcomes["check-configured"], run_harness.FAIL)
        self.assertEqual(outcomes["molecule-check"], run_harness.SKIP)

    def test_changed_tasks_sums_the_recap_lines_only(self) -> None:
        output = "TASK changed=9\nhost-a : ok=2 changed=1 unreachable=0\nhost-b : ok=1 changed=2\n"
        self.assertEqual(run_harness.changed_tasks(output), 3)

    def test_both_check_steps_run_the_converge_playbook_with_check_and_diff(self) -> None:
        run, calls = fake_runner()
        run_harness.run_role(self.make_role(), TOOLS, run, ENV)
        check = ("/tools/molecule", "converge", "-s", "default", "--", "--check", "--diff")
        self.assertEqual(calls.count(check), 2)

    def test_an_interrupt_still_destroys_the_instance_and_propagates(self) -> None:
        run, calls = fake_runner(interrupt_at="converge")
        with self.assertRaises(KeyboardInterrupt):
            run_harness.run_role(self.make_role(), TOOLS, run, ENV)
        self.assertEqual(calls[-1], ("/tools/molecule", "destroy", "-s", "default"))

    def test_missing_argument_specs_fails_the_interface_check(self) -> None:
        self.assertEqual(self.outcomes(specs="{}")["argument-specs"], run_harness.FAIL)

    def test_a_tasks_file_without_an_entry_point_fails(self) -> None:
        role = self.make_role()
        (role / "tasks" / "extra.yml").write_text("---\n", encoding="utf-8")
        run, _ = fake_runner(specs=spec_document("demo_role", ["main"]))
        outcomes = dict(run_harness.run_role(role, TOOLS, run, ENV))
        self.assertEqual(outcomes["argument-specs"], run_harness.FAIL)

    def test_an_underscore_tasks_file_needs_no_entry_point(self) -> None:
        role = self.make_role()
        (role / "tasks" / "_internal.yml").write_text("---\n", encoding="utf-8")
        run, _ = fake_runner(specs=spec_document("demo_role", ["main"]))
        outcomes = dict(run_harness.run_role(role, TOOLS, run, ENV))
        self.assertEqual(outcomes["argument-specs"], run_harness.OK)

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

    def test_the_summary_prints_the_reason_beside_a_failed_interface_check(self) -> None:
        run, _ = fake_runner(specs="{}")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            run_harness.main([str(self.make_role())], ENV, run, TOOLS)
        summary = out.getvalue().split("== demo_role (default) ==")[1]
        self.assertIn("FAIL argument-specs\n    meta/argument_specs.yml is missing", summary)


class ScenarioLimitTests(RoleCase):
    """A scenario file that could reach beyond a local container is refused (ANS-15)."""

    def problems(self, scenario: str) -> list[str]:
        """Write ``scenario`` as a role's default scenario and return the problems found."""
        base = Path(tempfile.mkdtemp(prefix="scenario-test-"))
        self.addCleanup(shutil.rmtree, base, True)
        (base / "molecule" / "default").mkdir(parents=True)
        (base / "molecule" / "default" / "molecule.yml").write_text(scenario, encoding="utf-8")
        return run_harness.check_scenarios(base)

    def assert_refused(self, scenario: str, fragment: str) -> None:
        """Assert the scenario is refused with a message containing ``fragment``."""
        found = self.problems(scenario)
        self.assertTrue(any(fragment in problem for problem in found), found)

    def test_the_skeleton_style_scenario_passes(self) -> None:
        self.assertEqual(self.problems(SCENARIO), [])

    def test_an_unmanaged_default_driver_is_refused(self) -> None:
        refused = SCENARIO.replace("name: docker", "name: default\n  options:\n    managed: false")
        self.assert_refused(refused, "only docker or podman")

    def test_podman_is_an_allowed_driver(self) -> None:
        self.assertEqual(self.problems(SCENARIO.replace("name: docker", "name: podman")), [])

    def test_a_missing_driver_is_refused(self) -> None:
        self.assert_refused(SCENARIO.replace("driver:\n  name: docker\n", ""), "only docker")

    def test_a_platform_docker_host_is_refused(self) -> None:
        refused = scenario(platform="    docker_host: tcp://203.0.113.1:2375\n")
        self.assert_refused(refused, "sets docker_host")

    def test_a_docker_host_in_the_provisioner_environment_is_refused(self) -> None:
        refused = scenario(provisioner="  env:\n    DOCKER_HOST: tcp://203.0.113.1:2375\n")
        self.assert_refused(refused, "sets DOCKER_HOST")

    def test_a_connection_option_naming_another_host_is_refused(self) -> None:
        group_vars = "  inventory:\n    group_vars:\n      all:\n"
        refused = scenario(provisioner=group_vars + "        ansible_connection: ssh\n")
        self.assert_refused(refused, "sets ansible_connection")

    def test_an_inventory_that_defines_hosts_is_refused(self) -> None:
        refused = scenario(provisioner="  inventory:\n    hosts:\n      other:\n        value: 1\n")
        self.assert_refused(refused, "inventory defines hosts")

    def test_an_inventory_that_only_sets_group_variables_passes(self) -> None:
        allowed = scenario(
            provisioner="  inventory:\n    group_vars:\n      all:\n        demo_flag: true\n"
        )
        self.assertEqual(self.problems(allowed), [])

    def test_a_platform_that_is_not_pre_built_is_refused(self) -> None:
        self.assert_refused(SCENARIO.replace("    pre_build_image: true\n", ""), "pre_build_image")

    def test_a_platform_image_without_a_digest_is_refused(self) -> None:
        self.assert_refused(SCENARIO.replace(f"@{DIGEST}", ""), "not pinned by digest")

    def test_a_mounted_engine_socket_is_refused(self) -> None:
        refused = scenario(
            platform="    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        self.assert_refused(refused, "engine socket")

    def test_a_privileged_platform_needs_a_stated_reason(self) -> None:
        self.assert_refused(scenario(platform="    privileged: true\n"), "without a comment")

    def test_added_capabilities_need_a_stated_reason(self) -> None:
        refused = scenario(platform="    capabilities:\n      - SYS_TIME\n")
        self.assert_refused(refused, "without a comment")

    def test_a_privileged_platform_with_a_reason_above_the_key_passes(self) -> None:
        reasoned = scenario(
            platform="    # The role under test starts a service manager.\n    privileged: true\n"
        )
        self.assertEqual(self.problems(reasoned), [])

    def test_a_second_privileged_platform_needs_a_reason_of_its_own(self) -> None:
        # One platform with two commented keys has two comments in the file. They
        # explain that platform, and must not stand in for a bare second one.
        first = (
            "    # The role under test starts a service manager.\n    privileged: true\n"
            "    # It also needs a capability.\n    capabilities:\n      - SYS_TIME\n"
        )
        second = (
            f"  - name: second\n    image: python:3.12-slim@{DIGEST}\n"
            "    pre_build_image: true\n    privileged: true\n"
        )
        self.assert_refused(scenario(platform=first + second), "without a comment")

    def test_two_privileged_platforms_each_with_a_reason_pass(self) -> None:
        first = "    # The first starts a service manager.\n    privileged: true\n"
        second = (
            f"  - name: second\n    image: python:3.12-slim@{DIGEST}\n"
            "    pre_build_image: true\n"
            "    # The second starts a service manager too.\n    privileged: true\n"
        )
        self.assertEqual(self.problems(scenario(platform=first + second)), [])

    def test_privileged_false_needs_no_reason(self) -> None:
        self.assertEqual(self.problems(scenario(platform="    privileged: false\n")), [])

    def test_a_scenario_with_no_platform_is_refused(self) -> None:
        self.assert_refused("---\ndriver:\n  name: docker\nplatforms: []\n", "no platform")

    def test_a_missing_default_scenario_is_refused(self) -> None:
        base = Path(tempfile.mkdtemp(prefix="scenario-test-"))
        self.addCleanup(shutil.rmtree, base, True)
        self.assertEqual(
            run_harness.check_scenarios(base), ["molecule/default/molecule.yml is missing"]
        )

    def test_a_scenario_that_is_not_yaml_is_refused(self) -> None:
        self.assert_refused("driver: [unclosed\n", "not valid YAML")

    def test_every_scenario_of_a_role_is_read_not_only_the_default(self) -> None:
        base = Path(tempfile.mkdtemp(prefix="scenario-test-"))
        self.addCleanup(shutil.rmtree, base, True)
        for name, text in (("default", SCENARIO), ("other", SCENARIO.replace("docker", "default"))):
            (base / "molecule" / name).mkdir(parents=True)
            (base / "molecule" / name / "molecule.yml").write_text(text, encoding="utf-8")
        found = run_harness.check_scenarios(base)
        self.assertTrue(any(problem.startswith("molecule/other/molecule.yml") for problem in found))

    def test_a_refused_scenario_skips_every_container_step_including_destroy(self) -> None:
        role = self.make_role(scenario=SCENARIO.replace("name: docker", "name: default"))
        run, calls = fake_runner()
        outcomes = dict(run_harness.run_role(role, TOOLS, run, ENV))
        self.assertEqual(outcomes["scenario-limits"], run_harness.FAIL)
        for name in MOLECULE_STEPS:
            self.assertEqual(outcomes[name], run_harness.SKIP)
        self.assertEqual([call for call in calls if call[0] == "/tools/molecule"], [])


class SecondScenarioTests(RoleCase):
    """A role's other scenarios run, each in its own run of the harness, and cannot pass unrun."""

    def molecule_calls(self, calls: Sequence[tuple[str, ...]]) -> list[tuple[str, ...]]:
        """Return only the Molecule commands among the calls."""
        return [call for call in calls if call[0] == "/tools/molecule"]

    def test_every_molecule_command_names_the_scenario_being_run(self) -> None:
        run, calls = fake_runner()
        role = self.make_role(also=["refusals"])
        run_harness.run_role(role, TOOLS, run, ENV, scenario="refusals")
        molecule = self.molecule_calls(calls)
        self.assertEqual(len(molecule), len(MOLECULE_STEPS))
        for call in molecule:
            self.assertEqual(call[2:4], ("-s", "refusals"), call)

    def test_the_default_scenario_is_named_too_so_it_never_depends_on_a_default(self) -> None:
        run, calls = fake_runner()
        run_harness.run_role(self.make_role(also=["refusals"]), TOOLS, run, ENV)
        for call in self.molecule_calls(calls):
            self.assertEqual(call[2:4], ("-s", "default"), call)

    def test_destroy_names_the_second_scenario_and_still_runs_after_a_failure(self) -> None:
        run, calls = fake_runner(failing=["converge"])
        role = self.make_role(also=["refusals"])
        outcomes = dict(run_harness.run_role(role, TOOLS, run, ENV, scenario="refusals"))
        self.assertEqual(outcomes["converge"], run_harness.FAIL)
        self.assertEqual(outcomes["destroy"], run_harness.OK)
        self.assertEqual(calls[-1], ("/tools/molecule", "destroy", "-s", "refusals"))

    def test_a_failing_second_scenario_fails_its_own_run(self) -> None:
        run, _ = fake_runner(failing=["converge"])
        role = self.make_role(also=["refusals"])
        self.assertEqual(
            run_harness.main([str(role), "--scenario", "refusals"], ENV, run, TOOLS), 1
        )

    def test_a_passing_second_scenario_passes_its_own_run(self) -> None:
        run, _ = fake_runner()
        role = self.make_role(also=["refusals"])
        self.assertEqual(
            run_harness.main([str(role), "--scenario", "refusals"], ENV, run, TOOLS), 0
        )

    def test_the_summary_names_the_scenario(self) -> None:
        run, _ = fake_runner()
        role = self.make_role(also=["refusals"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            run_harness.main([str(role), "--scenario", "refusals"], ENV, run, TOOLS)
        self.assertIn("== demo_role (refusals) ==", out.getvalue())

    def test_a_scenario_that_does_not_exist_fails_and_runs_no_container_step(self) -> None:
        run, calls = fake_runner()
        role = self.make_role()
        outcomes = dict(run_harness.run_role(role, TOOLS, run, ENV, scenario="refusals"))
        self.assertEqual(outcomes["scenario-limits"], run_harness.FAIL)
        for name in MOLECULE_STEPS:
            self.assertEqual(outcomes[name], run_harness.SKIP)
        self.assertEqual(self.molecule_calls(calls), [])

    def test_the_reason_names_the_missing_scenario(self) -> None:
        self.assertEqual(
            run_harness.check_scenarios(self.make_role(), "refusals"),
            ["molecule/refusals/molecule.yml is missing"],
        )

    def test_a_role_with_no_molecule_directory_still_fails_at_scenario_limits(self) -> None:
        run, calls = fake_runner()
        role = self.make_role(scenario=None)
        outcomes = dict(run_harness.run_role(role, TOOLS, run, ENV))
        self.assertEqual(outcomes["scenario-limits"], run_harness.FAIL)
        for name in MOLECULE_STEPS:
            self.assertEqual(outcomes[name], run_harness.SKIP)
        self.assertEqual(self.molecule_calls(calls), [])

    def test_a_role_with_only_a_second_scenario_fails_for_the_missing_default(self) -> None:
        role = self.make_role(scenario=None, also=["refusals"])
        self.assertEqual(
            run_harness.check_scenarios(role, "refusals"),
            ["molecule/default/molecule.yml is missing"],
        )

    def test_a_privileged_second_scenario_needs_a_stated_reason_in_any_run(self) -> None:
        role = self.make_role(also=["refusals"])
        bare = scenario(platform="    privileged: true\n")
        (role / "molecule" / "refusals" / "molecule.yml").write_text(bare, encoding="utf-8")
        for name in ("default", "refusals"):
            found = run_harness.check_scenarios(role, name)
            self.assertEqual(len(found), 1, found)
            self.assertTrue(found[0].startswith("molecule/refusals/molecule.yml: "), found)
            self.assertIn("without a comment", found[0])

    def test_a_second_scenario_that_links_to_the_default_file_is_read_through_the_link(
        self,
    ) -> None:
        role = self.make_role()
        (role / "molecule" / "refusals").mkdir()
        (role / "molecule" / "refusals" / "molecule.yml").symlink_to("../default/molecule.yml")
        self.assertEqual(run_harness.check_scenarios(role, "refusals"), [])
        default_file = role / "molecule" / "default" / "molecule.yml"
        default_file.write_text(SCENARIO.replace(f"@{DIGEST}", ""), encoding="utf-8")
        found = run_harness.check_scenarios(role, "refusals")
        self.assertEqual(len(found), 2, found)
        self.assertTrue(any(problem.startswith("molecule/refusals/") for problem in found), found)

    def test_a_broken_link_is_a_missing_scenario(self) -> None:
        role = self.make_role()
        (role / "molecule" / "refusals").mkdir()
        (role / "molecule" / "refusals" / "molecule.yml").symlink_to("../nowhere/molecule.yml")
        self.assertIn(
            "molecule/refusals/molecule.yml is missing",
            run_harness.check_scenarios(role, "refusals"),
        )

    def test_a_scenario_name_that_is_not_a_plain_directory_name_is_refused(self) -> None:
        run, calls = fake_runner()
        role = self.make_role()
        for bad in ("../default", "a b", "", "x;y", "a/b", "_x"):
            self.assertEqual(
                run_harness.main([str(role), "--scenario", bad], ENV, run, TOOLS), 2, bad
            )
        self.assertEqual(calls, [])

    def test_the_scenario_option_defaults_to_the_default_scenario(self) -> None:
        run, calls = fake_runner()
        self.assertEqual(run_harness.main([str(self.make_role())], ENV, run, TOOLS), 0)
        self.assertIn(("/tools/molecule", "create", "-s", "default"), calls)


class LeftOutStepTests(RoleCase):
    """A scenario can leave steps out, and a role cannot leave one out of every scenario."""

    CHECKS = ("check-fresh", "check-configured", "molecule-check")

    def write_skips(self, role: Path, scenario_name: str, skips: Sequence[str]) -> None:
        """Write a scenario's step list, with a comment and a blank line before the names."""
        text = "# the steps this scenario leaves out\n\n" + "".join(f"{name}\n" for name in skips)
        (role / "molecule" / scenario_name / run_harness.SKIP_FILE).write_text(
            text, encoding="utf-8"
        )

    def split_role(self) -> Path:
        """Return a role whose default leaves out the check steps and whose plan runs only them."""
        role = self.make_role(also=["plan"])
        self.write_skips(role, "default", self.CHECKS)
        self.write_skips(role, "plan", ["idempotence", "verify"])
        return role

    def run_scenario(
        self, role: Path, scenario_name: str, failing: Sequence[str] = ()
    ) -> tuple[dict[str, str], list[tuple[str, ...]]]:
        """Run one scenario of the role with the fake runner; return outcomes and the calls."""
        run, calls = fake_runner(failing=failing)
        outcomes = dict(run_harness.run_role(role, TOOLS, run, ENV, scenario=scenario_name))
        return outcomes, [call for call in calls if call[0] == "/tools/molecule"]

    def test_the_steps_a_scenario_leaves_out_are_reported_as_skipped_and_not_run(self) -> None:
        outcomes, calls = self.run_scenario(self.split_role(), "default")
        for name in self.CHECKS:
            self.assertEqual(outcomes[name], run_harness.SKIP, name)
        for name in ("create", "prepare", "converge", "idempotence", "verify", "destroy"):
            self.assertEqual(outcomes[name], run_harness.OK, name)
        self.assertFalse([call for call in calls if "--check" in call or call[1] == "check"], calls)

    def test_the_other_scenario_runs_the_steps_the_first_left_out(self) -> None:
        outcomes, calls = self.run_scenario(self.split_role(), "plan")
        for name in ("idempotence", "verify"):
            self.assertEqual(outcomes[name], run_harness.SKIP, name)
        for name in ("create", "prepare", "check-fresh", "converge", "check-configured"):
            self.assertEqual(outcomes[name], run_harness.OK, name)
        self.assertEqual(outcomes["molecule-check"], run_harness.OK)
        self.assertEqual(outcomes["destroy"], run_harness.OK)
        self.assertNotIn(("/tools/molecule", "idempotence", "-s", "plan"), calls)
        self.assertNotIn(("/tools/molecule", "verify", "-s", "plan"), calls)

    def test_the_two_scenarios_together_run_every_step(self) -> None:
        role = self.split_role()
        ran: set[str] = set()
        for name in ("default", "plan"):
            outcomes, _ = self.run_scenario(role, name)
            ran |= {step for step, status in outcomes.items() if status == run_harness.OK}
        self.assertTrue(set(MOLECULE_STEPS) <= ran, set(MOLECULE_STEPS) - ran)

    def test_a_role_with_no_step_list_runs_every_step(self) -> None:
        outcomes, calls = self.run_scenario(self.make_role(), "default")
        self.assertEqual([name for name in MOLECULE_STEPS if name not in outcomes], [])
        self.assertEqual(len(calls), len(MOLECULE_STEPS))

    def test_a_failure_after_a_left_out_step_still_skips_the_rest_and_destroys(self) -> None:
        outcomes, calls = self.run_scenario(self.split_role(), "default", failing=["verify"])
        self.assertEqual(outcomes["verify"], run_harness.FAIL)
        self.assertEqual(outcomes["destroy"], run_harness.OK)
        self.assertEqual(calls[-1], ("/tools/molecule", "destroy", "-s", "default"))

    def test_a_step_that_no_scenario_runs_is_refused_and_no_container_step_runs(self) -> None:
        role = self.make_role()
        self.write_skips(role, "default", ["verify"])
        found = run_harness.check_scenarios(role)
        self.assertEqual(
            found, ["verify runs in no scenario: every scenario's skip-steps.txt leaves it out"]
        )
        outcomes, calls = self.run_scenario(role, "default")
        self.assertEqual(outcomes["scenario-limits"], run_harness.FAIL)
        for name in MOLECULE_STEPS:
            self.assertEqual(outcomes[name], run_harness.SKIP, name)
        self.assertEqual(calls, [])

    def test_a_step_that_another_scenario_runs_is_not_refused(self) -> None:
        self.assertEqual(run_harness.check_scenarios(self.split_role()), [])

    def test_the_refusal_is_found_from_any_scenarios_run(self) -> None:
        role = self.split_role()
        self.write_skips(role, "plan", ["idempotence", "verify", "check-fresh"])
        for name in ("default", "plan"):
            found = run_harness.check_scenarios(role, name)
            self.assertEqual(len(found), 1, found)
            self.assertIn("check-fresh runs in no scenario", found[0])

    def test_steps_every_run_needs_cannot_be_left_out(self) -> None:
        for name in ("create", "prepare", "converge", "destroy", "nonsense"):
            role = self.make_role(also=["plan"])
            self.write_skips(role, "plan", [name])
            found = run_harness.check_scenarios(role)
            self.assertEqual(len(found), 1, (name, found))
            self.assertTrue(found[0].startswith("molecule/plan/skip-steps.txt: cannot leave out "))
            self.assertIn(name, found[0])

    def test_a_line_that_is_not_one_step_name_is_refused_and_leaves_nothing_out(self) -> None:
        bad_texts = (
            "skip: [verify]\n",
            "verify please\n",
            "- verify\n",
            "verify, idempotence\n",
            "verify # not at the start of the line\n",
        )
        for text in bad_texts:
            role = self.make_role(also=["plan"])
            (role / "molecule" / "plan" / run_harness.SKIP_FILE).write_text(text, encoding="utf-8")
            found = run_harness.check_scenarios(role)
            self.assertEqual(len(found), 1, (text, found))
            self.assertTrue(found[0].startswith("molecule/plan/skip-steps.txt: "), found)
            self.assertEqual(run_harness.read_skips(role / "molecule" / "plan")[0], [], text)
            outcomes, calls = self.run_scenario(role, "plan")
            self.assertEqual(outcomes["scenario-limits"], run_harness.FAIL, text)
            self.assertEqual(calls, [], text)

    def test_the_same_step_listed_twice_is_one_step(self) -> None:
        role = self.make_role(also=["plan"])
        self.write_skips(role, "plan", ["verify", "verify"])
        self.assertEqual(run_harness.read_skips(role / "molecule" / "plan"), (["verify"], []))
        self.assertEqual(run_harness.check_scenarios(role), [])


if __name__ == "__main__":
    unittest.main()
