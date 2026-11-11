"""Pin tests for the OVHcloud lock-probe workflow.

The workflow creates paid cloud resources with a service-account secret, so its
shape is the control: dispatch-only, held by a protected environment, secrets in
three steps and no more, and a destroy step that runs on every outcome. The
rule narrative is in ovh/copy2/probe/README.md.
"""

from __future__ import annotations

import pathlib
import re
import unittest

import yaml
from test_workflow_concurrency import load

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ovh-copy2-probe.yml"
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
PROBE_DIR = ROOT / "ovh" / "copy2" / "probe"
PROBE_STACK_FILE = ROOT / "ovh" / "copy2" / "Pulumi.probe.yaml"

ENVIRONMENT = "ovh-copy2-probe"
SECRET_NAMES = ("OVH_CLIENT_ID", "OVH_CLIENT_SECRET")
SECRET_STEPS = ("up", "check", "destroy")


def text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def workflow(source: str | None = None) -> dict:
    data = load(text() if source is None else source)
    assert isinstance(data, dict)
    return data


def job(data: dict) -> dict:
    assert list(data["jobs"]) == ["probe"], "the workflow holds exactly one job"
    return data["jobs"]["probe"]


def steps(data: dict) -> list[dict]:
    return job(data)["steps"]


def step(data: dict, step_id: str) -> dict:
    found = [s for s in steps(data) if s.get("id") == step_id]
    assert len(found) == 1, f"expected exactly one step with id {step_id}"
    return found[0]


def position(data: dict, step_id: str) -> int:
    return steps(data).index(step(data, step_id))


def triggers(data: dict) -> dict:
    # The loader reads `on` as a string key, as YAML 1.2 and GitHub do.
    return data["on"]


def pins(source: str) -> dict[str, str]:
    """Action name to the 40-hex sha it is pinned to."""
    return {
        m.group(1): m.group(2)
        for m in re.finditer(r"uses: ([\w./-]+)@([0-9a-f]{40}) # v\d", source)
    }


class TriggerTests(unittest.TestCase):
    def test_the_only_trigger_is_a_manual_dispatch(self) -> None:
        self.assertEqual(["workflow_dispatch"], list(triggers(workflow())))

    def test_no_schedule_pull_request_or_pull_request_target_appears_anywhere(
        self,
    ) -> None:
        body = re.sub(r"(?m)^\s*#.*$", "", text())
        for word in (
            "schedule:",
            "pull_request",
            "push:",
            "merge_group",
            "workflow_call",
            "workflow_run",
        ):
            with self.subTest(word=word):
                self.assertNotIn(word, body)

    def test_the_dispatch_takes_no_inputs(self) -> None:
        self.assertEqual({}, triggers(workflow())["workflow_dispatch"])

    def test_the_job_runs_from_main_only(self) -> None:
        self.assertEqual("github.ref == 'refs/heads/main'", job(workflow())["if"])


class EnvironmentTests(unittest.TestCase):
    def test_the_job_is_held_by_the_protected_environment(self) -> None:
        self.assertEqual(ENVIRONMENT, job(workflow())["environment"])

    def test_the_gate_reads_the_same_environment_the_job_names(self) -> None:
        self.assertEqual(ENVIRONMENT, job(workflow())["env"]["PROBE_ENVIRONMENT"])

    def test_the_gate_is_the_first_step_after_checkout_and_python(self) -> None:
        data = workflow()
        self.assertLess(position(data, "gate"), 4)
        self.assertEqual(
            "python3 ovh/copy2/probe/probe.py gate", step(data, "gate")["run"]
        )

    def test_the_gate_precedes_every_step_that_can_create_anything(self) -> None:
        data = workflow()
        for later in SECRET_STEPS:
            self.assertLess(position(data, "gate"), position(data, later))

    def test_the_project_in_the_workflow_is_the_project_in_the_stack_file(self) -> None:
        stack = yaml.safe_load(PROBE_STACK_FILE.read_text(encoding="utf-8"))
        allowed = stack["config"]["branchleft-ovh-copy2:allowedProjectId"]
        self.assertRegex(allowed, r"^[0-9a-f]{32}$")
        self.assertEqual(allowed, job(workflow())["env"]["OVH_CLOUD_PROJECT_SERVICE"])

    def test_only_one_probe_runs_at_a_time_and_a_running_one_is_never_cancelled(
        self,
    ) -> None:
        self.assertEqual(
            {"group": ENVIRONMENT, "cancel-in-progress": False},
            job(workflow())["concurrency"],
        )


class PermissionTests(unittest.TestCase):
    def test_the_workflow_and_job_permissions_are_the_minimum(self) -> None:
        data = workflow()
        self.assertEqual({"contents": "read"}, data["permissions"])
        self.assertEqual(
            {"contents": "read", "packages": "read"}, job(data)["permissions"]
        )

    def test_no_token_can_be_minted_and_nothing_can_write(self) -> None:
        body = text()
        self.assertNotIn("id-token", body)
        self.assertNotRegex(body, r"(?m):\s*write\s*$")


class SecretTests(unittest.TestCase):
    def test_the_two_ovh_secrets_are_read_by_the_up_check_and_destroy_steps_only(
        self,
    ) -> None:
        data = workflow()
        holders = [s["id"] for s in steps(data) if "secrets.OVH_" in str(s)]
        self.assertEqual(list(SECRET_STEPS), holders)
        for step_id in SECRET_STEPS:
            env = step(data, step_id)["env"]
            for name in SECRET_NAMES:
                self.assertEqual(f"${{{{ secrets.{name} }}}}", env[name])

    def test_no_secret_sits_in_the_workflow_or_job_environment(self) -> None:
        data = workflow()
        self.assertNotIn("env", data)
        self.assertNotIn("secrets.", str(job(data)["env"]))

    def test_the_only_other_secret_is_the_run_token_for_the_package_install(
        self,
    ) -> None:
        used = set(re.findall(r"secrets\.([A-Z0-9_]+)", text()))
        self.assertEqual({*SECRET_NAMES, "GITHUB_TOKEN"}, used)

    def test_the_install_step_never_sees_an_ovh_secret(self) -> None:
        install = [
            s for s in steps(workflow()) if s.get("name") == "Install dependencies"
        ]
        self.assertEqual(1, len(install))
        self.assertNotIn("OVH_", str(install[0]))

    def test_no_run_line_interpolates_an_expression(self) -> None:
        for s in steps(workflow()):
            with self.subTest(step=s.get("name")):
                self.assertNotIn("${{", str(s.get("run", "")))

    def test_nothing_is_uploaded_or_cached(self) -> None:
        body = text()
        for word in (
            "upload-artifact",
            "download-artifact",
            "actions/cache",
            "gh release",
            "ACTIONS_STEP_DEBUG",
        ):
            with self.subTest(word=word):
                self.assertNotIn(word, body)

    def test_the_state_backend_is_not_a_login_or_a_bucket(self) -> None:
        body = text()
        for word in ("pulumi login", "gs://", "s3://", "PULUMI_ACCESS_TOKEN"):
            self.assertNotIn(word, body)


class DestroyTests(unittest.TestCase):
    def test_the_destroy_step_runs_on_every_outcome_and_is_last(self) -> None:
        data = workflow()
        destroy = step(data, "destroy")
        self.assertTrue(destroy["if"].startswith("always()"))
        self.assertIn("steps.gate.outcome == 'success'", destroy["if"])
        self.assertIs(steps(data)[-1], destroy)

    def test_the_destroy_step_runs_the_destroy_command(self) -> None:
        run = step(workflow(), "destroy")["run"]
        self.assertEqual(
            '"$RUNNER_TEMP/probe-venv/bin/python" ovh/copy2/probe/probe.py destroy', run
        )

    def test_no_step_may_fail_silently(self) -> None:
        for s in steps(workflow()):
            with self.subTest(step=s.get("name")):
                self.assertNotIn("continue-on-error", s)
        self.assertNotIn("continue-on-error", job(workflow()))
        self.assertNotIn("|| true", text())

    def test_the_steps_run_in_the_order_that_keeps_secrets_late(self) -> None:
        data = workflow()
        order = [position(data, i) for i in ("gate", "up", "check", "destroy")]
        self.assertEqual(sorted(order), order)
        names = [s.get("name", "") for s in steps(data)]
        self.assertLess(names.index("Self-test the probe"), position(data, "up"))
        self.assertLess(names.index("Install dependencies"), position(data, "up"))

    def test_every_probe_step_has_its_own_timeout_and_the_job_outlasts_them(
        self,
    ) -> None:
        data = workflow()
        total = 0
        for step_id in ("gate", *SECRET_STEPS):
            total += step(data, step_id)["timeout-minutes"]
        self.assertGreater(job(data)["timeout-minutes"], total)


class PinTests(unittest.TestCase):
    def test_every_action_is_pinned_by_sha_with_a_version_comment(self) -> None:
        for line in text().splitlines():
            if "uses:" in line and not line.strip().startswith("#"):
                with self.subTest(line=line.strip()):
                    self.assertRegex(line, r"uses: [\w./-]+@[0-9a-f]{40} # v\d")

    def test_each_pin_is_the_one_ci_already_uses(self) -> None:
        known = pins(CI_YML.read_text(encoding="utf-8"))
        mine = pins(text())
        self.assertTrue(mine)
        for action, sha in mine.items():
            with self.subTest(action=action):
                self.assertEqual(known[action], sha)


class ProbeFilesTests(unittest.TestCase):
    def test_the_s3_client_lock_is_exact_and_hashed(self) -> None:
        lines = [
            line
            for line in (PROBE_DIR / "requirements.txt")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip() and not line.startswith("#")
        ]
        pinned = [line for line in lines if "==" in line]
        hashed = [line for line in lines if "--hash=sha256:" in line]
        self.assertTrue(pinned)
        self.assertEqual(len(pinned), len(hashed))
        self.assertTrue(all(re.search(r"==\d", line) for line in pinned))

    def test_the_workflow_installs_that_lock_with_hashes_required(self) -> None:
        install = [
            s for s in steps(workflow()) if "requirements.txt" in str(s.get("run", ""))
        ]
        self.assertEqual(1, len(install))
        for flag in ("--require-hashes", "--only-binary=:all:", "--require-virtualenv"):
            self.assertIn(flag, install[0]["run"])

    def test_the_backend_is_a_throwaway_file_backend_inside_the_runner_scratch_area(
        self,
    ) -> None:
        source = (PROBE_DIR / "probe.py").read_text(encoding="utf-8")
        self.assertIn('f"file://{self.backend_dir}"', source)
        self.assertIn("f\"{env['RUNNER_TEMP']}/ovh-copy2-probe\"", source)


if __name__ == "__main__":
    unittest.main()
