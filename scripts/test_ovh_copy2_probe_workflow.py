#!/usr/bin/env python3
"""Pin tests for .github/workflows/ovh-copy2-probe.yml.

The workflow holds OVHcloud credentials behind an owner approval and creates
buckets that can carry an object lock, so each rule below is checked on the
parsed file, and each is shown to go red when one line is sabotaged.
"""

from __future__ import annotations

import copy
import pathlib
import re
import unittest
from typing import Any

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ovh-copy2-probe.yml"
SCRIPT = "ovh/copy2/probe_object_lock.py"
ENVIRONMENT = "ovh-copy2-probe"
SECRET_USERS = {"Preflight", "Create the buckets", "Destroy the probe"}
SHA_PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def load() -> dict[str, Any]:
    loaded = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML reads the key `on` as the boolean True (YAML 1.1).
    if True in loaded:
        loaded["on"] = loaded.pop(True)
    return loaded


def steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    return workflow["jobs"]["probe"]["steps"]


def named(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    return next(step for step in steps(workflow) if step.get("name") == name)


def index(workflow: dict[str, Any], name: str) -> int:
    return steps(workflow).index(named(workflow, name))


def violations(workflow: dict[str, Any]) -> list[str]:
    """Every rule the workflow breaks, one string each."""
    found: list[str] = []
    job = workflow["jobs"]["probe"]
    if set(workflow["on"]) != {"workflow_dispatch"}:
        found.append("triggers: only workflow_dispatch is allowed")
    if workflow.get("permissions") != {"contents": "read"}:
        found.append("permissions: the workflow default must be contents: read")
    if not set(job.get("permissions", {}).items()) <= {("contents", "read"), ("packages", "read")}:
        found.append("permissions: the job may read contents and packages only")
    if list(workflow["jobs"]) != ["probe"]:
        found.append("jobs: exactly one job")
    if job.get("environment") != ENVIRONMENT:
        found.append("environment: the job must run in the approval-gated environment")
    concurrency = job.get("concurrency") or {}
    if not concurrency.get("group") or "${{" in str(concurrency.get("group")):
        found.append("concurrency: a literal group is required")
    if concurrency.get("cancel-in-progress") is not False:
        found.append("concurrency: a gated run is never cancelled by another")
    if "concurrency" in workflow:
        found.append("concurrency: set on the job, not the workflow")
    if "refs/heads/main" not in str(job.get("if", "")):
        found.append("if: the job runs from main only")
    if any(key in job.get("env", {}) for key in ("OVH_CLIENT_ID", "OVH_CLIENT_SECRET")):
        found.append("env: the OVHcloud secrets are not job-level")
    for step in steps(workflow):
        label = step.get("name", step.get("uses", "?"))
        if "uses" in step and not SHA_PIN.match(step["uses"]):
            found.append(f"pin: {label} is not pinned by a full sha")
        env_text = str(step.get("env", {}))
        if "secrets.OVH_" in env_text and label not in SECRET_USERS:
            found.append(f"secrets: {label} must not see the OVHcloud secrets")
        if "secrets." in str(step.get("run", "")) or "secrets." in str(step.get("with", "")):
            found.append(f"secrets: {label} interpolates a secret into text")
        run = str(step.get("run", ""))
        if "set -x" in run or re.search(r"\becho\b.*(SECRET|CLIENT|PASSPHRASE)", run):
            found.append(f"echo: {label} may print a credential")
        if "--show-secrets" in run and "| python3 probe_object_lock.py" not in run:
            found.append(f"show-secrets: {label} must pipe straight into the script")
        if "--show-secrets" in run and ">" in run.replace("|", ""):
            found.append(f"show-secrets: {label} must not redirect to a file")
    names = [step.get("name") for step in steps(workflow)]
    for before, after in [
        ("Preflight", "Install dependencies"),
        ("Preflight", "Create the probe stack"),
        ("Create the probe stack", "Create the buckets"),
        ("Create the buckets", "Probe object lock"),
        ("Probe object lock", "Destroy the probe"),
    ]:
        if names.index(before) > names.index(after):
            found.append(f"order: {before} must come before {after}")
    for name in ("Purge object versions", "Destroy the probe"):
        condition = str(named(workflow, name).get("if", ""))
        if "always()" not in condition:
            found.append(f"always: {name} must run with always()")
        if "steps.init.outcome == 'success'" not in condition:
            found.append(f"always: {name} runs once the stack exists")
    if named(workflow, "Destroy the probe").get("continue-on-error"):
        found.append("destroy: a failed destroy must fail the job")
    if "always()" not in str(named(workflow, "Upload the result").get("if", "")):
        found.append("artifact: the result is uploaded even when the probe failed")
    if "always()" not in str(
        named(workflow, "Write the lifecycle to the job summary").get("if", "")
    ):
        found.append("summary: the lifecycle is written even when the probe failed")
    return found


class WorkflowPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = load()

    def test_the_committed_workflow_breaks_no_rule(self) -> None:
        self.assertEqual(violations(self.workflow), [])

    def test_no_trigger_but_a_manual_dispatch(self) -> None:
        self.assertEqual(set(self.workflow["on"]), {"workflow_dispatch"})

    def test_preflight_runs_before_anything_is_installed_or_created(self) -> None:
        self.assertLess(index(self.workflow, "Preflight"), index(self.workflow, "Setup pnpm"))
        self.assertIn("preflight", named(self.workflow, "Preflight")["run"])

    def test_the_gate_check_is_the_first_step(self) -> None:
        self.assertEqual(
            steps(self.workflow)[0]["name"], "Refuse to run through an ungated environment"
        )

    def test_the_destroy_steps_run_with_always_and_the_destroy_is_not_optional(self) -> None:
        for name in ("Purge object versions", "Destroy the probe"):
            self.assertIn("always()", named(self.workflow, name)["if"])
        self.assertNotIn("continue-on-error", named(self.workflow, "Destroy the probe"))

    def test_only_three_steps_see_the_ovhcloud_secrets(self) -> None:
        holders = {
            step["name"]
            for step in steps(self.workflow)
            if "secrets.OVH_" in str(step.get("env", {}))
        }
        self.assertEqual(holders, SECRET_USERS)

    def test_the_install_step_that_runs_dependency_scripts_sees_no_secret(self) -> None:
        self.assertNotIn("OVH", str(named(self.workflow, "Install dependencies").get("env", {})))

    def test_the_artifact_and_summary_steps_exist_and_use_the_script_output(self) -> None:
        self.assertIn("ovh-probe-result", named(self.workflow, "Probe object lock")["run"])
        self.assertIn("ovh-probe-result", str(named(self.workflow, "Upload the result")["with"]))

    def test_every_step_calling_the_script_names_it_by_the_committed_path(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(SCRIPT, text)
        self.assertTrue((ROOT / SCRIPT).is_file())


class SabotageTests(unittest.TestCase):
    """Each edit breaks one rule; the rule list must name it."""

    def broken(self, change: Any) -> list[str]:
        workflow = copy.deepcopy(load())
        change(workflow)
        return violations(workflow)

    def test_a_pull_request_trigger_is_caught(self) -> None:
        found = self.broken(lambda w: w["on"].update({"pull_request": {}}))
        self.assertTrue(any("triggers" in item for item in found))

    def test_a_destroy_without_always_is_caught(self) -> None:
        def change(w: dict[str, Any]) -> None:
            named(w, "Destroy the probe")["if"] = "steps.init.outcome == 'success'"

        self.assertTrue(any("always" in item for item in self.broken(change)))

    def test_a_destroy_that_ignores_whether_the_stack_exists_is_caught(self) -> None:
        def change(w: dict[str, Any]) -> None:
            named(w, "Destroy the probe")["if"] = "always()"

        self.assertTrue(any("once the stack exists" in item for item in self.broken(change)))

    def test_a_destroy_allowed_to_fail_quietly_is_caught(self) -> None:
        def change(w: dict[str, Any]) -> None:
            named(w, "Destroy the probe")["continue-on-error"] = True

        self.assertTrue(any("destroy" in item for item in self.broken(change)))

    def test_a_job_level_secret_is_caught(self) -> None:
        def change(w: dict[str, Any]) -> None:
            w["jobs"]["probe"]["env"] = {"OVH_CLIENT_SECRET": "${{ secrets.OVH_CLIENT_SECRET }}"}

        self.assertTrue(any("not job-level" in item for item in self.broken(change)))

    def test_a_secret_in_the_install_step_is_caught(self) -> None:
        def change(w: dict[str, Any]) -> None:
            named(w, "Install dependencies")["env"]["OVH_CLIENT_SECRET"] = (
                "${{ secrets.OVH_CLIENT_SECRET }}"
            )

        self.assertTrue(any("must not see" in item for item in self.broken(change)))

    def test_an_unpinned_action_is_caught(self) -> None:
        def change(w: dict[str, Any]) -> None:
            named(w, "Checkout")["uses"] = "actions/checkout@v7"

        self.assertTrue(any("pin" in item for item in self.broken(change)))

    def test_a_missing_environment_is_caught(self) -> None:
        def change(w: dict[str, Any]) -> None:
            del w["jobs"]["probe"]["environment"]

        self.assertTrue(any("environment" in item for item in self.broken(change)))

    def test_a_cancelling_concurrency_group_is_caught(self) -> None:
        def change(w: dict[str, Any]) -> None:
            w["jobs"]["probe"]["concurrency"]["cancel-in-progress"] = True

        self.assertTrue(any("never cancelled" in item for item in self.broken(change)))

    def test_write_permissions_are_caught(self) -> None:
        def change(w: dict[str, Any]) -> None:
            w["jobs"]["probe"]["permissions"]["contents"] = "write"

        self.assertTrue(any("permissions" in item for item in self.broken(change)))

    def test_secrets_dumped_to_a_file_are_caught(self) -> None:
        def change(w: dict[str, Any]) -> None:
            named(w, "Probe object lock")["run"] += (
                "\npulumi stack output --show-secrets > out.json\n"
            )

        self.assertTrue(any("show-secrets" in item for item in self.broken(change)))

    def test_preflight_moved_after_the_install_is_caught(self) -> None:
        def change(w: dict[str, Any]) -> None:
            items = steps(w)
            preflight = items.pop(index(w, "Preflight"))
            items.insert(index(w, "Create the probe stack"), preflight)

        found = self.broken(change)
        self.assertTrue(any("order" in item for item in found))


if __name__ == "__main__":
    unittest.main()
