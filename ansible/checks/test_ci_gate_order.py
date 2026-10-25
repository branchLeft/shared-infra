"""The order and the gate of the Ansible workflow, and the schedules the CI work depends on.

ci_select.py chooses shards; this file holds the workflow to what the choice assumes:

* the shard job waits for the lint job, so a lint error starts no container;
* the shard job runs only when discover chose shards, and refuses the entry that stands for none;
* the gate job (the check the ruleset requires) fails unless the lint passed, and fails when
  shards were chosen and did not all pass;
* the merge queue still triggers the workflow, so "merge_group runs everything" can happen;
* the CrowdSec pin check opens a pull request on a stale pin and still fails when it cannot run;
* the ansible-hosts environment probe is scheduled and judges the environment;
* Dependabot runs monthly and grouped.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def load(path: Path) -> object:
    """Return a YAML file's document."""
    return YAML(typ="safe").load(path.read_text(encoding="utf-8"))


def get(node: object, *path: str | int) -> object:
    """Walk a loaded document by keys and indexes; None when any step is missing."""
    for step in path:
        if isinstance(node, dict) and isinstance(step, str):
            node = node.get(step)
        elif isinstance(node, list) and isinstance(step, int) and -len(node) <= step < len(node):
            node = node[step]
        else:
            return None
    return node


def keys(node: object) -> set[str]:
    """Return the keys of a mapping, or an empty set."""
    return {str(key) for key in node} if isinstance(node, dict) else set()


def items(node: object) -> list[object]:
    """Return the elements of a list, or an empty list."""
    return list(node) if isinstance(node, list) else []


def needs(job: object) -> set[str]:
    """Return the job keys a job waits for."""
    value = get(job, "needs")
    return {value} if isinstance(value, str) else {str(entry) for entry in items(value)}


def script(job: object) -> str:
    """Return the text of every run step of a job."""
    return "\n".join(str(get(step, "run") or "") for step in items(get(job, "steps")))


def only_job(workflow: object) -> object:
    """Return the one job of a workflow."""
    jobs = get(workflow, "jobs")
    return next(iter(jobs.values())) if isinstance(jobs, dict) else None


class AnsibleWorkflowOrderTest(unittest.TestCase):
    workflow = load(WORKFLOWS / "ansible.yml")

    def job(self, name: str) -> object:
        return get(self.workflow, "jobs", name)

    def test_the_jobs_the_rest_of_this_file_reads_exist(self) -> None:
        # A control: an empty read would make every test below pass.
        self.assertLessEqual(
            {"discover", "lint", "shard", "roles"}, keys(get(self.workflow, "jobs"))
        )

    def test_the_shards_wait_for_the_lint(self) -> None:
        self.assertLessEqual({"discover", "lint"}, needs(self.job("shard")))

    def test_the_shards_run_only_when_discover_chose_some(self) -> None:
        condition = str(get(self.job("shard"), "if"))
        self.assertIn("needs.discover.outputs.shards == 'true'", condition)
        self.assertIn("needs.discover.outputs.ansible == 'true'", condition)

    def test_discover_publishes_the_choice(self) -> None:
        outputs = keys(get(self.job("discover"), "outputs"))
        self.assertLessEqual({"ansible", "matrix", "shards"}, outputs)

    def test_the_entry_that_stands_for_no_shard_is_refused(self) -> None:
        refusal = get(self.job("shard"), "steps", 0)
        self.assertIn("matrix.kind != 'role'", str(get(refusal, "if")))
        self.assertIn("exit 1", str(get(refusal, "run")))

    def test_the_gate_needs_every_job_and_fails_on_a_lint_that_did_not_pass(self) -> None:
        gate = self.job("roles")
        self.assertEqual({"discover", "lint", "shard"}, needs(gate))
        self.assertEqual("always()", str(get(gate, "if")).strip())
        self.assertIn('[ "$LINT" != "success" ]', script(gate))
        self.assertIn('[ "$SHARD" != "success" ]', script(gate))

    def test_a_shard_job_that_did_not_succeed_fails_the_gate_when_shards_were_chosen(self) -> None:
        text = script(self.job("roles"))
        self.assertLess(
            text.index('[ "$SHARDS" = "false" ]'), text.index('[ "$SHARD" != "success" ]')
        )
        self.assertIn('[ "$SHARDS" != "true" ]', text)

    def test_the_merge_queue_triggers_the_workflow(self) -> None:
        self.assertLessEqual(
            {"merge_group", "pull_request", "push"}, keys(get(self.workflow, "on"))
        )


class CrowdsecPinCheckTest(unittest.TestCase):
    workflow = load(WORKFLOWS / "crowdsec-hub-pin-check.yml")

    def test_the_job_can_open_a_pull_request_with_its_own_token(self) -> None:
        job = only_job(self.workflow)
        self.assertEqual("write", get(job, "permissions", "pull-requests"))
        self.assertEqual("write", get(job, "permissions", "contents"))

    def test_the_pull_request_step_runs_only_for_a_stale_pin(self) -> None:
        steps = [
            step
            for step in items(get(only_job(self.workflow), "steps"))
            if "pull request" in str(get(step, "name"))
        ]
        self.assertEqual(1, len(steps))
        self.assertEqual("steps.check.outputs.status == '1'", get(steps[0], "if"))
        self.assertEqual("${{ secrets.GITHUB_TOKEN }}", get(steps[0], "env", "GH_TOKEN"))

    def test_a_check_that_could_not_run_still_goes_red(self) -> None:
        text = script(only_job(self.workflow))
        self.assertIn('[ "$status" -gt 1 ]', text)
        self.assertIn('exit "$status"', text)


class EnvironmentProbeTest(unittest.TestCase):
    workflow = load(WORKFLOWS / "ansible-environment-probe.yml")

    def test_the_probe_is_scheduled(self) -> None:
        self.assertTrue(get(self.workflow, "on", "schedule"))

    def test_the_probe_reads_with_a_read_only_token(self) -> None:
        permissions = get(self.workflow, "permissions")
        self.assertEqual({"contents", "actions"}, keys(permissions))
        for name in keys(permissions):
            self.assertEqual("read", get(permissions, name), name)

    def test_the_probe_judges_the_environment_with_the_delivery_check(self) -> None:
        text = " ".join(script(only_job(self.workflow)).split())
        self.assertIn("check_delivery.py environment", text)
        self.assertIn("environments/ansible-hosts/deployment-branch-policies", text)


class DependabotCadenceTest(unittest.TestCase):
    updates = items(get(load(ROOT / ".github" / "dependabot.yml"), "updates"))

    def test_every_ecosystem_runs_monthly(self) -> None:
        self.assertTrue(self.updates)
        for entry in self.updates:
            with self.subTest(entry=get(entry, "package-ecosystem"), at=get(entry, "directory")):
                self.assertEqual("monthly", get(entry, "schedule", "interval"))

    def test_the_groups_the_ecosystems_share_are_kept(self) -> None:
        grouped = {
            str(get(entry, "package-ecosystem")) for entry in self.updates if get(entry, "groups")
        }
        self.assertLessEqual({"npm", "uv", "github-actions"}, grouped)


if __name__ == "__main__":
    unittest.main()
