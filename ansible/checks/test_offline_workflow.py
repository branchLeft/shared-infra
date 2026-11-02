"""Pins on the offline-render workflow: it can reach no secret, no host and no wider token.

ansible-offline.yml renders templates on a runner and tells the reader what is wrong with
them. It must stay a workflow that holds nothing worth stealing: read-only token, no secret,
no environment, no SSH, no trigger that runs a fork's code with more than that. Each rule is
checked on the parsed file, and proven by mutating a copy of the real one: a rule that does
not fail on its mutation is not a rule.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from check_pins import load_yaml
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ansible-offline.yml"
ACTION = ROOT / ".github" / "actions" / "ansible-venv" / "action.yml"
ANSIBLE = ROOT / ".github" / "workflows" / "ansible.yml"
SABOTAGE = ROOT / "ansible" / "checks" / "sabotage_offline_render.py"
ALLOWED_TRIGGERS = {"pull_request", "push", "workflow_dispatch"}
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
PR_GROUP = "${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}"
PR_CONCURRENCY = {
    "group": PR_GROUP,
    "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
}
SSH_USE = re.compile(r"(?<![\w-])ssh(?!-keygen)(?![\w-])|ssh-agent|ssh-add|scp ", re.IGNORECASE)
CACHE_KEY = re.compile(r"^\s*key: (ansible-venv-.*)$", re.MULTILINE)
MAX_MINUTES = 15


def parse(text: str) -> dict[str, object]:
    """Return the YAML mapping in ``text``, or an empty one."""
    document = YAML(typ="safe").load(text)
    return {str(k): v for k, v in document.items()} if isinstance(document, dict) else {}


def steps_of(workflow: dict[str, object]) -> list[dict[str, object]]:
    """Return every step of every job."""
    found: list[dict[str, object]] = []
    jobs = workflow.get("jobs")
    for job in jobs.values() if isinstance(jobs, dict) else []:
        steps = job.get("steps") if isinstance(job, dict) else None
        if isinstance(steps, list):
            found.extend(step for step in steps if isinstance(step, dict))
    return found


def action_steps(action_text: str) -> list[dict[str, object]]:
    """Return every step of the composite action, which keeps them under runs."""
    runs = parse(action_text).get("runs")
    steps = runs.get("steps") if isinstance(runs, dict) else None
    return [step for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []


def findings(workflow_text: str, action_text: str, ansible_text: str) -> list[str]:
    """Return what is wrong with the workflow, its action or their match to ansible.yml."""
    workflow = parse(workflow_text)
    found: list[str] = []
    triggers = workflow.get("on")
    names = set(triggers) if isinstance(triggers, dict) else set()
    if not names:
        found.append("the workflow has no triggers")
    if names - ALLOWED_TRIGGERS:
        found.append(f"triggers outside the allowed set: {sorted(names - ALLOWED_TRIGGERS)}")
    if workflow.get("permissions") != {"contents": "read"}:
        found.append("the token is not exactly contents: read")
    if workflow.get("concurrency") != PR_CONCURRENCY:
        found.append("the concurrency block is not the pull-request one")
    jobs = workflow.get("jobs")
    for name, job in jobs.items() if isinstance(jobs, dict) else []:
        if not isinstance(job, dict):
            continue
        if "permissions" in job:
            found.append(f"job {name} sets its own permissions")
        if "environment" in job:
            found.append(f"job {name} runs in an environment")
        if "secrets" in job or "services" in job or "container" in job:
            found.append(f"job {name} takes secrets, services or a container")
        minutes = job.get("timeout-minutes")
        if not isinstance(minutes, int) or minutes > MAX_MINUTES:
            found.append(f"job {name} has no timeout of {MAX_MINUTES} minutes or less")
    if re.search(r"\bsecrets\.|\bvars\.", workflow_text):
        found.append("the workflow reads a secret or a variable")
    if re.search(r"\bsecrets\.|\bvars\.", action_text):
        found.append("the composite action reads a secret or a variable")
    for step in steps_of(workflow) + action_steps(action_text):
        used = step.get("uses")
        if isinstance(used, str) and not used.startswith("./") and not PINNED.match(used):
            found.append(f"action {used} is not pinned by a full commit SHA")
        command = step.get("run")
        if isinstance(command, str) and SSH_USE.search(command):
            found.append("a step uses ssh")
        if isinstance(used, str) and SSH_USE.search(used):
            found.append("a step uses an ssh action")
        with_ = step.get("with")
        if (
            isinstance(used, str)
            and used.startswith("actions/checkout")
            and (not isinstance(with_, dict) or with_.get("persist-credentials") is not False)
        ):
            found.append("checkout keeps its credentials")
    ours, theirs = CACHE_KEY.search(action_text), CACHE_KEY.search(ansible_text)
    if ours is None or theirs is None or ours[1] != theirs[1]:
        found.append("the tool environment cache key differs from ansible.yml's")
    return found


class WorkflowPins(unittest.TestCase):
    """The real files obey the rules, and each rule fails on its mutation."""

    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.action = ACTION.read_text(encoding="utf-8")
        self.ansible = ANSIBLE.read_text(encoding="utf-8")

    def mutated(self, old: str, new: str) -> list[str]:
        self.assertIn(old, self.workflow, "the mutation does not match the real file")
        return findings(self.workflow.replace(old, new, 1), self.action, self.ansible)

    def mutated_action(self, old: str, new: str) -> list[str]:
        self.assertIn(old, self.action, "the mutation does not match the real action")
        return findings(self.workflow, self.action.replace(old, new, 1), self.ansible)

    def test_the_real_files_have_no_finding(self) -> None:
        self.assertEqual([], findings(self.workflow, self.action, self.ansible))

    def test_a_secret_is_refused(self) -> None:
        got = self.mutated("    steps:\n", "    env:\n      T: ${{ secrets.TOKEN }}\n    steps:\n")
        self.assertIn("the workflow reads a secret or a variable", got)

    def test_pull_request_target_is_refused(self) -> None:
        got = self.mutated(
            "  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request_target:\n"
        )
        self.assertTrue(any("triggers outside" in f for f in got), got)

    def test_the_merge_queue_trigger_is_refused(self) -> None:
        got = self.mutated("  workflow_dispatch:\n", "  workflow_dispatch:\n  merge_group:\n")
        self.assertTrue(any("triggers outside" in f for f in got), got)

    def test_a_wider_token_is_refused(self) -> None:
        got = self.mutated("  contents: read\n", "  contents: write\n")
        self.assertIn("the token is not exactly contents: read", got)

    def test_an_environment_is_refused(self) -> None:
        got = self.mutated("    runs-on:", "    environment: ansible-hosts\n    runs-on:")
        self.assertTrue(any("environment" in f for f in got), got)

    def test_an_unpinned_action_is_refused(self) -> None:
        got = self.mutated(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@v7"
        )
        self.assertTrue(any("not pinned" in f for f in got), got)

    def test_an_unpinned_action_in_the_composite_is_refused(self) -> None:
        got = self.mutated_action(
            "    - name: Check the installed set\n",
            "    - uses: someorg/tool@v1\n\n    - name: Check the installed set\n",
        )
        self.assertIn("action someorg/tool@v1 is not pinned by a full commit SHA", got)

    def test_ssh_is_refused(self) -> None:
        got = self.mutated("docker compose version || true", "ssh host true")
        self.assertIn("a step uses ssh", got)

    def test_a_long_timeout_is_refused(self) -> None:
        got = self.mutated("timeout-minutes: 15", "timeout-minutes: 360")
        self.assertTrue(any("timeout" in f for f in got), got)

    def test_checkout_must_drop_its_credentials(self) -> None:
        got = self.mutated("persist-credentials: false", "persist-credentials: true")
        self.assertIn("checkout keeps its credentials", got)

    def test_a_different_cache_key_is_refused(self) -> None:
        action = self.action.replace(
            "ansible-venv-${{ runner.os }}", "ansible-venv2-${{ runner.os }}"
        )
        self.assertNotEqual(action, self.action)
        got = findings(self.workflow, action, self.ansible)
        self.assertIn("the tool environment cache key differs from ansible.yml's", got)

    def test_the_concurrency_block_must_be_the_pull_request_one(self) -> None:
        got = self.mutated(
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
            "cancel-in-progress: true",
        )
        self.assertIn("the concurrency block is not the pull-request one", got)

    def test_the_composite_action_the_workflow_uses_exists(self) -> None:
        used = [
            s["uses"]
            for s in steps_of(parse(self.workflow))
            if str(s.get("uses", "")).startswith("./")
        ]
        self.assertEqual(["./.github/actions/ansible-venv"], used)
        self.assertTrue(ACTION.is_file())

    def test_the_action_pins_match_the_ones_ansible_yml_uses(self) -> None:
        for text in (self.workflow, self.action):
            for pinned in re.findall(r"uses: (actions/[\w-]+@[0-9a-f]{40})", text):
                self.assertIn(pinned, self.ansible)

    def test_the_test_count_the_step_demands_is_the_number_of_proofs(self) -> None:
        count = len(
            re.findall(r"^    def test_", SABOTAGE.read_text(encoding="utf-8"), re.MULTILINE)
        )
        demanded = re.search(r"-lt (\d+) \]", self.workflow)
        self.assertIsNotNone(demanded)
        self.assertEqual(count, int(demanded[1]) if demanded else -1)

    def test_the_workflow_is_not_a_required_check(self) -> None:
        required = (ROOT / "scripts" / "test_merge_group_triggers.py").read_text(encoding="utf-8")
        self.assertNotIn("Ansible offline render", required)
        self.assertNotIn("Render the Ansible templates offline", required)

    def test_load_yaml_reads_the_workflow(self) -> None:
        document, problem = load_yaml(WORKFLOW)
        self.assertIsNone(problem)
        self.assertIsInstance(document, dict)


if __name__ == "__main__":
    unittest.main()
