#!/usr/bin/env python3
"""Pin tests: every required check also runs on merge_group, and no deploy job can.

The merge queue tests a queued pull request on a gh-readonly-queue/main/... ref,
and only a `merge_group` run reports checks there. A required workflow without
that trigger leaves the queue waiting for a check that never arrives. The same
trigger must never reach a plan or apply job, which is why those carry an
explicit push-to-main condition.
"""

from __future__ import annotations

import pathlib
import re
import unittest

from test_ci_apply_environments import APPLY_JOBS, PLAN_JOBS, job_block, job_names

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

# Every context ruleset 20952655 requires, with the workflow file that
# produces it. A caller's context reads "<workflow name> / <job key>".
REQUIRED = {
    "Type check": "ci.yml",
    "Type check (mail)": "ci.yml",
    "Lint + test (mail/provision)": "ci.yml",
    "Type check (hetzner)": "ci.yml",
    "Type check + test (hetzner-host)": "ci.yml",
    "Lint + test (hetzner/provision)": "ci.yml",
    "Validate (edge Caddy config)": "ci.yml",
    "Test (scripts)": "ci.yml",
    "Audit (Pulumi secrets + state backends)": "ci.yml",
    "Validate (monitoring stack config)": "ci.yml",
    "docs-lint / docs-lint": "docs-lint.yml",
    "Lint and test the Ansible roles": "ansible.yml",
}

# The workflow that reports the standards gate, not a required context today.
ALSO_ON_THE_QUEUE = ["standards.yml"]


def read(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def on_block(text: str) -> str:
    """The top-level `on:` mapping, up to the next top-level key."""
    match = re.search(r"^on:[ \t]*\n((?:[ \t]+.*\n|[ \t]*\n|[ \t]*#.*\n)*)", text, re.M)
    if not match:
        raise AssertionError("no top-level `on:` block")
    return match.group(1)


def job_if(job: str) -> str | None:
    """The job-level `if:` expression, folded onto one line, or None."""
    lines = job.split("\n")
    for i, line in enumerate(lines):
        if re.match(r"^    if:", line):
            parts = [line.split("if:", 1)[1].strip().lstrip(">-").strip()]
            for follow in lines[i + 1 :]:
                if follow.startswith("      ") and follow.strip():
                    parts.append(follow.strip())
                else:
                    break
            return " ".join(p for p in parts if p)
    return None


class MergeGroupTriggerTests(unittest.TestCase):
    def test_every_required_workflow_runs_on_merge_group(self):
        for name in sorted({*REQUIRED.values(), *ALSO_ON_THE_QUEUE}):
            with self.subTest(workflow=name):
                block = on_block(read(name))
                self.assertRegex(block, r"(?m)^  merge_group:")
                self.assertRegex(block, r"(?m)^    types: \[checks_requested\]")

    def test_no_workflow_filters_merge_group_by_path(self):
        # merge_group supports no `paths:` filter, so a filter on the other
        # triggers would make the queue run a different set than the PR did.
        for name in sorted({*REQUIRED.values(), *ALSO_ON_THE_QUEUE}):
            with self.subTest(workflow=name):
                self.assertNotRegex(on_block(read(name)), r"(?m)^\s+paths(-ignore)?:")

    def test_required_workflows_are_still_triggered_by_pull_request_and_push(self):
        for name in sorted({*REQUIRED.values(), *ALSO_ON_THE_QUEUE}):
            with self.subTest(workflow=name):
                block = on_block(read(name))
                self.assertRegex(block, r"(?m)^  pull_request:")
                self.assertRegex(block, r"(?m)^  push:")

    def test_workflows_that_publish_or_poll_do_not_run_on_merge_group(self):
        for name in ("publish-hetzner-host.yml", "publish-edge-caddy.yml", "crowdsec-hub-pin-check.yml"):
            with self.subTest(workflow=name):
                self.assertNotIn("merge_group", on_block(read(name)))

    def test_required_ci_jobs_have_no_condition_that_could_skip_them(self):
        # A skipped required check counts as passing, so none of these jobs may
        # carry a job-level `if:` that is false on merge_group.
        text = read("ci.yml")
        by_name: dict[str, str] = {}
        for key in job_names(text):
            named = re.search(r"^    name: (.*?)[ \t]*$", job_block(text, key), re.M)
            if named:
                by_name[named.group(1)] = key
        for context in [n for n, f in REQUIRED.items() if f == "ci.yml"]:
            with self.subTest(context=context):
                self.assertIn(context, by_name, f"no job named {context!r}")
                self.assertIsNone(job_if(job_block(text, by_name[context])))

    def test_every_plan_and_apply_job_runs_on_push_to_main_only(self):
        text = read("ci.yml")
        for job in [*PLAN_JOBS, *APPLY_JOBS]:
            with self.subTest(job=job):
                condition = job_if(job_block(text, job))
                self.assertIsNotNone(condition, f"{job} has no `if:`")
                self.assertIn("github.event_name == 'push'", condition)
                self.assertIn("github.ref == 'refs/heads/main'", condition)

    def test_the_change_detector_runs_on_push_to_main_only(self):
        condition = job_if(job_block(read("ci.yml"), "changes"))
        self.assertIsNotNone(condition)
        self.assertIn("github.event_name == 'push'", condition)

    def test_no_job_in_ci_runs_a_credentialed_step_on_merge_group(self):
        # Every job that names an environment is a plan or apply job, and each
        # of those is gated above. A new one would have to join that list.
        text = read("ci.yml")
        jobs = text.split("\njobs:\n", 1)[1]
        for match in re.finditer(r"^  ([A-Za-z0-9_-]+):[ \t]*$", jobs, re.M):
            key = match.group(1)
            if re.search(r"^    environment: ", job_block(text, key), re.M):
                with self.subTest(job=key):
                    self.assertIn(key, [*PLAN_JOBS, *APPLY_JOBS])

    def decide_step(self):
        text = read("ansible.yml")
        step = text.split("- name: Decide whether the Ansible inputs changed", 1)[1]
        return step.split("- name: List the shards", 1)[0]

    def test_ansible_gate_diffs_the_queue_entry_on_merge_group(self):
        # The queue entry is narrowed by its own diff, base_sha..head_sha, by the rules a
        # pull request has (ci_select.py); it is not diffed against HEAD or a push's `before`.
        step = self.decide_step()
        self.assertIn("MERGE_GROUP_BASE: ${{ github.event.merge_group.base_sha }}", step)
        self.assertIn("MERGE_GROUP_HEAD: ${{ github.event.merge_group.head_sha }}", step)
        merge_branch = step[step.index("merge_group)") :]
        merge_branch = merge_branch[: merge_branch.index(";;")]
        self.assertIn('base="$MERGE_GROUP_BASE"', merge_branch)
        self.assertIn('head="$MERGE_GROUP_HEAD"', merge_branch)
        self.assertIn('git diff --name-only -z --no-renames "$base" "$head"', step)
        self.assertNotIn("github.event.before", step)

    def test_ansible_gate_runs_every_check_when_the_queue_diff_cannot_be_read(self):
        # A base or head the runner cannot resolve must widen the run, never skip it.
        step = self.decide_step()
        unknown = step[step.index("git cat-file") :]
        self.assertIn('"${base}^{commit}"', unknown)
        self.assertIn('"${head}^{commit}"', unknown)
        branch = unknown[: unknown.index("fi\n")]
        self.assertIn('echo "ansible=true" >> "$GITHUB_OUTPUT"', branch)
        self.assertIn("exit 0", branch)
        self.assertLess(unknown.index("exit 0"), unknown.index("git diff"))

    def test_ansible_gate_runs_every_check_on_the_weekly_sweep(self):
        text = read("ansible.yml")
        self.assertRegex(on_block(text), r"(?m)^  schedule:\n    - cron: ")
        step = self.decide_step()
        other = step[step.index("*)") :]
        other = other[: other.index(";;")]
        self.assertIn('echo "ansible=true" >> "$GITHUB_OUTPUT"', other)
        self.assertIn("exit 0", other)

    def test_ansible_push_to_main_repeats_no_check_the_queue_ran(self):
        step = self.decide_step()
        push = step[step.index("push)") :]
        push = push[: push.index(";;")]
        self.assertIn('echo "ansible=false" >> "$GITHUB_OUTPUT"', push)
        self.assertIn("exit 0", push)

    def test_the_role_unit_step_is_in_the_lint_job_and_has_no_condition_of_its_own(self):
        # The lint job runs on a merge-queue check only through the discover output, which
        # the Decide step sets to true on merge_group. The role unit step must ride that
        # same condition, with no `if:` of its own that could skip it on a queued check,
        # and it must call the one script that holds the glob and the run.
        text = read("ansible.yml")
        lint = job_block(text, "lint")
        self.assertEqual("needs.discover.outputs.ansible == 'true'", job_if(lint))
        steps = [part for part in lint.split("\n      - name: ") if part.startswith("Run every role's unit tests")]
        self.assertEqual(1, len(steps), "the lint job must hold exactly one role unit step")
        self.assertNotIn("if:", steps[0])
        # The run line is exact: a trailing `|| true` or a continue-on-error on the step or
        # the job would let a failing role test pass the gate, so neither may appear.
        run_lines = [line for line in steps[0].splitlines() if line.strip().startswith("run:")]
        self.assertEqual(
            ["        run: 'PYTHON=\"$RUNNER_TEMP/ansible-venv/bin/python\" ansible/checks/run_role_unit_tests.sh ansible'"],
            run_lines,
        )
        self.assertNotIn("continue-on-error", steps[0])
        self.assertNotIn("continue-on-error", lint)


if __name__ == "__main__":
    unittest.main()
