#!/usr/bin/env python3
"""Pin tests: a pull_request run is grouped per pull request, and only those runs cancel.

Every workflow is parsed with PyYAML's safe_load, the parser ci.yml pins for
the stack-keys check, and every rule is checked on the parsed data, never on the
text. So a quoted key, an escaped quote, a multi-line quoted value, a list-form
or quoted trigger, and a `#` inside a value cannot hide a concurrency key.

The rules:
- A workflow with a pull_request trigger has one top-level concurrency block,
  exactly the run-keyed block below. Its group is keyed on the pull request
  number and falls back to the run id, and cancel-in-progress is the pull_request
  expression.
- A workflow without one has no cancel-in-progress that is true or an
  expression, at workflow level or job level. Its top-level group, if any, holds
  the run id, so no run shares a group with another.
- A job with an `environment:` never has a cancel-in-progress that is true or an
  expression, whatever its triggers.
- A job-level cancel-in-progress in a pull_request workflow may be the
  pull_request expression only when the job has no environment.
- Every check fails closed: a file that does not parse, whose top level is not a
  mapping, whose trigger block is missing or doubled, or whose concurrency value
  is not a mapping, is a violation.
"""

from __future__ import annotations

import pathlib
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

PR_EXPRESSION = "${{ github.event_name == 'pull_request' }}"
PR_CONCURRENCY = {
    "group": "${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}",
    "cancel-in-progress": PR_EXPRESSION,
}
PR_TRIGGERS = {"pull_request", "pull_request_target"}
ABSENT = object()


class Unclassifiable(Exception):
    """A trigger block the test cannot read; the file fails closed."""


def workflow_files() -> list[pathlib.Path]:
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def trigger_names(data: dict) -> set[str]:
    """Trigger names from the on: block, read as a string, a list or a mapping.

    PyYAML reads a bare `on:` key as the boolean True (YAML 1.1), and a quoted
    "on" as the string. A file with both, or with neither, cannot be classified.
    """
    keys = [key for key in data if key is True or key == "on"]
    if len(keys) != 1:
        raise Unclassifiable(f"want exactly one trigger block (on: or \"on\":), found {len(keys)}")
    trigger = data[keys[0]]
    if isinstance(trigger, str):
        return {trigger}
    if isinstance(trigger, list) and all(isinstance(item, str) for item in trigger):
        return set(trigger)
    if isinstance(trigger, dict) and all(isinstance(key, str) for key in trigger):
        return set(trigger)
    raise Unclassifiable(f"trigger block has a form the test cannot read: {trigger!r}")


def cancel_problem(where: str, value: object, allow_pr_expression: bool) -> str | None:
    """None when cancel-in-progress is allowed here, else the reason it is not."""
    if value is ABSENT or value is False or value == "false":
        return None
    if allow_pr_expression and value == PR_EXPRESSION:
        return None
    return f"{where} cancel-in-progress is {value!r}, which may cancel a non-pull_request run"


def top_level_problems(name: str, value: object, pull_request: bool) -> list[str]:
    if not isinstance(value, dict):
        return [f"{name}: top-level concurrency is not a mapping: {value!r}"]
    if pull_request:
        if value != PR_CONCURRENCY:
            return [f"{name}: top-level concurrency is not the run-keyed block: {value!r}"]
        return []
    found = []
    group = value.get("group")
    if not isinstance(group, str) or "github.run_id" not in group:
        found.append(f"{name}: top-level group is shared across runs: {group!r}")
    problem = cancel_problem("top level", value.get("cancel-in-progress", ABSENT), False)
    if problem:
        found.append(f"{name}: {problem}")
    return found


def job_problems(name: str, job_name: str, job: dict, pull_request: bool) -> list[str]:
    config = job["concurrency"]
    if not isinstance(config, dict):
        return [f"{name}: job {job_name} concurrency is not a mapping: {config!r}"]
    allow = pull_request and "environment" not in job
    problem = cancel_problem(f"job {job_name}", config.get("cancel-in-progress", ABSENT), allow)
    return [f"{name}: {problem}"] if problem else []


def violations(name: str, text: str) -> list[str]:
    """Every rule break in one workflow's text, or [] for a file that passes."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        return [f"{name}: does not parse as YAML: {type(error).__name__}"]
    if not isinstance(data, dict):
        return [f"{name}: top level is not a mapping"]
    try:
        names = trigger_names(data)
    except Unclassifiable as error:
        return [f"{name}: {error}"]
    pull_request = bool(names & PR_TRIGGERS)
    found: list[str] = []
    if "concurrency" in data:
        found += top_level_problems(name, data["concurrency"], pull_request)
    elif pull_request:
        found.append(f"{name}: pull_request workflow has no top-level concurrency block")
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return found + [f"{name}: jobs is not a mapping"]
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            found.append(f"{name}: job {job_name} is not a mapping")
        elif "concurrency" in job:
            found += job_problems(name, job_name, job, pull_request)
    return found


def parsed(path: pathlib.Path) -> tuple[dict, set[str]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data, trigger_names(data)


class WorkflowConcurrencyTests(unittest.TestCase):
    def test_every_workflow_file_is_walked(self):
        names = {path.name for path in workflow_files()}
        self.assertIn("ci.yml", names)
        self.assertIn("ansible.yml", names)
        self.assertIn("docs-lint.yml", names)
        self.assertIn("standards.yml", names)

    def test_every_workflow_passes_the_concurrency_rules(self):
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(violations(path.name, text), [])

    def test_every_pull_request_workflow_carries_the_run_keyed_block(self):
        pull_request_files = 0
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                data, names = parsed(path)
                if not names & PR_TRIGGERS:
                    continue
                pull_request_files += 1
                self.assertEqual(data.get("concurrency"), PR_CONCURRENCY)
        self.assertGreater(pull_request_files, 0)

    def test_merge_group_runs_are_keyed_on_the_run_not_the_ref(self):
        # A merge_group event carries no pull_request, so its group falls back
        # to the run id. Keyed on the ref or the workflow name alone, every
        # queued check run would share one group and replace one another.
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                data, names = parsed(path)
                if "merge_group" not in names:
                    continue
                group = str(data.get("concurrency", {}).get("group", ""))
                self.assertIn("github.run_id", group)
                self.assertNotIn("github.ref", group)


class DetectorTests(unittest.TestCase):
    """Each probe and evasion the rules must refuse, and the shapes they must pass."""

    PR_WORKFLOW = (
        "on:\n"
        "  pull_request:\n"
        "concurrency:\n"
        "  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}\n"
        "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n"
        "jobs:\n"
        "  check:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ok\n"
    )

    # Cycle-3 probe zz-p1-escape-hash: an escaped quote ends the quoted group early,
    # so the ' #' reads as a comment and the real cancel key is skipped.
    P1_ESCAPE_HASH = (
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: production\n"
        '    concurrency: {group: "deploy\\" #", cancel-in-progress: true}\n'
        "    steps:\n"
        "      - run: echo deploy\n"
    )

    # Cycle-3 probe zz-p2-quoted-top: a quoted top-level key, shared group, cancel true.
    P2_QUOTED_TOP = (
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        '"concurrency":\n'
        "  group: deploy-shared\n"
        "  cancel-in-progress: true\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: production\n"
        "    steps:\n"
        "      - run: echo deploy\n"
    )

    # Cycle-3 probe zz-p3-escaped-seq-trigger: an escaped pull_request in a block sequence.
    P3_ESCAPED_SEQ_TRIGGER = (
        "on:\n"
        "  - push\n"
        '  - "pull\\x5frequest"\n'
        "jobs:\n"
        "  check:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ok\n"
    )

    # Cycle-3 probe zz-p4-multiline-hash: a double-quoted value continued onto a line
    # that starts with '#', so the cancel key sits inside the quoted scalar's line.
    P4_MULTILINE_HASH = (
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: production\n"
        '    concurrency: {group: "deploy\n'
        '      #x", cancel-in-progress: true}\n'
        "    steps:\n"
        "      - run: echo deploy\n"
    )

    def test_probe_zz_p1_escape_hash_is_refused(self):
        self.assertNotEqual(violations("zz-p1-escape-hash.yml", self.P1_ESCAPE_HASH), [])

    def test_probe_zz_p2_quoted_top_is_refused(self):
        self.assertNotEqual(violations("zz-p2-quoted-top.yml", self.P2_QUOTED_TOP), [])

    def test_probe_zz_p3_escaped_seq_trigger_is_refused(self):
        self.assertNotEqual(violations("zz-p3-escaped-seq-trigger.yml", self.P3_ESCAPED_SEQ_TRIGGER), [])

    def test_probe_zz_p4_multiline_hash_is_refused(self):
        self.assertNotEqual(violations("zz-p4-multiline-hash.yml", self.P4_MULTILINE_HASH), [])

    def test_the_run_keyed_pull_request_workflow_passes(self):
        self.assertEqual(violations("pr.yml", self.PR_WORKFLOW), [])

    def test_block_sequence_trigger_counts_as_pull_request(self):
        text = "on:\n  - push\n  - pull_request\njobs:\n  check:\n    runs-on: ubuntu-latest\n"
        self.assertNotEqual(violations("seq.yml", text), [])

    def test_quoted_trigger_key_counts_as_pull_request(self):
        text = 'on:\n  "pull_request":\n    types: [opened]\njobs:\n  check:\n    runs-on: ubuntu-latest\n'
        self.assertNotEqual(violations("quoted.yml", text), [])

    def test_pull_request_target_counts_as_pull_request(self):
        text = "on:\n  pull_request_target:\njobs:\n  check:\n    runs-on: ubuntu-latest\n"
        self.assertNotEqual(violations("target.yml", text), [])

    def test_push_only_workflow_without_concurrency_passes(self):
        text = "on:\n  push:\n    branches: [main]\njobs:\n  check:\n    runs-on: ubuntu-latest\n"
        self.assertEqual(violations("push.yml", text), [])

    def test_quoted_on_key_is_read_as_the_trigger(self):
        self.assertEqual(violations("quoted-on.yml", self.PR_WORKFLOW.replace("on:", '"on":', 1)), [])

    def test_both_on_keys_fail_closed(self):
        text = self.PR_WORKFLOW.replace("on:", 'on:\n  push:\n"on":', 1)
        self.assertNotEqual(violations("both.yml", text), [])

    def test_missing_trigger_block_fails_closed(self):
        text = "jobs:\n  check:\n    runs-on: ubuntu-latest\n"
        self.assertNotEqual(violations("none.yml", text), [])

    def test_unparseable_file_fails_closed(self):
        self.assertNotEqual(violations("broken.yml", "on: [push\n"), [])

    def test_top_level_that_is_not_a_mapping_fails_closed(self):
        self.assertNotEqual(violations("list.yml", "- a\n- b\n"), [])

    def test_string_top_level_concurrency_fails_closed(self):
        text = "on:\n  push:\nconcurrency: deploy\njobs:\n  check:\n    runs-on: ubuntu-latest\n"
        self.assertNotEqual(violations("string.yml", text), [])

    def test_cancel_true_at_job_level_is_refused(self):
        text = (
            "on:\n  push:\n"
            "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
            "    concurrency:\n      group: deploy\n      cancel-in-progress: true\n"
        )
        self.assertNotEqual(violations("job.yml", text), [])

    def test_hash_inside_quotes_is_not_a_comment(self):
        text = (
            "on:\n  push:\n"
            "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
            '    concurrency: {group: "deploy #1", cancel-in-progress: true}\n'
        )
        self.assertNotEqual(violations("hash.yml", text), [])

    def test_commented_out_cancel_key_is_not_read(self):
        text = (
            "on:\n  push:\n"
            "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
            "    concurrency:\n      group: deploy-${{ github.run_id }}\n"
            "      # cancel-in-progress: true\n"
        )
        self.assertEqual(violations("comment.yml", text), [])

    def test_escaped_cancel_key_is_read(self):
        text = (
            "on:\n  push:\n"
            "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
            '    concurrency:\n      group: deploy\n      "cancel\\x2din\\x2dprogress": true\n'
        )
        self.assertNotEqual(violations("escaped.yml", text), [])

    def test_pull_request_expression_refused_in_a_push_workflow(self):
        text = (
            "on:\n  push:\n"
            "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n"
            f"    concurrency:\n      group: deploy\n      cancel-in-progress: {PR_EXPRESSION}\n"
        )
        self.assertNotEqual(violations("expr.yml", text), [])

    def test_pull_request_expression_refused_on_an_environment_job(self):
        text = self.PR_WORKFLOW.replace(
            "  check:\n    runs-on: ubuntu-latest\n",
            "  check:\n    runs-on: ubuntu-latest\n    environment: production\n"
            f"    concurrency:\n      group: deploy\n      cancel-in-progress: {PR_EXPRESSION}\n",
        )
        self.assertNotEqual(violations("env.yml", text), [])

    def test_pull_request_expression_allowed_on_a_job_without_environment(self):
        text = self.PR_WORKFLOW.replace(
            "  check:\n    runs-on: ubuntu-latest\n",
            "  check:\n    runs-on: ubuntu-latest\n"
            f"    concurrency:\n      group: check\n      cancel-in-progress: {PR_EXPRESSION}\n",
        )
        self.assertEqual(violations("job-pr.yml", text), [])

    def test_deploy_job_with_cancel_false_passes(self):
        text = (
            "on:\n  push:\n    branches: [main]\n"
            "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    environment: production\n"
            "    concurrency:\n      group: deploy\n      cancel-in-progress: false\n"
        )
        self.assertEqual(violations("deploy.yml", text), [])

    def test_pull_request_block_with_an_extra_key_is_refused(self):
        text = self.PR_WORKFLOW.replace(
            f"  cancel-in-progress: {PR_EXPRESSION}\n",
            f"  cancel-in-progress: {PR_EXPRESSION}\n  queue: max\n",
        )
        self.assertNotEqual(violations("extra.yml", text), [])


if __name__ == "__main__":
    unittest.main()
