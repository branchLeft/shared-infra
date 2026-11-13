#!/usr/bin/env python3
"""Pin tests: the workflow that verifies attested @branchleft packages is present and exact.

`problems(text)` reads the workflow and returns every way it departs from the
contract; the Sabotage class breaks one control at a time and requires the named
problem to appear, then requires the unmodified file to have none.
"""

from __future__ import annotations

import pathlib
import re
import unittest

from test_workflow_concurrency import load

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
VERIFY_YML = WORKFLOWS / "verify-package-attestations.yml"

ACTION = "branchLeft/github-workflows/.github/actions/verify-package-attestations"
ACTION_SHA = "2c34b90b367fd160bb01d311d29224d250460086"
ACTION_TAG = "v1.2.1"
JOB_PERMISSIONS = {"contents": "read", "packages": "read"}
USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$", re.MULTILINE)
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"^\s+# v\d+\.\d+\.\d+\s*$")


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def verify_step(job: dict) -> dict | None:
    found = [s for s in job.get("steps", []) if str(s.get("uses", "")).startswith(ACTION + "@")]
    return found[0] if len(found) == 1 else None


def problems(text: str) -> list[str]:
    found: list[str] = []
    data = load(text)
    if not isinstance(data, dict):
        return ["the workflow is not a mapping"]

    triggers = data.get("on")
    for name in ("pull_request", "push", "merge_group"):
        if not isinstance(triggers, dict) or name not in triggers:
            found.append(f"trigger {name} is missing")
    if isinstance(triggers, dict):
        for name, config in triggers.items():
            if isinstance(config, dict) and ("paths" in config or "paths-ignore" in config):
                found.append(f"trigger {name} carries a path filter, so a lockfile change might not start it")

    if data.get("permissions") != {"contents": "read"}:
        found.append(f"top-level permissions must be exactly contents: read, found {data.get('permissions')!r}")

    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or list(jobs) != ["verify"]:
        return found + ["the workflow must hold exactly one job, verify"]
    job = jobs["verify"]
    if job.get("permissions") != JOB_PERMISSIONS:
        found.append(f"job permissions must be exactly {JOB_PERMISSIONS}, found {job.get('permissions')!r}")
    if not isinstance(job.get("timeout-minutes"), int):
        found.append("the job has no timeout-minutes")
    if "needs" in job or "if" in job:
        found.append("the job must not wait on, or be skipped by, another job")

    step = verify_step(job)
    if step is None:
        found.append("there is not exactly one verify-package-attestations step")
    else:
        if step["uses"] != f"{ACTION}@{ACTION_SHA}":
            found.append(f"the verify step is not pinned to {ACTION_SHA}: {step['uses']!r}")
        if set(step.get("with", {})) - {"github-token"}:
            found.append("the verify step passes an input other than github-token")
        if step.get("with", {}).get("github-token") != "${{ secrets.GITHUB_TOKEN }}":
            found.append("the verify step does not use the run's own GITHUB_TOKEN")

    # CI-1: every action is a 40-hex sha with a trailing version comment, and the
    # verify step's comment names the tag the sha peels to.
    for match in USES_LINE.finditer(text):
        target, rest = match.group(1), match.group(2)
        if not PINNED.match(target):
            found.append(f"{target} is not pinned to a 40-character sha")
        if not VERSION_COMMENT.match(rest):
            found.append(f"{target} has no trailing version comment")
        if target.startswith(ACTION + "@") and rest.strip() != f"# {ACTION_TAG}":
            found.append(f"the verify step's comment is not # {ACTION_TAG}")
    return found


class VerifyWorkflowTests(unittest.TestCase):
    def test_the_workflow_has_no_problems(self):
        self.assertEqual(problems(read(VERIFY_YML)), [])

    def test_only_this_workflow_calls_the_action(self):
        # A separate workflow: no step of the required Ansible job, or of any other
        # workflow, carries the check.
        for path in sorted(WORKFLOWS.glob("*.yml")):
            if path != VERIFY_YML:
                with self.subTest(workflow=path.name):
                    self.assertNotIn(ACTION, read(path))

    def test_the_action_scans_from_the_repository_root(self):
        # The action's `root` defaults to `.`, which reaches every lockfile in the
        # tree; naming a narrower root would leave one out.
        step = verify_step(load(read(VERIFY_YML))["jobs"]["verify"])
        self.assertIsNotNone(step)
        self.assertNotIn("root", step.get("with", {}))


class Sabotage(unittest.TestCase):
    """Each control broken in a copy of the text must make `problems` name it."""

    def broken(self, old: str, new: str) -> list[str]:
        text = read(VERIFY_YML)
        mutated = text.replace(old, new, 1)
        self.assertNotEqual(text, mutated, "the sabotage did not change the file")
        return problems(mutated)

    def assert_named(self, found: list[str], fragment: str) -> None:
        self.assertTrue(any(fragment in p for p in found), f"{fragment!r} not in {found}")

    def test_a_the_verify_step_is_removed(self):
        text = read(VERIFY_YML)
        start = text.index("      - name: Verify every locked @branchleft package\n")
        self.assert_named(problems(text[:start]), "not exactly one verify-package-attestations step")

    def test_b_a_tag_pin_replaces_the_sha(self):
        found = self.broken(f"@{ACTION_SHA} # {ACTION_TAG}", f"@{ACTION_TAG}")
        self.assert_named(found, "not pinned to a 40-character sha")

    def test_c_the_sha_is_another_revision(self):
        found = self.broken(ACTION_SHA, "0" * 40)
        self.assert_named(found, "is not pinned to")

    def test_d_the_version_comment_is_dropped(self):
        found = self.broken(f" # {ACTION_TAG}\n        with:", "\n        with:")
        self.assert_named(found, "has no trailing version comment")

    def test_e_the_job_gains_a_permission(self):
        found = self.broken("      packages: read\n    steps:", "      packages: read\n      actions: write\n    steps:")
        self.assert_named(found, "job permissions must be exactly")

    def test_f_the_job_loses_packages_read(self):
        found = self.broken("      packages: read\n    steps:", "    steps:")
        self.assert_named(found, "job permissions must be exactly")

    def test_g_a_path_filter_appears(self):
        found = self.broken("  pull_request:\n", "  pull_request:\n    paths: ['mail/**']\n")
        self.assert_named(found, "path filter")

    def test_h_the_merge_queue_trigger_is_dropped(self):
        found = self.broken("  merge_group:\n    types: [checks_requested]\n", "")
        self.assert_named(found, "trigger merge_group is missing")

    def test_i_the_job_is_made_conditional(self):
        found = self.broken("    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    if: false\n")
        self.assert_named(found, "must not wait on, or be skipped by")

    def test_j_the_token_is_replaced(self):
        found = self.broken("${{ secrets.GITHUB_TOKEN }}", "${{ secrets.OTHER }}")
        self.assert_named(found, "run's own GITHUB_TOKEN")


if __name__ == "__main__":
    unittest.main()
