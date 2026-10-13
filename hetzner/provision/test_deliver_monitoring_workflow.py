#!/usr/bin/env python3
"""The monitoring delivery workflow's gate, shape, and refusal step.

The refusal step is run for real, with a stand-in `gh` that returns a chosen
environment object: a gate nobody has seen refuse is not shown to refuse. The
rest pins the properties that make the job safe to leave on push to `main` --
that it cannot run from a pull request or another branch, that its credentials
are bound as environment values and never interpolated into a script, and that
the refusal runs before any of them is read.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "deliver-monitoring.yml"
TEXT = WORKFLOW.read_text()
REFUSAL = "Refuse to deliver through an ungated environment"


def step_run(name: str) -> str:
    """The `run: |` body of the named step, dedented."""
    match = re.search(
        rf"- name: {re.escape(name)}\n(?:        .*\n|\n)*?        run: \|\n((?:          .*\n|\n)+)", TEXT
    )
    assert match, f"no step named {name!r} with a run block"
    return "\n".join(line[10:] for line in match.group(1).splitlines())


def step_order() -> list[str]:
    return re.findall(r"^      - name: (.+)$", TEXT, re.MULTILINE)


class RefusalStepTests(unittest.TestCase):
    def setUp(self):
        if shutil.which("jq") is None:
            self.skipTest("jq is not installed")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        gh = self.tmp / "gh"
        gh.write_text('#!/usr/bin/env bash\nif [ -n "${FAKE_GH_FAIL:-}" ]; then exit 1; fi\nprintf \'%s\' "$FAKE_GH_JSON"\n')
        gh.chmod(gh.stat().st_mode | stat.S_IXUSR)

    def run_step(self, environment: dict | None, gh_fails: bool = False):
        env = dict(os.environ, PATH=f"{self.tmp}{os.pathsep}{os.environ['PATH']}", GITHUB_REPOSITORY="org/repo")
        env["FAKE_GH_JSON"] = json.dumps(environment if environment is not None else {})
        if gh_fails:
            env["FAKE_GH_FAIL"] = "1"
        return subprocess.run(["bash", "-e", "-c", step_run(REFUSAL)], env=env, capture_output=True, text=True)

    reviewer = {"protection_rules": [{"type": "required_reviewers"}]}
    branches = {"deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}

    def test_a_reviewer_and_a_branch_policy_pass(self):
        self.assertEqual(self.run_step({**self.reviewer, **self.branches}).returncode, 0)

    def test_no_environment_protection_at_all_is_refused(self):
        result = self.run_step({"protection_rules": []})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no required-reviewer rule", result.stderr)

    def test_a_wait_timer_is_not_a_reviewer(self):
        result = self.run_step({"protection_rules": [{"type": "wait_timer"}], **self.branches})
        self.assertNotEqual(result.returncode, 0)

    def test_a_reviewer_without_a_branch_policy_is_refused(self):
        result = self.run_step({**self.reviewer, "deployment_branch_policy": None})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("open to every branch", result.stderr)

    def test_an_unreadable_environment_fails_closed(self):
        self.assertNotEqual(self.run_step(None, gh_fails=True).returncode, 0)


class WorkflowShapeTests(unittest.TestCase):
    def test_it_never_runs_for_a_pull_request_and_only_for_main(self):
        self.assertNotIn("pull_request", TEXT)
        self.assertIn("branches: [main]", TEXT)
        self.assertIn("workflow_dispatch:", TEXT)
        self.assertIn("if: github.ref == 'refs/heads/main'", TEXT)

    def test_the_job_waits_in_its_own_environment_not_a_shared_one(self):
        self.assertIn("environment: production-monitoring", TEXT)
        self.assertEqual(re.findall(r"^    environment: (.+)$", TEXT, re.MULTILINE), ["production-monitoring"])

    def test_deliveries_are_serialised_and_never_cancelled_mid_run(self):
        self.assertIn("group: deliver-monitoring", TEXT)
        self.assertIn("cancel-in-progress: false", TEXT)

    def test_the_refusal_comes_before_anything_reads_a_credential(self):
        order = step_order()
        self.assertEqual(order[0], REFUSAL)
        first_secret = TEXT.index("secrets.")
        self.assertLess(TEXT.index(REFUSAL), first_secret)

    def test_credentials_are_bound_as_env_never_interpolated_into_a_script(self):
        for line in TEXT.splitlines():
            if "${{" in line and not line.lstrip().startswith("#"):
                self.assertRegex(line, r"^\s+[A-Z][A-Z0-9_]*: \$\{\{ (secrets|vars|github)\.[A-Za-z0-9_]+ \}\}$", line)

    def test_the_host_is_pinned_not_trusted_on_first_use(self):
        body = step_run("Deliver the stack")
        self.assertIn("StrictHostKeyChecking=yes", body)
        self.assertIn("UserKnownHostsFile", body)
        self.assertIn("GlobalKnownHostsFile=/dev/null", body)
        self.assertNotIn("StrictHostKeyChecking=no", TEXT)
        self.assertNotIn("accept-new", TEXT)

    def test_the_key_file_is_removed_even_when_the_delivery_fails(self):
        body = step_run("Deliver the stack")
        self.assertIn("umask 077", body)
        self.assertRegex(body, r"trap 'rm -f .*' EXIT")

    def test_the_delivery_gives_ssh_no_command_of_its_own(self):
        body = step_run("Deliver the stack")
        self.assertNotIn("monitoring \\\n", body)
        self.assertIn('"root@${EDGE1_SSH_HOST}"', body)

    def test_the_rehearsal_runs_before_the_delivery(self):
        order = step_order()
        self.assertLess(order.index("Rehearse the delivery with no host"), order.index("Deliver the stack"))

    def test_every_action_is_pinned_to_a_commit(self):
        for ref in re.findall(r"uses: (\S+)", TEXT):
            self.assertRegex(ref, r"@[0-9a-f]{40}$", ref)

    def test_the_job_has_a_timeout(self):
        self.assertRegex(TEXT, r"timeout-minutes: \d+")

    def test_the_paths_filter_covers_what_is_delivered_and_the_machinery_that_delivers_it(self):
        for path in (
            "hetzner/monitoring/stack/**",
            "hetzner/provision/branchleft_sync_stack.py",
            "hetzner/scripts/monitoring-stack-archive.sh",
            ".github/workflows/deliver-monitoring.yml",
        ):
            self.assertIn(f"- '{path}'", TEXT)


if __name__ == "__main__":
    unittest.main()
