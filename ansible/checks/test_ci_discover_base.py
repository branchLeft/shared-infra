"""Tests for the commit a pull request is compared with in the Ansible discover job.

On a pull request the checkout is the test merge of the pull request into the base branch as
it stands now. The event's own base sha is where the branch stood earlier, so a diff against
it lists the files of every pull request merged since and ci_select.py then selects shards for
roles the pull request never touched. The first step of discover therefore diffs the merge
commit's first parent, but only when HEAD is a two-parent merge whose second parent is the
pull request's head; any other shape keeps the event's base, which lists more, never less.

These tests run that step's own shell text, taken from the workflow, in real git repositories.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ansible.yml"
STEP_START = "- name: Decide whether the Ansible inputs changed"
STEP_END = "- name: List the shards from the repository tree"
RUN_MARKER = "        run: |\n"


def step_script(workflow_text: str) -> str:
    """Return the shell text of the step that decides whether the Ansible inputs changed."""
    step = workflow_text.split(STEP_START, 1)[1].split(STEP_END, 1)[0]
    body = step.split(RUN_MARKER, 1)[1]
    return textwrap.dedent(body)


def clean_env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def git(directory: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed program, arguments are not shell-parsed
        ["git", *args],  # noqa: S607 - git on PATH is the runner's
        cwd=directory,
        env=clean_env(),
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


class DiscoverBaseTests(unittest.TestCase):
    """Run the real step against a repository whose base branch moved after the pull request."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        self.temp = Path(self.tmp.name) / "runner-temp"
        self.temp.mkdir()
        git(self.repo, "init", "--quiet", "-b", "main")
        for key, value in (
            ("user.email", "t@example.invalid"),
            ("user.name", "t"),
            ("commit.gpgsign", "false"),
        ):
            git(self.repo, "config", key, value)
        self.commit("start", {"ansible/roles/mine/tasks/main.yml": "1", "README.md": "1"})
        self.event_base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "--quiet", "-b", "feature")
        self.commit("the pull request", {"ansible/roles/mine/tasks/extra.yml": "1"})
        self.pr_head = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "--quiet", "main")
        self.commit("another pull request", {"ansible/roles/other/tasks/main.yml": "1"})
        self.tip = git(self.repo, "rev-parse", "HEAD")

    def commit(self, message: str, files: dict[str, str]) -> None:
        for path, content in files.items():
            full = self.repo / path
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(content, encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "--quiet", "-m", message)

    def merge_the_pull_request(self) -> None:
        git(self.repo, "merge", "--quiet", "--no-ff", "-m", "test merge", self.pr_head)

    def run_step(self, event: str, pull_request_head: str, **extra: str) -> tuple[list[str], str]:
        """Run the step; return the changed paths it wrote, and its output."""
        output = self.temp / "github-output"
        output.write_text("", encoding="utf-8")
        script = self.temp / "step.sh"
        script.write_text(step_script(WORKFLOW.read_text(encoding="utf-8")), encoding="utf-8")
        env = clean_env()
        env.update(
            {
                "EVENT_NAME": event,
                "PULL_REQUEST_BASE": self.event_base,
                "PULL_REQUEST_HEAD": pull_request_head,
                "MERGE_GROUP_BASE": "",
                "MERGE_GROUP_HEAD": "",
                "RUNNER_TEMP": str(self.temp),
                "GITHUB_OUTPUT": str(output),
                **extra,
            }
        )
        result = subprocess.run(  # noqa: S603 - the workflow's own step text, run on purpose
            ["bash", str(script)],  # noqa: S607 - bash on PATH is the runner's
            cwd=self.repo,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        listed = self.temp / "changed-files.z"
        names = sorted(name for name in listed.read_text(encoding="utf-8").split("\0") if name)
        return names, result.stdout

    def test_a_test_merge_is_compared_with_the_commit_it_merges_into(self) -> None:
        self.merge_the_pull_request()
        changed, said = self.run_step("pull_request", self.pr_head)
        self.assertEqual(["ansible/roles/mine/tasks/extra.yml"], changed)
        self.assertIn(self.tip, said)

    def test_the_event_base_alone_lists_the_other_pull_requests_files(self) -> None:
        # The fault this guards against: with no test merge to read, the stale base is used.
        self.merge_the_pull_request()
        changed, _ = self.run_step("pull_request", "0" * 40)
        self.assertEqual(
            ["ansible/roles/mine/tasks/extra.yml", "ansible/roles/other/tasks/main.yml"], changed
        )

    def test_a_head_that_is_not_a_merge_keeps_the_event_base(self) -> None:
        changed, _ = self.run_step("pull_request", self.pr_head)
        self.assertEqual(["ansible/roles/other/tasks/main.yml"], changed)

    def test_a_merge_of_three_parents_keeps_the_event_base(self) -> None:
        git(self.repo, "checkout", "--quiet", "-b", "second", self.event_base)
        self.commit("a second branch", {"docs/a.md": "1"})
        git(self.repo, "checkout", "--quiet", "main")
        git(self.repo, "merge", "--quiet", "-m", "octopus", self.pr_head, "second")
        self.assertEqual(4, len(git(self.repo, "rev-list", "--parents", "-n", "1", "HEAD").split()))
        changed, said = self.run_step("pull_request", self.pr_head)
        self.assertIn("ansible/roles/mine/tasks/extra.yml", changed)
        self.assertIn("ansible/roles/other/tasks/main.yml", changed)
        self.assertNotIn(self.tip, said)

    def test_a_merge_queue_entry_still_diffs_its_own_base_and_head(self) -> None:
        self.merge_the_pull_request()
        merge = git(self.repo, "rev-parse", "HEAD")
        changed, _ = self.run_step(
            "merge_group", "", MERGE_GROUP_BASE=self.event_base, MERGE_GROUP_HEAD=merge
        )
        self.assertEqual(
            ["ansible/roles/mine/tasks/extra.yml", "ansible/roles/other/tasks/main.yml"], changed
        )

    def test_the_step_reads_the_pull_request_head_from_the_event(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("PULL_REQUEST_HEAD: ${{ github.event.pull_request.head.sha }}", text)


if __name__ == "__main__":
    unittest.main()
