"""The order and the gate of the Ansible workflow, and the schedules the CI work depends on.

ci_select.py chooses shards; these tests hold the workflow to what that choice assumes. Each
test's name states the rule it holds; the reasons are in ansible/checks/README.md.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from ruamel.yaml import YAML
from shard_results import ADVISORY_PREFIX, BLOCKING_PREFIX

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

# The jobs that restore the tool environment and so carry the same install steps.
TOOL_JOBS = ("quick-lint", "lint", "shard", "shard-advisory")

# The steps that build or restore the tool environment. The quick gate copies these from the
# full lint, so a test holds the copy equal to the original and the two cannot drift.
ENVIRONMENT_STEPS = (
    "Name the Python the tool environment is built with",
    "Restore the tool environment",
    "Create the tool environment",
    "Install the pinned pip",
    "Install the pinned tools",
    "Check the installed set and list the collections",
)

# The commands the quick gate runs, written once here and compared with the full lint's own.
YAMLLINT_STEP = "yamllint every YAML file under ansible/"
SELECT_TESTS_COMMAND = (
    '"$RUNNER_TEMP/ansible-venv/bin/python" -m unittest discover -b -s ansible/checks'
    ' -p "test_ci_select.py"'
)

# Every step the full lint ran before the quick gate was added. The full lint keeps all of
# them and still gates the merge, so removing or renaming one must be a decision in a diff to
# this list and not a silent loss. A step added to the lint later is not listed here.
LINT_STEPS_THAT_STILL_RUN = (
    *ENVIRONMENT_STEPS,
    "Check the pins and the update route",
    YAMLLINT_STEP,
    "ansible-lint at the production profile",
    "Type-check the harness, the checks and the tools",
    "Lint the harness, the checks and the tools",
    "Check the harness, checks and tools formatting",
    "Test the harness",
    "Test the checks",
    "Test the tools",
    "Check each role's own program in files/",
    "Check each role's own library modules",
    "Run every role's unit tests",
)

# One row per outcome the gate must settle, as (what it shows, the values that differ from a run
# in which every job succeeded, the exit status the gate script must end with). OK is that run.
OK = {
    "DISCOVER": "success",
    "ANSIBLE": "true",
    "BLOCKING": "true",
    "QUICK": "success",
    "LINT": "success",
    "BLOCKING_RESULT": "success",
    "EVENT": "pull_request",
}
# What the shard job's condition must say about the merge queue, and the one event it is keyed on.
QUEUE_SKIP = "github.event_name != 'merge_group'"
GATE_TABLE: tuple[tuple[str, dict[str, str], int], ...] = (
    ("every job succeeded", {}, 0),
    ("the quick gate failed", {"QUICK": "failure"}, 1),
    ("the quick gate was skipped", {"QUICK": "skipped"}, 1),
    ("the quick gate was cancelled", {"QUICK": "cancelled"}, 1),
    ("the quick gate passed and the full lint failed", {"LINT": "failure"}, 1),
    ("the quick gate passed and the full lint was skipped", {"LINT": "skipped"}, 1),
    ("the quick gate passed and the full lint was cancelled", {"LINT": "cancelled"}, 1),
    (
        "the lint failed and the shards were skipped",
        {"LINT": "failure", "BLOCKING_RESULT": "skipped"},
        1,
    ),
    ("a chosen shard failed", {"BLOCKING_RESULT": "failure"}, 1),
    ("a chosen shard was skipped", {"BLOCKING_RESULT": "skipped"}, 1),
    ("discover failed", {"DISCOVER": "failure"}, 1),
    ("discover did not say whether inputs changed", {"ANSIBLE": ""}, 1),
    ("discover did not say whether shards are needed", {"BLOCKING": ""}, 1),
    (
        "no Ansible input changed",
        {"ANSIBLE": "false", "QUICK": "skipped", "LINT": "skipped", "BLOCKING_RESULT": "skipped"},
        0,
    ),
    ("no shard was needed", {"BLOCKING": "false", "BLOCKING_RESULT": "skipped"}, 0),
    (
        "no shard was needed and the full lint failed",
        {"BLOCKING": "false", "BLOCKING_RESULT": "skipped", "LINT": "failure"},
        1,
    ),
    (
        "no shard was needed and the quick gate failed",
        {"BLOCKING": "false", "BLOCKING_RESULT": "skipped", "QUICK": "failure"},
        1,
    ),
    ("a chosen shard was cancelled", {"BLOCKING_RESULT": "cancelled"}, 1),
    # The merge queue skips the container shards on purpose, because the pull request already
    # passed them; the lint and the quick gate still decide the queue's result.
    (
        "queue: lint passed and the shards were skipped",
        {"EVENT": "merge_group", "BLOCKING_RESULT": "skipped"},
        0,
    ),
    (
        "queue: the full lint failed and the shards were skipped",
        {"EVENT": "merge_group", "BLOCKING_RESULT": "skipped", "LINT": "failure"},
        1,
    ),
    (
        "queue: the quick gate failed and the shards were skipped",
        {"EVENT": "merge_group", "BLOCKING_RESULT": "skipped", "QUICK": "failure"},
        1,
    ),
    (
        "queue: the quick gate was skipped and the shards were skipped",
        {"EVENT": "merge_group", "BLOCKING_RESULT": "skipped", "QUICK": "skipped"},
        1,
    ),
    (
        "queue: discover failed",
        {"EVENT": "merge_group", "BLOCKING_RESULT": "skipped", "DISCOVER": "failure"},
        1,
    ),
    (
        "queue: a shard that ran and failed",
        {"EVENT": "merge_group", "BLOCKING_RESULT": "failure"},
        1,
    ),
    (
        "queue: a shard that was cancelled",
        {"EVENT": "merge_group", "BLOCKING_RESULT": "cancelled"},
        1,
    ),
    ("queue: a shard that ran and passed", {"EVENT": "merge_group"}, 0),
    (
        "queue: no Ansible input changed",
        {
            "EVENT": "merge_group",
            "ANSIBLE": "false",
            "QUICK": "skipped",
            "LINT": "skipped",
            "BLOCKING_RESULT": "skipped",
        },
        0,
    ),
    # Only the queue may skip a chosen shard, and the event name decides it, never a result.
    ("pull request: the shards were skipped", {"BLOCKING_RESULT": "skipped"}, 1),
    ("schedule: the shards were skipped", {"EVENT": "schedule", "BLOCKING_RESULT": "skipped"}, 1),
    (
        "manual run: the shards were skipped",
        {"EVENT": "workflow_dispatch", "BLOCKING_RESULT": "skipped"},
        1,
    ),
    ("no event name: the shards were skipped", {"EVENT": "", "BLOCKING_RESULT": "skipped"}, 1),
)


def load(path: Path) -> object:
    """Return a YAML file's document."""
    return YAML(typ="safe").load(path.read_text(encoding="utf-8"))


ANSIBLE_WORKFLOW = load(WORKFLOWS / "ansible.yml")


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


def run_gate(gate_script: str, values: dict[str, str]) -> int:
    """Run the gate's script under bash with the given needs and return its exit status.

    Raises:
        AssertionError: There is no bash to run it with.
    """
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **OK, **values}
    bash = shutil.which("bash")
    if bash is None:
        message = "bash is needed to run the gate's script"
        raise AssertionError(message)
    done = subprocess.run(  # noqa: S603 - the workflow's own gate script, run with fixed values
        [bash, "-c", gate_script],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return done.returncode


def without_the_lint_refusal(gate_script: str) -> str:
    """Return the gate's script with the block that refuses a lint that did not succeed cut out."""
    return re.sub(
        r'if \[ "\$LINT" != "success" \]; then\n.*?\n\s*fi\n', "", gate_script, flags=re.S
    )


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
            {
                "discover",
                "quick-lint",
                "lint",
                "shard",
                "shard-advisory",
                "roles",
                "report",
                "daily-issue",
            },
            keys(get(self.workflow, "jobs")),
        )

    def test_the_shards_wait_for_the_quick_gate_and_not_for_the_full_lint(self) -> None:
        self.assertEqual({"discover", "quick-lint"}, needs(self.job("shard")))

    def test_the_full_lint_stands_directly_before_the_shards(self) -> None:
        # test_run_role_unit_tests.py reads the text between the lint job and the shard job, so
        # nothing may stand between them, and the quick gate stands before the lint.
        jobs = get(self.workflow, "jobs")
        order = [str(name) for name in jobs] if isinstance(jobs, dict) else []
        self.assertEqual(order.index("lint") + 1, order.index("shard"))
        self.assertLess(order.index("quick-lint"), order.index("lint"))

    def test_the_quick_gate_waits_only_for_discover_and_runs_when_the_lint_does(self) -> None:
        quick, lint = self.job("quick-lint"), self.job("lint")
        self.assertEqual({"discover"}, needs(quick))
        self.assertEqual({"discover"}, needs(lint))
        self.assertEqual("needs.discover.outputs.ansible == 'true'", str(get(quick, "if")).strip())
        self.assertEqual(get(lint, "if"), get(quick, "if"))
        self.assertEqual(get(lint, "runs-on"), get(quick, "runs-on"))
        self.assertLessEqual(int(str(get(quick, "timeout-minutes"))), 10)

    def test_the_quick_gate_builds_its_environment_the_way_the_lint_does(self) -> None:
        # The copy is held equal to the original, step for step, so the two cannot drift.
        for name in ENVIRONMENT_STEPS:
            quick = [
                s for s in items(get(self.job("quick-lint"), "steps")) if get(s, "name") == name
            ]
            lint = [s for s in items(get(self.job("lint"), "steps")) if get(s, "name") == name]
            with self.subTest(step=name):
                self.assertEqual(1, len(quick))
                self.assertEqual(1, len(lint))
                self.assertEqual(lint[0], quick[0])

    def test_the_quick_gate_runs_yamllint_and_the_ci_select_tests_unconditionally(self) -> None:
        quick = items(get(self.job("quick-lint"), "steps"))
        lint = items(get(self.job("lint"), "steps"))
        yamllint = [s for s in quick if get(s, "name") == YAMLLINT_STEP]
        lint_yamllint = [s for s in lint if get(s, "name") == YAMLLINT_STEP]
        self.assertEqual(1, len(yamllint))
        self.assertEqual(lint_yamllint, yamllint, "the same command as the full lint's")
        selection = [s for s in quick if get(s, "run") == SELECT_TESTS_COMMAND]
        self.assertEqual(1, len(selection))
        self.assertTrue((ROOT / "ansible" / "checks" / "test_ci_select.py").is_file())
        for step in (yamllint[0], selection[0]):
            with self.subTest(step=get(step, "name")):
                self.assertIsNone(get(step, "if"))
                self.assertIsNone(get(step, "continue-on-error"))
        self.assertIsNone(get(self.job("quick-lint"), "continue-on-error"))
        for step in quick:
            self.assertNotIn("|| true", str(get(step, "run") or ""))

    def test_the_full_lint_keeps_every_step_it_had_and_none_may_fail_silently(self) -> None:
        lint = self.job("lint")
        names = [str(get(step, "name")) for step in items(get(lint, "steps"))]
        self.assertEqual([], [name for name in LINT_STEPS_THAT_STILL_RUN if name not in names])
        self.assertEqual(len(names), len(set(names)))
        self.assertIsNone(get(lint, "continue-on-error"))
        for step in items(get(lint, "steps")):
            self.assertIsNone(get(step, "continue-on-error"), get(step, "name"))

    def test_each_shard_job_runs_only_when_discover_chose_some_of_its_kind(self) -> None:
        for name, output in (("shard", "blocking"), ("shard-advisory", "advisory")):
            condition = str(get(self.job(name), "if"))
            with self.subTest(job=name):
                self.assertIn(f"needs.discover.outputs.{output} == 'true'", condition)
                self.assertIn("needs.discover.outputs.ansible == 'true'", condition)
                self.assertEqual(
                    f"${{{{ fromJSON(needs.discover.outputs.{output}_matrix) }}}}",
                    get(self.job(name), "strategy", "matrix"),
                )

    def test_discover_publishes_the_choice(self) -> None:
        outputs = keys(get(self.job("discover"), "outputs"))
        self.assertLessEqual(
            {"ansible", "matrix", "shards", "blocking", "blocking_matrix"}
            | {"advisory", "advisory_matrix"},
            outputs,
        )

    def test_the_entry_that_stands_for_no_shard_is_refused(self) -> None:
        for name in ("shard", "shard-advisory"):
            refusal = get(self.job(name), "steps", 0)
            with self.subTest(job=name):
                self.assertIn("matrix.kind != 'role'", str(get(refusal, "if")))
                self.assertIn("exit 1", str(get(refusal, "run")))

    def test_the_advisory_job_runs_the_same_steps_as_the_blocking_job(self) -> None:
        # The copy is held equal step for step, so a fix to one cannot miss the other.
        shard, advisory = self.job("shard"), self.job("shard-advisory")
        self.assertEqual(get(shard, "steps"), get(advisory, "steps"))
        for key in ("runs-on", "timeout-minutes", "needs"):
            self.assertEqual(get(shard, key), get(advisory, key), key)
        self.assertEqual(False, get(advisory, "strategy", "fail-fast"))
        self.assertIsNone(get(advisory, "continue-on-error"))
        self.assertIsNone(get(shard, "continue-on-error"))

    def test_the_shard_jobs_are_named_the_way_the_readers_of_the_results_expect(self) -> None:
        # shard_results.py reads the shard id from the job name; a rename here silently
        # empties the report, the daily issue and the pass counter.
        self.assertEqual(f"{BLOCKING_PREFIX}${{{{ matrix.name }}}}", get(self.job("shard"), "name"))
        self.assertEqual(
            f"{ADVISORY_PREFIX}${{{{ matrix.name }}}}", get(self.job("shard-advisory"), "name")
        )

    def test_the_gate_needs_every_job_but_the_advisory_shards_and_the_reports(self) -> None:
        gate = self.job("roles")
        self.assertEqual({"discover", "quick-lint", "lint", "shard"}, needs(gate))
        self.assertEqual("always()", str(get(gate, "if")).strip())
        self.assertIn('[ "$QUICK" != "success" ]', script(gate))
        self.assertIn('[ "$LINT" != "success" ]', script(gate))
        self.assertIn('[ "$BLOCKING_RESULT" != "success" ]', script(gate))

    def test_the_gate_reads_each_result_from_the_job_it_names(self) -> None:
        env = get(self.job("roles"), "steps", 0, "env")
        self.assertEqual("${{ needs.quick-lint.result }}", get(env, "QUICK"))
        self.assertEqual("${{ needs.lint.result }}", get(env, "LINT"))
        self.assertEqual("${{ needs.shard.result }}", get(env, "BLOCKING_RESULT"))
        self.assertEqual("${{ needs.discover.result }}", get(env, "DISCOVER"))

    def test_the_quick_gate_is_refused_after_discover_and_before_the_lint(self) -> None:
        text = script(self.job("roles"))
        self.assertLess(
            text.index('[ "$ANSIBLE" = "false" ]'), text.index('[ "$QUICK" != "success" ]')
        )
        self.assertLess(
            text.index('[ "$QUICK" != "success" ]'), text.index('[ "$LINT" != "success" ]')
        )
        self.assertLess(
            text.index('[ "$LINT" != "success" ]'), text.index('[ "$BLOCKING" = "false" ]')
        )

    def test_the_gate_settles_every_outcome_the_way_the_table_says(self) -> None:
        # The gate's own script, run under bash. The row that matters most is the full lint failing
        # after the quick gate passed: only the shards no longer wait for the full lint, and a merge
        # must still need it.
        gate_script = str(get(self.job("roles"), "steps", 0, "run"))
        for label, values, expected in GATE_TABLE:
            with self.subTest(row=label):
                self.assertEqual(expected, run_gate(gate_script, values))

    def test_the_gate_table_sees_the_full_lint_refusal_being_removed(self) -> None:
        # The control of the table above: the same script with the refusal of a lint that did not
        # succeed cut out lets that run through, so the table can tell the refusal is there.
        gate_script = str(get(self.job("roles"), "steps", 0, "run"))
        cut = without_the_lint_refusal(gate_script)
        self.assertNotEqual(gate_script, cut)
        self.assertNotIn('[ "$LINT" != "success" ]', cut)
        self.assertEqual(1, run_gate(gate_script, {"LINT": "failure"}))
        self.assertEqual(0, run_gate(cut, {"LINT": "failure"}))

    def test_every_container_shard_job_skips_in_the_merge_queue_by_the_event_name(self) -> None:
        # A container shard is any job that runs the harness. Its condition names the event, not
        # a result, and the pull request keeps the condition it had.
        jobs = get(self.workflow, "jobs")
        shard_jobs = [
            str(name)
            for name, job in (jobs.items() if isinstance(jobs, dict) else [])
            if "run_harness.py" in script(job)
        ]
        self.assertEqual(
            ["shard", "shard-advisory"], shard_jobs, "a control: the harness runs in two jobs"
        )
        for name in shard_jobs:
            condition = str(get(self.job(name), "if"))
            with self.subTest(job=name):
                self.assertIn(QUEUE_SKIP, condition)
                self.assertIn("needs.discover.outputs.ansible == 'true'", condition)
                self.assertNotIn("result", condition)
                self.assertNotIn("pull_request", condition)

    def test_the_lint_jobs_and_discover_run_in_the_merge_queue(self) -> None:
        for name in ("discover", "quick-lint", "lint", "roles"):
            condition = str(get(self.job(name), "if") or "")
            with self.subTest(job=name):
                self.assertNotIn("merge_group", condition)
                self.assertNotIn("github.event_name", condition)
                for step in items(get(self.job(name), "steps")):
                    self.assertNotIn("merge_group", str(get(step, "if") or ""))

    def test_the_gate_is_told_the_event_name_and_never_a_job_result_in_its_place(self) -> None:
        env = get(self.job("roles"), "steps", 0, "env")
        self.assertEqual("${{ github.event_name }}", get(env, "EVENT"))

    def test_the_gate_table_sees_the_queue_skip_being_widened_to_every_event(self) -> None:
        # The control of the rows above: with the event test cut out, the gate takes a skipped
        # shard from a pull request, and the table's rows for that case turn red.
        gate_script = str(get(self.job("roles"), "steps", 0, "run"))
        needle = '[ "$EVENT" = "merge_group" ] && '
        self.assertIn(needle, gate_script)
        widened = gate_script.replace(needle, "")
        self.assertEqual(1, run_gate(gate_script, {"BLOCKING_RESULT": "skipped"}))
        self.assertEqual(0, run_gate(widened, {"BLOCKING_RESULT": "skipped"}))

    def test_a_shard_job_that_did_not_succeed_fails_the_gate_when_shards_were_chosen(self) -> None:
        text = script(self.job("roles"))
        self.assertLess(
            text.index('[ "$BLOCKING" = "false" ]'),
            text.index('[ "$BLOCKING_RESULT" != "success" ]'),
        )
        self.assertIn('[ "$BLOCKING" != "true" ]', text)

    def test_the_merge_queue_triggers_the_workflow(self) -> None:
        self.assertLessEqual(
            {"merge_group", "pull_request", "push"}, keys(get(self.workflow, "on"))
        )

    def test_the_full_sweep_is_scheduled_daily_off_the_hour(self) -> None:
        # Drift in an external image or collection shows in no diff; only a sweep finds it.
        # One schedule only: every scheduled run is the daily sweep, which the pass counter reads.
        schedule = items(get(self.workflow, "on", "schedule"))
        self.assertEqual(1, len(schedule))
        fields = str(get(schedule[0], "cron")).split()
        self.assertEqual(5, len(fields))
        self.assertEqual(["*", "*", "*"], fields[2:], "the sweep runs every day")
        self.assertTrue(fields[0].isdigit() and fields[1].isdigit())
        self.assertNotIn(fields[0], ("0", "30"), "the minute is off the hour and the half hour")

    def test_every_tool_job_restores_the_tool_environment_from_a_pinned_cache(
        self,
    ) -> None:
        for name in TOOL_JOBS:
            steps = items(get(self.job(name), "steps"))
            caches = [step for step in steps if "actions/cache@" in str(get(step, "uses"))]
            with self.subTest(job=name):
                self.assertEqual(1, len(caches))
                self.assertRegex(str(get(caches[0], "uses")), r"^actions/cache@[0-9a-f]{40}$")
                key = str(get(caches[0], "with", "key"))
                self.assertIn("hashFiles('ansible/requirements.txt'", key)
                self.assertIn("ansible/checks/pip-requirements.txt", key)
                self.assertIn("steps.python.outputs.version", key)
                self.assertIn("ansible-venv", str(get(caches[0], "with", "path")))

    def test_the_installs_run_only_when_the_cache_missed(self) -> None:
        for name in TOOL_JOBS:
            for step in items(get(self.job(name), "steps")):
                text = str(get(step, "run") or "")
                if "python3 -m venv" in text or 'pip" install' in text:
                    with self.subTest(job=name, step=get(step, "name")):
                        self.assertEqual("steps.venv.outputs.cache-hit != 'true'", get(step, "if"))

    def test_the_environment_is_checked_whether_it_was_built_or_restored(self) -> None:
        for name in TOOL_JOBS:
            checks = [
                step
                for step in items(get(self.job(name), "steps"))
                if 'pip" check' in str(get(step, "run") or "")
            ]
            with self.subTest(job=name):
                self.assertEqual(1, len(checks))
                self.assertIsNone(get(checks[0], "if"))

    def test_a_push_to_main_runs_no_lint(self) -> None:
        text = str(get(self.job("discover"), "steps", 1, "run"))
        push = text[text.index("push)") :]
        self.assertIn('echo "ansible=false"', push[: push.index(";;")])


ISSUE_PERMISSIONS = {"contents": "read", "actions": "read", "issues": "write"}
ISSUE_CONDITION = "always() && github.event_name == 'schedule' && needs.roles.result == 'failure'"
# What a step of this workflow must never contain: nothing here starts, wakes or prompts an
# agent, or dispatches another workflow. The issue the daily run opens is read by a person.
FORBIDDEN_IN_STEPS = (
    "claude",
    "anthropic",
    "gh workflow run",
    "repository_dispatch",
    "createDispatchEvent",
    "--assignee",
    "--add-assignee",
)
TRIGGERS = {"pull_request", "push", "merge_group", "schedule", "workflow_dispatch"}


def issue_job_problems(job: object) -> list[str]:
    """Return what is wrong with the job that may open an issue; empty when it is as intended."""
    found = []
    condition = " ".join(str(get(job, "if")).split())
    if condition != ISSUE_CONDITION:
        found.append("it is not limited to the scheduled run with a red required check")
    if needs(job) != {"roles"}:
        found.append("it does not need exactly the gate job")
    if get(job, "permissions") != ISSUE_PERMISSIONS:
        found.append("its permissions are not read-only plus issues: write")
    return found


class AnsibleIssueAndReportJobsTest(unittest.TestCase):
    workflow = ANSIBLE_WORKFLOW

    def job(self, name: str) -> object:
        return get(self.workflow, "jobs", name)

    def test_only_the_issue_job_can_write_and_it_runs_for_the_scheduled_red_run_alone(self) -> None:
        self.assertEqual({"contents": "read"}, get(self.workflow, "permissions"))
        self.assertEqual([], issue_job_problems(self.job("daily-issue")))
        jobs = get(self.workflow, "jobs")
        for name in jobs if isinstance(jobs, dict) else []:
            if name != "daily-issue":
                with self.subTest(job=name):
                    permissions = get(self.job(str(name)), "permissions")
                    granted = permissions.values() if isinstance(permissions, dict) else []
                    self.assertNotIn("write", set(granted))

    def test_the_issue_job_check_sees_it_run_on_a_pull_request(self) -> None:
        # The control of the test above: the same job with its condition widened to a pull
        # request, or with a wider permission, is found.
        job = self.job("daily-issue")
        widened = dict(job) if isinstance(job, dict) else {}
        widened["if"] = "always() && github.event_name == 'pull_request'"
        self.assertIn(
            "it is not limited to the scheduled run with a red required check",
            issue_job_problems(widened),
        )
        wider = dict(job) if isinstance(job, dict) else {}
        wider["permissions"] = {**ISSUE_PERMISSIONS, "pull-requests": "write"}
        self.assertIn(
            "its permissions are not read-only plus issues: write", issue_job_problems(wider)
        )

    def test_the_report_job_only_reads_and_never_fails_the_run_for_a_red_shard(self) -> None:
        report = self.job("report")
        self.assertEqual({"contents": "read", "actions": "read"}, get(report, "permissions"))
        self.assertEqual({"discover", "shard", "shard-advisory"}, needs(report))
        self.assertIn("github.event_name != 'merge_group'", str(get(report, "if")))
        self.assertIn("always()", str(get(report, "if")))
        self.assertIn(
            "shard_results.py report --run-id", script(report), "it writes the step summary"
        )
        self.assertIn("$GITHUB_STEP_SUMMARY", script(report))

    def test_nothing_in_the_workflow_starts_wakes_or_prompts_an_agent(self) -> None:
        self.assertLessEqual(keys(get(self.workflow, "on")), TRIGGERS)
        jobs = get(self.workflow, "jobs")
        for name, job in jobs.items() if isinstance(jobs, dict) else []:
            for step in items(get(job, "steps")):
                text = f"{get(step, 'run') or ''} {get(step, 'uses') or ''}".lower()
                for word in FORBIDDEN_IN_STEPS:
                    with self.subTest(job=name, step=get(step, "name"), word=word):
                        self.assertNotIn(word.lower(), text)

    def test_the_issue_is_written_by_the_one_program_and_it_names_no_one(self) -> None:
        text = script(self.job("daily-issue"))
        self.assertEqual(1, text.count("daily_red_issue.py"))
        self.assertNotIn("@", text)
        self.assertEqual(
            "${{ github.token }}", get(self.job("daily-issue"), "steps", 1, "env", "GITHUB_TOKEN")
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
