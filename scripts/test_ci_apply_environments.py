#!/usr/bin/env python3
"""Pin tests for ci.yml's apply environments, gates and cancel step (stub gh)."""

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

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"

APPLY_JOBS = {
    "mail-apply": "production-mail",
    "hetzner-network-apply": "production",
    "hetzner-estate-apply": "production",
}
PLAN_JOBS = ["mail-plan", "hetzner-network-plan", "hetzner-estate-plan"]

# The reviewer App's integration id, as `app.id` on the live rule object.
REVIEWER_APP_ID = 5090756

GATE_NAME = "Refuse to apply through an ungated environment"
CANCEL_NAME = "Cancel older runs that are still waiting for approval"

# A stand-in for `gh api`: logs every call, answers from fixture files named
# by the environment, applies --jq with jq, and mimics gh's failure mode (the
# error body on stdout, a non-zero exit) when a fixture is absent. A `.raw`
# file beside a fixture is printed as is, exit 0, ignoring --jq.
STUB_GH = r"""#!/usr/bin/env bash
shift
method=GET
url=""
expr=""
while [ $# -gt 0 ]; do
  case "$1" in
    --method) method="$2"; shift 2 ;;
    --jq) expr="$2"; shift 2 ;;
    --silent) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "${method} ${url}" >> "${STUB_LOG}"
[ "${method}" = "POST" ] && exit 0
case "${url}" in
  *deployment_protection_rules*) file="${STUB_DIR}/rules.json" ;;
  */environments/*) file="${STUB_DIR}/environment.json" ;;
  */runs/*/jobs*) id="${url#*/runs/}"; id="${id%%/*}"; file="${STUB_DIR}/jobs-${id}.json" ;;
  */workflows/ci.yml/runs*) file="${STUB_DIR}/runs.json" ;;
  *) file="" ;;
esac
if [ -n "${file}" ] && [ -f "${file%.json}.raw" ]; then
  cat "${file%.json}.raw"
  exit 0
fi
if [ -z "${file}" ] || [ ! -f "${file}" ]; then
  echo '{"message":"Resource not accessible by integration","status":"403"}'
  exit 1
fi
if [ -n "${expr}" ]; then jq -r "${expr}" "${file}"; else cat "${file}"; fi
"""


def workflow_text() -> str:
    return CI_YML.read_text(encoding="utf-8")


def job_block(text: str, job: str) -> str:
    """The text of one top-level job: from its key to the next job key."""
    jobs = text.split("\njobs:\n", 1)[1]
    keys = list(re.finditer(r"^  ([A-Za-z0-9_-]+):[ \t]*$", jobs, re.M))
    for i, match in enumerate(keys):
        if match.group(1) == job:
            end = keys[i + 1].start() if i + 1 < len(keys) else len(jobs)
            return jobs[match.start() : end]
    raise AssertionError(f"job {job!r} not found in ci.yml")


def step_blocks(job: str) -> list[tuple[str, str]]:
    """(name, text) for each step of a job, including its leading comments."""
    steps = job.split("\n    steps:\n", 1)[1]
    starts = [m.start() for m in re.finditer(r"^      - ", steps, re.M)]
    out = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(steps)
        text = steps[start:end]
        name = re.match(r"      - name: (.*)", text)
        out.append((name.group(1).strip() if name else "", text))
    return out


def step(job: str, name: str) -> str:
    found = [text for n, text in step_blocks(job) if n == name]
    if len(found) != 1:
        raise AssertionError(f"expected exactly one step {name!r}, got {len(found)}")
    return found[0]


def run_script(step_text: str) -> str:
    """The `run: |` body of a step, dedented."""
    lines = step_text.split("\n")
    out, inside = [], False
    for line in lines:
        if not inside:
            if line == "        run: |":
                inside = True
            continue
        if line.strip() and not line.startswith("          "):
            break
        out.append(line[10:] if line.strip() else "")
    if not out:
        raise AssertionError("step has no `run: |` body")
    return "\n".join(out) + "\n"


def environment_of(job: str) -> str | None:
    match = re.search(r"^    environment: (\S+)[ \t]*$", job, re.M)
    return match.group(1) if match else None


class StubGh:
    """A temp directory holding a stub `gh` on PATH and fixture files."""

    def __init__(self, testcase: unittest.TestCase):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="ci-env-test-"))
        testcase.addCleanup(shutil.rmtree, self.dir, True)
        gh = self.dir / "gh"
        gh.write_text(STUB_GH, encoding="utf-8")
        gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
        self.log = self.dir / "calls.log"
        self.log.write_text("", encoding="utf-8")

    def put(self, name: str, value) -> None:
        (self.dir / name).write_text(json.dumps(value), encoding="utf-8")

    def run(self, script: str, cwd: str | None = None, **env: str) -> subprocess.CompletedProcess:
        full = {
            "PATH": f"{self.dir}{os.pathsep}{os.environ['PATH']}",
            "STUB_DIR": str(self.dir),
            "STUB_LOG": str(self.log),
            "GITHUB_REPOSITORY": "ORG/REPO",
            "GH_TOKEN": "TOKEN_PLACEHOLDER",
        }
        full.update(env)
        # GitHub runs `run:` bodies as `bash -e {0}`.
        return subprocess.run(
            ["bash", "-e", "-c", script],
            env=full,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines()


def environment_object(reviewers: bool) -> dict:
    rules = [{"id": 1, "type": "branch_policy"}]
    if reviewers:
        rules.append({"id": 2, "type": "required_reviewers", "reviewers": []})
    return {"name": "ENV", "protection_rules": rules}


class StructureTests(unittest.TestCase):
    def setUp(self):
        self.text = workflow_text()

    def test_apply_jobs_name_their_environments(self):
        for job, expected in APPLY_JOBS.items():
            with self.subTest(job=job):
                self.assertEqual(environment_of(job_block(self.text, job)), expected)

    def test_only_the_three_applies_and_mail_plan_declare_an_environment(self):
        # mail-plan has its own environment since #2195 (no reviewer, main only).
        declared = re.findall(r"^    environment: (\S+)", self.text, re.M)
        self.assertEqual(sorted(declared), sorted([*APPLY_JOBS.values(), "mail-plan"]))

    def test_mail_apply_is_the_only_job_in_production_mail(self):
        self.assertEqual(
            self.text.count("environment: production-mail"),
            1,
            "production-mail must belong to the mail apply alone",
        )
        self.assertIn("environment: production-mail", job_block(self.text, "mail-apply"))
        for job in ("hetzner-network-apply", "hetzner-estate-apply"):
            self.assertNotEqual(
                environment_of(job_block(self.text, job)), "production-mail"
            )

    def test_every_apply_job_opens_with_the_environment_gate(self):
        for job in APPLY_JOBS:
            with self.subTest(job=job):
                steps = step_blocks(job_block(self.text, job))
                self.assertEqual(steps[0][0], GATE_NAME)

    def test_gate_names_the_job_s_own_environment(self):
        mail = run_script(step(job_block(self.text, "mail-apply"), GATE_NAME))
        self.assertIn('environments/production-mail"', mail)
        self.assertNotIn("deployment_protection_rules", mail)
        self.assertIn("required_reviewers", mail)
        self.assertIn("the production-mail environment has no required-reviewer rule", mail)
        for job in ("hetzner-network-apply", "hetzner-estate-apply"):
            with self.subTest(job=job):
                body = run_script(step(job_block(self.text, job), GATE_NAME))
                self.assertIn('environments/production"', body)
                self.assertNotIn("production-mail", body)
                self.assertIn("required_reviewers", body)
                self.assertIn("deployment_protection_rules", body)
                self.assertIn(
                    "neither a required-reviewer rule nor an enabled custom "
                    "deployment protection rule",
                    body,
                )

    def test_mail_apply_otherwise_unchanged_guard_steps_present(self):
        job = job_block(self.text, "mail-apply")
        names = [n for n, _ in step_blocks(job)]
        for expected in (
            GATE_NAME,
            "Verify the deploy secrets are present",
            "Preview the plan",
            "Refuse to apply a plan that destroys the mail host",
            "Apply",
        ):
            self.assertIn(expected, names)
        self.assertLess(
            names.index("Refuse to apply a plan that destroys the mail host"),
            names.index("Apply"),
        )


class GateBehaviourTests(unittest.TestCase):
    def setUp(self):
        text = workflow_text()
        self.mail = run_script(step(job_block(text, "mail-apply"), GATE_NAME))
        self.prod = run_script(
            step(job_block(text, "hetzner-network-apply"), GATE_NAME)
        )
        self.estate = run_script(
            step(job_block(text, "hetzner-estate-apply"), GATE_NAME)
        )
        self.stub = StubGh(self)

    @staticmethod
    def rules(*enabled: bool, app_id: int = REVIEWER_APP_ID) -> dict:
        return {
            "total_count": len(enabled),
            "custom_deployment_protection_rules": [
                {"id": i, "enabled": e, "app": {"id": app_id}}
                for i, e in enumerate(enabled)
            ],
        }

    def test_mail_needs_a_required_reviewer_rule(self):
        self.stub.put("environment.json", environment_object(reviewers=True))
        result = self.stub.run(self.mail)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "GET repos/ORG/REPO/environments/production-mail", self.stub.calls()
        )

    def test_mail_refuses_without_a_reviewer_even_with_a_custom_rule(self):
        self.stub.put("environment.json", environment_object(reviewers=False))
        self.stub.put("rules.json", self.rules(True))
        result = self.stub.run(self.mail)
        self.assertEqual(result.returncode, 1)
        self.assertIn("production-mail environment has no required-reviewer", result.stderr)
        self.assertFalse(
            any("deployment_protection_rules" in c for c in self.stub.calls())
        )

    def test_mail_refuses_when_the_environment_cannot_be_read(self):
        result = self.stub.run(self.mail)
        self.assertNotEqual(result.returncode, 0)

    def test_production_accepts_a_reviewer_rule(self):
        for script in (self.prod, self.estate):
            self.stub.put("environment.json", environment_object(reviewers=True))
            self.stub.put("rules.json", self.rules())
            self.assertEqual(self.stub.run(script).returncode, 0)

    def test_production_accepts_an_enabled_custom_rule_alone(self):
        for script in (self.prod, self.estate):
            self.stub.put("environment.json", environment_object(reviewers=False))
            self.stub.put("rules.json", self.rules(True))
            result = self.stub.run(script)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_production_refuses_with_no_rule_at_all(self):
        self.stub.put("environment.json", environment_object(reviewers=False))
        self.stub.put("rules.json", self.rules())
        result = self.stub.run(self.prod)
        self.assertEqual(result.returncode, 1)
        self.assertIn("neither a required-reviewer rule", result.stderr)

    def test_production_ignores_a_disabled_custom_rule(self):
        self.stub.put("environment.json", environment_object(reviewers=False))
        self.stub.put("rules.json", self.rules(False))
        self.assertEqual(self.stub.run(self.prod).returncode, 1)

    def test_production_fails_closed_when_the_rules_endpoint_is_unreadable(self):
        self.stub.put("environment.json", environment_object(reviewers=False))
        result = self.stub.run(self.prod)
        self.assertEqual(result.returncode, 1)

    def test_production_ignores_another_apps_custom_rule(self):
        self.stub.put("environment.json", environment_object(reviewers=False))
        self.stub.put("rules.json", self.rules(True, app_id=REVIEWER_APP_ID + 1))
        self.assertEqual(self.stub.run(self.prod).returncode, 1)

    def test_a_non_numeric_rules_answer_with_a_zero_exit_counts_as_no_rule(self):
        # What a stub that applies the real jq never produces: a successful
        # answer that is not a number. The numeric guard must still refuse.
        self.stub.put("environment.json", environment_object(reviewers=False))
        (self.stub.dir / "rules.raw").write_text('{"message":"x"}\n', encoding="utf-8")
        for script in (self.prod, self.estate):
            result = self.stub.run(script)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("neither a required-reviewer rule", result.stderr)

    def test_a_non_numeric_reviewer_answer_with_a_zero_exit_counts_as_no_rule(self):
        (self.stub.dir / "environment.raw").write_text("x\n", encoding="utf-8")
        self.stub.put("rules.json", self.rules())
        for script in (self.prod, self.estate):
            result = self.stub.run(script)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("neither a required-reviewer rule", result.stderr)

    def test_the_gate_pins_the_reviewer_app_by_integration_id(self):
        for script in (self.prod, self.estate):
            self.assertIn(f".app.id == {REVIEWER_APP_ID}", script)

    def test_unreadable_rules_endpoint_does_not_break_a_reviewer_gate(self):
        self.stub.put("environment.json", environment_object(reviewers=True))
        self.assertEqual(self.stub.run(self.prod).returncode, 0)


class CancelStepStructureTests(unittest.TestCase):
    def setUp(self):
        self.text = workflow_text()

    def test_each_plan_job_runs_the_cancel_step_right_after_checkout(self):
        bodies = []
        for job in PLAN_JOBS:
            with self.subTest(job=job):
                block = job_block(self.text, job)
                names = [n for n, _ in step_blocks(block)]
                self.assertEqual(names[names.index("Checkout") + 1], CANCEL_NAME)
                bodies.append(step(block, CANCEL_NAME))
        self.assertEqual(len(set(bodies)), 1, "the three copies must not drift")

    def test_cancel_step_cannot_fail_the_plan(self):
        body = step(job_block(self.text, "mail-plan"), CANCEL_NAME)
        self.assertIn("continue-on-error: true", body)

    def test_actions_write_is_on_the_three_plan_jobs_only(self):
        header = self.text.split("\njobs:\n", 1)[0]
        self.assertNotIn("actions:", header)
        current, granted = None, []
        for line in self.text.split("\njobs:\n", 1)[1].split("\n"):
            key = re.match(r"^  ([A-Za-z0-9_-]+):[ \t]*$", line)
            if key:
                current = key.group(1)
            if re.match(r"^      actions: (?!read\b)\S+", line):
                granted.append(current)
        self.assertEqual(sorted(granted), sorted(PLAN_JOBS))
        for job in PLAN_JOBS:
            block = job_block(self.text, job)
            self.assertRegex(
                block,
                r"    permissions:\n      contents: read\n      packages: read\n      actions: write\n",
            )

    def test_no_workflow_concurrency_group(self):
        # A run paused for approval counts as in progress, so a workflow-level
        # group would queue newer runs behind it (and cancel-in-progress
        # would cancel an apply that had started). Job-level groups on the
        # applies are a different thing and stay.
        header = self.text.split("\njobs:\n", 1)[0]
        self.assertNotRegex(header, r"(?m)^concurrency:")


@unittest.skipUnless(shutil.which("jq"), "jq is needed to run the cancel step")
class CancelStepOrderTests(unittest.TestCase):
    """The cancel step runs scripts/cancel-superseded-waiting.py from the
    checkout, so in every job that calls it the checkout step must come first.
    Parsed as YAML, so the order is the workflow's real step order."""

    def setUp(self):
        import yaml

        self.workflow = yaml.safe_load(workflow_text())

    def test_the_script_step_comes_after_checkout_in_every_job_that_calls_it(self):
        callers = []
        for job_name, job in self.workflow["jobs"].items():
            steps = job.get("steps") or []
            for index, found in enumerate(steps):
                if "cancel-superseded-waiting.py" not in str(found.get("run", "")):
                    continue
                callers.append(job_name)
                checkouts = [
                    i for i, s in enumerate(steps)
                    if str(s.get("uses", "")).startswith("actions/checkout@")
                ]
                with self.subTest(job=job_name):
                    self.assertTrue(checkouts, "no checkout step before the script call")
                    self.assertLess(
                        min(checkouts),
                        index,
                        "the script call (step %d) runs before Checkout, so the file is "
                        "missing on the runner" % index,
                    )
        self.assertEqual(sorted(callers), sorted(PLAN_JOBS))


class CancelBehaviourTests(unittest.TestCase):
    CURRENT = 50

    def setUp(self):
        text = workflow_text()
        self.script = run_script(step(job_block(text, "mail-plan"), CANCEL_NAME))
        self.stub = StubGh(self)

    def run_with(self, runs, jobs_by_run, plans=("true", "true", "true")):
        self.stub.put("runs.json", {"workflow_runs": runs})
        for run_id, jobs in jobs_by_run.items():
            self.stub.put(f"jobs-{run_id}.json", {"jobs": jobs})
        result = self.stub.run(
            self.script,
            cwd=str(ROOT),
            GITHUB_RUN_NUMBER=str(self.CURRENT),
            GITHUB_STEP_SUMMARY=str(self.stub.dir / "summary.md"),
            PLANS_MAIL=plans[0],
            PLANS_NETWORK=plans[1],
            PLANS_ESTATE=plans[2],
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return [c for c in self.stub.calls() if c.startswith("POST ")]

    @staticmethod
    def run_row(run_id, number=10, status="waiting", branch="main", event="push"):
        return {
            "id": run_id,
            "run_number": number,
            "status": status,
            "head_branch": branch,
            "event": event,
        }

    @staticmethod
    def job(name, status, conclusion=None):
        return {"name": name, "status": status, "conclusion": conclusion}

    MAIL = "Apply (mail, pulumi up)"
    NETWORK = "Apply (hetzner network, pulumi up)"
    ESTATE = "Apply (hetzner estate, pulumi up)"

    def test_cancels_an_older_run_waiting_on_stacks_this_run_plans(self):
        posts = self.run_with(
            [self.run_row(101)],
            {
                101: [
                    self.job("Plan (mail, pulumi preview)", "completed", "success"),
                    self.job(self.MAIL, "waiting"),
                    self.job(self.NETWORK, "waiting"),
                    self.job(self.ESTATE, "completed", "skipped"),
                ]
            },
        )
        self.assertEqual(posts, ["POST repos/ORG/REPO/actions/runs/101/cancel"])

    def test_keeps_a_run_waiting_on_a_stack_this_push_does_not_plan(self):
        posts = self.run_with(
            [self.run_row(101)],
            {101: [self.job(self.MAIL, "waiting"), self.job(self.NETWORK, "waiting")]},
            plans=("true", "false", "false"),
        )
        self.assertEqual(posts, [])

    def test_keeps_a_run_whose_apply_is_in_progress(self):
        posts = self.run_with(
            [self.run_row(101)],
            {101: [self.job(self.MAIL, "in_progress"), self.job(self.NETWORK, "waiting")]},
        )
        self.assertEqual(posts, [])

    def test_clears_a_waiting_apply_whose_sibling_apply_already_finished(self):
        # Run 38425376153's shape: a finished sibling no longer protects a
        # waiting apply on a stack this push planned.
        posts = self.run_with(
            [self.run_row(101)],
            {101: [self.job(self.MAIL, "completed", "success"), self.job(self.NETWORK, "waiting")]},
        )
        self.assertEqual(posts, ["POST repos/ORG/REPO/actions/runs/101/cancel"])

    def test_the_summary_names_a_kept_run_and_why(self):
        self.run_with(
            [self.run_row(101)],
            {101: [self.job(self.MAIL, "in_progress"), self.job(self.NETWORK, "waiting")]},
        )
        summary = (self.stub.dir / "summary.md").read_text(encoding="utf-8")
        self.assertIn("Kept run 101", summary)
        self.assertIn("in progress", summary)

    def test_keeps_a_run_with_any_job_in_progress(self):
        posts = self.run_with(
            [self.run_row(101)],
            {
                101: [
                    self.job("Plan (hetzner estate, pulumi preview)", "in_progress"),
                    self.job(self.NETWORK, "waiting"),
                ]
            },
        )
        self.assertEqual(posts, [])

    def test_keeps_a_run_that_is_not_waiting_or_not_older(self):
        posts = self.run_with(
            [
                self.run_row(102, status="in_progress"),
                self.run_row(103, status="queued"),
                self.run_row(104, number=self.CURRENT),
                self.run_row(105, number=self.CURRENT + 1),
                self.run_row(106, branch="feature"),
                self.run_row(107, event="pull_request"),
            ],
            {
                run_id: [self.job(self.MAIL, "waiting")]
                for run_id in (102, 103, 104, 105, 106, 107)
            },
        )
        self.assertEqual(posts, [])

    def test_keeps_a_run_with_an_apply_it_does_not_recognise(self):
        posts = self.run_with(
            [self.run_row(101)],
            {101: [self.job("Apply (somewhere else, pulumi up)", "waiting")]},
        )
        self.assertEqual(posts, [])

    def test_keeps_a_run_with_no_apply_actually_waiting(self):
        # Nothing here is paused on an approval, so there is nothing a newer
        # run supersedes; the run is listed as waiting for another reason.
        every_apply_skipped = [
            self.job(self.MAIL, "completed", "skipped"),
            self.job(self.NETWORK, "completed", "skipped"),
            self.job(self.ESTATE, "completed", "skipped"),
            self.job("Plan (mail, pulumi preview)", "waiting"),
        ]
        every_apply_queued = [
            self.job(self.MAIL, "queued"),
            self.job(self.NETWORK, "pending"),
        ]
        for jobs in (every_apply_skipped, every_apply_queued):
            self.stub.log.write_text("", encoding="utf-8")
            posts = self.run_with([self.run_row(101)], {101: jobs})
            self.assertEqual(posts, [])

    def test_a_queued_downstream_apply_needs_its_own_stack_planned(self):
        jobs = [
            self.job(self.NETWORK, "waiting"),
            self.job(self.ESTATE, "queued"),
            self.job(self.MAIL, "completed", "skipped"),
        ]
        kept = self.run_with(
            [self.run_row(101)], {101: jobs}, plans=("false", "true", "false")
        )
        self.assertEqual(kept, [])
        self.stub.log.write_text("", encoding="utf-8")
        cancelled = self.run_with(
            [self.run_row(101)], {101: jobs}, plans=("false", "true", "true")
        )
        self.assertEqual(cancelled, ["POST repos/ORG/REPO/actions/runs/101/cancel"])

    def run_outside_repo(self, script):
        """Run the step from an empty directory with no scripts/ in it."""
        elsewhere = pathlib.Path(tempfile.mkdtemp(prefix="cancel-elsewhere-"))
        self.addCleanup(shutil.rmtree, elsewhere, True)
        self.stub.put("runs.json", {"workflow_runs": [self.run_row(101)]})
        self.stub.put("jobs-101.json", {"jobs": [self.job(self.ESTATE, "waiting")]})
        result = self.stub.run(
            script,
            cwd=str(elsewhere),
            GITHUB_RUN_NUMBER=str(self.CURRENT),
            GITHUB_STEP_SUMMARY=str(self.stub.dir / "summary.md"),
            PLANS_MAIL="true",
            PLANS_NETWORK="true",
            PLANS_ESTATE="true",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return [c for c in self.stub.calls() if c.startswith("POST ")]

    def test_a_missing_script_keeps_every_run_and_says_so(self):
        # The failure shape of an ordering mistake: the relative script path
        # does not resolve, so the run is kept and the summary names why.
        posts = self.run_outside_repo(self.script)
        self.assertEqual(posts, [])
        summary = (self.stub.dir / "summary.md").read_text(encoding="utf-8")
        self.assertIn("Kept run 101", summary)
        self.assertIn("could not be read", summary)

    def test_the_script_decides_the_same_when_run_by_its_absolute_path(self):
        absolute = str(ROOT / "scripts" / "cancel-superseded-waiting.py")
        script = self.script.replace("scripts/cancel-superseded-waiting.py", absolute)
        posts = self.run_outside_repo(script)
        self.assertEqual(posts, ["POST repos/ORG/REPO/actions/runs/101/cancel"])

    def test_a_listing_failure_cancels_nothing(self):
        result = self.stub.run(
            self.script,
            cwd=str(ROOT),
            GITHUB_RUN_NUMBER=str(self.CURRENT),
            GITHUB_STEP_SUMMARY=str(self.stub.dir / "summary.md"),
            PLANS_MAIL="true",
            PLANS_NETWORK="true",
            PLANS_ESTATE="true",
        )
        # The step itself goes red (it is continue-on-error, so the plan
        # still runs); the point is that nothing is cancelled on a bad read.
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([c for c in self.stub.calls() if c.startswith("POST ")], [])


NOOP_NAME = "Decide whether the plan changes anything"
SAVE_NAME = "Save the update plan for the no-change check"
PLAN_FILE = "preview-plan.json"
# Each plan job's working directory, which its relative script path depends on.
PLAN_WORKDIRS = {
    "mail-plan": "mail",
    "hetzner-network-plan": "hetzner",
    "hetzner-estate-plan": "hetzner/estate",
}
PLAN_OF_APPLY = {
    "mail-apply": "mail-plan",
    "hetzner-network-apply": "hetzner-network-plan",
    "hetzner-estate-apply": "hetzner-estate-plan",
}


def all_jobs(text: str) -> list[str]:
    jobs = text.split("\njobs:\n", 1)[1]
    return re.findall(r"^  ([A-Za-z0-9_-]+):[ \t]*$", jobs, re.M)


def gated_apply_jobs(text: str) -> list[str]:
    """Every job that declares an environment and is not one of the plan jobs."""
    return [
        job
        for job in all_jobs(text)
        if environment_of(job_block(text, job)) and job not in PLAN_JOBS
    ]


def job_if(job: str) -> str:
    """The job-level `if:` expression, folded onto one line."""
    lines = job.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("    if:"):
            parts = [line[len("    if:") :].strip()]
            for follow in lines[i + 1 :]:
                if not follow.startswith("      "):
                    break
                parts.append(follow.strip())
            return " ".join(p for p in parts if p not in ("", ">-", "|"))
    return ""


def and_operands(condition: str) -> list[str]:
    """Split an `if:` expression on `&&` outside parentheses and quotes."""
    operands, current, depth, quote, i = [], "", 0, "", 0
    while i < len(condition):
        char = condition[i]
        if quote:
            quote = "" if char == quote else quote
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and condition.startswith("&&", i):
            operands.append(current.strip())
            current, i = "", i + 2
            continue
        current += char
        i += 1
    operands.append(current.strip())
    return operands


def needs_of(job: str) -> list[str]:
    match = re.search(r"^    needs: \[([^\]]*)\]", job, re.M)
    if not match:
        return []
    return [n.strip() for n in match.group(1).split(",") if n.strip()]


class NoOpGateStructureTests(unittest.TestCase):
    def setUp(self):
        self.text = workflow_text()

    def test_the_gated_apply_jobs_are_the_three_known_ones(self):
        # A fourth gated apply must be added to APPLY_JOBS and PLAN_OF_APPLY
        # here, so it cannot arrive without the no-op condition below.
        self.assertEqual(sorted(gated_apply_jobs(self.text)), sorted(APPLY_JOBS))

    def test_every_gated_apply_job_needs_only_its_plan(self):
        for job in gated_apply_jobs(self.text):
            with self.subTest(job=job):
                self.assertEqual(needs_of(job_block(self.text, job)), [PLAN_OF_APPLY[job]])

    def test_no_gated_apply_condition_has_an_or(self):
        # An `||` lets one operand alone start the job, whatever the others say.
        for job in gated_apply_jobs(self.text):
            with self.subTest(job=job):
                condition = job_if(job_block(self.text, job))
                self.assertNotIn("||", condition, f"{job}: an `||` in the apply condition")

    def test_every_gated_apply_condition_is_the_three_exact_operands(self):
        for job in gated_apply_jobs(self.text):
            with self.subTest(job=job):
                operands = and_operands(job_if(job_block(self.text, job)))
                self.assertEqual(
                    sorted(operands),
                    sorted(
                        [
                            "github.event_name == 'push'",
                            "github.ref == 'refs/heads/main'",
                            f"needs.{PLAN_OF_APPLY[job]}.outputs.has_changes != 'false'",
                        ]
                    ),
                    f"{job}: the apply condition is not push, main and not-an-explicit-false",
                )

    def test_the_has_changes_operand_skips_only_on_an_explicit_false(self):
        # Tested alone: an unset output must not skip the apply, so the
        # operator is `!=` and the literal is 'false', not `== 'true'`.
        for job in gated_apply_jobs(self.text):
            with self.subTest(job=job):
                plan = PLAN_OF_APPLY[job]
                found = [
                    o
                    for o in and_operands(job_if(job_block(self.text, job)))
                    if "has_changes" in o
                ]
                self.assertEqual(
                    found,
                    [f"needs.{plan}.outputs.has_changes != 'false'"],
                    f"{job}: the has_changes operand is not `!= 'false'`, as one operand",
                )

    def test_the_operand_splitter_reads_top_level_and_only(self):
        self.assertEqual(and_operands("a == 1 && (b || c) && d"), ["a == 1", "(b || c)", "d"])
        self.assertEqual(and_operands("a == 'x && y' && b"), ["a == 'x && y'", "b"])
        self.assertEqual(and_operands("a || b"), ["a || b"])

    def test_each_plan_job_outputs_has_changes_from_the_noop_step(self):
        for job in PLAN_JOBS:
            with self.subTest(job=job):
                block = job_block(self.text, job)
                self.assertIn(
                    "\n    outputs:\n      has_changes: ${{ steps.noop.outputs.has_changes }}\n",
                    block,
                    f"{job} does not publish has_changes",
                )
                noop = step(block, NOOP_NAME)
                self.assertIn("        id: noop\n", noop)
                self.assertIn("        if: always()\n", noop)
                self.assertIn("plan-has-changes.py preview.json " + PLAN_FILE, noop)
                self.assertIn('--github-output "$GITHUB_OUTPUT"', noop)
                self.assertIn('--github-summary "$GITHUB_STEP_SUMMARY"', noop)

    def test_the_noop_step_comes_before_the_summary_so_its_line_is_first(self):
        for job in PLAN_JOBS:
            with self.subTest(job=job):
                names = [n for n, _ in step_blocks(job_block(self.text, job))]
                self.assertLess(
                    names.index(NOOP_NAME), names.index("Write the plan to the job summary")
                )

    def test_the_update_plan_is_saved_by_its_own_step_in_the_plan_jobs_only(self):
        self.assertEqual(self.text.count("--save-plan"), len(PLAN_JOBS))
        self.assertNotIn("PULUMI_EXPERIMENTAL", self.text)
        for job in PLAN_JOBS:
            with self.subTest(job=job):
                block = job_block(self.text, job)
                save = step(block, SAVE_NAME)
                self.assertIn("        continue-on-error: true\n", save)
                self.assertIn(
                    f"pulumi preview --stack production --save-plan {PLAN_FILE} > /dev/null",
                    save,
                )
                # The preview.json the delete guard reads is produced as before.
                self.assertIn(
                    "run: pulumi preview --stack production --json > preview.json\n",
                    step(block, "Preview the plan"),
                )
        for job in set(all_jobs(self.text)) - set(PLAN_JOBS):
            with self.subTest(job=job):
                block = job_block(self.text, job)
                self.assertNotIn("--save-plan", block)
                self.assertNotIn(PLAN_FILE, block)

    def test_the_plan_file_is_only_ever_read_by_the_script(self):
        # It can hold resource inputs and ciphertext: never uploaded, printed
        # or summarised.
        self.assertNotIn("upload-artifact", self.text)
        for job in PLAN_JOBS:
            for name, body in step_blocks(job_block(self.text, job)):
                if PLAN_FILE in body:
                    with self.subTest(job=job, step=name):
                        self.assertIn(name, (SAVE_NAME, NOOP_NAME))


@unittest.skipUnless(shutil.which("bash"), "bash is needed to run the decision step")
class NoOpStepBehaviourTests(unittest.TestCase):
    """Run each plan job's decision step, as written, against fixture files."""

    ROOT_URN = "urn:pulumi:production::STACK::pulumi:pulumi:Stack::STACK-production"

    def setUp(self):
        self.text = workflow_text()
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="noop-step-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "scripts").symlink_to(ROOT / "scripts")

    def run_step(self, job: str, preview, plan_file):
        workdir = self.tmp / PLAN_WORKDIRS[job]
        workdir.mkdir(parents=True, exist_ok=True)
        (workdir / "preview.json").write_text(json.dumps(preview), encoding="utf-8")
        if plan_file is not None:
            (workdir / PLAN_FILE).write_text(json.dumps(plan_file), encoding="utf-8")
        out = self.tmp / f"{job}.output"
        summary = self.tmp / f"{job}.summary"
        line = re.search(
            r"^        run: (.+)$", step(job_block(self.text, job), NOOP_NAME), re.M
        )
        self.assertIsNotNone(line, f"{job}: the decision step has no one-line run")
        script = line.group(1)
        result = subprocess.run(
            ["bash", "-e", "-c", script],
            cwd=workdir,
            env={
                "PATH": os.environ["PATH"],
                "GITHUB_OUTPUT": str(out),
                "GITHUB_STEP_SUMMARY": str(summary),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        read = lambda p: p.read_text(encoding="utf-8") if p.exists() else ""  # noqa: E731
        return result, read(out), read(summary)

    def preview(self, op="same"):
        step = {"op": op, "urn": self.ROOT_URN}
        if op == "same":
            # A same step carries both states; the old one holds the id and outputs.
            step["oldState"] = {"urn": self.ROOT_URN, "id": "ID", "outputs": {"k": "v"}}
            step["newState"] = {"urn": self.ROOT_URN}
        return {"steps": [step], "changeSummary": {op: 3}}

    def plan(self, diff=None):
        return {
            "resourcePlans": {
                self.ROOT_URN: {
                    "goal": {"inputDiff": {}, "outputDiff": diff or {}},
                    "steps": ["same"],
                }
            }
        }

    def test_a_no_op_plan_publishes_false_and_says_so_first(self):
        for job in PLAN_JOBS:
            with self.subTest(job=job):
                result, out, summary = self.run_step(job, self.preview(), self.plan())
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(out, "has_changes=false\n")
                self.assertEqual(
                    summary.splitlines()[0],
                    "No changes: the apply job is skipped and no approval is requested",
                )

    def test_a_changing_plan_publishes_true_and_counts_first(self):
        for job in PLAN_JOBS:
            with self.subTest(job=job):
                preview = self.preview("update")
                result, out, summary = self.run_step(job, preview, self.plan())
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(out, "has_changes=true\n")
                self.assertEqual(summary.splitlines()[0], "1 change: approval required")

    def test_an_output_only_change_publishes_true(self):
        for job in PLAN_JOBS:
            with self.subTest(job=job):
                plan = self.plan({"updates": {"greeting": "hello"}})
                _, out, summary = self.run_step(job, self.preview(), plan)
                self.assertEqual(out, "has_changes=true\n")
                self.assertEqual(summary.splitlines()[0], "1 change: approval required")

    def test_a_missing_plan_file_publishes_true(self):
        for job in PLAN_JOBS:
            with self.subTest(job=job):
                result, out, _ = self.run_step(job, self.preview(), None)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(out, "has_changes=true\n")


if __name__ == "__main__":
    unittest.main()
