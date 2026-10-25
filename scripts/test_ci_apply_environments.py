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

import test_workflow_concurrency as concurrency_rules

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"

def routed(plan_job: str) -> str:
    """The `environment:` value of an apply the spend gate routes: the free
    environment only on the exact string, `production` for anything else."""
    return (
        "${{ needs.%s.outputs.apply_environment == 'production-free' "
        "&& 'production-free' || 'production' }}" % plan_job
    )


APPLY_JOBS = {
    "mail-apply": "production-mail",
    "hetzner-network-apply": routed("hetzner-network-plan"),
    "hetzner-estate-apply": routed("hetzner-estate-plan"),
}
ROUTED_APPLY_JOBS = ("hetzner-network-apply", "hetzner-estate-apply")
PLAN_JOBS = ["mail-plan", "hetzner-network-plan", "hetzner-estate-plan"]
ROUTED_PLAN_JOBS = ("hetzner-network-plan", "hetzner-estate-plan")

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


def job_names(text: str) -> list[str]:
    """Every top-level job key, in file order."""
    jobs = text.split("\njobs:\n", 1)[1]
    return [m.group(1) for m in re.finditer(r"^  ([A-Za-z0-9_-]+):[ \t]*$", jobs, re.M)]


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
    match = re.search(r"^    environment: (.+?)[ \t]*$", job, re.M)
    return match.group(1) if match else None


def job_env_value(job: str, name: str) -> str | None:
    """A job-level `env:` entry (six spaces), or None."""
    match = re.search(r"^      %s: (.+?)[ \t]*$" % re.escape(name), job, re.M)
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
            # What the routed applies read; the mail apply names its own.
            "APPLY_ENVIRONMENT": "production",
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
        declared = re.findall(r"^    environment: (.+?)[ \t]*$", self.text, re.M)
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
                # The job's own environment, from the same expression the job's
                # `environment:` key uses (pinned equal in RouteStructureTests).
                self.assertIn('environments/${APPLY_ENVIRONMENT}"', body)
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

    def test_workflow_concurrency_is_keyed_per_run_and_cancels_only_pull_requests(self):
        # A run paused for approval counts as in progress. A workflow-level
        # group that push runs share would queue a newer apply behind it, and
        # a cancel on a non-PR run would cancel an apply that had started. The
        # rule lives in one place, the parsed checker in
        # test_workflow_concurrency.py, and this calls it on ci.yml: no second
        # copy of the rule, so no two pins that can disagree.
        self.assertEqual(concurrency_rules.violations("ci.yml", self.text), [])


class CancelStepOrderTests(unittest.TestCase):
    """The cancel step runs scripts/cancel-superseded-waiting.py from the
    checkout, so in every job that calls it the checkout step must come first.
    Line-structure parse of each job's steps list, standard library only."""

    def test_the_script_step_comes_after_checkout_in_every_job_that_calls_it(self):
        text = workflow_text()
        callers = []
        for job in job_names(text):
            block = job_block(text, job)
            if "\n    steps:\n" not in block:
                continue
            steps = step_blocks(block)
            calls = [
                i for i, (_, body) in enumerate(steps)
                if "cancel-superseded-waiting.py" in body
            ]
            if not calls:
                continue
            callers.append(job)
            checkouts = [
                i for i, (_, body) in enumerate(steps)
                if "uses: actions/checkout@" in body
            ]
            with self.subTest(job=job):
                self.assertTrue(checkouts, "no checkout step in the job")
                self.assertLess(
                    min(checkouts),
                    calls[0],
                    "the script call (step %d) runs before Checkout, so the file is "
                    "missing on the runner" % calls[0],
                )
        self.assertEqual(sorted(callers), sorted(PLAN_JOBS))


@unittest.skipUnless(shutil.which("jq"), "jq is needed to run the cancel step")
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

    def test_every_gated_apply_condition_is_the_push_and_main_operands(self):
        # The has_changes operand is the shared check's to hold; this pins the rest.
        for job in gated_apply_jobs(self.text):
            with self.subTest(job=job):
                operands = and_operands(job_if(job_block(self.text, job)))
                self.assertEqual(
                    sorted(o for o in operands if "has_changes" not in o),
                    sorted(["github.event_name == 'push'", "github.ref == 'refs/heads/main'"]),
                    f"{job}: the apply condition is not push and main",
                )

    def test_each_plan_job_previews_to_preview_json_as_before(self):
        # preview.json is the file the delete guard reads and the owner reviews.
        for job in PLAN_JOBS:
            with self.subTest(job=job):
                self.assertIn(
                    "run: pulumi preview --stack production --json > preview.json\n",
                    step(job_block(self.text, job), "Preview the plan"),
                )


SPEND_GATE_USES = re.compile(
    r"uses: branchLeft/github-workflows/\.github/actions/spend-gate@([0-9a-f]{40}) #"
)

ROUTE_NAME = "Choose the apply environment"
READY_NAME = "Check the free apply environment is gated"
SPEND_NAME = "Decide whether the plan could cost money"
REGATE_NAME = "Refuse a plan that could cost money on the free environment"
DELETE_STEP_OF_PLAN = {
    "hetzner-network-plan": "Refuse a plan that destroys the network",
    "hetzner-estate-plan": "Refuse a plan that destroys the estate",
}
DELETE_STEP_OF_APPLY = {
    "hetzner-network-apply": "Refuse to apply a plan that destroys the network",
    "hetzner-estate-apply": "Refuse to apply a plan that destroys the estate",
}
PLAN_OF_ROUTED_APPLY = {
    "hetzner-network-apply": "hetzner-network-plan",
    "hetzner-estate-apply": "hetzner-estate-plan",
}


def resolve_environment(expression: str, outputs: dict[str, str]) -> str:
    """Evaluate a routed `environment:` value the way GitHub does, for the one
    shape the workflow uses: `A == 'production-free' && 'production-free' ||
    'production'`, where A is the plan job's `apply_environment` output (an
    output that was never set is the empty string). Any other shape raises, so
    a rewrite of the expression cannot slip past the replay."""
    match = re.fullmatch(
        r"\$\{\{ needs\.([A-Za-z0-9_-]+)\.outputs\.apply_environment == 'production-free' "
        r"&& 'production-free' \|\| 'production' \}\}",
        expression,
    )
    if not match:
        raise AssertionError(f"not the routed environment expression: {expression!r}")
    # `a == b && c || d` is `(a == b && c) || d`; c is a non-empty string.
    if outputs.get(match.group(1), "") == "production-free":
        return "production-free"
    return "production"


class RouteStructureTests(unittest.TestCase):
    def setUp(self):
        self.text = workflow_text()

    def test_each_routed_apply_uses_the_exact_routed_expression(self):
        for job in ROUTED_APPLY_JOBS:
            with self.subTest(job=job):
                self.assertEqual(
                    environment_of(job_block(self.text, job)), routed(PLAN_OF_ROUTED_APPLY[job])
                )

    def test_the_apply_environment_variable_is_the_same_expression(self):
        for job in ROUTED_APPLY_JOBS:
            with self.subTest(job=job):
                block = job_block(self.text, job)
                self.assertEqual(job_env_value(block, "APPLY_ENVIRONMENT"), environment_of(block))

    def test_the_mail_jobs_are_never_routed(self):
        for job in ("mail-plan", "mail-apply"):
            block = job_block(self.text, job)
            self.assertNotIn("production-free", block)
            self.assertNotIn("apply_environment", block)
            self.assertNotIn("spend-gate", block)

    def test_each_routed_plan_job_publishes_the_route_step_output(self):
        for job in ROUTED_PLAN_JOBS:
            with self.subTest(job=job):
                self.assertIn(
                    "      apply_environment: ${{ steps.route.outputs.environment }}\n",
                    job_block(self.text, job),
                )

    def test_the_route_step_binds_exactly_the_four_inputs(self):
        for job in ROUTED_PLAN_JOBS:
            with self.subTest(job=job):
                body = step(job_block(self.text, job), ROUTE_NAME)
                for binding in (
                    "SPEND_VERDICT: ${{ steps.spend.outputs.verdict }}",
                    "PREVIEW_OUTCOME: ${{ steps.preview.outcome }}",
                    "DELETE_GUARD_OUTCOME: ${{ steps.deletes.outcome }}",
                    "FREE_ENVIRONMENT_READY: ${{ steps.free_ready.outputs.ready }}",
                ):
                    self.assertIn(binding, body)
                self.assertIn("id: route", body)
                # A fault here must not fail the plan: the output stays unset.
                self.assertIn("continue-on-error: true", body)

    def test_the_ids_the_route_reads_belong_to_the_right_steps(self):
        for job in ROUTED_PLAN_JOBS:
            with self.subTest(job=job):
                block = job_block(self.text, job)
                self.assertIn("id: preview", step(block, "Preview the plan"))
                self.assertIn("id: deletes", step(block, DELETE_STEP_OF_PLAN[job]))
                self.assertIn("id: spend", step(block, SPEND_NAME))
                self.assertIn("id: free_ready", step(block, READY_NAME))

    def test_the_routing_steps_run_after_the_delete_guard_and_before_the_summary(self):
        for job in ROUTED_PLAN_JOBS:
            with self.subTest(job=job):
                names = [n for n, _ in step_blocks(job_block(self.text, job))]
                order = [
                    "Preview the plan",
                    DELETE_STEP_OF_PLAN[job],
                    SPEND_NAME,
                    READY_NAME,
                    ROUTE_NAME,
                    "Decide whether the plan changes anything",
                    "Write the plan to the job summary",
                ]
                positions = [names.index(n) for n in order]
                self.assertEqual(positions, sorted(positions))

    def test_the_spend_gate_step_is_advisory_to_the_plan_and_runs_only_after_success(self):
        for job in ROUTED_PLAN_JOBS:
            with self.subTest(job=job):
                body = step(job_block(self.text, job), SPEND_NAME)
                self.assertIn("continue-on-error: true", body)
                # No `if:`: it takes the default success(), so a failed
                # preview or delete guard leaves its verdict unset.
                self.assertNotRegex(body, r"^        if:", "the gate must run only after success")
                self.assertIn("preview-json: preview.json", body)

    def test_the_gate_is_pinned_to_one_full_sha_everywhere(self):
        shas = set(SPEND_GATE_USES.findall(self.text))
        self.assertEqual(len(shas), 1, "the four uses must pin the same commit")
        self.assertEqual(len(SPEND_GATE_USES.findall(self.text)), 4)

    def test_the_apply_re_gates_its_own_preview_before_pulumi_up(self):
        for job in ROUTED_APPLY_JOBS:
            with self.subTest(job=job):
                block = job_block(self.text, job)
                names = [n for n, _ in step_blocks(block)]
                order = ["Preview the plan", DELETE_STEP_OF_APPLY[job], SPEND_NAME, REGATE_NAME, "Apply"]
                positions = [names.index(n) for n in order]
                self.assertEqual(positions, sorted(positions))
                self.assertEqual(positions[3] + 1, positions[4], "nothing may sit between the re-gate and Apply")
                regate = step(block, REGATE_NAME)
                self.assertNotRegex(regate, r"^        if:", "the re-gate must not be skippable")
                self.assertNotIn("continue-on-error", regate)
                self.assertIn("SPEND_VERDICT: ${{ steps.spend.outputs.verdict }}", regate)

    def test_the_apply_side_gate_cannot_block_the_owner_s_path(self):
        for job in ROUTED_APPLY_JOBS:
            with self.subTest(job=job):
                self.assertIn("continue-on-error: true", step(job_block(self.text, job), SPEND_NAME))

    def test_the_free_readiness_step_reads_only_the_free_environment(self):
        for job in ROUTED_PLAN_JOBS:
            with self.subTest(job=job):
                body = run_script(step(job_block(self.text, job), READY_NAME))
                self.assertIn("environments/production-free/deployment_protection_rules", body)
                self.assertIn(f".app.id == {REVIEWER_APP_ID}", body)
                self.assertNotIn("required_reviewers", body)


@unittest.skipUnless(shutil.which("jq"), "jq is needed to run the readiness and gate steps")
class RouteReplayTests(unittest.TestCase):
    """A dry replay of the whole chain the workflow runs, step by step, on a
    stub `gh`: readiness, the route, the environment expression, the apply's
    environment gate and its re-gate. Each test is one route."""

    def setUp(self):
        text = workflow_text()
        self.text = text
        self.stub = StubGh(self)
        self.work = self.stub.dir
        (self.work / "preview.json").write_text("{}", encoding="utf-8")
        self.outputs = self.work / "github-output"
        self.summary = self.work / "github-summary"

    @staticmethod
    def app_rule(enabled: bool = True, app_id: int = REVIEWER_APP_ID) -> dict:
        return {
            "total_count": 1,
            "custom_deployment_protection_rules": [{"id": 1, "enabled": enabled, "app": {"id": app_id}}],
        }

    def run_step(self, script: str, **env: str) -> subprocess.CompletedProcess:
        return self.stub.run(
            script,
            cwd=str(ROOT),
            GITHUB_OUTPUT=str(self.outputs),
            GITHUB_STEP_SUMMARY=str(self.summary),
            **env,
        )

    def output(self, key: str) -> str:
        if not self.outputs.exists():
            return ""
        for line in self.outputs.read_text(encoding="utf-8").splitlines():
            name, _, value = line.partition("=")
            if name == key:
                return value
        return ""

    def route(self, job: str, *, verdict: str, preview="success", deletes="success", rules=None) -> str:
        """Run readiness then the route step; return the plan job's output as
        the job would publish it (empty when the step wrote nothing)."""
        self.outputs.write_text("", encoding="utf-8")
        if rules is not None:
            self.stub.put("rules.json", rules)
        block = job_block(self.text, job)
        ready = self.run_step(run_script(step(block, READY_NAME)))
        self.assertEqual(ready.returncode, 0, ready.stderr)
        ready_value = self.output("ready")
        chosen = self.run_step(
            run_script(step(block, ROUTE_NAME)),
            SPEND_VERDICT=verdict,
            PREVIEW_OUTCOME=preview,
            DELETE_GUARD_OUTCOME=deletes,
            FREE_ENVIRONMENT_READY=ready_value,
        )
        self.assertEqual(chosen.returncode, 0, chosen.stderr)
        return self.output("environment")

    def environment_for(self, job: str, published: str) -> str:
        apply_job = {v: k for k, v in PLAN_OF_ROUTED_APPLY.items()}[job]
        expression = environment_of(job_block(self.text, apply_job))
        return resolve_environment(expression, {job: published})

    def apply_gate(self, apply_job: str, environment: str, *, reviewers=False, rules=None) -> int:
        self.stub.put("environment.json", environment_object(reviewers=reviewers))
        if rules is not None:
            self.stub.put("rules.json", rules)
        script = run_script(step(job_block(self.text, apply_job), GATE_NAME))
        return self.run_step(script, APPLY_ENVIRONMENT=environment).returncode

    def regate(self, apply_job: str, environment: str, verdict: str) -> int:
        script = run_script(step(job_block(self.text, apply_job), REGATE_NAME))
        return self.stub.run(script, cwd=str(self.work), APPLY_ENVIRONMENT=environment, SPEND_VERDICT=verdict).returncode

    def each_stack(self):
        for plan_job, apply_job in (
            ("hetzner-network-plan", "hetzner-network-apply"),
            ("hetzner-estate-plan", "hetzner-estate-apply"),
        ):
            with self.subTest(stack=plan_job):
                yield plan_job, apply_job

    def test_free_plan_with_a_gated_free_environment_runs_in_production_free(self):
        for plan_job, apply_job in self.each_stack():
            published = self.route(plan_job, verdict="FREE", rules=self.app_rule())
            self.assertEqual(published, "production-free")
            environment = self.environment_for(plan_job, published)
            self.assertEqual(environment, "production-free")
            self.assertEqual(self.apply_gate(apply_job, environment, rules=self.app_rule()), 0)
            self.assertEqual(self.regate(apply_job, environment, "FREE"), 0)
            self.assertIn(
                "GET repos/ORG/REPO/environments/production-free/deployment_protection_rules",
                self.stub.calls(),
            )

    def test_a_paid_plan_runs_in_production(self):
        for plan_job, apply_job in self.each_stack():
            published = self.route(plan_job, verdict="PAID", rules=self.app_rule())
            self.assertEqual(published, "production")
            self.assertEqual(self.environment_for(plan_job, published), "production")

    def test_a_plan_the_gate_could_not_read_runs_in_production(self):
        # The gate step failed or was skipped: its output is the empty string.
        for plan_job, apply_job in self.each_stack():
            published = self.route(plan_job, verdict="", rules=self.app_rule())
            self.assertEqual(published, "production")
            self.assertEqual(self.environment_for(plan_job, published), "production")

    def test_a_failed_preview_or_delete_guard_runs_in_production(self):
        for plan_job, apply_job in self.each_stack():
            for preview, deletes in (("failure", "success"), ("success", "failure"), ("skipped", "skipped")):
                published = self.route(
                    plan_job, verdict="FREE", preview=preview, deletes=deletes, rules=self.app_rule()
                )
                self.assertEqual(published, "production", (preview, deletes))

    def test_a_free_plan_with_no_free_environment_runs_in_production(self):
        # The environment is not created yet: the rules endpoint answers 404
        # (the stub's unreadable case), so readiness is false.
        for plan_job, apply_job in self.each_stack():
            (self.work / "rules.json").unlink(missing_ok=True)
            published = self.route(plan_job, verdict="FREE")
            self.assertEqual(published, "production")

    def test_a_free_plan_whose_environment_lost_the_app_rule_runs_in_production(self):
        for plan_job, apply_job in self.each_stack():
            for rules in (self.app_rule(enabled=False), self.app_rule(app_id=REVIEWER_APP_ID + 1)):
                published = self.route(plan_job, verdict="FREE", rules=rules)
                self.assertEqual(published, "production")

    def test_the_apply_refuses_a_free_environment_that_lost_its_rule_after_routing(self):
        for plan_job, apply_job in self.each_stack():
            published = self.route(plan_job, verdict="FREE", rules=self.app_rule())
            environment = self.environment_for(plan_job, published)
            self.assertEqual(environment, "production-free")
            self.assertEqual(self.apply_gate(apply_job, environment, rules=self.app_rule(enabled=False)), 1)

    def test_the_apply_refuses_a_plan_that_turned_paid_after_routing(self):
        for plan_job, apply_job in self.each_stack():
            for verdict in ("PAID", "", "free", "FREE\n"):
                self.assertEqual(self.regate(apply_job, "production-free", verdict), 1, verdict)

    def test_the_apply_on_production_is_not_blocked_by_the_gate(self):
        for plan_job, apply_job in self.each_stack():
            for verdict in ("FREE", "PAID", ""):
                self.assertEqual(self.regate(apply_job, "production", verdict), 0, verdict)

    def test_an_unknown_environment_name_is_refused_by_both_apply_steps(self):
        for plan_job, apply_job in self.each_stack():
            for name in ("", "production-mail", "production-free ", "staging", "Production"):
                self.assertEqual(self.apply_gate(apply_job, name, reviewers=True, rules=self.app_rule()), 1, name)
                self.assertEqual(self.regate(apply_job, name, "FREE"), 1, name)

    def test_the_apply_gate_reads_the_environment_it_runs_in(self):
        for plan_job, apply_job in self.each_stack():
            self.apply_gate(apply_job, "production", reviewers=True, rules=self.app_rule())
            self.apply_gate(apply_job, "production-free", rules=self.app_rule())
            calls = self.stub.calls()
            self.assertIn("GET repos/ORG/REPO/environments/production", calls)
            self.assertIn("GET repos/ORG/REPO/environments/production-free", calls)

    def test_only_the_exact_published_string_selects_the_free_environment(self):
        expression = routed("hetzner-network-plan")
        for published, expected in (
            ("production-free", "production-free"),
            ("production", "production"),
            ("", "production"),
            ("PRODUCTION-FREE", "production"),
            ("production-free ", "production"),
            ("production-free-2", "production"),
            ("true", "production"),
        ):
            with self.subTest(published=published):
                self.assertEqual(
                    resolve_environment(expression, {"hetzner-network-plan": published}), expected
                )
        # A plan job that published nothing at all (skipped or failed).
        self.assertEqual(resolve_environment(expression, {}), "production")


if __name__ == "__main__":
    unittest.main()
