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
    "hetzner-dns-apply": "production-dns",
    "hetzner-tenants-apply": "production",
}
ROUTED_APPLY_JOBS = ("hetzner-network-apply", "hetzner-estate-apply")
PLAN_JOBS = [
    "mail-plan",
    "hetzner-network-plan",
    "hetzner-estate-plan",
    "hetzner-dns-plan",
    "hetzner-tenants-plan",
]
ROUTED_PLAN_JOBS = ("hetzner-network-plan", "hetzner-estate-plan")
# The two stacks whose applies each have an environment of their own, never
# routed by the spend gate.
OWN_ENVIRONMENT_APPLIES = {
    "mail-apply": "production-mail",
    "hetzner-dns-apply": "production-dns",
}
DNS_APPLY = "hetzner-dns-apply"
DNS_PLAN = "hetzner-dns-plan"
# The tenants stack's pair. Its apply is in the literal `production`, never
# routed to `production-free`, and its plan has no environment (it reads its
# credentials from repository secrets, as the estate plan does).
TENANTS_APPLY = "hetzner-tenants-apply"
TENANTS_PLAN = "hetzner-tenants-plan"
TENANTS_SECRETS = (
    "HCLOUD_TOKEN_TENANTS",
    "PULUMI_PASSPHRASE_HETZNER_TENANTS",
    "PULUMI_SALT_HETZNER_TENANTS",
)
# The plan jobs that read their credentials from an environment of their own:
# main-only, no reviewer (issue #2195 for mail; the DNS plan mirrors it).
PLAN_ENVIRONMENTS = {"mail-plan": "mail-plan", DNS_PLAN: "dns-plan"}
# The three secrets that can write the DNS zone. They live in `dns-plan` and
# `production-dns`, so only these two jobs may name them.
DNS_SECRETS = ("HCLOUD_TOKEN_DNS", "PULUMI_PASSPHRASE_HETZNER_DNS", "PULUMI_SALT_HETZNER_DNS")

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


# Check jobs that once stood in ci.yml and now stand in a file of their own,
# with ci.yml's triggers. Nothing in ci.yml `needs` them. The gate tests that
# are about every check job read ci.yml and these files as one list of jobs
# (ci_jobs_text); the plan and apply jobs, and the `changes` job they read,
# stay in ci.yml and are read from it alone (workflow_text).
SPLIT_OUT_WORKFLOWS = ("ci-config-validate.yml",)
CHECK_WORKFLOWS = ("ci.yml", *SPLIT_OUT_WORKFLOWS)


def ci_jobs_text() -> str:
    """ci.yml, then the `jobs:` mapping of every file split out of it, as one text.

    job_block and job_names read it as they read ci.yml, so every pin that is
    about a check job still sees the job wherever it now lives."""
    text = CI_YML.read_text(encoding="utf-8")
    for name in SPLIT_OUT_WORKFLOWS:
        other = (CI_YML.parent / name).read_text(encoding="utf-8")
        text += other.split("\njobs:\n", 1)[1]
    return text


def job_block(text: str, job: str) -> str:
    """The text of one top-level job: from its key to the next job key."""
    jobs = text.split("\njobs:\n", 1)[1]
    keys = list(re.finditer(r"^  ([A-Za-z0-9_-]+):[ \t]*$", jobs, re.M))
    for i, match in enumerate(keys):
        if match.group(1) == job:
            end = keys[i + 1].start() if i + 1 < len(keys) else len(jobs)
            return jobs[match.start() : end]
    raise AssertionError(f"job {job!r} not found in ci.yml or the files split out of it")


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

    def test_only_the_five_applies_and_the_mail_and_dns_plans_declare_an_environment(self):
        # mail-plan has its own environment since #2195 (no reviewer, main only);
        # the DNS plan mirrors it with `dns-plan`.
        declared = re.findall(r"^    environment: (.+?)[ \t]*$", self.text, re.M)
        self.assertEqual(
            sorted(declared), sorted([*APPLY_JOBS.values(), *PLAN_ENVIRONMENTS.values()])
        )

    def test_the_plan_jobs_name_their_environments(self):
        for job, expected in PLAN_ENVIRONMENTS.items():
            with self.subTest(job=job):
                self.assertEqual(environment_of(job_block(self.text, job)), expected)
        for job in (*ROUTED_PLAN_JOBS, TENANTS_PLAN):
            with self.subTest(job=job):
                self.assertIsNone(environment_of(job_block(self.text, job)))

    def test_dns_plan_is_the_only_job_in_dns_plan(self):
        self.assertEqual(
            self.text.count("environment: dns-plan"),
            1,
            "dns-plan must belong to the DNS plan alone",
        )
        for job in all_jobs(self.text):
            if job != DNS_PLAN:
                with self.subTest(job=job):
                    self.assertNotEqual(environment_of(job_block(self.text, job)), "dns-plan")

    def test_the_dns_secrets_are_read_by_the_dns_plan_and_apply_only(self):
        for job in all_jobs(self.text):
            block = job_block(self.text, job)
            for secret in DNS_SECRETS:
                with self.subTest(job=job, secret=secret):
                    if job in (DNS_PLAN, DNS_APPLY):
                        self.assertIn(f"secrets.{secret}", block)
                    else:
                        self.assertNotIn(secret, block)

    def test_mail_apply_is_the_only_job_in_production_mail(self):
        self.assertEqual(
            self.text.count("environment: production-mail"),
            1,
            "production-mail must belong to the mail apply alone",
        )
        self.assertIn("environment: production-mail", job_block(self.text, "mail-apply"))
        for job in ("hetzner-network-apply", "hetzner-estate-apply", DNS_APPLY, TENANTS_APPLY):
            self.assertNotEqual(
                environment_of(job_block(self.text, job)), "production-mail"
            )

    def test_dns_apply_is_the_only_job_in_production_dns(self):
        # The mirror of the production-mail test above: GitHub approves per
        # environment per run, so a DNS apply sharing an environment with any
        # other apply would be released by that apply's approval.
        self.assertEqual(
            self.text.count("environment: production-dns"),
            1,
            "production-dns must belong to the DNS apply alone",
        )
        self.assertEqual(environment_of(job_block(self.text, DNS_APPLY)), "production-dns")
        for job in all_jobs(self.text):
            if job != DNS_APPLY:
                with self.subTest(job=job):
                    self.assertNotEqual(
                        environment_of(job_block(self.text, job)), "production-dns"
                    )

    def test_dns_apply_environment_is_a_literal_never_an_expression(self):
        environment = environment_of(job_block(self.text, DNS_APPLY))
        self.assertNotIn("${{", environment)
        self.assertNotIn("production-free", environment)

    def test_dns_plan_job_shape(self):
        plan = job_block(self.text, DNS_PLAN)
        self.assertEqual(
            needs_of(plan),
            ["changes", "hetzner-typecheck", "scripts-tests", "pulumi-inventory-audit"],
        )
        self.assertEqual(
            and_operands(job_if(plan)),
            [
                "github.event_name == 'push'",
                "github.ref == 'refs/heads/main'",
                "needs.changes.outputs.hetzner_dns == 'true'",
            ],
        )
        # The DNS secrets are environment-level, as the mail plan's are: the
        # plan has the main-only, no-reviewer `dns-plan` environment, so it
        # reads them without an approval and a branch cannot read them at all.
        self.assertEqual(environment_of(plan), "dns-plan")
        self.assertIn("      has_changes: ${{ steps.noop.outputs.has_changes }}\n", plan)
        self.assertEqual(
            job_env_value(plan, "HCLOUD_TOKEN"), "${{ secrets.HCLOUD_TOKEN_DNS }}"
        )

    def test_dns_apply_has_its_own_concurrency_group_that_never_cancels(self):
        block = job_block(self.text, DNS_APPLY)
        self.assertIn("      group: pulumi-hetzner-dns-deploy\n", block)
        self.assertIn("      cancel-in-progress: false\n", block)

    def test_dns_apply_guards_run_in_order_before_pulumi_up(self):
        block = job_block(self.text, DNS_APPLY)
        names = [n for n, _ in step_blocks(block)]
        order = [
            GATE_NAME,
            "Verify the deploy secrets are present",
            "Preview the plan",
            "Refuse to apply a plan that destroys the DNS zone",
            "Apply",
        ]
        positions = [names.index(n) for n in order]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(positions[3] + 1, positions[4], "nothing may sit between the guard and Apply")
        guard = run_script(step(block, "Refuse to apply a plan that destroys the DNS zone"))
        self.assertIn("assert-no-hetzner-deletes.py --self-test", guard)
        self.assertIn("assert-no-hetzner-deletes.py --verify-coverage ..", guard)
        self.assertNotRegex(
            step(block, "Refuse to apply a plan that destroys the DNS zone"),
            r"^        if:",
            "the delete guard must not be skippable",
        )

    def test_dns_plan_runs_the_delete_guard_before_the_verdict_and_summary(self):
        names = [n for n, _ in step_blocks(job_block(self.text, DNS_PLAN))]
        order = [
            "Preview the plan",
            "Refuse a plan that destroys the DNS zone",
            "Decide whether the plan changes anything",
            "Write the plan to the job summary",
        ]
        positions = [names.index(n) for n in order]
        self.assertEqual(positions, sorted(positions))

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

    def test_the_tenants_gate_reads_production_and_accepts_either_rule(self):
        body = run_script(step(job_block(self.text, TENANTS_APPLY), GATE_NAME))
        self.assertIn('environments/production"', body)
        self.assertNotIn("production-free", body)
        self.assertIn("required_reviewers", body)
        self.assertIn("deployment_protection_rules", body)
        self.assertIn(
            "neither a required-reviewer rule nor an enabled custom deployment protection rule",
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
        self.dns = run_script(step(job_block(text, DNS_APPLY), GATE_NAME))
        self.tenants = run_script(step(job_block(text, TENANTS_APPLY), GATE_NAME))
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

    def test_tenants_accepts_a_reviewer_rule_or_an_enabled_app_rule_alone(self):
        self.stub.put("environment.json", environment_object(reviewers=True))
        self.stub.put("rules.json", self.rules())
        self.assertEqual(self.stub.run(self.tenants).returncode, 0)
        self.stub.put("environment.json", environment_object(reviewers=False))
        self.stub.put("rules.json", self.rules(True))
        result = self.stub.run(self.tenants)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_tenants_reads_production_whatever_the_apply_environment_variable_says(self):
        # The tenants apply is never routed: its gate reads the literal
        # `production`, so a stray APPLY_ENVIRONMENT cannot move it.
        self.stub.put("environment.json", environment_object(reviewers=True))
        self.stub.put("rules.json", self.rules())
        result = self.stub.run(self.tenants, APPLY_ENVIRONMENT="production-free")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.stub.calls()
        self.assertIn("GET repos/ORG/REPO/environments/production", calls)
        self.assertFalse(any("production-free" in c for c in calls), calls)

    def test_tenants_refuses_with_no_rule_a_disabled_rule_or_another_apps_rule(self):
        for rules in (self.rules(), self.rules(False), self.rules(True, app_id=1)):
            self.stub.put("environment.json", environment_object(reviewers=False))
            self.stub.put("rules.json", rules)
            result = self.stub.run(self.tenants)
            self.assertEqual(result.returncode, 1)
            self.assertIn("neither a required-reviewer rule", result.stderr)

    def test_tenants_fails_closed_when_the_environment_or_rules_cannot_be_read(self):
        self.assertNotEqual(self.stub.run(self.tenants).returncode, 0)
        self.stub.put("environment.json", environment_object(reviewers=False))
        self.assertEqual(self.stub.run(self.tenants).returncode, 1)

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

    def test_dns_accepts_a_required_reviewer_rule(self):
        self.stub.put("environment.json", environment_object(reviewers=True))
        result = self.stub.run(self.dns)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dns_reads_production_dns_and_never_production(self):
        self.stub.put("environment.json", environment_object(reviewers=True))
        self.assertEqual(self.stub.run(self.dns).returncode, 0)
        self.assertEqual(
            self.stub.calls(), ["GET repos/ORG/REPO/environments/production-dns"]
        )

    def test_dns_refuses_an_enabled_reviewer_app_rule_alone(self):
        # The network and estate gates accept this rule, and an approval of it
        # is not the owner's. The DNS gate must not: this is the pinned
        # difference between the two (see also GateShapeTests).
        self.stub.put("environment.json", environment_object(reviewers=False))
        self.stub.put("rules.json", self.rules(True))
        self.assertEqual(self.stub.run(self.prod).returncode, 0, "control: the network gate accepts it")
        self.stub.log.write_text("", encoding="utf-8")
        result = self.stub.run(self.dns)
        self.assertEqual(result.returncode, 1)
        self.assertIn("production-dns environment has no required-reviewer", result.stderr)
        self.assertFalse(
            any("deployment_protection_rules" in c for c in self.stub.calls())
        )

    def test_dns_refuses_with_no_rule_at_all(self):
        self.stub.put("environment.json", environment_object(reviewers=False))
        result = self.stub.run(self.dns)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no required-reviewer rule", result.stderr)

    def test_dns_refuses_when_the_environment_cannot_be_read(self):
        result = self.stub.run(self.dns)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("no required-reviewer rule", result.stderr)

    def test_dns_non_numeric_answer_with_a_zero_exit_counts_as_no_rule(self):
        (self.stub.dir / "environment.raw").write_text("x\n", encoding="utf-8")
        result = self.stub.run(self.dns)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("no required-reviewer rule", result.stderr)

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
        self.assertEqual(len(bodies), 5)
        self.assertEqual(len(set(bodies)), 1, "the five copies must not drift")
        self.assertIn("PLANS_DNS: ${{ needs.changes.outputs.hetzner_dns }}", bodies[0])
        self.assertIn('--dns "${PLANS_DNS}"', bodies[0])
        self.assertIn("PLANS_TENANTS: ${{ needs.changes.outputs.hetzner_tenants }}", bodies[0])
        self.assertIn('--tenants "${PLANS_TENANTS}"', bodies[0])

    def test_cancel_step_cannot_fail_the_plan(self):
        body = step(job_block(self.text, "mail-plan"), CANCEL_NAME)
        self.assertIn("continue-on-error: true", body)

    def test_actions_write_is_on_the_five_plan_jobs_only(self):
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

    def run_with(self, runs, jobs_by_run, plans=("true", "true", "true", "true", "true")):
        # A four-value tuple predates the tenants stack: it plans tenants.
        plans = (*plans, "true") if len(plans) == 4 else plans
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
            PLANS_DNS=plans[3],
            PLANS_TENANTS=plans[4],
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
    DNS = "Apply (hetzner dns, pulumi up)"
    TENANTS = "Apply (hetzner tenants, pulumi up)"

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
            plans=("true", "false", "false", "false"),
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
            [self.run_row(101)], {101: jobs}, plans=("false", "true", "false", "false")
        )
        self.assertEqual(kept, [])
        self.stub.log.write_text("", encoding="utf-8")
        cancelled = self.run_with(
            [self.run_row(101)], {101: jobs}, plans=("false", "true", "true", "false")
        )
        self.assertEqual(cancelled, ["POST repos/ORG/REPO/actions/runs/101/cancel"])

    def test_a_waiting_dns_apply_is_cancelled_only_when_this_push_planned_dns(self):
        jobs = [self.job(self.DNS, "waiting")]
        kept = self.run_with(
            [self.run_row(101)], {101: jobs}, plans=("true", "true", "true", "false")
        )
        self.assertEqual(kept, [])
        self.stub.log.write_text("", encoding="utf-8")
        cancelled = self.run_with(
            [self.run_row(101)], {101: jobs}, plans=("false", "false", "false", "true")
        )
        self.assertEqual(cancelled, ["POST repos/ORG/REPO/actions/runs/101/cancel"])

    def test_a_waiting_tenants_apply_is_cancelled_only_when_this_push_planned_tenants(self):
        jobs = [self.job(self.TENANTS, "waiting")]
        kept = self.run_with(
            [self.run_row(101)], {101: jobs}, plans=("true", "true", "true", "true", "false")
        )
        self.assertEqual(kept, [])
        self.stub.log.write_text("", encoding="utf-8")
        cancelled = self.run_with(
            [self.run_row(101)], {101: jobs}, plans=("false", "false", "false", "false", "true")
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
            PLANS_DNS="true",
            PLANS_TENANTS="true",
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
            PLANS_DNS="true",
            PLANS_TENANTS="true",
        )
        # The step itself goes red (it is continue-on-error, so the plan
        # still runs); the point is that nothing is cancelled on a bad read.
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([c for c in self.stub.calls() if c.startswith("POST ")], [])


PLAN_OF_APPLY = {
    "mail-apply": "mail-plan",
    "hetzner-network-apply": "hetzner-network-plan",
    "hetzner-estate-apply": "hetzner-estate-plan",
    DNS_APPLY: DNS_PLAN,
    TENANTS_APPLY: TENANTS_PLAN,
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
    match = re.search(r"^    needs:\s*\[([^\]]*)\]", job, re.M)
    if not match:
        return []
    return [n.strip() for n in match.group(1).split(",") if n.strip()]


class NoOpGateStructureTests(unittest.TestCase):
    def setUp(self):
        self.text = workflow_text()

    def test_the_gated_apply_jobs_are_the_five_known_ones(self):
        # A sixth gated apply must be added to APPLY_JOBS and PLAN_OF_APPLY
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

    def test_the_mail_and_dns_jobs_are_never_routed(self):
        for job in ("mail-plan", "mail-apply", DNS_PLAN, DNS_APPLY, TENANTS_PLAN, TENANTS_APPLY):
            with self.subTest(job=job):
                block = job_block(self.text, job)
                self.assertNotIn("production-free", block)
                self.assertNotIn("apply_environment", block)
                self.assertNotIn("spend-gate", block)

    def test_the_dns_plan_has_no_route_or_spend_steps(self):
        names = [n for n, _ in step_blocks(job_block(self.text, DNS_PLAN))]
        for absent in (ROUTE_NAME, READY_NAME, SPEND_NAME):
            self.assertNotIn(absent, names)

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


# ---------------------------------------------------------------------------
# The DNS apply's own environment, and the lint that keeps it that way.
#
# GitHub approves per environment per run: an approval given for the network
# apply releases every job waiting in the same environment of that run. A DNS
# apply in `production` would therefore be released by an approval the owner
# gave for a network change. `production-dns` is the DNS apply's alone, and
# its gate accepts a required-reviewer rule only, never the reviewer App's
# custom rule that `production` and `production-free` also accept.
# ---------------------------------------------------------------------------

ROUTED_ENVIRONMENT_NAMES = {"production", "production-free"}
ENVIRONMENT_NAME = re.compile(r"production(?:-[a-z]+)?")

# What each apply's gate step may contain, per job:
#   environment  the literal environment the gate reads, or None when the job
#                is routed and the gate reads ${APPLY_ENVIRONMENT}
#   custom_rule  whether the gate may read the reviewer App's custom rule
#   bare_eq_ok   whether a numeric `-eq` on an unsanitised count is tolerated
# The mail gate's bare `-eq` is grandfathered here and filed as tech debt; it
# is not tolerated anywhere else.
GATE_ALLOWANCES = {
    "mail-apply": {"environment": "production-mail", "custom_rule": False, "bare_eq_ok": True},
    DNS_APPLY: {"environment": "production-dns", "custom_rule": False, "bare_eq_ok": False},
    "hetzner-network-apply": {"environment": None, "custom_rule": True, "bare_eq_ok": False},
    "hetzner-estate-apply": {"environment": None, "custom_rule": True, "bare_eq_ok": False},
    TENANTS_APPLY: {"environment": "production", "custom_rule": True, "bare_eq_ok": False},
}


def apply_gate_violations(text: str, job: str, allowances: dict = GATE_ALLOWANCES) -> list[str]:
    """Lint one apply job's gate step against that job's own allowance and
    return human-readable violations (empty when the gate is as allowed)."""
    allowance = allowances.get(job)
    if allowance is None:
        return [f"{job}: no gate allowance is recorded for this job"]
    try:
        body = run_script(step(job_block(text, job), GATE_NAME))
    except AssertionError as error:
        return [f"{job}: {error}"]
    environment = allowance["environment"]
    if environment is None:
        reads, names = 'environments/${APPLY_ENVIRONMENT}"', ROUTED_ENVIRONMENT_NAMES
    else:
        reads, names = f'environments/{environment}"', {environment}
    found = []
    if reads not in body:
        found.append(f"{job}: the gate does not read {reads}")
    if "required_reviewers" not in body:
        found.append(f"{job}: the gate does not look for a required_reviewers rule")
    reads_rules = "deployment_protection_rules" in body
    pins_app = str(REVIEWER_APP_ID) in body
    if allowance["custom_rule"]:
        if not (reads_rules and pins_app):
            found.append(f"{job}: the gate should read the reviewer App's rule by integration id")
    elif reads_rules or pins_app:
        found.append(
            f"{job}: the gate reads the reviewer App's custom rule, which this job's "
            "allowance does not permit"
        )
    if "-eq" in body and "*[!0-9]*" not in body and not allowance["bare_eq_ok"]:
        found.append(f"{job}: the gate compares a count with -eq and never sanitises it")
    stray = sorted(set(ENVIRONMENT_NAME.findall(body)) - names)
    if stray:
        found.append(f"{job}: the gate names another environment: {', '.join(stray)}")
    return found


class _AnyOutput(dict):
    """A plan job's outputs that answer one fixed value for every key."""

    def __init__(self, value: str):
        super().__init__()
        self.value = value

    def get(self, key, default=""):
        return self.value


def environment_isolation_violations(text: str) -> list[str]:
    """`production-dns` is the literal environment of the DNS apply alone, and
    no other job's environment can resolve to it."""
    found = []
    holders = [j for j in all_jobs(text) if environment_of(job_block(text, j)) == "production-dns"]
    if holders != [DNS_APPLY]:
        found.append(f"production-dns must be the environment of {DNS_APPLY} alone; held by {holders}")
    if text.count("environment: production-dns") != 1:
        found.append("`environment: production-dns` must appear exactly once in ci.yml")
    own = environment_of(job_block(text, DNS_APPLY))
    if own is None or "${{" in own or own in ROUTED_ENVIRONMENT_NAMES:
        found.append(f"{DNS_APPLY}: the environment must be the literal production-dns, not {own!r}")
    for job in all_jobs(text):
        if job == DNS_APPLY:
            continue
        block = job_block(text, job)
        for line in re.findall(r"^\s*(?:environment|APPLY_ENVIRONMENT): .*$", block, re.M):
            if "production-dns" in line:
                found.append(f"{job}: names production-dns: {line.strip()}")
        expression = environment_of(block)
        if expression and expression.startswith("${{"):
            try:
                for published in ("production-free", "production-dns", "production", ""):
                    resolved = resolve_environment(expression, _AnyOutput(published))
                    if resolved == "production-dns":
                        found.append(f"{job}: its environment can resolve to production-dns")
            except AssertionError as error:
                found.append(f"{job}: {error}")
    return found


def plan_environment_violations(text: str) -> list[str]:
    """The DNS plan reads the zone-writing secrets from `dns-plan` (main only,
    no reviewer, as `mail-plan`), so: `dns-plan` is the literal environment of
    the DNS plan alone; the plan starts on a push to main only, which is what
    keeps the main-only policy from ever meeting a branch; the plan is never in
    the apply's environment; and no other job names the DNS secrets."""
    found = []
    own = environment_of(job_block(text, DNS_PLAN))
    if own != "dns-plan":
        found.append(f"{DNS_PLAN}: the environment must be the literal dns-plan, not {own!r}")
    holders = [j for j in all_jobs(text) if environment_of(job_block(text, j)) == "dns-plan"]
    if holders != [DNS_PLAN]:
        found.append(f"dns-plan must be the environment of {DNS_PLAN} alone; held by {holders}")
    if text.count("environment: dns-plan") != 1:
        found.append("`environment: dns-plan` must appear exactly once in ci.yml")
    operands = and_operands(job_if(job_block(text, DNS_PLAN)))
    for required in ("github.event_name == 'push'", "github.ref == 'refs/heads/main'"):
        if required not in operands:
            found.append(f"{DNS_PLAN}: the job must start only when {required}")
    for job in all_jobs(text):
        if job in (DNS_PLAN, DNS_APPLY):
            continue
        block = job_block(text, job)
        for secret in DNS_SECRETS:
            if secret in block:
                found.append(f"{job}: names the DNS secret {secret}")
    return found


class GateShapeTests(unittest.TestCase):
    """The per-job gate lint, run on the real ci.yml."""

    def setUp(self):
        self.text = workflow_text()

    def test_the_allowances_cover_every_apply_job_and_no_other(self):
        self.assertEqual(sorted(GATE_ALLOWANCES), sorted(APPLY_JOBS))

    def test_every_apply_gate_is_as_its_own_allowance_permits(self):
        for job in GATE_ALLOWANCES:
            with self.subTest(job=job):
                self.assertEqual(apply_gate_violations(self.text, job), [])

    def test_dns_gate_allows_a_required_reviewers_rule_only(self):
        # One of the two pins on the DNS-only strictness (the other is
        # GateBehaviourTests.test_dns_refuses_an_enabled_reviewer_app_rule_alone).
        self.assertEqual(apply_gate_violations(self.text, DNS_APPLY), [])
        gate = run_script(step(job_block(self.text, DNS_APPLY), GATE_NAME))
        self.assertNotIn("deployment_protection_rules", gate)
        self.assertNotIn(str(REVIEWER_APP_ID), gate)
        self.assertIn("required_reviewers", gate)

    def test_the_dns_allowance_is_the_strictest_row(self):
        row = GATE_ALLOWANCES[DNS_APPLY]
        self.assertEqual(
            row, {"environment": "production-dns", "custom_rule": False, "bare_eq_ok": False}
        )

    def test_the_allowance_is_per_job_not_global(self):
        # The mail gate's bare -eq passes under the mail row and is flagged
        # under any stricter row, so the exemption cannot spread to a new gate.
        self.assertEqual(apply_gate_violations(self.text, "mail-apply"), [])
        strict = {"mail-apply": dict(GATE_ALLOWANCES["mail-apply"], bare_eq_ok=False)}
        self.assertTrue(
            any("never sanitises" in v for v in apply_gate_violations(self.text, "mail-apply", strict))
        )
        # A routed gate judged by the DNS row (no App rule, a literal
        # environment) is flagged, so the rows really differ per job.
        routed_as_dns = {"hetzner-network-apply": GATE_ALLOWANCES[DNS_APPLY]}
        self.assertTrue(apply_gate_violations(self.text, "hetzner-network-apply", routed_as_dns))

    def test_the_isolation_lint_is_clean_on_the_real_workflow(self):
        self.assertEqual(environment_isolation_violations(self.text), [])

    def test_the_plan_environment_lint_is_clean_on_the_real_workflow(self):
        self.assertEqual(plan_environment_violations(self.text), [])


class DnsApplyIsolationTests(unittest.TestCase):
    """THE SABOTAGE TEST. Each case breaks one part of the mechanism that keeps
    an approval meant for another stack from releasing a DNS apply, on the real
    ci.yml text in memory, and must be flagged (red); the unmutated text must
    be clean (green)."""

    def setUp(self):
        self.text = workflow_text()

    @staticmethod
    def problems(text: str) -> list[str]:
        found = environment_isolation_violations(text) + plan_environment_violations(text)
        for job in GATE_ALLOWANCES:
            found += apply_gate_violations(text, job)
        return found

    @staticmethod
    def mutate(text: str, job: str, old: str, new: str) -> str:
        block = job_block(text, job)
        if old not in block:
            raise AssertionError(f"mutation target not found in {job}: {old!r}")
        if text.count(block) != 1:
            raise AssertionError(f"job block of {job} is not unique in ci.yml")
        return text.replace(block, block.replace(old, new, 1))

    def mutations(self) -> dict[str, str]:
        text = self.text
        dns = job_block(text, DNS_APPLY)
        network = job_block(text, "hetzner-network-apply")
        dns_gate = step(dns, GATE_NAME)
        network_gate = step(network, GATE_NAME)
        guard_line = """          case "${reviewers}" in '' | *[!0-9]*) reviewers=0 ;; esac\n"""
        return {
            "(1) the dns apply moves into the shared production environment": self.mutate(
                text, DNS_APPLY, "    environment: production-dns", "    environment: production"
            ),
            "(2) the dns gate is swapped for the network gate that accepts the App rule": self.mutate(
                text, DNS_APPLY, dns_gate, network_gate
            ),
            "(3) the dns gate loses its numeric sanitising guard": self.mutate(
                text, DNS_APPLY, guard_line, ""
            ),
            "(4) production-dns is also given to the network apply": self.mutate(
                text,
                "hetzner-network-apply",
                f"    environment: {environment_of(network)}",
                "    environment: production-dns",
            ),
            "(5) the dns apply is routed like the network apply": self.mutate(
                text,
                DNS_APPLY,
                "    environment: production-dns",
                f"    environment: {routed('hetzner-network-plan')}",
            ),
            "(6) the dns gate reads production, not production-dns": self.mutate(
                text, DNS_APPLY, "environments/production-dns", "environments/production"
            ),
            # The plan job's environment (the DNS secrets live there).
            "(7) the dns plan loses its environment": self.mutate(
                text, DNS_PLAN, "    environment: dns-plan\n", ""
            ),
            "(8) the dns plan moves into the apply's production-dns": self.mutate(
                text, DNS_PLAN, "    environment: dns-plan", "    environment: production-dns"
            ),
            "(9) the dns plan may start on a branch": self.mutate(
                text,
                DNS_PLAN,
                "github.event_name == 'push' && github.ref == 'refs/heads/main' &&\n",
                "github.event_name == 'push' &&\n",
            ),
            "(10) dns-plan is also given to the network plan": self.mutate(
                text,
                "hetzner-network-plan",
                "    runs-on: ubuntu-latest\n",
                "    runs-on: ubuntu-latest\n    environment: dns-plan\n",
            ),
            "(11) the network plan reads the DNS token": self.mutate(
                text,
                "hetzner-network-plan",
                "secrets.HCLOUD_TOKEN_ESTATE",
                "secrets.HCLOUD_TOKEN_DNS",
            ),
            "(12) the dns apply moves into dns-plan": self.mutate(
                text, DNS_APPLY, "    environment: production-dns", "    environment: dns-plan"
            ),
        }

    def test_sabotaged_workflows_are_flagged_and_the_real_one_is_clean(self):
        # GREEN: the real workflow is clean for every job.
        self.assertEqual(self.problems(self.text), [])
        # RED: every mutation is flagged.
        for name, mutated in self.mutations().items():
            with self.subTest(mutation=name):
                self.assertNotEqual(mutated, self.text, "the mutation changed nothing")
                self.assertTrue(self.problems(mutated), f"not flagged: {name}")

    def test_each_mutation_is_caught_by_the_lint_that_is_meant_to_catch_it(self):
        flagged_by = {
            "(1)": environment_isolation_violations,
            "(4)": environment_isolation_violations,
            "(5)": environment_isolation_violations,
            "(2)": lambda t: apply_gate_violations(t, DNS_APPLY),
            "(3)": lambda t: apply_gate_violations(t, DNS_APPLY),
            "(6)": lambda t: apply_gate_violations(t, DNS_APPLY),
            "(7)": plan_environment_violations,
            "(8)": plan_environment_violations,
            "(9)": plan_environment_violations,
            "(10)": plan_environment_violations,
            "(11)": plan_environment_violations,
            "(12)": plan_environment_violations,
        }
        for name, mutated in self.mutations().items():
            with self.subTest(mutation=name):
                self.assertTrue(flagged_by[name.split()[0]](mutated))


PUBLICPRESS_RUNBOOK = ROOT / "hetzner" / "dns" / "RUNBOOK-dns-publicpress-cutover.md"


def runbook_step(text: str, number: int) -> str:
    """One numbered owner step of the publicpress runbook: from its `### N.`
    heading to the next heading."""
    match = re.search(rf"^### {number}\. .*?(?=^##+ )", text, re.M | re.S)
    if not match:
        raise AssertionError(f"step {number} not found in {PUBLICPRESS_RUNBOOK.name}")
    return match.group(0)


def fenced_blocks(markdown: str) -> list[str]:
    return re.findall(r"^```[^\n]*\n(.*?)^```", markdown, re.M | re.S)


class DnsRunbookTests(unittest.TestCase):
    """The publicpress cutover is applied through CI, not by hand: the runbook
    steps that create the zone must say so, in terms of the environments ci.yml
    really has. A pin on the wording of a production-DNS procedure."""

    def setUp(self):
        ci = workflow_text()
        self.apply_env = environment_of(job_block(ci, DNS_APPLY))
        self.plan_env = environment_of(job_block(ci, DNS_PLAN))
        runbook = PUBLICPRESS_RUNBOOK.read_text(encoding="utf-8")
        self.step2 = runbook_step(runbook, 2)
        self.step3 = runbook_step(runbook, 3)

    def test_the_environment_names_are_the_real_ones(self):
        # Guards the pins below against a rename in ci.yml.
        self.assertEqual(self.apply_env, "production-dns")
        self.assertEqual(self.plan_env, "dns-plan")

    def test_steps_2_and_3_hold_no_hand_pulumi_command(self):
        for number, body in ((2, self.step2), (3, self.step3)):
            for block in fenced_blocks(body):
                with self.subTest(step=number):
                    self.assertNotRegex(block, r"pulumi\s+(up|preview)")

    def test_steps_2_and_3_name_both_environments(self):
        self.assertIn(f"`{self.plan_env}`", self.step2)
        self.assertIn(f"`{self.apply_env}`", self.step3)

    def test_step_3_approves_the_apply_environment_alone(self):
        self.assertIn(f"`{self.apply_env}` alone", self.step3)

    def test_step_2_says_a_non_create_is_a_stop_and_to_reject(self):
        self.assertIn("STOP", self.step2)
        self.assertIn("Reject", self.step2)
        self.assertIn("branchleft.co.uk", self.step2)


def filter_patterns(text: str, name: str) -> list[str]:
    match = re.search(rf"^            {name}:\n((?:              - '.*'\n)+)", text, re.M)
    if not match:
        raise AssertionError(f"filter {name!r} not found in the changes job")
    return re.findall(r"'(.*)'", match.group(1))


def filter_matches(patterns: list[str], path: str) -> bool:
    """dorny/paths-filter globbing, for the only two shapes the filters use:
    an exact path, and `dir/**`."""
    for pattern in patterns:
        if pattern.endswith("/**"):
            if path.startswith(pattern[:-2]):
                return True
        elif pattern == path:
            return True
    return False


RELATIVE_IMPORT = re.compile(r"""(?:from|import)\s+['"](\.{1,2}/[^'"]+)['"]""")


def import_graph(entry_files: list[str]) -> dict[str, str]:
    """Every repo-relative file reachable from the entries by relative import,
    mapped to its source text."""
    seen: dict[str, str] = {}
    queue = list(entry_files)
    while queue:
        rel = queue.pop()
        if rel in seen:
            continue
        source = (ROOT / rel).read_text(encoding="utf-8")
        seen[rel] = source
        for target in RELATIVE_IMPORT.findall(source):
            base = (ROOT / rel).parent / target
            for candidate in (base.with_suffix(".ts"), base / "index.ts"):
                if candidate.is_file():
                    queue.append(str(candidate.relative_to(ROOT)))
                    break
            else:
                raise AssertionError(f"{rel} imports {target!r}, which resolves to no .ts file")
    return seen


class DnsFilterTests(unittest.TestCase):
    """A wrong path filter skips a plan with no red anywhere, so it is pinned
    against the real import graph rather than trusted."""

    def setUp(self):
        self.text = workflow_text()
        self.patterns = filter_patterns(self.text, "hetzner_dns")

    def test_the_changes_job_publishes_the_dns_output(self):
        self.assertIn(
            "      hetzner_dns: ${{ steps.filter.outputs.hetzner_dns }}\n",
            job_block(self.text, "changes"),
        )

    def test_filter_covers_the_dns_program_import_graph(self):
        main = re.search(r"^main:\s*(\S+)", (ROOT / "hetzner/dns/Pulumi.yaml").read_text(), re.M)
        entry = str((ROOT / "hetzner/dns" / main.group(1)).resolve().relative_to(ROOT))
        graph = import_graph([entry, "hetzner/dns.ts", "hetzner/dnsZone.ts"])
        self.assertIn("hetzner/projectGuard.ts", graph, "the traced graph lost projectGuard.ts")
        zone_files = re.findall(r"file: '([^']+\.json)'", graph["hetzner/dnsZone.ts"])
        self.assertIn("zone.json", zone_files)
        files = sorted(graph) + [f"hetzner/dns/{name}" for name in zone_files]
        files += [
            "hetzner/dns/Pulumi.yaml",
            "hetzner/dns/Pulumi.production.yaml",
            "hetzner/dns/zonecheck.py",
            "hetzner/package.json",
            "hetzner/pnpm-lock.yaml",
            "hetzner/.nvmrc",
            "hetzner/tsconfig.json",
            "scripts/assert-no-hetzner-deletes.py",
            ".github/workflows/ci.yml",
        ]
        for rel in files:
            with self.subTest(file=rel):
                self.assertTrue((ROOT / rel).exists(), f"{rel} does not exist")
                self.assertTrue(filter_matches(self.patterns, rel), f"{rel} is not in the filter")

    def test_hetzner_host_is_in_the_filter_only_if_the_program_imports_it(self):
        graph = import_graph(["hetzner/dns.ts", "hetzner/dnsZone.ts"])
        imports_host = any("@branchleft/hetzner-host" in source for source in graph.values())
        self.assertEqual(filter_matches(self.patterns, "hetzner-host/host.ts"), imports_host)

    def test_the_filter_does_not_fire_on_the_other_stacks_alone(self):
        for rel in ("hetzner/estate.ts", "hetzner/network.ts", "hetzner/egress.ts", "mail/server.ts"):
            with self.subTest(file=rel):
                self.assertFalse(filter_matches(self.patterns, rel))

    def test_the_filter_helper_tells_a_listed_path_from_an_unlisted_one(self):
        # The matcher itself, so a filter test cannot pass on a matcher that
        # matches everything.
        self.assertTrue(filter_matches(["a/**"], "a/b/c.json"))
        self.assertFalse(filter_matches(["a/**"], "ab/c.json"))
        self.assertFalse(filter_matches(["a/b.ts"], "a/c.ts"))


class SplitOutWorkflowTests(unittest.TestCase):
    """A job moved out of ci.yml must not take a credential, an environment or a
    write grant with it, and ci.yml must not wait on it: ci.yml's own pins above
    read ci.yml alone, so these are the same pins over the files split out."""

    def test_a_split_out_file_holds_no_credential_environment_or_write_grant(self):
        for name in SPLIT_OUT_WORKFLOWS:
            text = (CI_YML.parent / name).read_text(encoding="utf-8")
            code = "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))
            with self.subTest(workflow=name):
                self.assertNotRegex(code, r"(?m)^\s*environment:")
                self.assertNotRegex(code, r"(?m)^\s*(actions|id-token|contents|packages|pull-requests|issues): write")
                self.assertNotIn("secrets.", code.replace("secrets.GITHUB_TOKEN", ""))
                self.assertNotIn("pulumi", code.lower())

    def test_no_job_of_ci_yml_waits_on_a_split_out_job(self):
        # A needs: on a job in another file is not a dependency GitHub can
        # resolve, and a plan that did not wait for one would lose its gate.
        split_out = [key for name in SPLIT_OUT_WORKFLOWS for key in job_names((CI_YML.parent / name).read_text(encoding="utf-8"))]
        self.assertTrue(split_out)
        text = workflow_text()
        for job in job_names(text):
            needs = re.search(r"^    needs:(.*?)(?=^    \S|\Z)", job_block(text, job), re.M | re.S)
            with self.subTest(job=job):
                for key in split_out:
                    self.assertNotIn(key, needs.group(1) if needs else "")

    def test_a_job_key_is_in_one_file_only(self):
        keys = [key for name in CHECK_WORKFLOWS for key in job_names((CI_YML.parent / name).read_text(encoding="utf-8"))]
        self.assertEqual(sorted(keys), sorted(set(keys)))


# ---------------------------------------------------------------------------
# The tenants stack's plan and apply, and the lint that keeps them gated.
#
# The tenants apply runs in the literal `production`, so the owner reads every
# tenants plan: it is never routed to `production-free`, which the reviewer App
# answers alone. It waits behind the estate apply because the tenants program
# reads the estate stack's outputs. Nothing but these two jobs may hold the
# tenants project's token, passphrase or salt.
# ---------------------------------------------------------------------------

# Every job the tenants plan must wait on: the network pair, because a failed
# network plan leaves both estate jobs skipped, and the estate pair, because the
# tenants program reads the estate stack's outputs.
TENANTS_PLAN_NEEDS = {
    "changes",
    "hetzner-typecheck",
    "hetzner-host-typecheck",
    "hetzner-provision-checks",
    "scripts-tests",
    "pulumi-inventory-audit",
    "hetzner-network-plan",
    "hetzner-network-apply",
    "hetzner-estate-plan",
    "hetzner-estate-apply",
}
# What a tenants job may read from `secrets`: the tenants project's own three,
# the state bucket's Object Storage key (one backend, shared with the estate)
# and the run's own token.
TENANTS_ALLOWED_SECRETS = {
    *TENANTS_SECRETS,
    "HETZNER_S3_ACCESS_KEY_ID",
    "HETZNER_S3_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
}
TENANTS_DELETE_GUARD_PLAN = "Refuse a plan that destroys the tenants estate"
TENANTS_DELETE_GUARD_APPLY = "Refuse to apply a plan that destroys the tenants estate"


def tenants_violations(text: str) -> list[str]:
    """Everything wrong with the tenants pair in `text`, as readable lines."""
    found: list[str] = []
    try:
        plan, apply = job_block(text, TENANTS_PLAN), job_block(text, TENANTS_APPLY)
    except AssertionError as error:
        return [str(error)]

    # Environments: the apply is the literal `production`, never routed.
    own = environment_of(apply)
    if own != "production":
        found.append(f"{TENANTS_APPLY}: the environment must be the literal production, not {own!r}")
    if environment_of(plan) is not None:
        found.append(f"{TENANTS_PLAN}: the plan must have no environment of its own")
    for name, block in ((TENANTS_PLAN, plan), (TENANTS_APPLY, apply)):
        for word in ("production-free", "apply_environment", "APPLY_ENVIRONMENT", "spend-gate"):
            if word in block:
                found.append(f"{name}: routes by the spend gate ({word} appears)")

    # Order: the apply waits for its own plan alone; the plan waits for the
    # network and estate pairs and does not start on a failed or cancelled run.
    if needs_of(apply) != [TENANTS_PLAN]:
        found.append(f"{TENANTS_APPLY}: must need {TENANTS_PLAN} alone, needs {needs_of(apply)}")
    missing = sorted(TENANTS_PLAN_NEEDS - set(needs_of(plan)))
    if missing:
        found.append(f"{TENANTS_PLAN}: does not wait for {', '.join(missing)}")
    plan_if = and_operands(job_if(plan))
    for required in (
        "github.event_name == 'push'",
        "github.ref == 'refs/heads/main'",
        "needs.changes.outputs.hetzner_tenants == 'true'",
        "!failure()",
        "!cancelled()",
    ):
        if required not in plan_if:
            found.append(f"{TENANTS_PLAN}: the condition lacks {required}")
    apply_if = and_operands(job_if(apply))
    for required in (
        "github.event_name == 'push'",
        "github.ref == 'refs/heads/main'",
        "needs.hetzner-tenants-plan.outputs.has_changes != 'false'",
    ):
        if required not in apply_if:
            found.append(f"{TENANTS_APPLY}: the condition lacks {required}")

    # Concurrency: one apply at a time, never cancelled part-way.
    if "      group: pulumi-hetzner-tenants-deploy\n" not in apply:
        found.append(f"{TENANTS_APPLY}: its own concurrency group is missing")
    if "      cancel-in-progress: false\n" not in apply:
        found.append(f"{TENANTS_APPLY}: the apply must never cancel in progress")

    # Guards: the gate first, the delete guard immediately before `Apply`, and
    # neither skippable.
    names = [n for n, _ in step_blocks(apply)]
    expected = [
        GATE_NAME,
        "Verify the deploy secrets are present",
        "Preview the plan",
        TENANTS_DELETE_GUARD_APPLY,
        "Apply",
    ]
    if any(n not in names for n in expected):
        found.append(f"{TENANTS_APPLY}: a guard step is missing: {[n for n in expected if n not in names]}")
    else:
        positions = [names.index(n) for n in expected]
        if names[0] != GATE_NAME:
            found.append(f"{TENANTS_APPLY}: the environment gate must be the first step")
        if positions != sorted(positions) or positions[3] + 1 != positions[4]:
            found.append(f"{TENANTS_APPLY}: guard steps are out of order or something sits before Apply")
        guard = step(apply, TENANTS_DELETE_GUARD_APPLY)
        if re.search(r"^        if:", guard, re.M) or "continue-on-error" in guard:
            found.append(f"{TENANTS_APPLY}: the delete guard must not be skippable")
        body = run_script(guard)
        for command in (
            "assert-no-hetzner-deletes.py --self-test",
            "assert-no-hetzner-deletes.py --verify-coverage ..",
            "assert-no-hetzner-deletes.py preview.json",
        ):
            if command not in body:
                found.append(f"{TENANTS_APPLY}: the delete guard does not run {command}")
        if "pulumi up --stack production --yes" not in step(apply, "Apply"):
            found.append(f"{TENANTS_APPLY}: Apply is not `pulumi up --stack production --yes`")
    plan_names = [n for n, _ in step_blocks(plan)]
    plan_order = [
        "Preview the plan",
        TENANTS_DELETE_GUARD_PLAN,
        "Decide whether the plan changes anything",
        "Write the plan to the job summary",
    ]
    if any(n not in plan_names for n in plan_order):
        found.append(f"{TENANTS_PLAN}: a step is missing: {[n for n in plan_order if n not in plan_names]}")
    else:
        positions = [plan_names.index(n) for n in plan_order]
        if positions != sorted(positions):
            found.append(f"{TENANTS_PLAN}: the delete guard must run before the verdict and summary")
        if re.search(r"^        if:", step(plan, TENANTS_DELETE_GUARD_PLAN), re.M):
            found.append(f"{TENANTS_PLAN}: the delete guard must not be skippable")

    # Credential scope: both jobs read the tenants secrets and nothing outside
    # the allowed set; no other job reads the tenants secrets.
    for name, block in ((TENANTS_PLAN, plan), (TENANTS_APPLY, apply)):
        read = set(re.findall(r"secrets\.([A-Z0-9_]+)", block))
        for secret in sorted(set(TENANTS_SECRETS) - read):
            found.append(f"{name}: does not read {secret}")
        for secret in sorted(read - TENANTS_ALLOWED_SECRETS):
            found.append(f"{name}: reads {secret}, outside the tenants credential scope")
    for job in all_jobs(text):
        if job in (TENANTS_PLAN, TENANTS_APPLY):
            continue
        for secret in TENANTS_SECRETS:
            if secret in job_block(text, job):
                found.append(f"{job}: names the tenants secret {secret}")

    # The gate itself, against the tenants allowance.
    found += apply_gate_violations(text, TENANTS_APPLY)
    return found


class TenantsStructureTests(unittest.TestCase):
    def setUp(self):
        self.text = workflow_text()

    def test_the_tenants_pair_is_clean_on_the_real_workflow(self):
        self.assertEqual(tenants_violations(self.text), [])

    def test_the_tenants_apply_is_the_literal_production(self):
        self.assertEqual(environment_of(job_block(self.text, TENANTS_APPLY)), "production")

    def test_the_shared_no_op_gate_check_covers_the_tenants_pair(self):
        # scripts-tests runs the shared action's contract check over every
        # plan/apply pair; a pair left out of its list is a pair never checked.
        check = step(job_block(self.text, "scripts-tests"), "Check the no-op gate contract")
        pairs = re.search(r"^          pairs: (.+)$", check, re.M).group(1).split()
        self.assertEqual(
            sorted(pairs), sorted(f"{PLAN_OF_APPLY[a]}:{a}" for a in APPLY_JOBS)
        )

    def test_the_tenants_plan_publishes_has_changes_and_no_route(self):
        plan = job_block(self.text, TENANTS_PLAN)
        self.assertIn("      has_changes: ${{ steps.noop.outputs.has_changes }}\n", plan)
        self.assertNotIn("apply_environment", plan)

    def test_the_tenants_plan_preview_runs_in_the_stack_directory(self):
        plan, apply = job_block(self.text, TENANTS_PLAN), job_block(self.text, TENANTS_APPLY)
        for block in (plan, apply):
            self.assertIn("      run:\n        working-directory: hetzner/tenants\n", block)
        self.assertIn("working-directory: hetzner/tenants\n", step(plan, "Decide whether the plan changes anything"))
        self.assertEqual(job_env_value(plan, "HCLOUD_TOKEN"), "${{ secrets.HCLOUD_TOKEN_TENANTS }}")
        self.assertEqual(job_env_value(apply, "HCLOUD_TOKEN"), "${{ secrets.HCLOUD_TOKEN_TENANTS }}")

    def test_the_tenants_jobs_install_from_the_shared_package_root(self):
        # The tenants project's `main` is ../tenants.ts, so its dependencies are
        # hetzner/'s, as the estate's are.
        for job in (TENANTS_PLAN, TENANTS_APPLY):
            with self.subTest(job=job):
                install = step(job_block(self.text, job), "Install dependencies")
                self.assertIn("working-directory: hetzner\n", install)
                self.assertIn("pnpm install --frozen-lockfile", install)

    def test_the_stack_pins_its_own_state_backend_and_main(self):
        yaml = (ROOT / "hetzner/tenants/Pulumi.yaml").read_text(encoding="utf-8")
        self.assertRegex(yaml, r"(?m)^main: \.\./tenants\.ts$")
        self.assertIn("name: branchleft-hetzner-tenants", yaml)
        # The state backend is pinned in the project file, so a workstation's
        # `pulumi login` cannot point CI's stack at another store.
        self.assertRegex(yaml, r"(?m)^backend:\n  url: ")


class TenantsFilterTests(unittest.TestCase):
    """A wrong path filter skips a plan with no red anywhere, so the tenants
    filter is pinned against the program's real import graph."""

    @staticmethod
    def missing(text: str) -> list[str]:
        patterns = filter_patterns(text, "hetzner_tenants")
        main = re.search(r"^main:\s*(\S+)", (ROOT / "hetzner/tenants/Pulumi.yaml").read_text(), re.M)
        entry = str((ROOT / "hetzner/tenants" / main.group(1)).resolve().relative_to(ROOT))
        graph = import_graph([entry])
        files = sorted(graph)
        files += [
            "hetzner/tenants/Pulumi.yaml",
            "hetzner/tenants/Pulumi.production.yaml",
            "hetzner/package.json",
            "hetzner/pnpm-lock.yaml",
            "hetzner/.nvmrc",
            "hetzner/tsconfig.json",
            "scripts/assert-no-hetzner-deletes.py",
            ".github/workflows/ci.yml",
        ]
        if any("@branchleft/hetzner-host" in source for source in graph.values()):
            files.append("hetzner-host/host.ts")
        # The program reads the estate stack's outputs by StackReference. That
        # is not an import, so the estate's own inputs are named by hand: an
        # estate change that moves edge1's address must re-plan this stack.
        if "branchleft-hetzner-estate" in graph[entry]:
            files += [
                "hetzner/estate.ts",
                "hetzner/estate/Pulumi.yaml",
                "hetzner/estate/Pulumi.production.yaml",
            ]
        return [rel for rel in files if not filter_matches(patterns, rel)]

    def setUp(self):
        self.text = workflow_text()

    def test_the_changes_job_publishes_the_tenants_output(self):
        self.assertIn(
            "      hetzner_tenants: ${{ steps.filter.outputs.hetzner_tenants }}\n",
            job_block(self.text, "changes"),
        )

    def test_the_filter_covers_the_tenants_import_graph_and_the_estate_reference(self):
        self.assertEqual(self.missing(self.text), [])

    def test_every_listed_path_exists(self):
        for pattern in filter_patterns(self.text, "hetzner_tenants"):
            with self.subTest(pattern=pattern):
                target = pattern[:-3] if pattern.endswith("/**") else pattern
                self.assertTrue((ROOT / target).exists(), f"{pattern} names nothing")

    def test_a_tenants_runbook_edit_plans_nothing(self):
        patterns = filter_patterns(self.text, "hetzner_tenants")
        for rel in (
            "hetzner/tenants/RUNBOOK-adopt-console-servers.md",
            "hetzner/tenants/RUNBOOK-edget-gateway-proof.md",
        ):
            with self.subTest(file=rel):
                self.assertFalse(filter_matches(patterns, rel))

    def test_the_other_stacks_filters_do_not_fire_on_a_tenants_only_change(self):
        for stack in ("mail", "hetzner_network", "hetzner_estate", "hetzner_dns"):
            patterns = filter_patterns(self.text, stack)
            for rel in ("hetzner/tenants.ts", "hetzner/tenants/Pulumi.production.yaml"):
                with self.subTest(stack=stack, file=rel):
                    self.assertFalse(filter_matches(patterns, rel))

    def test_the_mail_dns_and_other_stacks_alone_do_not_fire_the_tenants_filter(self):
        patterns = filter_patterns(self.text, "hetzner_tenants")
        for rel in ("hetzner/dns.ts", "hetzner/network.ts", "mail/server.ts", "hetzner/dns/zone.json"):
            with self.subTest(file=rel):
                self.assertFalse(filter_matches(patterns, rel))


class TenantsSabotageTests(unittest.TestCase):
    """THE SABOTAGE TEST for the tenants gate. Each case breaks one control that
    keeps a tenants apply behind the owner's approval, on the real ci.yml text in
    memory, and must be flagged (red); the unmutated text must be clean (green)."""

    def setUp(self):
        self.text = workflow_text()

    @staticmethod
    def problems(text: str) -> list[str]:
        found = tenants_violations(text)
        found += TenantsFilterTests.missing(text)
        found += environment_isolation_violations(text)
        found += plan_environment_violations(text)
        return found

    @staticmethod
    def mutate(text: str, job: str, old: str, new: str) -> str:
        block = job_block(text, job)
        if old not in block:
            raise AssertionError(f"mutation target not found in {job}: {old!r}")
        if text.count(block) != 1:
            raise AssertionError(f"job block of {job} is not unique in ci.yml")
        return text.replace(block, block.replace(old, new, 1))

    def mutations(self) -> dict[str, str]:
        text = self.text
        apply = job_block(text, TENANTS_APPLY)
        guard = step(apply, TENANTS_DELETE_GUARD_APPLY)
        gate = step(apply, GATE_NAME)
        network_gate = step(job_block(text, "hetzner-network-apply"), GATE_NAME)
        filter_line = "              - 'hetzner/egress.ts'\n"
        # The network filter lists egress.ts too, so cut it from the tenants
        # filter alone.
        tenants_start = text.index("            hetzner_tenants:\n")
        mutated_changes = (
            text[:tenants_start]
            + text[tenants_start:].replace(filter_line, "", 1)
        )
        return {
            "(1) the tenants apply is routed to the free environment": self.mutate(
                text,
                TENANTS_APPLY,
                "    environment: production\n",
                f"    environment: {routed(TENANTS_PLAN)}\n",
            ),
            "(2) the tenants apply names no environment": self.mutate(
                text, TENANTS_APPLY, "    environment: production\n", ""
            ),
            "(3) the tenants apply is moved into the mail environment": self.mutate(
                text, TENANTS_APPLY, "    environment: production\n", "    environment: production-mail\n"
            ),
            "(4) the tenants gate is swapped for one that reads another environment": self.mutate(
                text, TENANTS_APPLY, 'environments/production"', 'environments/production-dns"'
            ),
            "(5) the tenants gate loses its reviewer-rule lookup": self.mutate(
                text, TENANTS_APPLY, "select(.type == \"required_reviewers\")", "select(.type == \"wait_timer\")"
            ),
            "(6) the tenants gate loses its numeric sanitising": self.mutate(
                self.mutate(
                    text,
                    TENANTS_APPLY,
                    """          case "${reviewers}" in '' | *[!0-9]*) reviewers=0 ;; esac\n""",
                    "",
                ),
                TENANTS_APPLY,
                """          case "${custom}" in '' | *[!0-9]*) custom=0 ;; esac\n""",
                "",
            ),
            "(7) the tenants delete guard is skippable": self.mutate(
                text,
                TENANTS_APPLY,
                f"      - name: {TENANTS_DELETE_GUARD_APPLY}\n",
                f"      - name: {TENANTS_DELETE_GUARD_APPLY}\n        if: always()\n",
            ),
            "(8) the tenants delete guard no longer checks the plan": self.mutate(
                text,
                TENANTS_APPLY,
                "if ! python3 ../../scripts/assert-no-hetzner-deletes.py preview.json; then",
                "if ! true; then",
            ),
            "(9) the tenants delete guard is removed from the apply": self.mutate(
                text, TENANTS_APPLY, guard, ""
            ),
            "(10) the tenants apply no longer waits for its plan alone": self.mutate(
                text, TENANTS_APPLY, "    needs: [hetzner-tenants-plan]\n", "    needs: []\n"
            ),
            "(11) the tenants plan stops waiting for the estate apply": self.mutate(
                text, TENANTS_PLAN, "        hetzner-estate-apply,\n", ""
            ),
            "(12) the tenants plan stops waiting for the network apply": self.mutate(
                text, TENANTS_PLAN, "        hetzner-network-apply,\n", ""
            ),
            "(13) the tenants plan may start on a branch": self.mutate(
                text,
                TENANTS_PLAN,
                "github.event_name == 'push' && github.ref == 'refs/heads/main' &&\n",
                "github.event_name == 'push' &&\n",
            ),
            "(14) the tenants apply may start on a branch": self.mutate(
                text,
                TENANTS_APPLY,
                "github.event_name == 'push' && github.ref == 'refs/heads/main' &&\n",
                "github.event_name == 'push' &&\n",
            ),
            "(15) the tenants apply can be cancelled part-way": self.mutate(
                text, TENANTS_APPLY, "      cancel-in-progress: false\n", "      cancel-in-progress: true\n"
            ),
            "(16) the tenants apply shares the estate's concurrency group": self.mutate(
                text,
                TENANTS_APPLY,
                "      group: pulumi-hetzner-tenants-deploy\n",
                "      group: pulumi-hetzner-estate-deploy\n",
            ),
            "(17) the tenants plan reads the estate token": self.mutate(
                text, TENANTS_PLAN, "secrets.HCLOUD_TOKEN_TENANTS", "secrets.HCLOUD_TOKEN_ESTATE"
            ),
            "(18) the estate plan reads the tenants token": self.mutate(
                text, "hetzner-estate-plan", "secrets.HCLOUD_TOKEN_ESTATE", "secrets.HCLOUD_TOKEN_TENANTS"
            ),
            "(19) the tenants apply is run behind a spend-gate route": self.mutate(
                text,
                TENANTS_APPLY,
                "    environment: production\n",
                "    environment: production\n    # routed by spend-gate\n",
            ),
            "(20) the tenants filter stops listing egress.ts": mutated_changes,
        }

    def test_the_real_workflow_is_clean_and_every_sabotage_is_flagged(self):
        # GREEN: the real workflow is clean.
        self.assertEqual(self.problems(self.text), [])
        # RED: every mutation is flagged.
        for name, mutated in self.mutations().items():
            with self.subTest(mutation=name):
                self.assertNotEqual(mutated, self.text, "the mutation changed nothing")
                self.assertTrue(self.problems(mutated), f"not flagged: {name}")

    def test_the_gate_sabotage_is_caught_by_the_gate_lint(self):
        mutations = self.mutations()
        for name in (
            "(4) the tenants gate is swapped for one that reads another environment",
            "(5) the tenants gate loses its reviewer-rule lookup",
            "(6) the tenants gate loses its numeric sanitising",
        ):
            with self.subTest(mutation=name):
                self.assertTrue(apply_gate_violations(mutations[name], TENANTS_APPLY))

    def test_the_network_gate_is_not_the_tenants_gate(self):
        # The tenants gate reads the literal environment: the routed gate, which
        # reads ${APPLY_ENVIRONMENT}, is flagged under the tenants allowance.
        routed_gate = step(job_block(self.text, "hetzner-network-apply"), GATE_NAME)
        swapped = self.mutate(self.text, TENANTS_APPLY, step(job_block(self.text, TENANTS_APPLY), GATE_NAME), routed_gate)
        self.assertTrue(apply_gate_violations(swapped, TENANTS_APPLY))


if __name__ == "__main__":
    unittest.main()
