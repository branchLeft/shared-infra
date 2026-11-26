#!/usr/bin/env python3
"""Pin tests for .github/workflows/tenants-preview.yml, read as parsed YAML.

The workflow is the manual way to plan and apply the tenants stack. These tests hold that
it starts only by `workflow_dispatch`, that neither job can run off main, that the apply
waits in `production` behind the ungated-environment check, and that every step is the
step ci.yml's own tenants jobs run.
"""

from __future__ import annotations

import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
PREVIEW = WORKFLOWS / "tenants-preview.yml"
CI = WORKFLOWS / "ci.yml"
GROUP = "pulumi-hetzner-tenants-deploy"
MAIN_ONLY = "github.ref == 'refs/heads/main'"
# The steps ci.yml's plan job has that a dispatch has no use for: it cancels older runs that
# wait on a push's approvals, and a dispatch is never one of those runs.
CI_ONLY_PLAN_STEPS = ("Cancel older runs that are still waiting for approval",)

Mapping = dict[str, object]


def load(path: pathlib.Path) -> Mapping:
    """The workflow, parsed. YAML 1.1 reads the bare key `on` as `True`; it is renamed back."""
    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)  # noqa: S101
    return {("on" if key is True else str(key)): value for key, value in parsed.items()}


def job(path: pathlib.Path, name: str) -> Mapping:
    found = load(path)["jobs"]
    assert isinstance(found, dict)  # noqa: S101
    return found[name]


def steps(found: Mapping) -> list[Mapping]:
    listed = found["steps"]
    assert isinstance(listed, list)  # noqa: S101
    return listed


def top_level_and_operands(condition: str) -> list[str]:
    """The `&&` operands of a condition with no parentheses or quoted `&&` in it."""
    return [part.strip() for part in re.split(r"&&", " ".join(condition.split()))]


class TriggerTests(unittest.TestCase):
    def test_it_starts_only_by_hand(self) -> None:
        triggers = load(PREVIEW)["on"]
        assert isinstance(triggers, dict)  # noqa: S101
        self.assertEqual(list(triggers), ["workflow_dispatch"])

    def test_the_default_token_is_read_only(self) -> None:
        self.assertEqual(load(PREVIEW)["permissions"], {"contents": "read", "packages": "read"})

    def test_ci_yml_gained_no_manual_trigger(self) -> None:
        # A dispatch of ci.yml would run every plan job's checks beside the apply, and the
        # no-op gate check refuses an `||` in their conditions. The trigger lives here.
        triggers = load(CI)["on"]
        assert isinstance(triggers, dict)  # noqa: S101
        self.assertEqual(sorted(triggers), ["merge_group", "pull_request", "push"])


class MainOnlyGuardTests(unittest.TestCase):
    def test_both_jobs_are_guarded_to_main(self) -> None:
        for name in ("plan", "apply"):
            with self.subTest(job=name):
                condition = str(job(PREVIEW, name)["if"])
                self.assertNotIn("||", condition)
                self.assertIn(MAIN_ONLY, top_level_and_operands(condition))

    def test_the_plan_is_guarded_to_main_alone(self) -> None:
        self.assertEqual(job(PREVIEW, "plan")["if"], MAIN_ONLY)

    def test_the_apply_needs_the_plan_and_only_the_plan(self) -> None:
        self.assertEqual(job(PREVIEW, "apply")["needs"], ["plan"])

    def test_the_apply_skips_only_on_an_explicit_no_change_verdict(self) -> None:
        operands = top_level_and_operands(str(job(PREVIEW, "apply")["if"]))
        self.assertEqual(
            sorted(operands),
            sorted([MAIN_ONLY, "needs.plan.outputs.has_changes != 'false'"]),
        )

    def test_no_job_condition_names_a_status_function(self) -> None:
        # always(), failure() and cancelled() would run the apply when the plan was skipped.
        for name in ("plan", "apply"):
            with self.subTest(job=name):
                condition = str(job(PREVIEW, name)["if"])
                for function in ("always()", "failure()", "cancelled()"):
                    self.assertNotIn(function, condition)

    def test_there_are_exactly_two_jobs(self) -> None:
        found = load(PREVIEW)["jobs"]
        assert isinstance(found, dict)  # noqa: S101
        self.assertEqual(sorted(found), ["apply", "plan"])


class ApplyGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.apply = job(PREVIEW, "apply")

    def test_the_apply_waits_in_the_literal_production_environment(self) -> None:
        self.assertEqual(self.apply["environment"], "production")

    def test_the_plan_names_no_environment(self) -> None:
        self.assertNotIn("environment", job(PREVIEW, "plan"))

    def test_the_apply_shares_the_tenants_group_and_never_cancels(self) -> None:
        self.assertEqual(self.apply["concurrency"], {"group": GROUP, "cancel-in-progress": False})

    def test_the_ungated_environment_check_is_the_first_step_and_reads_no_secret(self) -> None:
        first = steps(self.apply)[0]
        self.assertEqual(first["name"], "Refuse to apply through an ungated environment")
        self.assertNotIn("secrets.", yaml.safe_dump(first).replace("github.token", ""))


class TwinTests(unittest.TestCase):
    """Every step is the step ci.yml's own tenants job runs, so the two cannot drift."""

    def test_the_plan_steps_are_ci_ymls_less_the_cancel_step(self) -> None:
        ci_steps = [
            s for s in steps(job(CI, "hetzner-tenants-plan")) if s.get("name") not in CI_ONLY_PLAN_STEPS
        ]
        self.assertEqual(steps(job(PREVIEW, "plan")), ci_steps)

    def test_the_apply_steps_are_ci_yml_s(self) -> None:
        self.assertEqual(steps(job(PREVIEW, "apply")), steps(job(CI, "hetzner-tenants-apply")))

    def test_the_jobs_carry_ci_yml_s_credentials_and_working_directory(self) -> None:
        for mine, theirs in (("plan", "hetzner-tenants-plan"), ("apply", "hetzner-tenants-apply")):
            for key in ("env", "defaults", "timeout-minutes", "runs-on"):
                with self.subTest(job=mine, key=key):
                    self.assertEqual(job(PREVIEW, mine)[key], job(CI, theirs)[key])

    def test_the_plan_publishes_ci_yml_s_has_changes_output(self) -> None:
        self.assertEqual(
            job(PREVIEW, "plan")["outputs"], job(CI, "hetzner-tenants-plan")["outputs"]
        )


if __name__ == "__main__":
    unittest.main()
