#!/usr/bin/env python3
"""Pin tests for .github/workflows/tenants-state-rewrap.yml, read as parsed YAML.

Narrative: scripts/tenants_state_rewrap.md.
"""

from __future__ import annotations

import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "tenants-state-rewrap.yml"
STEP_ENV_ONLY = ("PULUMI_PASSPHRASE_HETZNER_TENANTS", "HCLOUD_TOKEN_TENANTS")
GROUP = "pulumi-hetzner-tenants-deploy"
SHA_PIN = re.compile(r"^[\w./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$")

Mapping = dict[str, object]


def load() -> Mapping:
    """The workflow, parsed. YAML 1.1 reads the bare key `on` as `True`; it is renamed back."""
    parsed = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)  # noqa: S101
    return {("on" if key is True else str(key)): value for key, value in parsed.items()}


def jobs(doc: Mapping) -> dict[str, Mapping]:
    found = doc["jobs"]
    assert isinstance(found, dict)  # noqa: S101
    return found


def job_named(name: str) -> Mapping:
    return jobs(load())[name]


def steps_of(job: Mapping) -> list[Mapping]:
    found = job["steps"]
    assert isinstance(found, list)  # noqa: S101
    return found


def step_named(job: Mapping, prefix: str) -> Mapping:
    matches = [s for s in steps_of(job) if str(s.get("name", "")).startswith(prefix)]
    assert len(matches) == 1, prefix  # noqa: S101
    return matches[0]


def step_index(job: Mapping, prefix: str) -> int:
    return steps_of(job).index(step_named(job, prefix))


class TriggerTests(unittest.TestCase):
    def test_it_starts_only_by_hand(self) -> None:
        doc = load()
        triggers = doc["on"]
        assert isinstance(triggers, dict)  # noqa: S101
        self.assertEqual(list(triggers), ["workflow_dispatch"])

    def test_drop_reproducible_is_a_boolean_input_that_defaults_to_false(self) -> None:
        triggers = load()["on"]
        assert isinstance(triggers, dict)  # noqa: S101
        inputs = triggers["workflow_dispatch"]["inputs"]
        self.assertEqual(list(inputs), ["drop_reproducible"])
        self.assertEqual(inputs["drop_reproducible"]["type"], "boolean")
        self.assertIs(inputs["drop_reproducible"]["default"], False)
        self.assertIs(inputs["drop_reproducible"]["required"], False)

    def test_the_flag_reaches_inspect_and_rewrap_only_through_the_input_and_never_restore(
        self,
    ) -> None:
        for job_name, step_prefix in (("inspect", "Count"), ("rewrap", "Re-key the state")):
            with self.subTest(job=job_name):
                step = step_named(job_named(job_name), step_prefix)
                env = step["env"]
                assert isinstance(env, dict)  # noqa: S101
                self.assertEqual(env["DROP_REPRODUCIBLE"], "${{ inputs.drop_reproducible }}")
                run = str(step["run"])
                self.assertIn('if [ "${DROP_REPRODUCIBLE}" = "true" ]; then', run)
                self.assertIn("args+=(--drop-reproducible)", run)
                self.assertEqual(run.count("--drop-reproducible"), 1)
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(text.count("--drop-reproducible"), 2)
        restore = step_named(job_named("rewrap"), "Put the aside copy back")
        self.assertNotIn("drop", yaml.safe_dump(restore).lower())

    def test_there_are_two_jobs_and_both_run_only_on_main(self) -> None:
        found = jobs(load())
        self.assertEqual(sorted(found), ["inspect", "rewrap"])
        for name, job in found.items():
            assert isinstance(job, dict)  # noqa: S101
            self.assertEqual(job["if"], "github.ref == 'refs/heads/main'", name)

    def test_the_default_token_is_read_only(self) -> None:
        self.assertEqual(load()["permissions"], {"contents": "read"})


class InspectTests(unittest.TestCase):
    def test_it_has_no_environment(self) -> None:
        self.assertNotIn("environment", job_named("inspect"))

    def test_it_reads_the_state_bucket_and_nothing_that_changes_anything(self) -> None:
        text = yaml.safe_dump(job_named("inspect"))
        for name in STEP_ENV_ONLY:
            self.assertNotIn(name, text)
        self.assertIn("HETZNER_S3_ACCESS_KEY_ID", text)

    def test_it_runs_the_read_only_command_and_never_the_others(self) -> None:
        text = "\n".join(str(s.get("run", "")) for s in steps_of(job_named("inspect")))
        self.assertIn("tenants_state_rewrap.py inspect", text)
        self.assertNotIn("rewrap --", text)
        self.assertNotIn("restore", text)


class RewrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.job = job_named("rewrap")

    def test_it_needs_the_inspection_and_waits_in_production(self) -> None:
        self.assertEqual(self.job["needs"], ["inspect"])
        self.assertEqual(self.job["environment"], "production")

    def test_the_gate_check_comes_before_checkout_and_before_any_secret(self) -> None:
        first = steps_of(self.job)[0]
        self.assertTrue(
            str(first["name"]).startswith("Refuse to run through an ungated environment")
        )
        self.assertNotIn("secrets.", yaml.safe_dump(first).replace("github.token", ""))

    def test_the_two_jobs_share_the_tenants_concurrency_group_and_never_cancel(self) -> None:
        for name, job in jobs(load()).items():
            with self.subTest(job=name):
                self.assertEqual(job["concurrency"], {"group": GROUP, "cancel-in-progress": False})

    def test_no_secret_is_set_at_job_level(self) -> None:
        self.assertNotIn("env", self.job)
        self.assertNotIn("env", load())

    def test_the_self_tests_run_with_no_secret_in_scope_and_a_skipped_real_test_fails(self) -> None:
        for prefix in ("Self-test the tool", "Self-test the delete guard"):
            self.assertNotIn("secrets.", yaml.safe_dump(step_named(self.job, prefix)))
        self.assertEqual(
            step_named(self.job, "Self-test the tool")["env"], {"REWRAP_REQUIRE_PULUMI": "1"}
        )

    def test_the_steps_run_in_the_order_the_narrative_gives(self) -> None:
        order = [
            "Refuse to run through an ungated environment",
            "Checkout",
            "Install Pulumi CLI",
            "Self-test the tool",
            "Self-test the delete guard",
            "Verify the secrets are present",
            "Re-key the state",
            "Put the aside copy back",
        ]
        indexes = [step_index(self.job, prefix) for prefix in order]
        self.assertEqual(indexes, sorted(indexes))

    def test_the_rewrap_step_is_given_the_delete_guard_and_the_new_passphrase(self) -> None:
        rewrap = step_named(self.job, "Re-key the state")
        self.assertEqual(rewrap["id"], "rewrap")
        self.assertIn("--delete-guard scripts/assert-no-hetzner-deletes.py", str(rewrap["run"]))
        env = rewrap["env"]
        assert isinstance(env, dict)  # noqa: S101
        self.assertEqual(
            env["PULUMI_CONFIG_PASSPHRASE"], "${{ secrets.PULUMI_PASSPHRASE_HETZNER_TENANTS }}"
        )
        self.assertEqual(env["HCLOUD_TOKEN"], "${{ secrets.HCLOUD_TOKEN_TENANTS }}")
        self.assertNotIn("SALT", yaml.safe_dump(self.job))

    def test_the_restore_step_runs_on_any_outcome_but_success_and_holds_only_the_bucket_key(
        self,
    ) -> None:
        restore = step_named(self.job, "Put the aside copy back")
        self.assertEqual(restore["if"], "always() && steps.rewrap.outcome != 'success'")
        text = yaml.safe_dump(restore)
        for name in STEP_ENV_ONLY:
            self.assertNotIn(name, text)
        self.assertIn("tenants_state_rewrap.py restore", str(restore["run"]))


class WholeFileTests(unittest.TestCase):
    def test_every_action_is_pinned_to_a_sha_with_a_version_comment(self) -> None:
        for line in WORKFLOW.read_text(encoding="utf-8").splitlines():
            stripped = line.strip().removeprefix("- ")
            if stripped.startswith("uses:"):
                self.assertRegex(stripped.removeprefix("uses:").strip(), SHA_PIN)

    def test_the_pins_are_the_ones_ci_yml_already_uses(self) -> None:
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for line in WORKFLOW.read_text(encoding="utf-8").splitlines():
            stripped = line.strip().removeprefix("- ")
            if stripped.startswith("uses:") and not stripped.startswith("uses: ./"):
                pin = stripped.removeprefix("uses:").strip().split(" #")[0]
                if "setup-python" in pin or "pulumi/actions" in pin or "checkout" in pin:
                    self.assertIn(pin, ci)

    def test_no_expression_is_expanded_inside_a_run_body(self) -> None:
        for name, job in jobs(load()).items():
            for step in steps_of(job):
                self.assertNotIn("${{", str(step.get("run", "")), (name, step.get("name")))

    def test_no_state_bucket_url_is_named_here(self) -> None:
        self.assertNotIn("s3://", WORKFLOW.read_text(encoding="utf-8"))

    def test_nothing_in_it_can_apply_or_delete(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for forbidden in (" pulumi up", "pulumi destroy", "aws s3 rm", "--show-" + "secrets"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
