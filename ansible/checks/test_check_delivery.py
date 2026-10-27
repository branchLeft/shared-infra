"""Tests for the check of the Ansible delivery caller and of its environment.

The caller tests start from the committed workflow and weaken one line at a time, so a
check that has gone blind to a weakening fails here and not in a review. The environment
tests use answers shaped like the live GitHub responses for the existing environments.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

import check_delivery
from check_pins import load_yaml
from test_ci_watched_paths import parse_watched

ROOT = check_delivery.REPO_ROOT
WORKFLOWS = ROOT / ".github" / "workflows"
GOOD_TAG = "branchLeft/github-workflows/.github/workflows/ansible-gated-apply.yml@v1.0.11"


def mutable(value: object) -> dict[str, object]:
    """Return ``value`` itself, not a copy, when it is a mapping.

    Raises:
        TypeError: ``value`` is not a mapping.
    """
    if not isinstance(value, dict):
        raise TypeError(type(value).__name__)
    return value


def committed() -> dict[str, object]:
    """Return a fresh copy of the caller as committed.

    Raises:
        OSError: the caller cannot be read as YAML.
    """
    document, problem = load_yaml(ROOT / check_delivery.CALLER)
    if problem is not None:
        raise OSError(problem)
    return copy.deepcopy(mutable(document))


def job_of(document: dict[str, object]) -> dict[str, object]:
    """Return the delivery job of ``document``."""
    return mutable(mutable(document["jobs"])["delivery"])


def proof_of(document: dict[str, object]) -> dict[str, object]:
    """Return the queue-proof job of ``document``."""
    return mutable(mutable(document["jobs"])[check_delivery.PROOF_JOB])


def steps(document: dict[str, object]) -> list[object]:
    """Return the step list of the queue-proof job, itself and not a copy.

    Raises:
        TypeError: the steps are not a list.
    """
    listed = proof_of(document)["steps"]
    if not isinstance(listed, list):
        raise TypeError(type(listed).__name__)
    return listed


def step_of(document: dict[str, object], index: int) -> dict[str, object]:
    """Return step ``index`` of the queue-proof job."""
    return mutable(steps(document)[index])


def section(job: dict[str, object], key: str) -> dict[str, object]:
    """Return the ``with`` or ``secrets`` mapping of ``job``."""
    return mutable(job[key])


CHOSEN = (
    "${{ needs.plan.outputs.apply_environment == 'production-free' "
    "&& 'production-free' || 'production' }}"
)

# Each of these is an expression C4 must not read, and each is one change away from CHOSEN.
UNREADABLE_EXPRESSIONS = {
    "a different operator in the test": (
        "${{ needs.plan.outputs.e != 'production-free' && 'production-free' || 'production' }}"
    ),
    "the operators swapped": (
        "${{ needs.plan.outputs.e == 'production-free' || 'production-free' && 'production' }}"
    ),
    "a non-literal second branch": (
        "${{ needs.plan.outputs.e == 'production-free' && 'production-free' "
        "|| needs.plan.outputs.f }}"
    ),
    "a non-literal first branch": (
        "${{ needs.plan.outputs.e == 'production-free' && github.ref_name || 'production' }}"
    ),
    "a third branch": (
        "${{ needs.plan.outputs.e == 'production-free' && 'production-free' || 'production' "
        "|| 'staging' }}"
    ),
    "a result that differs from the literal tested": (
        "${{ needs.plan.outputs.e == 'production-free' && 'production' || 'production-free' }}"
    ),
    "the github context in the test": (
        "${{ github.ref_name == 'production-free' && 'production-free' || 'production' }}"
    ),
    "the inputs context in the test": (
        "${{ inputs.target == 'production-free' && 'production-free' || 'production' }}"
    ),
    "the vars context in the test": (
        "${{ vars.TARGET == 'production-free' && 'production-free' || 'production' }}"
    ),
    "a need that is not an output": (
        "${{ needs.plan.result == 'production-free' && 'production-free' || 'production' }}"
    ),
    "an output compared with another output": (
        "${{ needs.plan.outputs.e == needs.plan.outputs.f && 'production-free' || 'production' }}"
    ),
    "string concatenation": "${{ needs.plan.outputs.e }}-free",
    "a prefix before the expression": (
        "prod-${{ needs.plan.outputs.e == 'production-free' && 'production-free' || 'production' }}"
    ),
    "a second expression after it": (
        "${{ needs.plan.outputs.e == 'production-free' && 'production-free' || 'production' }}"
        "${{ matrix.target }}"
    ),
    "format()": "${{ format('{0}-free', needs.plan.outputs.e) }}",
    "contains()": (
        "${{ contains(needs.plan.outputs.e, 'free') && 'production-free' || 'production' }}"
    ),
    "a nested expression": (
        "${{ needs.plan.outputs.e == '${{ inputs.t }}' && '${{ inputs.t }}' || 'production' }}"
    ),
    "an empty literal": "${{ needs.plan.outputs.e == '' && '' || 'production' }}",
    "a literal with a space": (
        "${{ needs.plan.outputs.e == 'production free' && 'production free' || 'production' }}"
    ),
    "a double-quoted literal": (
        '${{ needs.plan.outputs.e == "production-free" && "production-free" || "production" }}'
    ),
    "a bare output": "${{ needs.plan.outputs.e }}",
    "a newline inside the expression": (
        "${{ needs.plan.outputs.e ==\n'production-free' && 'production-free' || 'production' }}"
    ),
    "a newline before the closing braces": (
        "${{ needs.plan.outputs.e == 'production-free' && 'production-free' || 'production'\n}}"
    ),
}


class CallerTests(unittest.TestCase):
    """The caller as committed passes, and each weakening of it is named."""

    def setUp(self) -> None:
        self.others, problems = check_delivery.environments_used(
            WORKFLOWS, Path(check_delivery.CALLER).name
        )
        self.assertEqual([], problems)

    def weakened(self, change: Callable[[dict[str, object]], None]) -> list[str]:
        document = committed()
        change(document)
        return check_delivery.caller_findings(document, self.others)

    def assert_names(self, findings: list[str], mechanism: str) -> None:
        self.assertTrue(
            any(mechanism in finding for finding in findings),
            f"no finding names {mechanism!r}: {findings}",
        )

    def test_the_caller_as_committed_has_no_finding(self) -> None:
        self.assertEqual([], check_delivery.check_caller(ROOT))

    def test_the_other_environments_are_read_from_the_other_workflows(self) -> None:
        self.assertIn("production", self.others)
        self.assertNotIn(check_delivery.ENVIRONMENT, self.others)

    def test_a_pull_request_trigger_is_named(self) -> None:
        def add_event(document: dict[str, object]) -> None:
            mutable(document["on"])["pull_request"] = None

        self.assert_names(self.weakened(add_event), "on has pull_request")

    def test_other_triggers_are_named(self) -> None:
        for event in ("workflow_dispatch", "schedule", "merge_group", "release"):

            def add_event(document: dict[str, object], event: str = event) -> None:
                mutable(document["on"])[event] = None

            self.assert_names(self.weakened(add_event), f"on has {event}")

    def test_a_filter_or_a_wider_push_is_named(self) -> None:
        pushes: list[object] = [
            {"branches": ["main"], "paths": ["ansible/**"]},
            {"branches": ["main"], "paths-ignore": ["docs/**"]},
            {"branches": ["main", "release"]},
            {"branches": ["main"], "tags": ["v*"]},
            {"branches": "main"},
            None,
        ]
        for push in pushes:

            def set_push(document: dict[str, object], push: object = push) -> None:
                document["on"] = {"push": push}

            self.assert_names(self.weakened(set_push), "on.push must be exactly")

    def test_only_an_exact_tag_passes(self) -> None:
        workflow = "branchLeft/github-workflows/.github/workflows/ansible-gated-apply.yml"
        refused = ("@main", "@v1", "@v1.0", "@" + "a" * 40, "@v1.0.11-rc1", "@v1.0.11\n", "")
        for ref in refused:

            def set_uses(document: dict[str, object], ref: str = ref) -> None:
                job_of(document)["uses"] = workflow + ref

            self.assert_names(self.weakened(set_uses), "exact tag")
        for ref in ("@v1.0.12", "@v2.3.4"):

            def set_good(document: dict[str, object], ref: str = ref) -> None:
                job_of(document)["uses"] = workflow + ref

            self.assertEqual([], self.weakened(set_good))

    def test_another_workflow_or_repository_is_named(self) -> None:
        for uses in (
            "branchLeft/github-workflows/.github/workflows/docs-lint.yml@v1.0.11",
            "someone/github-workflows/.github/workflows/ansible-gated-apply.yml@v1.0.11",
            "./.github/workflows/ansible.yml",
        ):

            def set_uses(document: dict[str, object], uses: str = uses) -> None:
                job_of(document)["uses"] = uses

            self.assert_names(self.weakened(set_uses), "exact tag")

    def test_inherited_secrets_are_named(self) -> None:
        def inherit(document: dict[str, object]) -> None:
            job_of(document)["secrets"] = "inherit"

        self.assert_names(self.weakened(inherit), "secrets: inherit")

    def test_an_explicit_apply_key_is_named(self) -> None:
        def pass_key(document: dict[str, object]) -> None:
            section(job_of(document), "secrets")["ssh_apply_key"] = "${{ secrets.APPLY }}"

        self.assert_names(self.weakened(pass_key), "the apply key is a secret of the environment")

    def test_another_secret_or_a_swapped_secret_is_named(self) -> None:
        def add_secret(document: dict[str, object]) -> None:
            section(job_of(document), "secrets")["extra"] = "${{ secrets.OTHER }}"

        def swap_secret(document: dict[str, object]) -> None:
            section(job_of(document), "secrets")["ssh_hosts"] = "${{ secrets.ANSIBLE_CHECK_KEY }}"

        self.assert_names(self.weakened(add_secret), "secrets passes extra")
        self.assert_names(self.weakened(swap_secret), "secrets.ssh_hosts must be")

    def test_an_environment_that_releases_a_pulumi_apply_is_named(self) -> None:
        for environment in sorted(self.others):

            def set_environment(
                document: dict[str, object], environment: str = environment
            ) -> None:
                section(job_of(document), "with")["environment"] = environment

            self.assert_names(self.weakened(set_environment), "so one approval could release both")

    def test_an_environment_passed_through_a_called_workflow_is_read(self) -> None:
        # The other workflow names ansible-hosts's neighbour in with.environment, not as a job key.
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory)
            (workflows / "other.yml").write_text(
                "jobs:\n  plan:\n    uses: org/repo/.github/workflows/x.yml@v1.0.0\n"
                "    with:\n      environment: mail-plan\n",
                encoding="utf-8",
            )
            names, findings = check_delivery.environments_used(workflows, "caller.yml")
        self.assertEqual([], findings)
        self.assertIn("mail-plan", names)

    def test_an_environment_given_as_an_expression_is_a_finding(self) -> None:
        # An expression cannot be read, so C4 refuses to pass it silently.
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory)
            (workflows / "other.yml").write_text(
                "jobs:\n  plan:\n    uses: org/repo/.github/workflows/x.yml@v1.0.0\n"
                "    with:\n      environment: ${{ inputs.env }}\n",
                encoding="utf-8",
            )
            _, findings = check_delivery.environments_used(workflows, "caller.yml")
        self.assertTrue(any("by expression" in finding for finding in findings), findings)

    def test_a_job_level_environment_expression_is_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory)
            (workflows / "other.yml").write_text(
                "jobs:\n  apply:\n    runs-on: ubuntu-latest\n"
                "    environment: ${{ matrix.target }}\n",
                encoding="utf-8",
            )
            _, findings = check_delivery.environments_used(workflows, "caller.yml")
        self.assertTrue(any("by expression" in finding for finding in findings), findings)

    def test_a_mapping_environment_expression_is_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory)
            (workflows / "other.yml").write_text(
                "jobs:\n  apply:\n    runs-on: ubuntu-latest\n    environment:\n"
                "      name: ${{ matrix.target }}\n      url: https://example.org\n",
                encoding="utf-8",
            )
            _, findings = check_delivery.environments_used(workflows, "caller.yml")
        self.assertTrue(any("by expression" in finding for finding in findings), findings)

    def test_a_mapping_environment_name_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory)
            (workflows / "other.yml").write_text(
                "jobs:\n  apply:\n    runs-on: ubuntu-latest\n    environment:\n"
                "      name: staging\n      url: https://example.org\n",
                encoding="utf-8",
            )
            names, findings = check_delivery.environments_used(workflows, "caller.yml")
        self.assertEqual([], findings)
        self.assertIn("staging", names)

    def test_environment_names_are_compared_without_regard_to_case(self) -> None:
        # GitHub answers /environments/Production with the environment named production, so a
        # workflow that spells the apply environment another way still shares its approval.
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory)
            (workflows / "other.yml").write_text(
                "jobs:\n  apply:\n    runs-on: ubuntu-latest\n    environment: Ansible-Hosts\n",
                encoding="utf-8",
            )
            names, findings = check_delivery.environments_used(workflows, "caller.yml")
        self.assertEqual([], findings)
        document = committed()
        self.assert_names(
            check_delivery.caller_findings(document, names), "so one approval could release both"
        )

    def test_a_write_permission_is_named(self) -> None:
        for key, value in (("contents", "write"), ("actions", "write"), ("id-token", "write")):

            def widen(document: dict[str, object], key: str = key, value: str = value) -> None:
                mutable(document["permissions"])[key] = value

            self.assert_names(self.weakened(widen), "permissions must be exactly")

    def test_a_missing_permissions_block_is_named(self) -> None:
        def drop(document: dict[str, object]) -> None:
            del document["permissions"]

        self.assert_names(self.weakened(drop), "permissions must be exactly")

    def test_a_job_key_that_skips_or_redirects_the_call_is_named(self) -> None:
        extras: dict[str, object] = {
            "if": "github.actor != 'x'",
            "needs": ["other"],
            "permissions": {"contents": "write"},
            "environment": "production",
        }
        for key, value in extras.items():

            def add_key(document: dict[str, object], key: str = key, value: object = value) -> None:
                job_of(document)[key] = value

            self.assert_names(self.weakened(add_key), f"job delivery has {key}")

    def test_a_dry_run_is_named(self) -> None:
        for key, value in (("dry-run", True), ("dry-run-stub", "stub.sh")):

            def add_input(
                document: dict[str, object], key: str = key, value: object = value
            ) -> None:
                section(job_of(document), "with")[key] = value

            self.assert_names(self.weakened(add_input), f"with has {key}")

    def test_a_skip_that_is_not_the_proofs_answer_is_named(self) -> None:
        # A static true skips the re-test of a merge that never went through the queue.
        for value in (True, "true", "${{ true }}", "${{ needs.queue-proof.outputs.tested }}", None):

            def set_skip(document: dict[str, object], value: object = value) -> None:
                section(job_of(document), "with")[check_delivery.SKIP_INPUT] = value

            self.assert_names(self.weakened(set_skip), f"with.{check_delivery.SKIP_INPUT} must be")

    def test_a_missing_skip_or_check_name_input_is_named(self) -> None:
        for key in (check_delivery.SKIP_INPUT, check_delivery.CHECK_NAME_INPUT):

            def drop(document: dict[str, object], key: str = key) -> None:
                del section(job_of(document), "with")[key]

            self.assert_names(self.weakened(drop), f"with.{key} must be")

    def test_a_wrong_check_name_is_named(self) -> None:
        for value in ("Ansible checks passed", "Lint and test the Ansible roles ", "", None):

            def set_name(document: dict[str, object], value: object = value) -> None:
                section(job_of(document), "with")[check_delivery.CHECK_NAME_INPUT] = value

            self.assert_names(
                self.weakened(set_name), f"with.{check_delivery.CHECK_NAME_INPUT} must be"
            )

    def test_the_check_name_is_the_name_of_the_gate_job_of_ansible_yml(self) -> None:
        # The name is the one the merge queue run publishes, so it has one source: the job.
        document, problem = load_yaml(WORKFLOWS / "ansible.yml")
        self.assertIsNone(problem)
        jobs = mutable(mutable(document)["jobs"])
        self.assertEqual(check_delivery.GATE_CHECK_NAME, mutable(jobs["roles"])["name"])

    def test_a_delivery_that_waits_for_anything_but_the_proof_is_named(self) -> None:
        for needs in (["other"], ["queue-proof", "other"], "queue-proof", [], None):

            def set_needs(document: dict[str, object], needs: object = needs) -> None:
                job_of(document)["needs"] = needs

            self.assert_names(self.weakened(set_needs), "job delivery has needs")

    def test_a_delivery_with_no_needs_is_named(self) -> None:
        def drop(document: dict[str, object]) -> None:
            del job_of(document)["needs"]

        self.assert_names(self.weakened(drop), "job delivery must have needs")

    def test_a_missing_or_extra_job_is_named(self) -> None:
        def drop_proof(document: dict[str, object]) -> None:
            del mutable(document["jobs"])[check_delivery.PROOF_JOB]

        def add_job(document: dict[str, object]) -> None:
            mutable(document["jobs"])["third"] = {"runs-on": "ubuntu-24.04"}

        self.assert_names(self.weakened(drop_proof), "jobs must hold exactly the two jobs")
        self.assert_names(self.weakened(add_job), "jobs must hold exactly the two jobs")

    def test_a_proof_job_key_that_can_skip_or_hide_the_proof_is_named(self) -> None:
        extras: dict[str, object] = {
            "if": "github.actor != 'x'",
            "continue-on-error": True,
            "needs": ["delivery"],
            "environment": "production",
            "permissions": {"contents": "write"},
            "strategy": {"matrix": {"a": [1]}},
        }
        for key, value in extras.items():

            def add_key(document: dict[str, object], key: str = key, value: object = value) -> None:
                proof_of(document)[key] = value

            self.assert_names(self.weakened(add_key), f"job queue-proof has {key}")

    def test_a_proof_output_that_is_not_the_proof_steps_is_named(self) -> None:
        for value in ("true", "${{ steps.proof.outputs.other }}", "${{ steps.x.outputs.tested }}"):

            def set_output(document: dict[str, object], value: str = value) -> None:
                mutable(proof_of(document)["outputs"])["tested"] = value

            self.assert_names(self.weakened(set_output), "job queue-proof outputs must be")

    def test_a_proof_job_that_is_not_checkout_and_the_proof_step_is_named(self) -> None:
        def extra_step(document: dict[str, object]) -> None:
            steps(document).append({"run": "echo hello"})

        def one_step(document: dict[str, object]) -> None:
            del steps(document)[0]

        self.assert_names(self.weakened(extra_step), "exactly two steps")
        self.assert_names(self.weakened(one_step), "exactly two steps")

    def test_a_checkout_of_another_ref_or_with_credentials_is_named(self) -> None:
        extras: list[dict[str, object]] = [
            {"ref": "refs/heads/other"},
            {"persist-credentials": True},
        ]
        for extra in extras:

            def set_with(document: dict[str, object], extra: dict[str, object] = extra) -> None:
                step_of(document, 0)["with"] = {"persist-credentials": False, **extra}

            self.assert_names(self.weakened(set_with), "the checkout step with must be")

    def test_a_proof_step_that_does_not_run_the_script_on_the_runs_is_named(self) -> None:
        runs = {
            "writes the answer itself": 'echo "tested=true" >> "$GITHUB_OUTPUT"',
            "runs another script": 'python3 other.py --runs r --sha "$SHA" >> "$GITHUB_OUTPUT"',
            "judges another commit": (
                'python3 ansible/checks/merge_group_proof.py --runs r --sha "abc" '
                '| tee -a "$GITHUB_OUTPUT"'
            ),
            "writes no output": 'python3 ansible/checks/merge_group_proof.py --runs r --sha "$SHA"',
            "adds a literal answer": (
                'python3 ansible/checks/merge_group_proof.py --runs r --sha "$SHA" '
                '| tee -a "$GITHUB_OUTPUT"; echo tested=true >> "$GITHUB_OUTPUT"'
            ),
        }
        for name, text in runs.items():

            def set_run(document: dict[str, object], text: str = text) -> None:
                step_of(document, 1)["run"] = text

            with self.subTest(name=name):
                self.assert_names(self.weakened(set_run), "step proof run")

    def test_a_proof_step_with_another_commit_token_or_a_condition_is_named(self) -> None:
        def other_id(document: dict[str, object]) -> None:
            step_of(document, 1)["id"] = "other"

        def conditional(document: dict[str, object]) -> None:
            step_of(document, 1)["if"] = "always()"

        def tolerant(document: dict[str, object]) -> None:
            step_of(document, 1)["continue-on-error"] = True

        for name in check_delivery.PROOF_ENV:
            # Each variable in turn is pointed at something else: another commit, another token.

            def point_elsewhere(document: dict[str, object], name: str = name) -> None:
                mutable(step_of(document, 1)["env"])[name] = "${{ github.event.before }}"

            self.assert_names(self.weakened(point_elsewhere), "step proof env must be")
        self.assert_names(self.weakened(other_id), "step proof id must be")
        self.assert_names(self.weakened(conditional), "step proof has if")
        self.assert_names(self.weakened(tolerant), "step proof has continue-on-error")

    def test_a_narrowed_or_changed_input_is_named(self) -> None:
        def narrow(document: dict[str, object]) -> None:
            section(job_of(document), "with")["role-directories"] = "roles/*\n"

        def repoint(document: dict[str, object]) -> None:
            section(job_of(document), "with")["python-paths"] = "."

        def rename(document: dict[str, object]) -> None:
            section(job_of(document), "with")["environment"] = "ansible"

        self.assert_names(self.weakened(narrow), "with.role-directories must be")
        self.assert_names(self.weakened(repoint), "with.python-paths must be")
        self.assert_names(self.weakened(rename), "with.environment must be")

    def test_a_second_job_or_a_new_top_level_key_is_named(self) -> None:
        def second_job(document: dict[str, object]) -> None:
            mutable(document["jobs"])["extra"] = {"runs-on": "ubuntu-24.04"}

        def add_env(document: dict[str, object]) -> None:
            document["env"] = {"A": "b"}

        self.assert_names(self.weakened(second_job), "jobs must hold exactly the two jobs")
        self.assert_names(self.weakened(add_env), "the workflow has env")

    def test_a_workflow_that_is_not_a_mapping_is_refused(self) -> None:
        for document in (None, "push", ["on"], 3):
            self.assertEqual(
                [f"{check_delivery.CALLER} is not a YAML mapping"],
                check_delivery.caller_findings(document, self.others),
            )

    def test_a_missing_caller_is_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github" / "workflows").mkdir(parents=True)
            findings = check_delivery.check_caller(root)
        self.assertEqual(1, len(findings))
        self.assertIn("cannot be read", findings[0])

    def test_the_pull_request_gate_runs_when_the_caller_alone_changes(self) -> None:
        text = (WORKFLOWS / "ansible.yml").read_text(encoding="utf-8")
        self.assertIn(check_delivery.CALLER, parse_watched(text))
        without = text.replace(f"            {check_delivery.CALLER}\n", "")
        self.assertNotEqual(text, without)
        self.assertNotIn(check_delivery.CALLER, parse_watched(without))


def reviewer(kind: str, label: str) -> dict[str, object]:
    """Return one reviewer entry shaped like the environment call answers."""
    key = "login" if kind == "User" else "slug"
    return {"type": kind, "reviewer": {key: label, "id": 1, "type": kind}}


def environment(
    *,
    name: str = "ansible-hosts",
    reviewers: list[dict[str, object]] | None = None,
    prevent_self_review: bool = True,
    can_admins_bypass: bool = False,
    custom_branch_policies: bool = True,
) -> dict[str, object]:
    """Return an environment answer set up as the owner step says.

    Prevent self-review is ticked, as the gated apply requires, and administrators may not bypass
    the rules.
    """
    rules: list[dict[str, object]] = [
        {
            "id": 1,
            "type": "required_reviewers",
            "prevent_self_review": prevent_self_review,
            "reviewers": [reviewer("Team", "branchleft-admin")] if reviewers is None else reviewers,
        }
    ]
    policy: dict[str, object] | None = None
    if custom_branch_policies:
        rules.append({"id": 2, "type": "branch_policy"})
        policy = {"custom_branch_policies": True, "protected_branches": False}
    return {
        "name": name,
        "can_admins_bypass": can_admins_bypass,
        "protection_rules": rules,
        "deployment_branch_policy": policy,
    }


MAIN_ONLY: dict[str, object] = {
    "total_count": 1,
    "branch_policies": [{"id": 1, "name": "main", "type": "branch"}],
}
NOT_FOUND: dict[str, object] = {"message": "Not Found", "status": "404"}
WITH_KEY: dict[str, object] = {"total_count": 1, "secrets": [{"name": "SSH_APPLY_KEY"}]}


class ChosenEnvironmentTests(unittest.TestCase):
    """C4 reads the one closed expression for an environment name, and refuses every other."""

    def test_the_closed_shape_names_both_environments_and_is_no_finding(self) -> None:
        # A job output that picks between two literals is read, and C4 judges both literals.
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory)
            (workflows / "other.yml").write_text(
                "jobs:\n  apply:\n    runs-on: ubuntu-latest\n"
                f"    environment: {json.dumps(CHOSEN)}\n",
                encoding="utf-8",
            )
            names, findings = check_delivery.environments_used(workflows, "caller.yml")
        self.assertEqual([], findings)
        self.assertEqual(frozenset({"production-free", "production"}), names)

    def test_the_closed_shape_is_read_in_a_mapping_and_in_a_called_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory)
            (workflows / "mapping.yml").write_text(
                "jobs:\n  apply:\n    runs-on: ubuntu-latest\n    environment:\n"
                f"      name: {json.dumps(CHOSEN)}\n      url: https://example.org\n",
                encoding="utf-8",
            )
            (workflows / "called.yml").write_text(
                "jobs:\n  plan:\n    uses: org/repo/.github/workflows/x.yml@v1.0.0\n"
                f"    with:\n      environment: {json.dumps(CHOSEN)}\n",
                encoding="utf-8",
            )
            names, findings = check_delivery.environments_used(workflows, "caller.yml")
        self.assertEqual([], findings)
        self.assertEqual(frozenset({"production-free", "production"}), names)

    def test_the_closed_shape_may_be_spaced_differently(self) -> None:
        spaced = "${{  needs.a-b.outputs.c_d   ==  'x.y'  &&  'x.y'  ||  'Z-1'  }}"
        self.assertEqual(("x.y", "Z-1"), check_delivery.chosen_environments(spaced))

    def test_both_literals_of_the_closed_shape_are_judged_as_named(self) -> None:
        # A job that may release into the apply environment shares its approval, whichever
        # branch it takes, so naming ansible-hosts in either branch is the same finding as
        # naming it outright.
        expression = (
            "${{ needs.plan.outputs.e == 'production' && 'production' || 'ansible-hosts' }}"
        )
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory)
            (workflows / "other.yml").write_text(
                "jobs:\n  apply:\n    runs-on: ubuntu-latest\n"
                f"    environment: {json.dumps(expression)}\n",
                encoding="utf-8",
            )
            names, findings = check_delivery.environments_used(workflows, "caller.yml")
        self.assertEqual([], findings)
        self.assertIn("ansible-hosts", names)
        findings = check_delivery.caller_findings(committed(), names)
        self.assertTrue(
            any("so one approval could release both" in finding for finding in findings), findings
        )

    def test_every_other_expression_stays_a_finding_naming_the_expression(self) -> None:
        for why, expression in UNREADABLE_EXPRESSIONS.items():
            with self.subTest(why):
                with tempfile.TemporaryDirectory() as directory:
                    workflows = Path(directory)
                    (workflows / "other.yml").write_text(
                        "jobs:\n  apply:\n    runs-on: ubuntu-latest\n"
                        f"    environment: {json.dumps(expression)}\n",
                        encoding="utf-8",
                    )
                    names, findings = check_delivery.environments_used(workflows, "caller.yml")
                self.assertEqual(frozenset(), names)
                self.assertEqual(1, len(findings), findings)
                self.assertIn("by expression", findings[0])
                self.assertIn(repr(expression), findings[0])

    def test_the_refused_expressions_stay_refused_in_a_mapping_and_a_called_workflow(self) -> None:
        expression = UNREADABLE_EXPRESSIONS["a non-literal second branch"]
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory)
            (workflows / "mapping.yml").write_text(
                "jobs:\n  apply:\n    runs-on: ubuntu-latest\n    environment:\n"
                f"      name: {json.dumps(expression)}\n",
                encoding="utf-8",
            )
            (workflows / "called.yml").write_text(
                "jobs:\n  plan:\n    uses: org/repo/.github/workflows/x.yml@v1.0.0\n"
                f"    with:\n      environment: {json.dumps(expression)}\n",
                encoding="utf-8",
            )
            names, findings = check_delivery.environments_used(workflows, "caller.yml")
        self.assertEqual(frozenset(), names)
        self.assertEqual(2, len(findings), findings)

    def test_the_committed_workflows_name_the_spend_gate_routing(self) -> None:
        names, findings = check_delivery.environments_used(
            WORKFLOWS, Path(check_delivery.CALLER).name
        )
        self.assertEqual([], findings)
        self.assertTrue({"production-free", "production"} <= names, names)


class EnvironmentTests(unittest.TestCase):
    """The environment is ready only when it is protected as the reusable workflow assumes."""

    def judge(
        self,
        described: object,
        policies: object = MAIN_ONLY,
        secrets: object | None = WITH_KEY,
    ) -> list[str]:
        return check_delivery.environment_findings("ansible-hosts", described, policies, secrets)

    def assert_names(self, findings: list[str], mechanism: str) -> None:
        self.assertTrue(
            any(mechanism in finding for finding in findings),
            f"no finding names {mechanism!r}: {findings}",
        )

    def test_a_protected_environment_is_ready(self) -> None:
        self.assertEqual([], self.judge(environment()))

    def test_the_branchleft_admin_team_is_the_expected_reviewer(self) -> None:
        # The environment's reviewer is the branchleft-admin team.
        described = environment(reviewers=[reviewer("Team", "branchleft-admin")])
        self.assertEqual([], self.judge(described))

    def test_the_owner_user_alone_is_not_the_expected_reviewer(self) -> None:
        described = environment(reviewers=[reviewer("User", "Rob-branchLeft")])
        self.assert_names(self.judge(described), "User Rob-branchLeft approve")

    def test_a_missing_environment_is_not_ready(self) -> None:
        self.assert_names(self.judge(NOT_FOUND, NOT_FOUND, None), "was not returned")

    def test_an_environment_with_another_name_is_not_ready(self) -> None:
        self.assert_names(self.judge(environment(name="production")), "was not returned")

    def test_production_as_it_is_live_is_not_ready(self) -> None:
        live = {
            "name": "production",
            "can_admins_bypass": True,
            "deployment_branch_policy": None,
            "protection_rules": [
                {
                    "id": 3,
                    "type": "required_reviewers",
                    "prevent_self_review": False,
                    "reviewers": [reviewer("User", "Rob-branchLeft")],
                }
            ],
        }
        findings = check_delivery.environment_findings("production", live, NOT_FOUND, None)
        self.assert_names(findings, "no custom branch policy")
        self.assert_names(findings, "no branch policy list")
        self.assert_names(findings, "lets administrators bypass")

    def test_administrators_who_may_bypass_are_not_ready(self) -> None:
        # A new environment answers True, and the admin whose merge started the run could then
        # release it with no reviewer, which defeats the bypass rule.
        self.assert_names(
            self.judge(environment(can_admins_bypass=True)), "lets administrators bypass"
        )

    def test_a_missing_bypass_setting_is_not_ready(self) -> None:
        # A missing key fails closed: the probe must prove the ruled value, not its absence.
        described = environment()
        del described["can_admins_bypass"]
        self.assert_names(self.judge(described), "lets administrators bypass")

    def test_a_bypass_setting_that_is_not_a_boolean_is_not_ready(self) -> None:
        for value in (None, "false", 0):
            described = environment()
            described["can_admins_bypass"] = value
            self.assert_names(self.judge(described), "lets administrators bypass")

    def test_administrators_who_may_not_bypass_are_ready(self) -> None:
        self.assertEqual([], self.judge(environment(can_admins_bypass=False)))

    def test_prevent_self_review_ticked_is_ready(self) -> None:
        # The gated apply keeps Prevent self-review on.
        self.assertEqual([], self.judge(environment(prevent_self_review=True)))

    def test_prevent_self_review_unticked_is_not_ready(self) -> None:
        # Unticked lets the merging person approve their own deploy, so the probe names it.
        self.assert_names(
            self.judge(environment(prevent_self_review=False)),
            "does not have Prevent self-review ticked",
        )
        self.assert_names(
            self.judge(environment(prevent_self_review=False)),
            "could approve the deploy that merge started",
        )

    def test_a_missing_self_review_setting_is_not_ready(self) -> None:
        # A missing key fails closed: the probe must prove the ruled value, not its absence.
        described = environment()
        described["protection_rules"] = [
            {
                "id": 1,
                "type": "required_reviewers",
                "reviewers": [reviewer("User", "Rob-branchLeft")],
            },
            {"id": 2, "type": "branch_policy"},
        ]
        self.assert_names(self.judge(described), "does not have Prevent self-review ticked")

    def test_no_reviewer_rule_is_not_ready(self) -> None:
        described = environment()
        described["protection_rules"] = [{"id": 2, "type": "branch_policy"}]
        self.assert_names(self.judge(described), "no required reviewers rule")

    def test_an_empty_reviewer_list_is_not_ready(self) -> None:
        self.assert_names(self.judge(environment(reviewers=[])), "lists no reviewer")

    def test_a_reviewer_who_is_not_the_owner_is_not_ready(self) -> None:
        for who in (reviewer("User", "someone-else"), reviewer("Team", "other-team")):
            self.assert_names(
                self.judge(environment(reviewers=[who])), "only the branchleft-admin team may"
            )
        both = environment(reviewers=[reviewer("User", "Rob-branchLeft"), reviewer("User", "x")])
        self.assert_names(self.judge(both), "User x approve")

    def test_an_unreadable_reviewer_is_not_ready(self) -> None:
        described = environment(reviewers=[{"type": "User"}])
        self.assert_names(self.judge(described), "unreadable")

    def test_no_custom_branch_policy_is_not_ready(self) -> None:
        self.assert_names(
            self.judge(environment(custom_branch_policies=False)), "no custom branch policy"
        )

    def test_a_branch_other_than_main_is_not_ready(self) -> None:
        for names in (["release"], ["main", "release"], []):
            policies = {
                "total_count": len(names),
                "branch_policies": [{"name": n, "type": "branch"} for n in names],
            }
            self.assert_names(
                self.judge(environment(), policies), "must deploy from the branch main"
            )
        tag_policy = {"branch_policies": [{"name": "main", "type": "tag"}]}
        self.assert_names(self.judge(environment(), tag_policy), "must deploy from the branch main")

    def test_a_missing_apply_key_is_not_ready(self) -> None:
        for secrets in (
            {"total_count": 0, "secrets": []},
            {"secrets": [{"name": "OTHER"}]},
            NOT_FOUND,
        ):
            self.assert_names(self.judge(environment(), MAIN_ONLY, secrets), "holds no secret")

    def test_the_apply_key_is_found_whatever_its_case(self) -> None:
        for name in ("ssh_apply_key", "SSH_APPLY_KEY", "Ssh_Apply_Key"):
            secrets = {"secrets": [{"name": name}]}
            self.assertEqual([], self.judge(environment(), MAIN_ONLY, secrets))

    def test_unlisted_secrets_are_not_judged(self) -> None:
        self.assertEqual([], self.judge(environment(), MAIN_ONLY, None))

    def test_an_answer_of_the_wrong_shape_is_not_ready(self) -> None:
        odd_answers: list[object] = [None, "ok", [], 3]
        for odd in odd_answers:
            self.assertNotEqual([], self.judge(odd, odd, odd))


class CommandLineTests(unittest.TestCase):
    """The command exits 1 on a finding and 0 on none, and prints what it found."""

    def run_main(self, argv: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = check_delivery.main(argv)
        return status, output.getvalue()

    def write(self, directory: Path, name: str, document: object) -> Path:
        path = directory / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_the_committed_caller_passes(self) -> None:
        status, output = self.run_main(["caller"])
        self.assertEqual(0, status)
        self.assertIn("0 finding(s)", output)

    def test_a_protected_environment_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            where = Path(directory)
            args = [
                "environment",
                "--environment",
                str(self.write(where, "e.json", environment())),
                "--policies",
                str(self.write(where, "p.json", MAIN_ONLY)),
                "--secrets",
                str(self.write(where, "s.json", WITH_KEY)),
            ]
            status, output = self.run_main(args)
        self.assertEqual(0, status)
        self.assertIn("0 finding(s)", output)

    def test_a_missing_environment_fails_and_says_so(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            where = Path(directory)
            args = [
                "environment",
                "--environment",
                str(self.write(where, "e.json", NOT_FOUND)),
                "--policies",
                str(self.write(where, "p.json", NOT_FOUND)),
            ]
            status, output = self.run_main(args)
        self.assertEqual(1, status)
        self.assertIn("FAIL environment ansible-hosts was not returned", output)
        self.assertIn("the secrets were not listed", output)

    def test_an_unreadable_answer_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            where = Path(directory)
            broken = where / "e.json"
            broken.write_text("not json", encoding="utf-8")
            args = [
                "environment",
                "--environment",
                str(broken),
                "--policies",
                str(self.write(where, "p.json", MAIN_ONLY)),
            ]
            status, output = self.run_main(args)
        self.assertEqual(1, status)
        self.assertIn("e.json cannot be read as JSON", output)


if __name__ == "__main__":
    unittest.main()
