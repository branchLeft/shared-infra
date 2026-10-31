"""Structure tests for the nightly drift-check caller (.github/workflows/ansible-drift-check.yml).

The caller runs the check-only reusable workflow of branchLeft/github-workflows at an exact
tag. The committed caller must pass ``caller_findings``, and each weakening of it must be
named by it, so a check that has gone blind fails here and not in a review. The live proof
(a manual run, a scheduled run, a pinned-tag run and a drifted host) is the owner's and is
not a test here.
"""

from __future__ import annotations

import copy
import re
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import cast

from check_delivery import MIN_RELEASE, PUSH_PLAYBOOK
from check_pins import load_yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CALLER = ".github/workflows/ansible-drift-check.yml"
JOB = "drift-check"
HOST_LABEL = "ansible-estate"
TRIGGERS = frozenset({"schedule", "workflow_dispatch"})
PERMISSIONS = {"actions": "read", "contents": "read", "issues": "write"}
SECRETS = {
    "ssh_hosts": "${{ secrets.ANSIBLE_HOSTS }}",
    "ssh_known_hosts": "${{ secrets.ANSIBLE_KNOWN_HOSTS }}",
    "ssh_check_key": "${{ secrets.ANSIBLE_CHECK_KEY }}",
    # An unset repository secret is empty, and empty means every host is pulled.
    "ssh_push_hosts": "${{ secrets.ANSIBLE_PUSH_HOSTS }}",
    # Both or neither: an unset repository secret is empty, and empty means no jump.
    "ssh_jump_host": "${{ secrets.SSH_JUMP_HOST }}",
    "ssh_jump_key": "${{ secrets.SSH_JUMP_KEY }}",
}
# An exact tag (CI-5, and check_delivery.py), never a branch, a commit id or a major version.
REUSABLE = re.compile(
    r"branchLeft/github-workflows/\.github/workflows/ansible-drift-check\.yml"
    r"@v(\d+)\.(\d+)\.(\d+)",
    re.ASCII,
)
TOP_KEYS = frozenset({"name", "on", "permissions", "jobs"})
JOB_KEYS = frozenset({"uses", "with", "secrets"})


def as_mapping(value: object) -> dict[str, object] | None:
    """Return ``value`` as a mapping with string keys, or None when it is not one."""
    if not isinstance(value, dict):
        return None
    return {str(key): item for key, item in value.items()}


def caller_findings(workflow: object) -> list[str]:
    """Return every way ``workflow`` departs from the designed caller; none means it passes."""
    top = as_mapping(workflow)
    if top is None:
        return ["the caller is not a YAML mapping"]
    findings = [
        f"the workflow has {key}, which is not allowed"
        for key in sorted(top)
        if key not in TOP_KEYS
    ]
    events = as_mapping(top.get("on"))
    if events is None or frozenset(events) != TRIGGERS:
        findings.append(f"on must name exactly {sorted(TRIGGERS)}, got {top.get('on')!r}")
    if top.get("permissions") != PERMISSIONS:
        findings.append(
            "permissions must be exactly actions: read, contents: read and issues: write "
            "(the drift job reads the run record, the alert job opens an issue), "
            f"got {top.get('permissions')!r}"
        )
    jobs = as_mapping(top.get("jobs"))
    if jobs is None or sorted(jobs) != [JOB]:
        return [*findings, f"jobs must hold exactly one job, {JOB}, got {top.get('jobs')!r}"]
    job = as_mapping(jobs[JOB])
    if job is None:
        return [*findings, f"job {JOB} must be a mapping, got {jobs[JOB]!r}"]
    findings += [
        f"job {JOB} has {key}, which is not allowed"
        + (
            " (a named environment would hold the call to an approval)"
            if key == "environment"
            else ""
        )
        for key in sorted(job)
        if key not in JOB_KEYS
    ]
    uses = job.get("uses")
    pinned = REUSABLE.fullmatch(uses) if isinstance(uses, str) else None
    if pinned is None:
        findings.append(
            f"job {JOB} must call ansible-drift-check.yml at an exact tag, got {uses!r}"
        )
    elif tuple(int(part) for part in pinned.groups()) < MIN_RELEASE:
        findings.append(
            f"job {JOB} calls {uses!r}, older than the first release that declares the push "
            "list secret and the push-playbook input, so passing them would fail the call"
        )
    if job.get("with") != {"host-label": HOST_LABEL, "push-playbook": PUSH_PLAYBOOK}:
        findings.append(
            f"with must be exactly host-label: {HOST_LABEL} and push-playbook: {PUSH_PLAYBOOK}, "
            f"got {job.get('with')!r}"
        )
    if job.get("secrets") != SECRETS:
        findings.append(
            "secrets must name exactly the six repository secrets and no apply key or inherit, "
            f"got {job.get('secrets')!r}"
        )
    return findings


def committed() -> dict[str, object]:
    """Return a fresh copy of the committed caller.

    Raises:
        AssertionError: the caller cannot be read as YAML, or it is not a mapping.
    """
    document, problem = load_yaml(REPO_ROOT / CALLER)
    mapping = as_mapping(document)
    if problem is None and mapping is None:
        problem = f"{CALLER} is not a mapping"
    if problem is not None or mapping is None:
        raise AssertionError(problem)
    return copy.deepcopy(mapping)


class DriftCallerTests(unittest.TestCase):
    """The committed caller passes, and each weakening of it is named."""

    def weakened(self, change: Callable[[dict[str, object]], None]) -> list[str]:
        document = committed()
        change(document)
        return caller_findings(document)

    def job(self, document: dict[str, object]) -> dict[str, object]:
        # The live mapping, not a copy: a change to it must reach ``document``.
        # The fixture is built by the test itself, so the shape is known here.
        jobs = cast("dict[str, object]", document["jobs"])
        return cast("dict[str, object]", jobs[JOB])

    def test_committed_caller_passes(self) -> None:
        self.assertEqual([], caller_findings(committed()))

    def test_permissions_are_exactly_the_three_grants(self) -> None:
        def add_grant(doc: dict[str, object]) -> None:
            doc["permissions"] = {**PERMISSIONS, "pull-requests": "write"}

        def drop_issues(doc: dict[str, object]) -> None:
            doc["permissions"] = {"actions": "read", "contents": "read"}

        def widen_contents(doc: dict[str, object]) -> None:
            doc["permissions"] = {**PERMISSIONS, "contents": "write"}

        for change in (add_grant, drop_issues, widen_contents):
            with self.subTest(change=change.__name__):
                findings = self.weakened(change)
                self.assertTrue(any("permissions must be exactly" in f for f in findings), findings)

    def test_no_environment_on_the_caller_job(self) -> None:
        findings = self.weakened(lambda doc: self.job(doc).update(environment="ansible-hosts"))
        self.assertTrue(any("environment" in f for f in findings), findings)

    def test_no_apply_key_and_no_inherited_secrets(self) -> None:
        def pass_apply_key(doc: dict[str, object]) -> None:
            self.job(doc)["secrets"] = {
                **SECRETS,
                "ssh_apply_key": "${{ secrets.ANSIBLE_APPLY_KEY }}",
            }

        def inherit(doc: dict[str, object]) -> None:
            self.job(doc)["secrets"] = "inherit"

        for change in (pass_apply_key, inherit):
            with self.subTest(change=change.__name__):
                findings = self.weakened(change)
                self.assertTrue(any("secrets must name exactly" in f for f in findings), findings)

    def test_reference_is_an_exact_tag_not_a_sha_branch_or_major(self) -> None:
        base = "branchLeft/github-workflows/.github/workflows/ansible-drift-check.yml@"
        sha = "0123456789abcdef0123456789abcdef01234567"
        self.assertEqual([], self.weakened(lambda doc: self.job(doc).update(uses=base + "v1.0.19")))
        for ref in (sha, "main", "v1", "v1.0"):
            with self.subTest(ref=ref):

                def point_at(doc: dict[str, object], uses: str = base + ref) -> None:
                    self.job(doc).update(uses=uses)

                findings = self.weakened(point_at)
                self.assertTrue(any("exact tag" in f for f in findings), findings)

    def test_a_pin_below_the_jump_release_is_named(self) -> None:
        base = "branchLeft/github-workflows/.github/workflows/ansible-drift-check.yml@"
        for ref in ("v1.0.15", "v1.0.17", "v1.0.18", "v1.0.13", "v0.9.99"):
            with self.subTest(ref=ref):

                def point_at(doc: dict[str, object], uses: str = base + ref) -> None:
                    self.job(doc).update(uses=uses)

                findings = self.weakened(point_at)
                self.assertTrue(any("first release that declares" in f for f in findings), findings)

    def test_a_caller_without_a_jump_secret_is_named(self) -> None:
        for name in ("ssh_jump_host", "ssh_jump_key"):
            with self.subTest(name=name):

                def drop_secret(doc: dict[str, object], name: str = name) -> None:
                    secrets = cast("dict[str, object]", self.job(doc)["secrets"])
                    del secrets[name]

                findings = self.weakened(drop_secret)
                self.assertTrue(any("secrets must name exactly" in f for f in findings), findings)

    def test_a_wrong_jump_secret_expression_is_named(self) -> None:
        # The jump key must never be the check key, and a literal is no secret.
        wrong = (
            "",
            "literal-value",
            "${{ secrets.ANSIBLE_CHECK_KEY }}",
            "${{ secrets.SSH_APPLY_KEY }}",
        )
        for name in ("ssh_jump_host", "ssh_jump_key"):
            for value in wrong:
                with self.subTest(name=name, value=value):

                    def set_secret(
                        doc: dict[str, object], name: str = name, value: str = value
                    ) -> None:
                        secrets = cast("dict[str, object]", self.job(doc)["secrets"])
                        secrets[name] = value

                    findings = self.weakened(set_secret)
                    self.assertTrue(
                        any("secrets must name exactly" in f for f in findings), findings
                    )

    def test_the_push_list_secret_and_playbook_are_fixed(self) -> None:
        # The control: each line is weakened from the committed caller, which is green. The push
        # list must be the ANSIBLE_PUSH_HOSTS secret and the playbook the one constant, and a
        # caller on a release that does not declare them fails on GitHub.
        def drop_secret(doc: dict[str, object]) -> None:
            secrets = cast("dict[str, object]", self.job(doc)["secrets"])
            del secrets["ssh_push_hosts"]

        def drop_playbook(doc: dict[str, object]) -> None:
            inputs = cast("dict[str, object]", self.job(doc)["with"])
            del inputs["push-playbook"]

        self.assertEqual([], self.weakened(lambda doc: None))
        for change, mechanism in (
            (drop_secret, "secrets must name exactly"),
            (drop_playbook, "with must be exactly"),
        ):
            with self.subTest(change=change.__name__):
                findings = self.weakened(change)
                self.assertTrue(any(mechanism in f for f in findings), findings)
        for value in (
            "",
            "literal-value",
            "${{ secrets.ANSIBLE_HOSTS }}",
            "${{ secrets.ANSIBLE_CHECK_KEY }}",
            "${{ secrets.SSH_APPLY_KEY }}",
        ):
            with self.subTest(secret=value):

                def set_secret(doc: dict[str, object], value: str = value) -> None:
                    secrets = cast("dict[str, object]", self.job(doc)["secrets"])
                    secrets["ssh_push_hosts"] = value

                findings = self.weakened(set_secret)
                self.assertTrue(any("secrets must name exactly" in f for f in findings), findings)
        for path in ("ansible/playbooks/edge1.yml", "../ansible/playbooks/demo1.yml", "", None):
            with self.subTest(playbook=path):

                def set_playbook(doc: dict[str, object], path: object = path) -> None:
                    cast("dict[str, object]", self.job(doc)["with"])["push-playbook"] = path

                findings = self.weakened(set_playbook)
                self.assertTrue(any("push-playbook" in f for f in findings), findings)

    def test_triggers_are_schedule_and_manual_only(self) -> None:
        def add_pull_request(doc: dict[str, object]) -> None:
            doc["on"] = {**committed_triggers(doc), "pull_request": None}

        def drop_manual(doc: dict[str, object]) -> None:
            doc["on"] = {"schedule": committed_triggers(doc)["schedule"]}

        for change in (add_pull_request, drop_manual):
            with self.subTest(change=change.__name__):
                findings = self.weakened(change)
                self.assertTrue(any("on must name exactly" in f for f in findings), findings)

    def test_host_label_is_the_one_input(self) -> None:
        findings = self.weakened(
            lambda doc: self.job(doc).update({"with": {"host-label": "other"}})
        )
        self.assertTrue(any("host-label" in f for f in findings), findings)


def committed_triggers(doc: dict[str, object]) -> dict[str, object]:
    """Return the trigger mapping of ``doc`` as a new dict, so a test can edit one key of it."""
    return dict(as_mapping(doc["on"]) or {})


if __name__ == "__main__":
    unittest.main()
