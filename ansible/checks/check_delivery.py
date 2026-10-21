"""Check the caller of the gated apply, and the environment that gates it (ANS-17).

``caller`` reads .github/workflows/ansible-delivery.yml and fails on anything that
would let a pull request, a schedule or a manual run reach a host, float on a moved
workflow, hand the repository's secrets or the apply key to the call, share an approval
with the Pulumi applies, or widen the token. ``environment`` reads the answers of three
read-only GitHub calls and fails unless the deployment environment is protected as the
reusable workflow assumes, because that workflow cannot read the protection itself and a
missing environment is created unprotected by the first run that names it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from check_pins import load_yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CALLER = ".github/workflows/ansible-delivery.yml"

JOB = "delivery"
ENVIRONMENT = "ansible-hosts"
# Used with fullmatch and in ASCII mode: only an exact tag (CI-5), never a branch, a
# commit id or a major version that a later tag could move under the caller.
REUSABLE = re.compile(
    r"branchLeft/github-workflows/\.github/workflows/ansible-gated-apply\.yml@v\d+\.\d+\.\d+",
    re.ASCII,
)
ROLE_DIRECTORIES = ["roles/*", "patterns/*"]
PYTHON_PATHS = "harness checks"
PERMISSIONS = {"contents": "read", "actions": "read"}
# The only secrets the call passes. The apply key is not among them: it is a secret of
# the environment, which only a job that passed the approval can read.
SECRETS = {
    "ssh_hosts": "${{ secrets.ANSIBLE_HOSTS }}",
    "ssh_known_hosts": "${{ secrets.ANSIBLE_KNOWN_HOSTS }}",
    "ssh_check_key": "${{ secrets.ANSIBLE_CHECK_KEY }}",
}
APPLY_KEY = "ssh_apply_key"

WORKFLOW_KEYS = frozenset({"name", "on", "permissions", "jobs"})
JOB_KEYS = frozenset({"uses", "with", "secrets"})
INPUT_KEYS = frozenset({"environment", "role-directories", "python-paths"})
# What a key that must not be there would do, for the finding's text.
WHY = {
    "dry-run": "a dry run replaces the host call, so a green run would reach no host",
    "dry-run-stub": "a stand-in for the host",
    "if": "a condition can skip the delivery without a red run",
    "needs": "a dependency can skip the delivery without a red run",
    "environment": "the environment is an input of the call, not a job key",
    "permissions": "the token is set once, for the whole workflow",
}

# Who may approve the apply: the owner, directly or through the owner-only team that
# CODEOWNERS names. No other user, team or app is an approver of this environment.
OWNER_REVIEWERS = frozenset({("User", "Rob-branchLeft"), ("Team", "branchleft-admin")})
BRANCH = "main"


def as_mapping(value: object) -> dict[str, object] | None:
    """Return ``value`` with string keys when it is a mapping, else None."""
    if not isinstance(value, dict):
        return None
    return {str(key): item for key, item in value.items()}


def unexpected(mapping: dict[str, object], allowed: frozenset[str], where: str) -> list[str]:
    """Return one finding for each key of ``mapping`` that ``allowed`` does not name."""
    return [
        f"{where} has {key}, which is not allowed" + (f": {WHY[key]}" if key in WHY else "")
        for key in sorted(mapping)
        if key not in allowed
    ]


def trigger_findings(on: object) -> list[str]:
    """Check the workflow starts on a push to main and on nothing else."""
    events = as_mapping(on)
    if events is None:
        return [f"on must be a mapping with the push event alone, got {on!r}"]
    findings = [
        f"on has {event}: only a push to {BRANCH} may start a delivery, "
        "so a pull request, a schedule or a manual run must not"
        for event in sorted(events)
        if event != "push"
    ]
    if events.get("push") != {"branches": [BRANCH]}:
        findings.append(
            f"on.push must be exactly branches: [{BRANCH}] with no paths filter, tag or other "
            f"branch, a filter skips a delivery without a red run, got {events.get('push')!r}"
        )
    return findings


def input_findings(inputs: object, other_environments: frozenset[str]) -> list[str]:
    """Check the inputs of the call are the three set here, with the values set here."""
    given = as_mapping(inputs)
    if given is None:
        return [f"with must be a mapping of the call's inputs, got {inputs!r}"]
    findings = unexpected(given, INPUT_KEYS, "with")
    environment = given.get("environment")
    if environment != ENVIRONMENT:
        findings.append(f"with.environment must be {ENVIRONMENT}, got {environment!r}")
    if isinstance(environment, str) and environment in other_environments:
        findings.append(
            f"with.environment {environment} is also an environment of another workflow here, "
            "so one approval could release both an Ansible apply and a Pulumi apply"
        )
    directories = given.get("role-directories")
    lines = directories.splitlines() if isinstance(directories, str) else None
    if lines is None or [line for line in lines if line] != ROLE_DIRECTORIES:
        findings.append(
            f"with.role-directories must be {ROLE_DIRECTORIES} so a delivery covers what "
            f"the pull request gate covers, got {directories!r}"
        )
    if given.get("python-paths") != PYTHON_PATHS:
        findings.append(
            f"with.python-paths must be {PYTHON_PATHS!r}, got {given.get('python-paths')!r}"
        )
    return findings


def secret_findings(secrets: object) -> list[str]:
    """Check the call names its three secrets one by one and never passes the apply key."""
    if secrets == "inherit":
        return [
            "secrets: inherit passes every secret of the repository, the apply key "
            "included, to the call: name the three secrets"
        ]
    given = as_mapping(secrets)
    if given is None:
        return [f"secrets must be a mapping of the three named secrets, got {secrets!r}"]
    findings = []
    for key in sorted(given):
        if key == APPLY_KEY:
            findings.append(
                f"secrets passes {APPLY_KEY}: the apply key is a secret of the environment "
                "and is read only after the approval, so it is never passed"
            )
        elif key not in SECRETS:
            findings.append(f"secrets passes {key}, which is not one of the three named secrets")
    findings.extend(
        f"secrets.{key} must be {expected}, got {given.get(key)!r}"
        for key, expected in SECRETS.items()
        if given.get(key) != expected
    )
    return findings


def job_findings(jobs: object, other_environments: frozenset[str]) -> list[str]:
    """Check the one job calls the reusable workflow at an exact tag and sets nothing else."""
    declared = as_mapping(jobs)
    if declared is None or sorted(declared) != [JOB]:
        return [f"jobs must hold exactly one job, {JOB}, got {jobs!r}"]
    job = as_mapping(declared[JOB])
    if job is None:
        return [f"job {JOB} must be a mapping, got {declared[JOB]!r}"]
    findings = unexpected(job, JOB_KEYS, f"job {JOB}")
    uses = job.get("uses")
    if not isinstance(uses, str) or REUSABLE.fullmatch(uses) is None:
        findings.append(
            f"job {JOB} must call ansible-gated-apply.yml of branchLeft/github-workflows at an "
            f"exact tag vMAJOR.MINOR.PATCH (CI-5), got {uses!r}"
        )
    findings.extend(input_findings(job.get("with"), other_environments))
    findings.extend(secret_findings(job.get("secrets")))
    return findings


def caller_findings(workflow: object, other_environments: frozenset[str]) -> list[str]:
    """Return every way ``workflow`` weakens the delivery; none means it is as designed."""
    top = as_mapping(workflow)
    if top is None:
        return [f"{CALLER} is not a YAML mapping"]
    findings = unexpected(top, WORKFLOW_KEYS, "the workflow")
    findings.extend(trigger_findings(top.get("on")))
    if top.get("permissions") != PERMISSIONS:
        findings.append(
            "permissions must be exactly contents: read and actions: read (the plan job "
            f"reads the run record), got {top.get('permissions')!r}"
        )
    findings.extend(job_findings(top.get("jobs"), other_environments))
    return findings


def environments_used(workflows: Path, skip: str) -> tuple[frozenset[str], list[str]]:
    """Return the environments every other workflow's jobs run in, and what could not be read.

    A job names its environment either as a job key or, when it calls a reusable workflow,
    as an input in ``with``. A name that is an expression (``${{``) cannot be read, so it is
    a finding and never a silent pass.
    """
    names: set[str] = set()
    findings: list[str] = []
    for path in sorted(workflows.glob("*.y*ml")):
        if path.name == skip:
            continue
        document, problem = load_yaml(path)
        if problem is not None:
            findings.append(problem)
            continue
        top = as_mapping(document)
        jobs = as_mapping(top.get("jobs")) if top is not None else None
        for job in (jobs or {}).values():
            declared = as_mapping(job)
            if declared is None:
                continue
            spelled = [declared.get("environment")]
            if isinstance(declared.get("uses"), str):
                spelled.append((as_mapping(declared.get("with")) or {}).get("environment"))
            for environment in spelled:
                named = as_mapping(environment)
                if named is not None:
                    environment = named.get("name")
                if isinstance(environment, str) and "${{" in environment:
                    findings.append(
                        f"{path.name} names an environment by expression {environment!r}: "
                        "C4 cannot read which environment it releases, so it is a finding"
                    )
                elif isinstance(environment, str):
                    names.add(environment)
    return frozenset(names), findings


def check_caller(root: Path) -> list[str]:
    """Read the caller under ``root`` and return its findings."""
    workflows = root / ".github" / "workflows"
    others, findings = environments_used(workflows, Path(CALLER).name)
    document, problem = load_yaml(root / CALLER)
    if problem is not None:
        return [*findings, problem]
    return [*findings, *caller_findings(document, others)]


def environment_findings(
    name: str, environment: object, policies: object, secrets: object | None
) -> list[str]:
    """Judge the answers of the environment, branch-policy and secret-list calls.

    A missing environment answers with a body that has no name, and the same goes for a
    branch-policy list of an environment with no branch policy, so a 404 is a finding and
    not a pass. ``secrets`` is None when the caller could not list the secrets.
    """
    described = as_mapping(environment)
    if described is None or described.get("name") != name:
        return [
            f"environment {name} was not returned (a missing one answers 404), and the first "
            "run that names a missing environment creates it with no protection"
        ]
    findings: list[str] = []
    rules = described.get("protection_rules")
    reviewer_rules = [
        rule
        for rule in (as_mapping(item) for item in (rules if isinstance(rules, list) else []))
        if rule is not None and rule.get("type") == "required_reviewers"
    ]
    if not reviewer_rules:
        findings.append(
            f"environment {name} has no required reviewers rule: the apply would not wait"
        )
    for rule in reviewer_rules:
        # Owner ruling 6320444361 (self-review-deploy-2338, answer A): Prevent self-review stays
        # on for this environment. Anything but exactly True, a missing key included, is a
        # finding, so the probe proves the ruled value and not an absence of the field.
        if rule.get("prevent_self_review") is not True:
            findings.append(
                f"environment {name} does not have Prevent self-review ticked: owner ruling "
                "6320444361 requires it on, so the owner's own merge cannot release a run "
                "it started without the approval path recorded in ws#2338"
            )
        listed = rule.get("reviewers")
        reviewers = [as_mapping(entry) for entry in (listed if isinstance(listed, list) else [])]
        if not reviewers:
            findings.append(f"environment {name} lists no reviewer")
        for entry in reviewers:
            who = reviewer_identity(entry)
            if who not in OWNER_REVIEWERS:
                findings.append(
                    f"environment {name} lets {who[0]} {who[1]} approve: only the owner may"
                )
    policy = as_mapping(described.get("deployment_branch_policy"))
    if policy is None or policy.get("custom_branch_policies") is not True:
        findings.append(f"environment {name} has no custom branch policy: any branch could deploy")
    findings.extend(branch_policy_findings(name, policies))
    if secrets is not None:
        listed_secrets = as_mapping(secrets)
        entries = listed_secrets.get("secrets") if listed_secrets is not None else None
        held = {
            str(entry.get("name", "")).casefold()
            for entry in (
                as_mapping(item) for item in (entries if isinstance(entries, list) else [])
            )
            if entry is not None
        }
        if APPLY_KEY not in held:
            findings.append(f"environment {name} holds no secret {APPLY_KEY}")
    return findings


def reviewer_identity(entry: dict[str, object] | None) -> tuple[str, str]:
    """Return (type, login or slug) of one reviewer entry, or ('unreadable', '') when unreadable."""
    if entry is None:
        return ("unreadable", "")
    person = as_mapping(entry.get("reviewer"))
    kind = entry.get("type")
    if person is None or not isinstance(kind, str):
        return ("unreadable", "")
    label = person.get("login") if kind == "User" else person.get("slug")
    return (kind, label) if isinstance(label, str) else ("unreadable", "")


def branch_policy_findings(name: str, policies: object) -> list[str]:
    """Check the environment deploys from the default branch only."""
    listed = as_mapping(policies)
    entries = listed.get("branch_policies") if listed is not None else None
    if not isinstance(entries, list):
        return [f"environment {name} has no branch policy list (a missing policy answers 404)"]
    pairs = [
        (entry.get("name"), entry.get("type"))
        for entry in (as_mapping(item) for item in entries)
        if entry is not None
    ]
    if pairs != [(BRANCH, "branch")]:
        return [f"environment {name} must deploy from the branch {BRANCH} alone, got {pairs!r}"]
    return []


def read_json(path: Path) -> tuple[object, str | None]:
    """Return the JSON in ``path``, or a finding saying why it could not be read."""
    try:
        document: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return None, f"{path.name} cannot be read as JSON: {type(error).__name__}"
    return document, None


def main(argv: Sequence[str]) -> int:
    """Print every finding and return 1 if there is one."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", maxsplit=1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    caller = commands.add_parser("caller", help="check the caller workflow")
    caller.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root to check")
    environment = commands.add_parser("environment", help="check the environment's protection")
    environment.add_argument("--name", default=ENVIRONMENT)
    environment.add_argument("--environment", type=Path, required=True, dest="described")
    environment.add_argument("--policies", type=Path, required=True)
    environment.add_argument("--secrets", type=Path, default=None)
    args = parser.parse_args(argv)
    notes: list[str] = []
    if args.command == "caller":
        findings = check_caller(args.root)
    else:
        findings = []
        answers: list[object] = []
        for path in (args.described, args.policies, args.secrets):
            if path is None:
                answers.append(None)
                continue
            document, problem = read_json(path)
            answers.append(document)
            if problem is not None:
                findings.append(problem)
        if args.secrets is None:
            notes.append(f"the secrets were not listed, so {APPLY_KEY} was not checked")
        findings.extend(environment_findings(args.name, answers[0], answers[1], answers[2]))
    for finding in findings:
        print(f"FAIL {finding}")
    for note in notes:
        print(f"note {note}")
    print(f"check_delivery {args.command}: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
