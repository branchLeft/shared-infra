"""Check the caller of the gated apply, and the environment that gates it (ANS-17).

``caller`` reads .github/workflows/ansible-delivery.yml and fails on anything that
would let a pull request, a schedule or a manual run reach a host, float on a moved
workflow, hand the call any secret but the six it names, share an approval
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
    r"branchLeft/github-workflows/\.github/workflows/ansible-gated-apply\.yml@v(\d+)\.(\d+)\.(\d+)",
    re.ASCII,
)
# The oldest release of the reusable workflows a caller may pin: it declares the jump secrets and
# the shard-timeout-minutes input. A call that passes a secret or an input the called workflow
# does not declare fails on GitHub, so a pin below this is a broken delivery. The drift caller's
# test imports it: this is its one home.
MIN_RELEASE = (1, 0, 18)
ROLE_DIRECTORIES = ["roles/*", "patterns/*"]
# The one expression C4 reads in an environment name, and it reads this shape alone:
#   ${{ needs.<job>.outputs.<name> == '<A>' && '<A>' || '<B>' }}
# A and B are plain literals (an ASCII letter or digit first, then letters, digits, dot,
# underscore or hyphen), and A is the same literal in the test and in the result, so the
# value is A or B and nothing else. Used with fullmatch and in ASCII mode: another operator,
# a branch that is not a literal, a third branch, another context (github, inputs, vars),
# concatenation, a function call, a nested expression or any text around it does not match.
ENVIRONMENT_LITERAL = r"[A-Za-z0-9][A-Za-z0-9._-]*"
CHOSEN_ENVIRONMENT = re.compile(
    r"\$\{\{[ \t]+needs\.[A-Za-z_][A-Za-z0-9_-]*\.outputs\.[A-Za-z_][A-Za-z0-9_-]*"
    r"[ \t]+==[ \t]+'(?P<first>" + ENVIRONMENT_LITERAL + r")'"
    r"[ \t]+&&[ \t]+'(?P=first)'"
    r"[ \t]+\|\|[ \t]+'(?P<second>" + ENVIRONMENT_LITERAL + r")'"
    r"[ \t]+\}\}",
    re.ASCII,
)
PYTHON_PATHS = "harness checks"
# The script, relative to the Ansible directory, that tests one role: the entry point the pull
# request gate runs (ansible.yml), so a delivery and the gate run one sequence.
ROLE_TEST_COMMAND = "harness/run_harness.py"
PERMISSIONS = {"contents": "read", "actions": "read"}
# The only secrets the call passes, each named by its expression. The apply key is an
# environment secret: the call names it too, and only the job in the environment reads it.
SECRETS = {
    "ssh_hosts": "${{ secrets.ANSIBLE_HOSTS }}",
    "ssh_known_hosts": "${{ secrets.ANSIBLE_KNOWN_HOSTS }}",
    "ssh_check_key": "${{ secrets.ANSIBLE_CHECK_KEY }}",
    "ssh_apply_key": "${{ secrets.SSH_APPLY_KEY }}",
    # Both or neither: an unset repository secret is empty, and empty means no jump.
    "ssh_jump_host": "${{ secrets.SSH_JUMP_HOST }}",
    "ssh_jump_key": "${{ secrets.SSH_JUMP_KEY }}",
}
APPLY_KEY = "ssh_apply_key"

WORKFLOW_KEYS = frozenset({"name", "on", "permissions", "jobs"})
JOB_KEYS = frozenset({"uses", "with", "secrets", "needs"})
SKIP_INPUT = "skip-rerun-after-merge-group"
CHECK_NAME_INPUT = "merge-group-check-name"
INPUT_KEYS = frozenset(
    {
        "environment",
        "role-directories",
        "python-paths",
        "role-test-command",
        SKIP_INPUT,
        CHECK_NAME_INPUT,
        "shard-timeout-minutes",
    }
)
# The delivery may skip its lint and Molecule re-run only on the answer of the proof job, which
# is true for a successful merge_group run of this exact commit (merge_group_proof.py). A static
# true would skip it for a merge that never went through the queue, or refuse that merge.
PROOF_JOB = "queue-proof"
PROOF_STEP = "proof"
SKIP_EXPRESSION = "${{ needs.queue-proof.outputs.tested == 'true' }}"
PROOF_OUTPUTS = {"tested": "${{ steps.proof.outputs.tested }}"}
# The check run the merge queue publishes for the gate: the name of the gate job of ansible.yml
# (test_check_delivery.py reads it from there). The reusable workflow looks for it by this name.
GATE_CHECK_NAME = "Lint and test the Ansible roles"
PROOF_SCRIPT = "ansible/checks/merge_group_proof.py"
PROOF_JOB_KEYS = frozenset({"name", "runs-on", "timeout-minutes", "outputs", "steps"})
CHECKOUT_KEYS = frozenset({"name", "uses", "with"})
PROOF_STEP_KEYS = frozenset({"name", "id", "env", "run"})
CHECKOUT_WITH = {"persist-credentials": False}
PROOF_ENV = {
    "GH_TOKEN": "${{ github.token }}",
    "REPO": "${{ github.repository }}",
    "SHA": "${{ github.sha }}",
}
# What a key that must not be there would do, for the finding's text.
WHY = {
    "dry-run": "a dry run replaces the host call, so a green run would reach no host",
    "dry-run-stub": "a stand-in for the host",
    "if": "a condition can skip the delivery without a red run",
    "needs": "a dependency can skip the delivery without a red run",
    "continue-on-error": "a failed proof would read as a pass",
    "environment": "the environment is an input of the call, not a job key",
    "permissions": "the token is set once, for the whole workflow",
}

# Who may approve the apply: the branchleft-admin team alone. No other user, team or app is an
# approver of this environment. The probe does not read a team's members, so membership of the
# team is not checked here.
OWNER_REVIEWERS = frozenset({("Team", "branchleft-admin")})
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
    # GitHub reads an environment name without regard to case, so Ansible-Hosts and
    # ansible-hosts are one environment and one approval.
    folded = {name.casefold() for name in other_environments}
    if isinstance(environment, str) and environment.casefold() in folded:
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
    if given.get("role-test-command") != ROLE_TEST_COMMAND:
        findings.append(
            f"with.role-test-command must be {ROLE_TEST_COMMAND!r}, the entry point the pull "
            "request gate runs, so a delivery tests a role as the gate does, got "
            f"{given.get('role-test-command')!r}"
        )
    if given.get(SKIP_INPUT) != SKIP_EXPRESSION:
        findings.append(
            f"with.{SKIP_INPUT} must be {SKIP_EXPRESSION!r}, so only a commit the proof job found "
            f"tested by the merge queue skips the re-test, got {given.get(SKIP_INPUT)!r}"
        )
    if given.get(CHECK_NAME_INPUT) != GATE_CHECK_NAME:
        findings.append(
            f"with.{CHECK_NAME_INPUT} must be {GATE_CHECK_NAME!r}, the gate job of ansible.yml, "
            f"got {given.get(CHECK_NAME_INPUT)!r}"
        )
    return findings


def secret_findings(secrets: object) -> list[str]:
    """Check the call names its six secrets one by one, the apply key and the jump pair too."""
    if secrets == "inherit":
        return [
            "secrets: inherit passes every secret of the repository to the call: name the six "
            "secrets"
        ]
    given = as_mapping(secrets)
    if given is None:
        return [f"secrets must be a mapping of the six named secrets, got {secrets!r}"]
    findings = []
    for key in sorted(given):
        if key not in SECRETS:
            findings.append(f"secrets passes {key}, which is not one of the six named secrets")
    findings.extend(
        f"secrets.{key} must be {expected}, got {given.get(key)!r}"
        for key, expected in SECRETS.items()
        if given.get(key) != expected
    )
    return findings


def proof_step_findings(steps: object) -> list[str]:
    """Check the proof job is the checkout and the one step that runs the proof script."""
    mappings = [as_mapping(step) for step in steps] if isinstance(steps, list) else []
    if len(mappings) != 2:
        return [f"job {PROOF_JOB} must hold exactly two steps (checkout, proof), got {steps!r}"]
    checkout, proof = mappings
    if checkout is None or proof is None:
        return [f"job {PROOF_JOB} steps must be mappings, got {steps!r}"]
    findings = unexpected(checkout, CHECKOUT_KEYS, "the checkout step")
    uses = checkout.get("uses")
    if not isinstance(uses, str) or not uses.startswith("actions/checkout@"):
        findings.append(f"the checkout step must use actions/checkout, got {uses!r}")
    if checkout.get("with") != CHECKOUT_WITH:
        findings.append(
            f"the checkout step with must be {CHECKOUT_WITH!r}: the commit pushed, no credentials "
            f"kept, got {checkout.get('with')!r}"
        )
    findings.extend(unexpected(proof, PROOF_STEP_KEYS, f"step {PROOF_STEP}"))
    if proof.get("id") != PROOF_STEP:
        findings.append(f"step {PROOF_STEP} id must be {PROOF_STEP}, got {proof.get('id')!r}")
    if proof.get("env") != PROOF_ENV:
        findings.append(
            f"step {PROOF_STEP} env must be {PROOF_ENV!r}: the pushed commit and the run's own "
            f"read-only token, got {proof.get('env')!r}"
        )
    run = proof.get("run")
    wanted = (f"python3 {PROOF_SCRIPT} --runs", '--sha "$SHA"', "$GITHUB_OUTPUT")
    # A literal answer in the script text would decide the skip without the evidence.
    if not isinstance(run, str) or any(part not in run for part in wanted) or "tested=" in run:
        findings.append(
            f"step {PROOF_STEP} run must run {PROOF_SCRIPT} on the runs file and the pushed "
            f"commit and write its output to $GITHUB_OUTPUT, and set no answer itself, got {run!r}"
        )
    return findings


def proof_findings(declared: object) -> list[str]:
    """Check the proof job is the one fixed shape that decides whether the re-test is skipped."""
    job = as_mapping(declared)
    if job is None:
        return [f"job {PROOF_JOB} must be a mapping, got {declared!r}"]
    findings = unexpected(job, PROOF_JOB_KEYS, f"job {PROOF_JOB}")
    if job.get("outputs") != PROOF_OUTPUTS:
        findings.append(
            f"job {PROOF_JOB} outputs must be {PROOF_OUTPUTS!r}, got {job.get('outputs')!r}"
        )
    findings.extend(proof_step_findings(job.get("steps")))
    return findings


def job_findings(jobs: object, other_environments: frozenset[str]) -> list[str]:
    """Check the proof job is fixed and the call is the reusable workflow at an exact tag."""
    declared = as_mapping(jobs)
    if declared is None or sorted(declared) != sorted([PROOF_JOB, JOB]):
        return [f"jobs must hold exactly the two jobs {PROOF_JOB} and {JOB}, got {jobs!r}"]
    findings = proof_findings(declared[PROOF_JOB])
    job = as_mapping(declared[JOB])
    if job is None:
        return [*findings, f"job {JOB} must be a mapping, got {declared[JOB]!r}"]
    findings.extend(unexpected(job, JOB_KEYS, f"job {JOB}"))
    if "needs" not in job:
        findings.append(f"job {JOB} must have needs {[PROOF_JOB]!r}, so it waits for the proof")
    elif job["needs"] != [PROOF_JOB]:
        findings.append(
            f"job {JOB} has needs {job['needs']!r}, which is not allowed: it must be exactly "
            f"{[PROOF_JOB]!r}, so it waits for the proof and for nothing that could skip it"
        )
    uses = job.get("uses")
    pinned = REUSABLE.fullmatch(uses) if isinstance(uses, str) else None
    if pinned is None:
        findings.append(
            f"job {JOB} must call ansible-gated-apply.yml of branchLeft/github-workflows at an "
            f"exact tag vMAJOR.MINOR.PATCH (CI-5), got {uses!r}"
        )
    elif tuple(int(part) for part in pinned.groups()) < MIN_RELEASE:
        floor = ".".join(str(part) for part in MIN_RELEASE)
        findings.append(
            f"job {JOB} calls {uses!r}, older than v{floor}, the first release that declares the "
            "jump secrets: a call that passes a secret the workflow does not declare fails"
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


def chosen_environments(expression: str) -> tuple[str, str] | None:
    """Return the two environments the one accepted expression names, else None.

    The accepted expression is ``CHOSEN_ENVIRONMENT``: a job output picks between two literals.
    Nothing else is read, so a caller that has to be sure which environment a job releases
    treats None as unreadable.
    """
    found = CHOSEN_ENVIRONMENT.fullmatch(expression)
    if found is None:
        return None
    return found["first"], found["second"]


def environments_used(workflows: Path, skip: str) -> tuple[frozenset[str], list[str]]:
    """Return the environments every other workflow's jobs run in, and what could not be read.

    A job names its environment as a job key or as ``with.environment`` of a call, as a string
    or a mapping's ``name``. An expression cannot be read, so it is a finding, except the closed
    shape of ``CHOSEN_ENVIRONMENT``, whose two literals are both judged (see the README).

    Named limit: a remote reusable workflow (``uses: org/repo/...@tag``) may run in an
    environment named inside it, and nothing here can see that.
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
                    chosen = chosen_environments(environment)
                    if chosen is None:
                        findings.append(
                            f"{path.name} names an environment by expression {environment!r}: "
                            "C4 cannot read which environment it releases, so it is a finding"
                        )
                    else:
                        names.update(chosen)
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
    # Administrators may release a blocked run without a reviewer unless this is exactly False,
    # and a new environment answers True. A missing key is a finding, so the probe proves the
    # ruled value and not an absence of the field.
    if described.get("can_admins_bypass") is not False:
        findings.append(
            f"environment {name} lets administrators bypass its protection rules: an administrator "
            "whose merge started a run could then release it without the approval path, so 'Allow "
            "administrators to bypass configured protection rules' must be off"
        )
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
        # The owner keeps Prevent self-review on for this environment, so a person who merged a
        # change cannot approve the deploy their merge started. Anything but exactly True, a
        # missing key included, is a finding, so the probe proves the set value and not an
        # absence of the field.
        if rule.get("prevent_self_review") is not True:
            findings.append(
                f"environment {name} does not have Prevent self-review ticked: without it, a "
                "person who merged a change could approve the deploy that merge started"
            )
        listed = rule.get("reviewers")
        reviewers = [as_mapping(entry) for entry in (listed if isinstance(listed, list) else [])]
        if not reviewers:
            findings.append(f"environment {name} lists no reviewer")
        for entry in reviewers:
            who = reviewer_identity(entry)
            if who not in OWNER_REVIEWERS:
                findings.append(
                    f"environment {name} lets {who[0]} {who[1]} approve: only the branchleft-admin "
                    "team may"
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
