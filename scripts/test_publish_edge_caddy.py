#!/usr/bin/env python3
"""Pin tests for publish-edge-caddy.yml: what it refuses, and that each refusal can fail.

The workflow is parsed with the strict loader from test_workflow_concurrency, never
grepped. problems() is the whole set of pins, so a mutated copy of the file can be
fed to it; the step bodies that decide a refusal are also run under bash with a fake
docker. The rules are written up in test_publish_edge_caddy.md.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import re
import subprocess
import tempfile
import unittest
from collections.abc import Callable, Iterator

import yaml

import test_workflow_concurrency as concurrency_rules

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW_NAME = "publish-edge-caddy.yml"
WORKFLOW = ROOT / ".github" / "workflows" / WORKFLOW_NAME
DOCKERFILE = ROOT / "hetzner" / "edge" / "Dockerfile"

JOB_NAME = "publish"
STEP_ORDER = [
    "main-only",
    "revision",
    "native-architecture",
    "checkout",
    "tag",
    "login",
    "absent",
    "build",
    "built-architecture",
    "push",
    "digest",
    "summary",
]
ALLOWED_ACTIONS = {"actions/checkout", "docker/login-action"}
PINNED_ACTION = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"#\s*v\d+\.\d+\.\d+\s*$")
LATEST = re.compile(r"(?<![\w-])latest(?![\w-])")
SECRET_OTHER_THAN_GITHUB_TOKEN = re.compile(r"\bsecrets\b(?!\.GITHUB_TOKEN\b)")
ALL_HEX = "0123456789abcdef"
DIGEST = "sha256:" + ALL_HEX * 4

Path = tuple[str | int, ...]
Check = Callable[[dict[str, object], str], list[str]]


class WorkflowShapeError(Exception):
    """A key, step or value the pins need is missing or has the wrong shape."""


def mapping(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise WorkflowShapeError(f"{where} is not a mapping with string keys")
    return value


def the_job(data: dict[str, object]) -> dict[str, object]:
    jobs = mapping(data.get("jobs"), "jobs")
    if list(jobs) != [JOB_NAME]:
        raise WorkflowShapeError(f"jobs must be exactly [{JOB_NAME!r}], found {list(jobs)}")
    return mapping(jobs[JOB_NAME], f"job {JOB_NAME}")


def the_steps(data: dict[str, object]) -> list[dict[str, object]]:
    steps = the_job(data).get("steps")
    if not isinstance(steps, list):
        raise WorkflowShapeError("the job has no steps list")
    return [mapping(step, f"step {index}") for index, step in enumerate(steps)]


def step_by_id(data: dict[str, object], step_id: str) -> dict[str, object]:
    for step in the_steps(data):
        if step.get("id") == step_id:
            return step
    raise WorkflowShapeError(f"step {step_id!r} is missing")


def run_of(data: dict[str, object], step_id: str) -> str:
    run = step_by_id(data, step_id).get("run")
    if not isinstance(run, str):
        raise WorkflowShapeError(f"step {step_id!r} has no run body")
    return "\n".join(line for line in run.splitlines() if not line.lstrip().startswith("#"))


def env_of(step: dict[str, object]) -> dict[str, object]:
    return mapping(step.get("env", {}), "env")


def strings(value: object, path: Path = ()) -> Iterator[tuple[Path, str]]:
    """Every string in the parsed workflow with the keys and indexes that lead to it."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from strings(child, (*path, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from strings(child, (*path, index))


def missing_fragments(where: str, body: str, fragments: list[str]) -> list[str]:
    return [f"{where} lacks {fragment!r}" for fragment in fragments if fragment not in body]


def check_triggers(data: dict[str, object], text: str) -> list[str]:
    found = []
    names = concurrency_rules.trigger_names(data)
    if names != {"workflow_dispatch"}:
        found.append(f"trigger set must be exactly workflow_dispatch, found {sorted(names)}")
    dispatch = mapping(mapping(data["on"], "on")["workflow_dispatch"], "workflow_dispatch")
    inputs = mapping(dispatch.get("inputs"), "inputs")
    revision = mapping(inputs.get("revision"), "input revision")
    if list(inputs) != ["revision"] or revision.get("required") is not True or revision.get("type") != "string":
        found.append("the only input must be a required string named revision")
    return found


def check_permissions(data: dict[str, object], text: str) -> list[str]:
    found = []
    if data.get("permissions") != {"contents": "read"}:
        found.append(f"top-level permissions must be exactly contents: read, found {data.get('permissions')!r}")
    wanted = {"contents": "read", "packages": "write"}
    if the_job(data).get("permissions") != wanted:
        found.append(f"job permissions must be exactly {wanted}, found {the_job(data).get('permissions')!r}")
    return found


def check_pins(data: dict[str, object], text: str) -> list[str]:
    found = []
    seen = set()
    for step in the_steps(data):
        uses = step.get("uses")
        if uses is None:
            continue
        if not isinstance(uses, str) or not PINNED_ACTION.match(uses):
            found.append(f"uses {uses!r} is not pinned to a 40-character commit")
            continue
        seen.add(uses.split("@")[0])
        lines = [line for line in text.splitlines() if "uses:" in line and uses in line]
        if not any(VERSION_COMMENT.search(line) for line in lines):
            found.append(f"uses {uses!r} has no '# vX.Y.Z' comment")
    if seen != ALLOWED_ACTIONS:
        found.append(f"actions used must be exactly {sorted(ALLOWED_ACTIONS)}, found {sorted(seen)}")
    return found


def check_job_settings(data: dict[str, object], text: str) -> list[str]:
    found = []
    job = the_job(data)
    timeout = job.get("timeout-minutes")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        found.append(f"timeout-minutes must be a positive integer, found {timeout!r}")
    if job.get("runs-on") != "ubuntu-latest":
        found.append(f"runs-on must be ubuntu-latest, found {job.get('runs-on')!r}")
    checkout = mapping(step_by_id(data, "checkout").get("with"), "checkout with")
    if checkout.get("persist-credentials") is not False:
        found.append("checkout must set persist-credentials: false")
    if job.get("concurrency") != {"group": "publish-edge-caddy-image", "cancel-in-progress": False}:
        found.append(f"job concurrency must be the literal group without cancelling, found {job.get('concurrency')!r}")
    return found


def check_main_only(data: dict[str, object], text: str) -> list[str]:
    found = []
    if the_job(data).get("if") != "github.ref == 'refs/heads/main'":
        found.append(f"the job's if must be the main-only condition, found {the_job(data).get('if')!r}")
    steps = the_steps(data)
    if not steps or steps[0].get("id") != "main-only":
        found.append("the first step must be the main-only guard")
    found += missing_fragments(
        "main-only step", run_of(data, "main-only"), ['"$GITHUB_REF" != "refs/heads/main"', "exit 1"]
    )
    return found


def check_order(data: dict[str, object], text: str) -> list[str]:
    ids = [step.get("id") for step in the_steps(data)]
    return [] if ids == STEP_ORDER else [f"step ids must be {STEP_ORDER} in that order, found {ids}"]


def check_login_and_secrets(data: dict[str, object], text: str) -> list[str]:
    found = []
    login = step_by_id(data, "login")
    arguments = mapping(login.get("with"), "login with")
    if not str(login.get("uses", "")).startswith("docker/login-action@"):
        found.append("the login step must use docker/login-action")
    if arguments.get("registry") != "ghcr.io":
        found.append("the login step must log in to ghcr.io")
    if arguments.get("password") != "${{ secrets.GITHUB_TOKEN }}":
        found.append(f"the login password must be secrets.GITHUB_TOKEN, found {arguments.get('password')!r}")
    for path, value in strings(data):
        if SECRET_OTHER_THAN_GITHUB_TOKEN.search(value):
            found.append(f"{'.'.join(map(str, path))} names a secret other than GITHUB_TOKEN")
    return found


def check_revision_reaches_shell_only_through_env(data: dict[str, object], text: str) -> list[str]:
    found = []
    revision = step_by_id(data, "revision")
    if env_of(revision).get("REVISION") != "${{ inputs.revision }}":
        found.append("the revision step must read inputs.revision through env: REVISION")
    for step in the_steps(data):
        run = step.get("run")
        if isinstance(run, str) and "${{" in run:
            found.append(f"step {step.get('id')!r} interpolates an expression into its run body")
    for path, value in strings(data):
        if "inputs.revision" in value and not (len(path) >= 2 and path[-2] == "env"):
            found.append(f"inputs.revision is used outside an env value at {'.'.join(map(str, path))}")
    return found


def check_no_forbidden_words(data: dict[str, object], text: str) -> list[str]:
    found = []
    for path, value in strings(data):
        where = ".".join(map(str, path))
        if LATEST.search(value):
            found.append(f"{where} mentions a latest tag")
        for word in ("--platform", "qemu", "buildx", "list-modules"):
            if word in value.lower():
                found.append(f"{where} contains {word!r}")
    return found


def check_revision_and_tag_steps(data: dict[str, object], text: str) -> list[str]:
    found = missing_fragments(
        "revision step",
        run_of(data, "revision"),
        ["^[1-9][0-9]*$", "[[ $REVISION =~ $pattern ]]", "exit 1", 'echo "REVISION=$REVISION" >> "$GITHUB_ENV"'],
    )
    found += missing_fragments(
        "tag step",
        run_of(data, "tag"),
        [
            "hetzner/edge/Dockerfile",
            "^ARG CADDY_VERSION=",
            "^[0-9]+\\.[0-9]+\\.[0-9]+$",
            "[[ $caddy_version =~ $pattern ]]",
            "exit 1",
            "IMAGE_TAG=caddy-${caddy_version}-${REVISION}",
        ],
    )
    return found


def check_architecture_steps(data: dict[str, object], text: str) -> list[str]:
    found = missing_fragments(
        "native-architecture step",
        run_of(data, "native-architecture"),
        ["uname -m", "x86_64", "{{.Server.Arch}}", '"$server" != "amd64"', "exit 1"],
    )
    found += missing_fragments(
        "built-architecture step",
        run_of(data, "built-architecture"),
        ["{{.Architecture}}", '"$architecture" != "amd64"', "exit 1"],
    )
    return found


def check_build_step(data: dict[str, object], text: str) -> list[str]:
    return missing_fragments(
        "build step",
        run_of(data, "build"),
        [
            "docker build",
            "--file hetzner/edge/Dockerfile",
            "--label org.opencontainers.image.source=https://github.com/branchLeft/shared-infra",
            '--label "org.opencontainers.image.revision=$GITHUB_SHA"',
            '--tag "$IMAGE:$IMAGE_TAG"',
        ],
    )


def check_refusals(data: dict[str, object], text: str) -> list[str]:
    found = missing_fragments(
        "absent step",
        run_of(data, "absent"),
        ['docker manifest inspect "$IMAGE:$IMAGE_TAG"', "no such manifest", "manifest unknown", "exit 1"],
    )
    found += missing_fragments(
        "digest step",
        run_of(data, "digest"),
        [
            "RepoDigests",
            "^sha256:[0-9a-f]{64}$",
            "[[ $digest =~ $pattern ]]",
            "exit 1",
            'echo "image=$IMAGE@$digest" >> "$GITHUB_OUTPUT"',
        ],
    )
    if the_job(data).get("outputs") != {"image": "${{ steps.digest.outputs.image }}"}:
        found.append("the job must expose exactly the image output from the digest step")
    return found


def check_summary(data: dict[str, object], text: str) -> list[str]:
    found = missing_fragments(
        "summary step",
        run_of(data, "summary"),
        ["GITHUB_STEP_SUMMARY", "NO DIGEST", "Build and publish the Caddy image"],
    )
    summary = step_by_id(data, "summary")
    if the_steps(data)[-1] is not summary:
        found.append("the summary must be the last step")
    if summary.get("if") != "always()":
        found.append("the summary step must run if: always()")
    if env_of(summary).get("PINNED_IMAGE") != "${{ steps.digest.outputs.image }}":
        found.append("the summary must read the digest step's image output")
    return found


CHECKS: tuple[Check, ...] = (
    check_triggers,
    check_permissions,
    check_pins,
    check_job_settings,
    check_main_only,
    check_order,
    check_login_and_secrets,
    check_revision_reaches_shell_only_through_env,
    check_no_forbidden_words,
    check_revision_and_tag_steps,
    check_architecture_steps,
    check_build_step,
    check_refusals,
    check_summary,
)


def problems(text: str, others: tuple[tuple[str, object, str], ...] = ()) -> list[str]:
    """Every pin the workflow text breaks, or [] for a file that holds them all.

    A missing job, step or key is a problem, never a pass. others are the other
    workflows' top-level concurrency groups, as test_workflow_concurrency.others_for returns them.
    """
    try:
        data = concurrency_rules.load(text)
    except yaml.YAMLError as error:
        return [f"does not parse as strict YAML: {error}"]
    if not isinstance(data, dict):
        return ["top level is not a mapping"]
    found = list(concurrency_rules.violations(WORKFLOW_NAME, text, others))
    for check in CHECKS:
        try:
            found += check(data, text)
        except (WorkflowShapeError, concurrency_rules.Unclassifiable, KeyError) as error:
            found.append(f"{check.__name__}: cannot read the workflow: {error}")
    return found


def real_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def other_workflows() -> tuple[tuple[str, object, str], ...]:
    documents = [(path.name, path.read_text(encoding="utf-8")) for path in concurrency_rules.workflow_files()]
    return concurrency_rules.others_for(WORKFLOW_NAME, documents)


class PublishEdgeCaddyPinTests(unittest.TestCase):
    def test_the_workflow_holds_every_pin(self) -> None:
        self.assertEqual(problems(real_text(), other_workflows()), [])

    def test_the_workflow_is_one_of_the_walked_files(self) -> None:
        self.assertIn(WORKFLOW_NAME, {path.name for path in concurrency_rules.workflow_files()})

    def test_the_workflow_builds_the_dockerfile_it_reads_the_version_from(self) -> None:
        self.assertRegex(DOCKERFILE.read_text(encoding="utf-8"), r"(?m)^ARG CADDY_VERSION=\d+\.\d+\.\d+$")


TRIGGER_HEAD = "on:\n  workflow_dispatch:\n    inputs:"
CHECKOUT_PIN = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
LOGIN_PIN = "docker/login-action@81c6f93d4bc991e510b342a00b419b3bb4efc5c6"

# name -> (text to replace, replacement, a fragment the reported problems must contain)
MUTATIONS = {
    "a-push-trigger": (TRIGGER_HEAD, "on:\n  push:\n  workflow_dispatch:\n    inputs:", "trigger set"),
    "a-pull-request-trigger": (TRIGGER_HEAD, "on:\n  pull_request:\n  workflow_dispatch:\n    inputs:", "trigger set"),
    "a-pull-request-target-trigger": (
        TRIGGER_HEAD,
        "on:\n  pull_request_target:\n  workflow_dispatch:\n    inputs:",
        "trigger set",
    ),
    "a-schedule-trigger": (
        TRIGGER_HEAD,
        "on:\n  schedule:\n    - cron: '0 0 * * *'\n  workflow_dispatch:\n    inputs:",
        "trigger set",
    ),
    "a-merge-group-trigger": (TRIGGER_HEAD, "on:\n  merge_group:\n  workflow_dispatch:\n    inputs:", "trigger set"),
    "a-revision-input-not-required": ("        required: true\n", "        required: false\n", "named revision"),
    "b-packages-write-at-top": (
        "permissions:\n  contents: read\n\njobs:",
        "permissions:\n  contents: read\n  packages: write\n\njobs:",
        "top-level permissions",
    ),
    "b-job-loses-packages-write": ("      packages: write\n", "", "job permissions"),
    "b-job-gains-another-permission": (
        "      packages: write\n",
        "      packages: write\n      id-token: write\n",
        "job permissions",
    ),
    "c-checkout-pinned-by-tag": (CHECKOUT_PIN, "actions/checkout@v7", "not pinned"),
    "c-login-pinned-by-short-sha": (LOGIN_PIN, "docker/login-action@81c6f93", "not pinned"),
    "c-version-comment-removed": (CHECKOUT_PIN + " # v7.0.1", CHECKOUT_PIN, "no '# vX.Y.Z' comment"),
    "c-qemu-action-used": (
        LOGIN_PIN + " # v4.7.0",
        "docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130 # v3.7.0",
        "actions used",
    ),
    "d-main-only-condition-removed": ("    if: github.ref == 'refs/heads/main'\n", "", "main-only condition"),
    "d-main-only-guard-disabled": (
        'if [ "$GITHUB_REF" != "refs/heads/main" ]; then',
        "if false; then",
        "main-only step",
    ),
    "e-digest-check-disabled": ("if ! [[ $digest =~ $pattern ]]; then", "if false; then", "digest step"),
    "e-digest-pattern-loosened": ("pattern='^sha256:[0-9a-f]{64}$'", "pattern='^sha256:[0-9a-f]+$'", "digest step"),
    "f-overwrite-refusal-removed": (
        'docker manifest inspect "$IMAGE:$IMAGE_TAG"',
        'docker pull "$IMAGE:$IMAGE_TAG"',
        "absent step",
    ),
    "f-overwrite-refusal-renamed-away": ("        id: absent\n", "        id: absent-removed\n", "absent"),
    "g-platform-flag-added": (
        "            --file hetzner/edge/Dockerfile \\\n",
        "            --platform linux/arm64 \\\n            --file hetzner/edge/Dockerfile \\\n",
        "--platform",
    ),
    "g-qemu-named": ('echo "REVISION=$REVISION"', 'echo qemu; echo "REVISION=$REVISION"', "qemu"),
    "h-latest-tag-added": (
        '            --tag "$IMAGE:$IMAGE_TAG" \\\n',
        '            --tag "$IMAGE:$IMAGE_TAG" \\\n            --tag "$IMAGE:latest" \\\n',
        "latest",
    ),
    "i-revision-interpolated-into-run": (
        'echo "REVISION=$REVISION" >> "$GITHUB_ENV"',
        'echo "REVISION=${{ inputs.revision }}" >> "$GITHUB_ENV"',
        "interpolates an expression",
    ),
    "i-revision-read-without-env": (
        "          REVISION: ${{ inputs.revision }}\n",
        "          REVISION: '2'\n",
        "through env",
    ),
    "i-revision-used-in-with": (
        "          registry: ghcr.io\n",
        "          registry: ghcr.io\n          logout: ${{ inputs.revision }}\n",
        "outside an env value",
    ),
    "j-timeout-removed": ("    timeout-minutes: 15\n", "", "timeout-minutes"),
    "j-persist-credentials-removed": (
        "          persist-credentials: false\n",
        "          fetch-depth: 1\n",
        "persist-credentials",
    ),
    "j-cancel-in-progress-true": (
        "      cancel-in-progress: false\n",
        "      cancel-in-progress: true\n",
        "concurrency",
    ),
    "j-job-group-made-an-expression": (
        "      group: publish-edge-caddy-image\n",
        "      group: ${{ github.run_id }}\n",
        "concurrency",
    ),
    "k-other-secret": ("password: ${{ secrets.GITHUB_TOKEN }}", "password: ${{ secrets.PERSONAL_TOKEN }}", "secret"),
    "k-second-secret-beside": (
        "      IMAGE: ghcr.io/branchleft/edge-caddy\n",
        "      IMAGE: ghcr.io/branchleft/edge-caddy\n      EXTRA: ${{ secrets.PERSONAL_TOKEN }}\n",
        "secret",
    ),
    "l-module-assertion-copied": (
        '--tag "$IMAGE:$IMAGE_TAG" \\',
        '--tag "$IMAGE:$IMAGE_TAG" \\\n            --build-arg X="caddy list-modules" \\',
        "list-modules",
    ),
    "m-summary-not-always": ("        if: always()\n", "", "if: always()"),
    "m-summary-silent-without-digest": ("NO DIGEST", "DONE", "summary step"),
    "n-architecture-precheck-removed": ('[ "$server" != "amd64" ]', "false", "native-architecture"),
    "n-built-architecture-check-removed": ('[ "$architecture" != "amd64" ]', "false", "built-architecture"),
    "o-revision-check-removed": ("if ! [[ $REVISION =~ $pattern ]]; then", "if false; then", "revision step"),
    "o-tag-version-check-removed": ("if ! [[ $caddy_version =~ $pattern ]]; then", "if false; then", "tag step"),
    "p-step-removed": (
        '      - name: Push the image\n        id: push\n        run: docker push "$IMAGE:$IMAGE_TAG"\n\n',
        "",
        "step ids",
    ),
}


class PublishEdgeCaddyMutationTests(unittest.TestCase):
    def test_every_mutation_is_reported_by_the_pins(self) -> None:
        text = real_text()
        for name, (old, new, fragment) in MUTATIONS.items():
            with self.subTest(mutation=name):
                self.assertEqual(text.count(old), 1, f"the mutation's target occurs {text.count(old)} times")
                reported = problems(text.replace(old, new), other_workflows())
                self.assertTrue(
                    any(fragment in problem for problem in reported),
                    f"no problem mentions {fragment!r}; got {reported}",
                )

    def test_unparseable_and_empty_files_fail_closed(self) -> None:
        for name, text in {"unparseable": "on: [push\n", "empty": "", "no jobs": "on:\n  workflow_dispatch:\n"}.items():
            with self.subTest(file=name):
                self.assertNotEqual(problems(text), [])

    def test_a_pin_in_a_comment_does_not_satisfy_a_check(self) -> None:
        check = "if ! [[ $digest =~ $pattern ]]; then"
        in_shell = real_text().replace(check, f"if false; then\n          # {check}")
        in_yaml = (
            real_text()
            .replace(check, "if false; then")
            .replace("      - name: Read and verify", f"      # {check}\n      - name: Read and verify")
        )
        for name, text in {"shell comment": in_shell, "yaml comment": in_yaml}.items():
            with self.subTest(comment=name):
                self.assertNotEqual(problems(text, other_workflows()), [])


@dataclasses.dataclass(frozen=True)
class StepResult:
    returncode: int
    output: str
    github_env: str
    github_output: str
    github_summary: str


FAKE_DOCKER = '#!/bin/sh\nprintf \'%s\\n\' "$FAKE_DOCKER_OUTPUT"\nexit "${FAKE_DOCKER_STATUS:-0}"\n'
FAKE_UNAME = '#!/bin/sh\necho "$FAKE_UNAME_OUTPUT"\n'


def run_step(
    step_id: str,
    env: dict[str, str],
    docker_output: str = "",
    docker_status: int = 0,
    uname_output: str = "x86_64",
    working_directory: pathlib.Path = ROOT,
) -> StepResult:
    """Run one step's run body under `bash -e`, as the runner does, with fake docker and uname."""
    data = concurrency_rules.load(real_text())
    assert isinstance(data, dict)
    body = run_of(data, step_id)
    job_env = {key: str(value) for key, value in env_of(the_job(data)).items()}
    with tempfile.TemporaryDirectory() as scratch:
        directory = pathlib.Path(scratch)
        bin_directory = directory / "bin"
        bin_directory.mkdir()
        for name, script in (("docker", FAKE_DOCKER), ("uname", FAKE_UNAME)):
            (bin_directory / name).write_text(script, encoding="utf-8")
            (bin_directory / name).chmod(0o755)
        files = {name: directory / name for name in ("env", "output", "summary")}
        for path in files.values():
            path.write_text("", encoding="utf-8")
        script_path = directory / "step.sh"
        script_path.write_text(body, encoding="utf-8")
        completed = subprocess.run(
            ["bash", "-e", str(script_path)],
            cwd=working_directory,
            env={
                "PATH": f"{bin_directory}:{os.environ['PATH']}",
                "HOME": str(directory),
                **job_env,
                "GITHUB_ENV": str(files["env"]),
                "GITHUB_OUTPUT": str(files["output"]),
                "GITHUB_STEP_SUMMARY": str(files["summary"]),
                "FAKE_DOCKER_OUTPUT": docker_output,
                "FAKE_DOCKER_STATUS": str(docker_status),
                "FAKE_UNAME_OUTPUT": uname_output,
                **env,
            },
            capture_output=True,
            text=True,
            check=False,
        )
        return StepResult(
            completed.returncode,
            completed.stdout + completed.stderr,
            files["env"].read_text(encoding="utf-8"),
            files["output"].read_text(encoding="utf-8"),
            files["summary"].read_text(encoding="utf-8"),
        )


class MainOnlyGuardTests(unittest.TestCase):
    def test_main_passes_and_anything_else_is_refused(self) -> None:
        self.assertEqual(run_step("main-only", {"GITHUB_REF": "refs/heads/main"}).returncode, 0)
        for ref in ("refs/heads/feature", "refs/heads/main2", "refs/tags/v1", "refs/pull/1/merge", ""):
            with self.subTest(ref=ref):
                result = run_step("main-only", {"GITHUB_REF": ref})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("only from refs/heads/main", result.output)


class RevisionValidationTests(unittest.TestCase):
    def test_a_positive_integer_is_passed_on_and_nothing_else(self) -> None:
        for revision in ("1", "2", "10", "123456"):
            with self.subTest(revision=revision):
                result = run_step("revision", {"REVISION": revision})
                self.assertEqual((result.returncode, result.github_env), (0, f"REVISION={revision}\n"))

    def test_anything_else_is_refused_and_leaves_the_environment_untouched(self) -> None:
        refused = ["", "0", "01", "-1", "+1", "1.5", "abc", " 1", "1 ", "1\nINJECTED=1", "1; touch x", "$(id)", "２"]
        for revision in refused:
            with self.subTest(revision=revision):
                result = run_step("revision", {"REVISION": revision})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.github_env, "")
                self.assertIn("revision must be a positive integer", result.output)


class TagStepTests(unittest.TestCase):
    def tag_for(self, dockerfile: str | None) -> StepResult:
        with tempfile.TemporaryDirectory() as scratch:
            directory = pathlib.Path(scratch)
            if dockerfile is not None:
                (directory / "hetzner" / "edge").mkdir(parents=True)
                (directory / "hetzner" / "edge" / "Dockerfile").write_text(dockerfile, encoding="utf-8")
            return run_step("tag", {"REVISION": "7"}, working_directory=directory)

    def test_the_tag_joins_the_dockerfile_version_and_the_revision(self) -> None:
        result = self.tag_for("FROM scratch\nARG CADDY_VERSION=9.8.7\nARG OTHER=1\n")
        self.assertEqual((result.returncode, result.github_env), (0, "IMAGE_TAG=caddy-9.8.7-7\n"))

    def test_the_real_dockerfile_yields_a_well_formed_tag(self) -> None:
        result = run_step("tag", {"REVISION": "7"})
        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.github_env, r"^IMAGE_TAG=caddy-\d+\.\d+\.\d+-7\n$")

    def test_only_the_arg_line_is_read(self) -> None:
        result = self.tag_for("ARG CADDY_VERSION=1.2.3\nIMAGE_TAG=evil\n$(id)\n")
        self.assertEqual(result.github_env, "IMAGE_TAG=caddy-1.2.3-7\n")

    def test_a_missing_doubled_or_malformed_version_is_refused(self) -> None:
        refused = {
            "no file": None,
            "no line": "FROM scratch\n",
            "two lines": "ARG CADDY_VERSION=1.2.3\nARG CADDY_VERSION=1.2.4\n",
            "two parts": "ARG CADDY_VERSION=1.2\n",
            "suffix": "ARG CADDY_VERSION=1.2.3-rc1\n",
            "word": "ARG CADDY_VERSION=latest\n",
            "empty": "ARG CADDY_VERSION=\n",
        }
        for name, dockerfile in refused.items():
            with self.subTest(dockerfile=name):
                result = self.tag_for(dockerfile)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.github_env, "")


class NativeArchitectureTests(unittest.TestCase):
    def test_only_an_amd64_runner_and_server_pass(self) -> None:
        self.assertEqual(
            run_step("native-architecture", {}, docker_output="amd64", uname_output="x86_64").returncode, 0
        )
        for machine, server in (("aarch64", "amd64"), ("x86_64", "arm64"), ("aarch64", "arm64"), ("x86_64", "")):
            with self.subTest(machine=machine, server=server):
                result = run_step("native-architecture", {}, docker_output=server, uname_output=machine)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("native amd64 required", result.output)

    def test_a_docker_that_cannot_answer_fails_the_step(self) -> None:
        result = run_step("native-architecture", {}, docker_output="cannot connect", docker_status=1)
        self.assertNotEqual(result.returncode, 0)


class BuiltArchitectureTests(unittest.TestCase):
    ENV = {"IMAGE_TAG": "caddy-1.2.3-4"}

    def test_only_an_amd64_image_passes(self) -> None:
        self.assertEqual(run_step("built-architecture", self.ENV, docker_output="amd64").returncode, 0)
        for architecture in ("arm64", "386", "", "amd64 arm64"):
            with self.subTest(architecture=architecture):
                result = run_step("built-architecture", self.ENV, docker_output=architecture)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not amd64", result.output)


class OverwriteRefusalTests(unittest.TestCase):
    ENV = {"IMAGE_TAG": "caddy-1.2.3-4"}

    def refusal(self, output: str, status: int) -> StepResult:
        return run_step("absent", self.ENV, docker_output=output, docker_status=status)

    def test_an_existing_tag_is_refused(self) -> None:
        for output in ('{"schemaVersion": 2}', "", "no such manifest: looks absent but status says it exists"):
            with self.subTest(output=output):
                result = self.refusal(output, 0)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("already exists", result.output)

    def test_a_plain_not_found_is_the_only_permission_to_push(self) -> None:
        for output in ("no such manifest: ghcr.io/branchleft/edge-caddy:caddy-1.2.3-4", "manifest unknown"):
            with self.subTest(output=output):
                self.assertEqual(self.refusal(output, 1).returncode, 0)

    def test_any_other_failure_is_refused_not_read_as_absent(self) -> None:
        others = [
            "denied: permission_denied: read_package",
            "unauthorized: authentication required",
            "Get https://ghcr.io/v2/: dial tcp: lookup ghcr.io: no such host",
            "toomanyrequests: rate limit exceeded",
            "name unknown: repository name not known to registry",
            "",
        ]
        for output in others:
            with self.subTest(output=output):
                result = self.refusal(output, 1)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("could not tell", result.output)


class DigestVerificationTests(unittest.TestCase):
    ENV = {"IMAGE_TAG": "caddy-1.2.3-4"}
    IMAGE = "ghcr.io/branchleft/edge-caddy"

    def read(self, docker_output: str, docker_status: int = 0) -> StepResult:
        return run_step("digest", self.ENV, docker_output=docker_output, docker_status=docker_status)

    def test_a_well_formed_digest_becomes_the_image_output(self) -> None:
        result = self.read(f"{self.IMAGE}@{DIGEST}")
        self.assertEqual((result.returncode, result.github_output), (0, f"image={self.IMAGE}@{DIGEST}\n"))

    def test_a_digest_of_another_repository_is_ignored_in_favour_of_ours(self) -> None:
        result = self.read(f"example.invalid/other@sha256:{'1' * 64}\n{self.IMAGE}@{DIGEST}")
        self.assertEqual((result.returncode, result.github_output), (0, f"image={self.IMAGE}@{DIGEST}\n"))

    def test_a_missing_doubled_or_malformed_digest_fails_and_publishes_nothing(self) -> None:
        refused = {
            "none": "",
            "other repository only": f"example.invalid/other@{DIGEST}",
            "short": f"{self.IMAGE}@sha256:{'a' * 63}",
            "long": f"{self.IMAGE}@sha256:{'a' * 65}",
            "uppercase": f"{self.IMAGE}@sha256:{'A' * 64}",
            "no algorithm": f"{self.IMAGE}@{'a' * 64}",
            "other algorithm": f"{self.IMAGE}@sha512:{'a' * 64}",
            "not hex": f"{self.IMAGE}@sha256:{'g' * 64}",
            "tag not digest": f"{self.IMAGE}:caddy-1.2.3-4",
            "two digests": f"{self.IMAGE}@{DIGEST}\n{self.IMAGE}@sha256:{'b' * 64}",
            "trailing text": f"{self.IMAGE}@{DIGEST} extra",
        }
        for name, output in refused.items():
            with self.subTest(digest=name):
                result = self.read(output)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.github_output, "")

    def test_a_second_line_cannot_smuggle_an_output_key(self) -> None:
        result = self.read(f"{self.IMAGE}@{DIGEST}\nimage=evil")
        self.assertEqual(result.github_output, f"image={self.IMAGE}@{DIGEST}\n")

    def test_a_docker_that_cannot_inspect_fails_the_step(self) -> None:
        result = self.read(f"{self.IMAGE}@{DIGEST}", docker_status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.github_output, "")


class SummaryTests(unittest.TestCase):
    BASE = {"GITHUB_SHA": "f" * 40, "IMAGE_TAG": "caddy-1.2.3-4"}

    def test_a_run_with_a_digest_prints_commit_tag_reference_and_the_public_reminder(self) -> None:
        pinned = f"ghcr.io/branchleft/edge-caddy@{DIGEST}"
        summary = run_step("summary", {**self.BASE, "PINNED_IMAGE": pinned}).github_summary
        for fragment in (
            "f" * 40,
            "caddy-1.2.3-4",
            f"Pin this: `{pinned}`",
            "must be public",
            "Build and publish the Caddy image",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, summary)
        self.assertNotIn("NO DIGEST", summary)

    def test_a_run_without_a_digest_says_so_plainly_and_names_no_reference(self) -> None:
        for env in ({**self.BASE, "PINNED_IMAGE": ""}, {"GITHUB_SHA": "f" * 40, "PINNED_IMAGE": ""}):
            with self.subTest(env=sorted(env)):
                summary = run_step("summary", env).github_summary
                self.assertIn("NO DIGEST", summary)
                self.assertNotIn("Pin this", summary)
                self.assertNotIn("sha256", summary)


if __name__ == "__main__":
    unittest.main()
