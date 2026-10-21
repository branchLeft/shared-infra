#!/usr/bin/env python3
"""Pin tests: a pull_request run is grouped per pull request, and only those runs cancel.

Every rule is checked on the parsed workflow, never on its text. The rules, the
parser and the job-group comparison are written up in test_workflow_concurrency.md.
"""

from __future__ import annotations

import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
CI_YML = WORKFLOWS / "ci.yml"
PRE_COMMIT = ROOT / ".pre-commit-config.yaml"

PR_EXPRESSION = "${{ github.event_name == 'pull_request' }}"
PR_GROUP = "${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}"
PR_CONCURRENCY = {"group": PR_GROUP, "cancel-in-progress": PR_EXPRESSION}
PR_BLOCK = f"concurrency:\n  group: {PR_GROUP}\n  cancel-in-progress: {PR_EXPRESSION}\n"
PR_TRIGGERS = {"pull_request", "pull_request_target"}
CONCURRENCY_KEYS = {"group", "cancel-in-progress"}
ABSENT = object()

# The only ${{ }} terms a run-keyed group may be built from. The run id is
# accepted only as one of these, never as text in a literal or a quoted string.
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
RUN_KEYED_TERMS = {"github.workflow", "github.run_id"}
# The pull request number falls back to the run id, so it keeps runs apart only
# in a workflow that has a pull_request trigger. The review events carry the
# number too, with no fallback, so there it would put every run for one pull
# request in one group.
PR_NUMBER_TERM = "github.event.pull_request.number || github.run_id"
PR_NUMBER_TRIGGERS = {"pull_request_review", "pull_request_review_comment"}

BOOL_TAG = "tag:yaml.org,2002:bool"
MERGE_TAG = "tag:yaml.org,2002:merge"
PYYAML_PIN = "pyyaml==6.0.3"


class StrictYamlError(yaml.YAMLError):
    """A construct PyYAML would resolve but GitHub may not: the file is refused."""


class Unclassifiable(Exception):
    """A trigger block the test cannot read; the file fails closed."""


class WorkflowLoader(yaml.SafeLoader):
    """SafeLoader that refuses explicit tags, duplicate and merge keys, and reads booleans as YAML 1.2."""

    def refuse_explicit_tag(self) -> None:
        # The next event is the node about to be composed. An explicit tag
        # (`!!bool`, `!!str`, a bare `!`) overrides the resolver below, and
        # PyYAML applies its YAML 1.1 table to `!!bool "off"`; how GitHub reads
        # a tagged scalar is unverified, so the file is refused.
        tag = getattr(self.peek_event(), "tag", None)
        if tag is not None:
            raise StrictYamlError(f"explicit tag {tag!r} is refused")

    def compose_scalar_node(self, anchor):
        self.refuse_explicit_tag()
        return super().compose_scalar_node(anchor)

    def compose_sequence_node(self, anchor):
        self.refuse_explicit_tag()
        return super().compose_sequence_node(anchor)

    def compose_mapping_node(self, anchor):
        self.refuse_explicit_tag()
        return super().compose_mapping_node(anchor)

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            seen = set()
            for key_node, _ in node.value:
                if key_node.tag == MERGE_TAG:
                    raise StrictYamlError("merge key (<<) is refused")
                key = self.construct_object(key_node, deep=True)
                try:
                    repeated = key in seen
                except TypeError:
                    raise StrictYamlError("unhashable mapping key") from None
                if repeated:
                    raise StrictYamlError(f"duplicate key {key!r}")
                seen.add(key)
        return super().construct_mapping(node, deep)


WorkflowLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != BOOL_TAG]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    BOOL_TAG, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


def load(text: str) -> object:
    loader = WorkflowLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def workflow_files() -> list[pathlib.Path]:
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def trigger_names(data: dict) -> set[str]:
    """Trigger names from the on: block, read as a string, a list or a mapping."""
    if "on" not in data:
        raise Unclassifiable('no trigger block (the top-level key "on")')
    trigger = data["on"]
    if isinstance(trigger, str):
        return {trigger}
    if isinstance(trigger, list) and trigger and all(isinstance(item, str) for item in trigger):
        return set(trigger)
    if isinstance(trigger, dict) and trigger and all(isinstance(key, str) for key in trigger):
        return set(trigger)
    raise Unclassifiable(f"trigger block has a form the test cannot read: {trigger!r}")


def run_keyed(group: object, pull_request: bool) -> bool:
    """True when the group is literal text plus whitelisted terms, with the run id as a term.

    The pull request number term is a whitelisted term only when pull_request is true.
    """
    if not isinstance(group, str):
        return False
    terms = [" ".join(body.split()) for body in EXPRESSION.findall(group)]
    literal = EXPRESSION.sub("", group)
    if "${{" in literal or "}}" in literal:
        return False
    allowed = RUN_KEYED_TERMS | ({PR_NUMBER_TERM} if pull_request else set())
    return all(term in allowed for term in terms) and any("github.run_id" in term for term in terms)


def group_template(top_group: str, workflow_label: str) -> str:
    """A regex for every value the workflow's group can evaluate to, built from its parts.

    Literal text is escaped. github.workflow is the workflow's name, and a run id
    or pull request number is a run of digits. A term not known here matches
    anything, so the comparison refuses more, never less.
    """
    pattern = ""
    end = 0
    for match in EXPRESSION.finditer(top_group):
        pattern += re.escape(top_group[end : match.start()].casefold())
        term = " ".join(match.group(1).split())
        if term == "github.workflow":
            pattern += re.escape(workflow_label.casefold())
        elif term in {"github.run_id", PR_NUMBER_TERM}:
            pattern += r"\d+"
        else:
            pattern += ".*"
        end = match.end()
    return pattern + re.escape(top_group[end:].casefold())


def same_literal_group(job_group: str, top_group: object, workflow_label: str) -> bool:
    """True when the job's literal group is a value the workflow's group can have, ignoring case.

    A literal top group is compared as text with casefold(). A top group that
    holds expressions is compared with group_template: a job literal that fully
    matches it names a group that run or pull request has, so the job waits on
    its own run. A sibling that is not a full match, such as `x-mail`, is fine.
    """
    if not isinstance(top_group, str):
        return False
    if "${{" not in top_group:
        return job_group.casefold() == top_group.casefold()
    return re.fullmatch(group_template(top_group, workflow_label), job_group.casefold()) is not None


def cancel_problem(where: str, config: dict) -> str | None:
    """None when this concurrency mapping's cancel-in-progress is absent or false, else why not.

    The pull_request expression is not allowed here: it is allowed only on the
    top-level pull_request block, which top_level_problems checks by equality.
    """
    value = config.get("cancel-in-progress", ABSENT)
    if value is ABSENT or value is False:
        return None
    return f"{where} cancel-in-progress is {value!r}, which may cancel a non-pull_request run"


def shape_problem(where: str, config: object) -> str | None:
    if not isinstance(config, dict):
        return f"{where} concurrency is not a mapping: {config!r}"
    extra = sorted(str(key) for key in config if key not in CONCURRENCY_KEYS)
    if extra:
        return f"{where} concurrency has an unexpected key: {extra}"
    return None


def top_level_problems(name: str, config: object, pull_request: bool) -> list[str]:
    problem = shape_problem("top-level", config)
    if problem:
        return [f"{name}: {problem}"]
    if pull_request:
        if config != PR_CONCURRENCY:
            return [f"{name}: top-level concurrency is not the run-keyed block: {config!r}"]
        return []
    found = []
    group = config.get("group")
    if not run_keyed(group, False):
        found.append(f"{name}: top-level group is shared across runs, or not run-keyed: {group!r}")
    problem = cancel_problem("top-level", config)
    if problem:
        found.append(f"{name}: {problem}")
    return found


def merge_group_problems(name: str, data: dict, pull_request: bool) -> list[str]:
    config = data.get("concurrency")
    group = config.get("group") if isinstance(config, dict) else None
    if not isinstance(group, str):
        return [f"{name}: merge_group workflow has no top-level group"]
    found = []
    if not run_keyed(group, pull_request):
        found.append(f"{name}: merge_group group is not keyed on the run id: {group!r}")
    if "github.ref" in group:
        found.append(f"{name}: merge_group group is keyed on the ref: {group!r}")
    return found


def job_problems(name: str, job_name: str, job: dict, top_group: object, workflow_label: str) -> list[str]:
    """A job never cancels, and never takes the workflow's own group.

    The pull_request expression is refused here: a job group every run shares lets
    a pull request run cancel a push run, and the per-pull-request group is the
    workflow's own group, so the job would wait on its own run.
    """
    where = f"job {job_name}"
    problem = shape_problem(where, job["concurrency"])
    if problem:
        return [f"{name}: {problem}"]
    config = job["concurrency"]
    found = []
    group = config.get("group", ABSENT)
    if not isinstance(group, str) or not group.strip():
        shown = "missing" if group is ABSENT else repr(group)
        found.append(f"{name}: {where} group must be a non-empty string literal, not {shown}")
    elif "${{" in group:
        found.append(f"{name}: {where} group must be a plain literal, not an expression: {group!r}")
    elif same_literal_group(group, top_group, workflow_label):
        found.append(
            f"{name}: {where} has the same group as the workflow, so it would wait on its own run: {group!r}"
        )
    problem = cancel_problem(where, config)
    if problem:
        found.append(f"{name}: {problem}")
    return found


def violations(name: str, text: str) -> list[str]:
    """Every rule break in one workflow's text, or [] for a file that passes."""
    try:
        data = load(text)
    except yaml.YAMLError as error:
        reason = str(error).splitlines()[0] if str(error) else type(error).__name__
        return [f"{name}: does not parse as strict YAML: {reason}"]
    if not isinstance(data, dict):
        return [f"{name}: top level is not a mapping"]
    stray = [key for key in data if not isinstance(key, str)]
    if stray:
        return [f"{name}: top-level key that is not a string: {stray!r}"]
    try:
        names = trigger_names(data)
    except Unclassifiable as error:
        return [f"{name}: {error}"]
    pull_request = bool(names & PR_TRIGGERS)
    found: list[str] = []
    if "concurrency" in data:
        found += top_level_problems(name, data["concurrency"], pull_request)
    elif pull_request:
        found.append(f"{name}: pull_request workflow has no top-level concurrency block")
    if pull_request and names & PR_NUMBER_TRIGGERS:
        found.append(
            f"{name}: {sorted(names & PR_NUMBER_TRIGGERS)} carries a pull request number with no fallback, "
            "so its runs for one pull request would share the per-pull-request group"
        )
    if "merge_group" in names:
        found += merge_group_problems(name, data, pull_request)
    top = data.get("concurrency")
    top_group = top.get("group") if isinstance(top, dict) else None
    # github.workflow is the name: key, or the file path when there is none.
    workflow_name = data.get("name")
    workflow_label = workflow_name if isinstance(workflow_name, str) and workflow_name else f".github/workflows/{name}"
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return found + [f"{name}: jobs is not a mapping"]
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            found.append(f"{name}: job {job_name} is not a mapping")
        elif "concurrency" in job:
            found += job_problems(name, job_name, job, top_group, workflow_label)
    return found


def triggers_of(path: pathlib.Path) -> set[str]:
    return trigger_names(load(path.read_text(encoding="utf-8")))


class WorkflowConcurrencyTests(unittest.TestCase):
    def test_every_workflow_file_is_walked(self):
        names = {path.name for path in workflow_files()}
        self.assertIn("ci.yml", names)
        self.assertIn("ansible.yml", names)
        self.assertIn("docs-lint.yml", names)
        self.assertIn("standards.yml", names)

    def test_every_workflow_passes_the_concurrency_rules(self):
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(violations(path.name, text), [])

    def test_the_rules_are_not_vacuous_on_the_real_tree(self):
        # A walk that found no pull_request or merge_group workflow would pass
        # every rule above without testing one.
        pull_request = [p.name for p in workflow_files() if triggers_of(p) & PR_TRIGGERS]
        merge_group = [p.name for p in workflow_files() if "merge_group" in triggers_of(p)]
        self.assertIn("ci.yml", pull_request)
        self.assertIn("ansible.yml", pull_request)
        self.assertIn("ci.yml", merge_group)


PUSH_ON = "on:\n  push:\n    branches: [main]\n"
PR_ON = "on:\n  pull_request:\n"
PUSH_PR_ON = "on:\n  push:\n    branches: [main]\n  pull_request:\n"
JOBS ="jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"


def deploy_jobs(job_lines: str = "") -> str:
    """A jobs block with one environment-gated job; job_lines are indented four spaces."""
    return (
        "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    environment: production\n"
        + job_lines
        + "    steps:\n      - run: echo deploy\n"
    )


def job_concurrency(cancel: str, group: str = "deploy") -> str:
    return f"    concurrency:\n      group: {group}\n      cancel-in-progress: {cancel}\n"


PR_WORKFLOW = PR_ON + PR_BLOCK + JOBS
# A job with no environment whose group every run shares, with the pull_request expression.
JOBS_WITH_CHECK_GROUP = (
    "jobs:\n  check:\n    runs-on: ubuntu-latest\n" + job_concurrency(PR_EXPRESSION, "check")
)

def job_group_under(
    job_group: str, top_group: str = "x-${{ github.run_id }}", pull_request: bool = False, name: str = ""
) -> str:
    """A workflow with the given top-level group and one check job with the given group, never cancelling.

    name is the workflow's name: key, or none when empty.
    """
    head = PR_ON + PR_BLOCK if pull_request else PUSH_ON + f"concurrency:\n  group: {top_group}\n  cancel-in-progress: false\n"
    return (f"name: {name}\n" if name else "") + head + "jobs:\n  check:\n    runs-on: ubuntu-latest\n" + job_concurrency("false", job_group)


# name -> (workflow text, a fragment that must appear in a violation). The
# fragment keeps a fixture from being refused for the wrong reason, such as a
# typo that merely fails to parse.
REFUSED = {
    # Cycle 1: a list-form trigger and a quoted trigger key.
    "zz-c1-seq-trigger": (
        "on:\n  - push\n  - pull_request\n" + JOBS,
        "no top-level concurrency block",
    ),
    "zz-c1-quoted-trigger": (
        'on:\n  "pull_request":\n    types: [opened]\n' + JOBS,
        "no top-level concurrency block",
    ),
    # Cycle 2: a quoted cancel key, an escaped cancel key, a '#' inside a quoted
    # flow value, and a shared top-level group.
    "zz-c2-quoted-cancel-key": (
        PUSH_ON + deploy_jobs('    concurrency:\n      group: deploy\n      "cancel-in-progress": true\n'),
        "cancel-in-progress is True",
    ),
    "zz-c2-escaped-cancel-key": (
        PUSH_ON + deploy_jobs('    concurrency:\n      group: deploy\n      "cancel\\x2din\\x2dprogress": true\n'),
        "cancel-in-progress is True",
    ),
    "zz-c2-flow-hash": (
        PUSH_ON + deploy_jobs('    concurrency: {group: "deploy#1", cancel-in-progress: true}\n'),
        "cancel-in-progress is True",
    ),
    "zz-c2-shared-group": (
        PUSH_ON + "concurrency:\n  group: deploy-shared\n" + JOBS,
        "shared across runs",
    ),
    # Cycle 3: an escaped quote that ends a quoted group early, a quoted
    # top-level key, an escaped sequence trigger, and a multi-line quoted value.
    "zz-p1-escape-hash": (
        PUSH_ON + deploy_jobs('    concurrency: {group: "deploy\\" #", cancel-in-progress: true}\n'),
        "cancel-in-progress is True",
    ),
    "zz-p2-quoted-top": (
        PUSH_ON + '"concurrency":\n  group: deploy-shared\n' + deploy_jobs(),
        "shared across runs",
    ),
    "zz-p2-quoted-top-cancel-true": (
        PUSH_ON + '"concurrency":\n  group: deploy-shared\n  cancel-in-progress: true\n' + deploy_jobs(),
        "cancel-in-progress is True",
    ),
    "zz-p2-quoted-top-cancel-false": (
        PUSH_ON + '"concurrency":\n  group: deploy-shared\n  cancel-in-progress: false\n' + deploy_jobs(),
        "shared across runs",
    ),
    "zz-p3-escaped-seq-trigger": (
        'on:\n  - push\n  - "pull\\x5frequest"\n' + JOBS,
        "no top-level concurrency block",
    ),
    "zz-p4-multiline-hash": (
        PUSH_ON + deploy_jobs('    concurrency: {group: "deploy\n      #x", cancel-in-progress: true}\n'),
        "cancel-in-progress is True",
    ),
    # D2: the trigger block.
    "d2-on-both-forms": (PUSH_ON + '"on":\n  pull_request:\n' + JOBS, "duplicate key"),
    "d2-on-neither-form": (JOBS, "no trigger block"),
    "d2-pull-request-target-has-no-block": ("on:\n  pull_request_target:\n" + JOBS, "no top-level concurrency block"),
    # D3: fail closed.
    "d3-unparseable": ("on: [push\n", "does not parse"),
    "d3-two-documents": (PUSH_ON + JOBS + "---\n" + PUSH_ON + JOBS, "does not parse"),
    "d3-top-level-list": ("- a\n- b\n", "top level is not a mapping"),
    "d3-empty-file": ("", "top level is not a mapping"),
    "d3-non-string-top-key": (PUSH_ON + "true: 1\n" + JOBS, "not a string"),
    "d3-trigger-is-a-number": ("on: 5\n" + JOBS, "cannot read"),
    "d3-trigger-is-empty": ("on: {}\n" + JOBS, "cannot read"),
    "d3-top-concurrency-is-a-string": (PUSH_ON + "concurrency: deploy\n" + JOBS, "concurrency is not a mapping"),
    "d3-top-concurrency-is-null": (PUSH_ON + "concurrency:\n" + JOBS, "concurrency is not a mapping"),
    "d3-job-concurrency-is-a-string": (PUSH_ON + deploy_jobs("    concurrency: deploy\n"), "concurrency is not a mapping"),
    "d3-concurrency-has-an-extra-key": (
        PUSH_ON + "concurrency:\n  group: x-${{ github.run_id }}\n  queue: max\n" + JOBS,
        "unexpected key",
    ),
    "d3-jobs-is-a-list": (PUSH_ON + "jobs:\n  - a\n", "jobs is not a mapping"),
    "d3-job-is-not-a-mapping": (PUSH_ON + "jobs:\n  check: 5\n", "is not a mapping"),
    # D4: the cancel rules.
    "d4-push-job-cancel-true": (PUSH_ON + deploy_jobs(job_concurrency("true")), "cancel-in-progress is True"),
    "d4-push-top-cancel-true": (
        PUSH_ON + "concurrency:\n  group: x-${{ github.run_id }}\n  cancel-in-progress: true\n" + JOBS,
        "cancel-in-progress is True",
    ),
    "d4-push-job-cancel-expression": (
        PUSH_ON + deploy_jobs(job_concurrency(PR_EXPRESSION)),
        "cancel-in-progress is",
    ),
    "d4-push-top-cancel-expression": (
        PUSH_ON + f"concurrency:\n  group: x-${{{{ github.run_id }}}}\n  cancel-in-progress: {PR_EXPRESSION}\n" + JOBS,
        "cancel-in-progress is",
    ),
    "d4-pr-environment-job-cancel-expression": (
        PR_ON + PR_BLOCK + deploy_jobs(job_concurrency(PR_EXPRESSION)),
        "job deploy cancel-in-progress is",
    ),
    "d4-pr-environment-job-cancel-true": (
        PR_ON + PR_BLOCK + deploy_jobs(job_concurrency("true")),
        "job deploy cancel-in-progress is True",
    ),
    # D4a: the exact block on a pull_request workflow.
    "d4a-pr-group-keyed-on-the-ref": (
        PR_ON + "concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n"
        f"  cancel-in-progress: {PR_EXPRESSION}\n" + JOBS,
        "not the run-keyed block",
    ),
    "d4a-pr-cancel-true": (
        PR_ON + f"concurrency:\n  group: {PR_GROUP}\n  cancel-in-progress: true\n" + JOBS,
        "not the run-keyed block",
    ),
    "d4a-pr-block-with-an-extra-key": (PR_ON + PR_BLOCK + "  queue: max\n" + JOBS, "unexpected key"),
    "d4a-pr-no-block": (PR_ON + JOBS, "no top-level concurrency block"),
    # D4b: a non-pull_request top-level group holds the run id.
    "d4b-push-top-group-without-the-run-id": (
        PUSH_ON + "concurrency:\n  group: deploy\n  cancel-in-progress: false\n" + JOBS,
        "shared across runs",
    ),
    "d4b-push-top-group-without-a-group": (
        PUSH_ON + "concurrency:\n  cancel-in-progress: false\n" + JOBS,
        "shared across runs",
    ),
    # D4c: the merge_group group is run-keyed and not keyed on the ref.
    "d4c-merge-group-without-a-block": ("on:\n  merge_group:\n" + JOBS, "merge_group workflow has no top-level group"),
    "d4c-merge-group-keyed-on-the-ref": (
        "on:\n  merge_group:\nconcurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n" + JOBS,
        "merge_group group is not keyed on the run id",
    ),
    "d4c-merge-group-keyed-on-run-and-ref": (
        "on:\n  merge_group:\nconcurrency:\n  group: ${{ github.run_id }}-${{ github.ref }}\n" + JOBS,
        "merge_group group is keyed on the ref",
    ),
    # Cycle 4, finding 1 and cycle 5, finding 1: the pull_request expression is
    # refused on every job. A job group shared by every run lets a pull request
    # run cancel a push run, and the per-pull-request group is the workflow's own
    # group, which a job would wait on for its own run.
    "g1-mixed-triggers-shared-job-group": (
        PUSH_PR_ON + PR_BLOCK + JOBS_WITH_CHECK_GROUP,
        "job check cancel-in-progress is",
    ),
    "g1-pull-request-only-shared-job-group": (
        PR_ON + PR_BLOCK + JOBS_WITH_CHECK_GROUP,
        "job check cancel-in-progress is",
    ),
    "g1-job-group-keyed-on-the-ref": (
        PUSH_PR_ON
        + PR_BLOCK
        + "jobs:\n  check:\n    runs-on: ubuntu-latest\n"
        + job_concurrency(PR_EXPRESSION, "${{ github.workflow }}-${{ github.ref }}"),
        "job check cancel-in-progress is",
    ),
    "g1-job-group-without-a-group": (
        PUSH_PR_ON
        + PR_BLOCK
        + "jobs:\n  check:\n    runs-on: ubuntu-latest\n    concurrency:\n      cancel-in-progress: "
        + PR_EXPRESSION
        + "\n",
        "job check cancel-in-progress is",
    ),
    # Cycle 5, finding 1: the two shapes cycle 4 accepted are refused.
    "h1-job-expression-with-the-per-pr-group": (
        PR_ON + PR_BLOCK + "jobs:\n  check:\n    runs-on: ubuntu-latest\n" + job_concurrency(PR_EXPRESSION, PR_GROUP),
        "job check cancel-in-progress is",
    ),
    "h1-job-expression-with-the-per-pr-group-mixed": (
        PUSH_PR_ON + PR_BLOCK + "jobs:\n  check:\n    runs-on: ubuntu-latest\n" + job_concurrency(PR_EXPRESSION, PR_GROUP),
        "job check cancel-in-progress is",
    ),
    "h1-job-group-equals-the-workflow-group-never-cancels": (
        PR_ON + PR_BLOCK + "jobs:\n  check:\n    runs-on: ubuntu-latest\n" + job_concurrency("false", PR_GROUP),
        "plain literal",
    ),
    "h1-job-group-equals-the-workflow-group-no-cancel-key": (
        PR_ON + PR_BLOCK + "jobs:\n  check:\n    runs-on: ubuntu-latest\n    concurrency:\n      group: " + PR_GROUP + "\n",
        "plain literal",
    ),
    "h1-push-job-group-equals-the-workflow-group": (
        PUSH_ON
        + "concurrency:\n  group: x-${{ github.run_id }}\n  cancel-in-progress: false\n"
        + "jobs:\n  check:\n    runs-on: ubuntu-latest\n"
        + job_concurrency("false", "x-${{ github.run_id }}"),
        "plain literal",
    ),
    "h1-job-group-equals-the-workflow-group-spaced-differently": (
        PUSH_ON
        + "concurrency:\n  group: x-${{ github.run_id }}\n  cancel-in-progress: false\n"
        + "jobs:\n  check:\n    runs-on: ubuntu-latest\n"
        + job_concurrency("false", "x-${{github.run_id}}"),
        "plain literal",
    ),
    # Cycle 4, finding 2: the run id counts only as a term inside ${{ }}.
    "g2-literal-run-id-text": (
        PUSH_ON + "concurrency:\n  group: deploy-github.run_id\n  cancel-in-progress: false\n" + JOBS,
        "shared across runs",
    ),
    "g2-quoted-run-id-in-an-expression": (
        PUSH_ON + "concurrency:\n  group: ${{ 'github.run_id' }}\n  cancel-in-progress: false\n" + JOBS,
        "shared across runs",
    ),
    "g2-constant-before-the-run-id": (
        PUSH_ON + "concurrency:\n  group: ${{ 'x' || github.run_id }}\n  cancel-in-progress: false\n" + JOBS,
        "shared across runs",
    ),
    "g2-run-id-in-a-function-string": (
        PUSH_ON + "concurrency:\n  group: ${{ format('{0}', 'github.run_id') }}\n  cancel-in-progress: false\n" + JOBS,
        "shared across runs",
    ),
    "g2-run-id-inside-a-broken-expression": (
        PUSH_ON + "concurrency:\n  group: x-${{ github.run_id }}-${{\n  cancel-in-progress: false\n" + JOBS,
        "shared across runs",
    ),
    "g2-merge-group-literal-run-id": (
        "on:\n  merge_group:\nconcurrency:\n  group: queue-github.run_id\n" + JOBS,
        "merge_group group is not keyed on the run id",
    ),
    "g2-merge-group-quoted-run-id": (
        "on:\n  merge_group:\nconcurrency:\n  group: ${{ '${{ github.run_id }}' }}\n" + JOBS,
        "merge_group group is not keyed on the run id",
    ),
    # Cycle 5, finding 2: the pull request number term is allowed only in a
    # workflow with a pull_request trigger. Review events carry the number too,
    # so every run for one pull request would share a group.
    "h2-push-group-with-the-pr-number-term": (
        PUSH_ON + f"concurrency:\n  group: {PR_GROUP}\n  cancel-in-progress: false\n" + JOBS,
        "shared across runs",
    ),
    "h2-pull-request-review-group-with-the-pr-number-term": (
        "on:\n  pull_request_review:\n" + f"concurrency:\n  group: {PR_GROUP}\n  cancel-in-progress: false\n" + JOBS,
        "shared across runs",
    ),
    "h2-pull-request-review-comment-group-with-the-pr-number-term": (
        "on:\n  pull_request_review_comment:\n" + f"concurrency:\n  group: {PR_GROUP}\n  cancel-in-progress: false\n" + JOBS,
        "shared across runs",
    ),
    "h2-merge-group-with-the-pr-number-term": (
        f"on:\n  merge_group:\nconcurrency:\n  group: {PR_GROUP}\n" + JOBS,
        "merge_group group is not keyed on the run id",
    ),
    "h2-pull-request-plus-review-trigger": (
        "on:\n  pull_request:\n  pull_request_review:\n" + PR_BLOCK + JOBS,
        "share the per-pull-request group",
    ),
    "h2-pull-request-plus-review-comment-trigger": (
        "on:\n  - pull_request\n  - pull_request_review_comment\n" + PR_BLOCK + JOBS,
        "share the per-pull-request group",
    ),
    # Cycle 5, finding 3: an explicit tag overrides the resolver, and PyYAML
    # still applies its YAML 1.1 table to !!bool.
    "h3-explicit-bool-off": (PUSH_ON + deploy_jobs(job_concurrency('!!bool "off"')), "explicit tag"),
    "h3-explicit-bool-no": (PUSH_ON + deploy_jobs(job_concurrency("!!bool 'no'")), "explicit tag"),
    "h3-explicit-bool-false": (PUSH_ON + deploy_jobs(job_concurrency("!!bool false")), "explicit tag"),
    "h3-explicit-str-true": (PUSH_ON + deploy_jobs(job_concurrency("!!str true")), "explicit tag"),
    "h3-non-specific-tag": (PUSH_ON + deploy_jobs(job_concurrency("! false")), "explicit tag"),
    "h3-explicit-tag-on-a-key": (
        PUSH_ON + deploy_jobs("    concurrency:\n      group: deploy\n      !!str cancel-in-progress: true\n"),
        "explicit tag",
    ),
    "h3-explicit-tag-on-a-mapping": (
        PUSH_ON + deploy_jobs("    concurrency: !!map\n      group: deploy\n      cancel-in-progress: true\n"),
        "explicit tag",
    ),
    "h3-explicit-tag-on-a-sequence": (
        "on: !!seq [push]\n" + JOBS,
        "explicit tag",
    ),
    # Finding 3: where PyYAML and GitHub could read a file differently.
    "f3-duplicate-cancel-key-top-level": (
        PR_ON + f"concurrency:\n  group: {PR_GROUP}\n  cancel-in-progress: true\n  cancel-in-progress: false\n" + JOBS,
        "duplicate key",
    ),
    "f3-duplicate-cancel-key-job-level": (
        PUSH_ON
        + deploy_jobs(
            "    concurrency:\n      group: deploy\n      cancel-in-progress: true\n      cancel-in-progress: false\n"
        ),
        "duplicate key",
    ),
    "f3-duplicate-concurrency-key": (
        PR_ON + PR_BLOCK + "concurrency:\n  group: x-${{ github.run_id }}\n" + JOBS,
        "duplicate key",
    ),
    "f3-duplicate-job-id": (PUSH_ON + "jobs:\n  a:\n    runs-on: x\n  a:\n    runs-on: y\n", "duplicate key"),
    "f3-merge-key": (
        PUSH_ON + deploy_jobs("    concurrency:\n      <<: {cancel-in-progress: true}\n      group: deploy\n"),
        "merge key",
    ),
    "f3-quoted-false": (PUSH_ON + deploy_jobs(job_concurrency('"false"')), "cancel-in-progress is 'false'"),
    "f3-quoted-zero": (PUSH_ON + deploy_jobs(job_concurrency('"0"')), "cancel-in-progress is '0'"),
    "f3-yaml11-off": (PUSH_ON + deploy_jobs(job_concurrency("off")), "cancel-in-progress is 'off'"),
    "f3-yaml11-no": (PUSH_ON + deploy_jobs(job_concurrency("no")), "cancel-in-progress is 'no'"),
    "f3-yaml11-yes": (PUSH_ON + deploy_jobs(job_concurrency("yes")), "cancel-in-progress is 'yes'"),
    "f3-null-cancel": (PUSH_ON + deploy_jobs(job_concurrency("")), "cancel-in-progress is None"),
    # Cycle 7 (r3 D1, D2, D3): the verdict's probes (a) to (e), and the case-folded
    # literal and prefix comparisons. A job group holding ${{ }} is refused whatever
    # it evaluates to; a job literal is compared case-folded with the workflow group.
    "r3-a-format-call": (job_group_under("${{ format('x-{0}', github.run_id) }}"), "plain literal"),
    "r3-b-parenthesised-run-id": (job_group_under("x-${{ (github.run_id) }}"), "plain literal"),
    "r3-c-operator-spacing": (
        job_group_under("${{github.workflow}}-${{github.event.pull_request.number||github.run_id}}", pull_request=True),
        "plain literal",
    ),
    "r3-d-split-literal": (job_group_under("${{ 'x-' }}${{ github.run_id }}"), "plain literal"),
    "r3-e-case-of-the-workflow-group": (job_group_under("X-${{ github.run_id }}"), "plain literal"),
    # Literal against literal. The top-level literal is itself refused as shared
    # across runs, so the fragment names the job rule.
    "r3-literal-equal": (job_group_under("deploy-shared", top_group="deploy-shared"), "same group as the workflow"),
    "r3-literal-case-differs-job-upper": (
        job_group_under("Deploy-Shared", top_group="deploy-shared"),
        "same group as the workflow",
    ),
    "r3-literal-case-differs-top-upper": (
        job_group_under("deploy-shared", top_group="Deploy-Shared"),
        "same group as the workflow",
    ),
    # casefold(), not lower(): the sharp s folds to "ss". A deliberate over-refusal.
    "r3-literal-casefold-sharp-s": (
        job_group_under("straße", top_group="strasse"),
        "same group as the workflow",
    ),
    # A job group that is missing, empty or not a string is refused, not skipped.
    "r3-job-group-missing": (
        PUSH_ON + "jobs:\n  check:\n    runs-on: ubuntu-latest\n    concurrency:\n      cancel-in-progress: false\n",
        "group must be a non-empty string literal, not missing",
    ),
    "r3-job-group-empty": (job_group_under('""'), "group must be a non-empty string literal"),
    "r3-job-group-null": (job_group_under("null"), "group must be a non-empty string literal, not None"),
    "r3-job-group-integer": (job_group_under("123"), "group must be a non-empty string literal, not 123"),
    "r3-job-group-boolean": (job_group_under("true"), "group must be a non-empty string literal, not True"),
    # Cycle 8 (finding 1): a job literal equal to what an expression group
    # evaluates to. The per-pull-request group is the same value for every run of
    # one pull request, so a literal can name it; a run id that already exists
    # can be named too. One fixture for each term.
    "c8-pr-number-term-in-a-pull-request-workflow": (
        job_group_under("CI-369", pull_request=True, name="CI"),
        "same group as the workflow",
    ),
    "c8-pr-number-term-lowercase-job-literal": (
        job_group_under("ci-369", pull_request=True, name="CI"),
        "same group as the workflow",
    ),
    "c8-run-id-term-in-a-push-workflow": (
        job_group_under("x-39646213815"),
        "same group as the workflow",
    ),
    "c8-run-id-term-uppercase-job-literal": (
        job_group_under("X-39646213815"),
        "same group as the workflow",
    ),
    "c8-workflow-term-and-run-id-term": (
        job_group_under("CI-123", top_group="${{ github.workflow }}-${{ github.run_id }}", name="CI"),
        "same group as the workflow",
    ),
    "c8-workflow-name-with-regex-characters": (
        job_group_under("a.b+c-123", top_group="${{ github.workflow }}-${{ github.run_id }}", name="a.b+c"),
        "same group as the workflow",
    ),
    # No name: key, so github.workflow is the file path. The probe's file name is
    # the fixture name, so the file path is spelled out in the job literal.
    "c8-workflow-term-is-the-file-path-without-a-name": (
        job_group_under(
            ".github/workflows/c8-workflow-term-is-the-file-path-without-a-name.yml-123",
            top_group="${{ github.workflow }}-${{ github.run_id }}",
        ),
        "same group as the workflow",
    ),
    # A group term the template does not know matches anything: the job is refused,
    # beside the top-level violation.
    "c8-unknown-term-in-the-workflow-group": (
        job_group_under("anything-123", top_group="${{ github.sha }}-${{ github.run_id }}"),
        "same group as the workflow",
    ),
}

# name -> workflow text the rules must pass: the shapes a refusal must not catch.
ACCEPTED = {
    "the run-keyed pull_request workflow": PR_WORKFLOW,
    "the run-keyed pull_request_target workflow": "on:\n  pull_request_target:\n" + PR_BLOCK + JOBS,
    "a quoted on key": PR_WORKFLOW.replace("on:", '"on":', 1),
    "a list trigger with the block": "on:\n  - push\n  - pull_request\n" + PR_BLOCK + JOBS,
    "a pull_request and merge_group workflow with the block": "on:\n  pull_request:\n  merge_group:\n" + PR_BLOCK + JOBS,
    "a push-only workflow with no concurrency": PUSH_ON + JOBS,
    "a deploy job that never cancels": PUSH_ON + deploy_jobs(job_concurrency("false")),
    "a deploy job with no cancel key": PUSH_ON + deploy_jobs("    concurrency:\n      group: deploy\n"),
    "a '#' inside a quoted group": PUSH_ON + deploy_jobs('    concurrency: {group: "deploy #1", cancel-in-progress: false}\n'),
    "a commented-out cancel key": PUSH_ON + deploy_jobs("    concurrency:\n      group: deploy\n      # cancel-in-progress: true\n"),
    "a run-keyed push group that never cancels": PUSH_ON
    + "concurrency:\n  group: x-${{ github.run_id }}\n  cancel-in-progress: false\n"
    + JOBS,
    "a run-keyed merge_group workflow": "on:\n  merge_group:\nconcurrency:\n  group: ${{ github.workflow }}-${{ github.run_id }}\n" + JOBS,
    "a never-cancelling job in a pull_request workflow": PR_ON + PR_BLOCK + deploy_jobs(job_concurrency("false")),
    "a job with its own group and no cancel key in a pull_request workflow": PR_ON
    + PR_BLOCK
    + "jobs:\n  check:\n    runs-on: ubuntu-latest\n    concurrency:\n      group: check\n",
    "a job literal that differs from the run-keyed workflow group": PUSH_ON
    + "concurrency:\n  group: x-${{ github.run_id }}\n  cancel-in-progress: false\n"
    + "jobs:\n  check:\n    runs-on: ubuntu-latest\n"
    + job_concurrency("false", "y-deploy"),
    # A prefix of the expression group is not a refusal: `x-mail` cannot equal a
    # group that holds the run id, and it is a legitimate sibling name.
    "a job literal that starts with the text of the run-keyed workflow group": PUSH_ON
    + "concurrency:\n  group: x-${{ github.run_id }}\n  cancel-in-progress: false\n"
    + "jobs:\n  check:\n    runs-on: ubuntu-latest\n"
    + job_concurrency("false", "x-mail"),
    "a job literal under a workflow group whose text before the expression is empty": PUSH_ON
    + "concurrency:\n  group: ${{ github.workflow }}-${{ github.run_id }}\n  cancel-in-progress: false\n"
    + "jobs:\n  check:\n    runs-on: ubuntu-latest\n"
    + job_concurrency("false", "-deploy"),
    # Cycle 8: the template match is on the whole group, so these siblings pass.
    "a job literal that is the workflow name plus text under the per-pull-request block": "name: CI\n"
    + PR_ON
    + PR_BLOCK
    + "jobs:\n  check:\n    runs-on: ubuntu-latest\n"
    + job_concurrency("false", "CI-deploy"),
    "a pulumi-style job literal under the per-pull-request block": "name: CI\n"
    + PR_ON
    + PR_BLOCK
    + "jobs:\n  check:\n    runs-on: ubuntu-latest\n"
    + job_concurrency("false", "pulumi-production-deploy"),
    "a job literal with a digit run but another prefix": job_group_under("y-39646213815"),
    "a job literal that is the run-keyed text plus a suffix": job_group_under("x-39646213815-mail"),
    "a '!' inside plain text is not a tag": PUSH_ON
    + "jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo !!bool !important\n",
    "a quoted string that starts with '!!'": PUSH_ON
    + deploy_jobs('    concurrency: {group: "!!bool off", cancel-in-progress: false}\n'),
}


class DetectorTests(unittest.TestCase):
    """Each probe and evasion the rules must refuse, and the shapes they must pass."""

    def test_every_refused_fixture_is_refused_for_its_reason(self):
        for probe, (text, fragment) in REFUSED.items():
            with self.subTest(probe=probe):
                found = violations(f"{probe}.yml", text)
                self.assertTrue(
                    any(fragment in line for line in found),
                    f"{probe}: expected a violation containing {fragment!r}, got {found!r}",
                )

    def test_every_accepted_shape_passes(self):
        for shape, text in ACCEPTED.items():
            with self.subTest(shape=shape):
                self.assertEqual(violations("accepted.yml", text), [])

    def test_the_fixtures_are_not_workflow_files(self):
        # They are strings fed to the checker. A copy under .github/workflows
        # would be loaded by GitHub as a real workflow.
        self.assertEqual([p for p in WORKFLOWS.glob("zz-*")], [])

    def test_a_lowercase_or_capitalised_boolean_is_read_as_one(self):
        for spelling in ("false", "False", "FALSE"):
            with self.subTest(spelling=spelling):
                text = PUSH_ON + deploy_jobs(job_concurrency(spelling))
                self.assertEqual(violations("bool.yml", text), [])
        for spelling in ("true", "True", "TRUE"):
            with self.subTest(spelling=spelling):
                text = PUSH_ON + deploy_jobs(job_concurrency(spelling))
                self.assertTrue(violations("bool.yml", text))


class RealTreeMutationTests(unittest.TestCase):
    """The rules refuse the real workflows once a rule is broken in them."""

    def read(self, name: str) -> str:
        return (WORKFLOWS / name).read_text(encoding="utf-8")

    def assert_refused(self, name: str, text: str, fragment: str) -> None:
        found = violations(name, text)
        self.assertTrue(any(fragment in line for line in found), f"{fragment!r} not in {found!r}")

    def test_ansible_without_its_concurrency_block_is_refused(self):
        text = self.read("ansible.yml")
        self.assertIn(PR_BLOCK, text)
        self.assert_refused("ansible.yml", text.replace(PR_BLOCK, ""), "no top-level concurrency block")

    def test_ci_without_its_concurrency_block_is_refused(self):
        text = self.read("ci.yml")
        self.assertIn(PR_BLOCK, text)
        self.assert_refused("ci.yml", text.replace(PR_BLOCK, ""), "no top-level concurrency block")

    def test_ci_with_a_cancelling_apply_job_is_refused(self):
        text = self.read("ci.yml")
        self.assertIn("      cancel-in-progress: false\n", text)
        self.assert_refused(
            "ci.yml",
            text.replace("      cancel-in-progress: false\n", "      cancel-in-progress: true\n", 1),
            "cancel-in-progress is True",
        )

    def test_ci_with_the_pull_request_expression_on_an_apply_job_is_refused(self):
        text = self.read("ci.yml")
        self.assert_refused(
            "ci.yml",
            text.replace("      cancel-in-progress: false\n", f"      cancel-in-progress: {PR_EXPRESSION}\n", 1),
            "cancel-in-progress is",
        )

    def test_ci_with_a_group_keyed_on_the_ref_is_refused(self):
        text = self.read("ci.yml")
        broken = text.replace(PR_BLOCK, PR_BLOCK.replace("github.event.pull_request.number || github.run_id", "github.ref"))
        self.assertNotEqual(broken, text)
        self.assert_refused("ci.yml", broken, "not the run-keyed block")


class ScriptsSuiteDependencyTests(unittest.TestCase):
    """Every place the scripts suite runs has PyYAML, so this module imports.

    The suite runs in two ci.yml jobs and in the scripts-tests pre-commit hook.
    A place without PyYAML fails at `import yaml` when the suite is discovered.
    """

    def jobs_running_the_scripts_suite(self, workflow: dict) -> dict:
        return {
            job_name: job
            for job_name, job in workflow["jobs"].items()
            if any("unittest discover -s scripts" in str(step.get("run", "")) for step in job.get("steps", []))
        }

    def test_both_ci_jobs_that_run_the_suite_install_pyyaml_on_a_managed_python(self):
        workflow = load(CI_YML.read_text(encoding="utf-8"))
        jobs = self.jobs_running_the_scripts_suite(workflow)
        self.assertEqual(sorted(jobs), ["pulumi-inventory-audit", "scripts-tests"])
        for job_name, job in jobs.items():
            with self.subTest(job=job_name):
                steps = job["steps"]
                suite = next(i for i, s in enumerate(steps) if "unittest discover -s scripts" in str(s.get("run", "")))
                python = [i for i, s in enumerate(steps) if str(s.get("uses", "")).startswith("actions/setup-python@")]
                install = [i for i, s in enumerate(steps) if PYYAML_PIN in str(s.get("run", ""))]
                self.assertTrue(python and python[0] < suite, "no Set up Python step before the suite")
                self.assertTrue(install and install[0] < suite, "no PyYAML install before the suite")
                self.assertLess(python[0], install[0], "PyYAML is installed before the managed Python is set up")

    def test_the_pre_commit_hook_that_runs_the_suite_installs_pyyaml(self):
        config = load(PRE_COMMIT.read_text(encoding="utf-8"))
        hooks = [hook for repo in config["repos"] for hook in repo["hooks"] if hook["id"] == "scripts-tests"]
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0]["language"], "python")
        self.assertIn(PYYAML_PIN, hooks[0].get("additional_dependencies", []))


if __name__ == "__main__":
    unittest.main()
