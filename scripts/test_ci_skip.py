#!/usr/bin/env python3
"""Pin tests for the changed-path skip in ci.yml.

A wrong path map skips a required check silently, so this file proves the map
two ways and proves the proof: the real code and workflow pass every invariant,
and each mutant (a deliberate break, applied in memory to the decision code, to
the map or to the ci.yml text) must make the same invariant checker raise.
Read test_ci_skip.md for what each group pins and why.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import tempfile
import types
import unittest

import ci_skip
from test_ci_apply_environments import job_block, job_names, step_blocks
from test_merge_group_triggers import REQUIRED, job_if

SCRIPTS = pathlib.Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
CI_SKIP_PY = SCRIPTS / "ci_skip.py"

SKIP_USES = "./.github/actions/ci-skip"
GUARD = "steps.skip.outputs.run != 'false'"
GUARDS = (GUARD, f"always() && {GUARD}")

# The literal set, not read from ci_skip: adding to or removing from it is an
# edit to this test, which a reviewer sees.
EXPECTED_ALWAYS_RUN = {
    "scripts-tests",
    "pulumi-inventory-audit",
    "typecheck",
    "hetzner-typecheck",
    "hetzner-host-typecheck",
    "hetzner-provision-checks",
}
RULED_ALWAYS_RUN = {"scripts-tests", "pulumi-inventory-audit"}

# For each path, the only jobs that read it (the rest must skip when it alone changed).
READERS = {
    "mail/index.ts": {"mail-typecheck", "mail-provision-checks"},
    "mail/provision/check_shim_image_starts.py": {"mail-typecheck", "mail-provision-checks", "shim-image-starts"},
    "hetzner/edge/render.ts": {"edge-config-validate"},
    "hetzner/edge/stack/Caddyfile": {"edge-config-validate"},
    "hetzner/monitoring/render.ts": {"monitoring-config-validate"},
    "hetzner/monitoring/stack/prometheus/alerts.yml": {"monitoring-config-validate"},
    "hetzner/RUNBOOK-monitoring.md": {"monitoring-config-validate"},
    "hetzner/nextcloud1/stack/compose.yml": {"nextcloud1-config-validate"},
    "hetzner/control-plane/stack/compose.yml": {"control-plane-config-validate"},
    "hetzner/provision/stack_keys_check.py": {"control-plane-config-validate"},
    "hetzner/provision/fixtures/stack-keys-quoted-env-file.yml": {"control-plane-config-validate"},
}
# Changes no skippable job reads: every one skips.
READ_BY_NONE = [
    "ansible/roles/base/tasks/main.yml",
    "ansible/checks/ci_select.py",
    "hetzner/dns/zone.json",
    "hetzner/provision/branchleft_deploy.py",
    "hetzner/estate.ts",
    "hetzner-host/host.ts",
    "scripts/test_ci_apply_environments.py",
    ".github/workflows/ansible.yml",
    ".github/CODEOWNERS",
    ".claude/settings.json",
]
UNIVERSAL_PATHS = [
    ".github/workflows/ci.yml",
    ".github/actions/ci-skip/action.yml",
    "scripts/ci_skip.py",
    "scripts/trace_reads.py",
]
# Outside every zone: the map has never heard of them, so every job runs.
UNMAPPED = ["README.md", "package.json", "sites.ts", ".nvmrc", "docs/x.md", "newdir/x.txt", "ansible"]
SHA_A = "a" * 40
SHA_B = "b" * 40


def load_variant(old: str | None = None, new: str = "") -> types.SimpleNamespace:
    """ci_skip.py with one exact text replaced, compiled in memory; the file on disk is never touched."""
    source = CI_SKIP_PY.read_text(encoding="utf-8")
    if old is not None:
        if source.count(old) != 1:
            raise AssertionError(f"mutation target is not in ci_skip.py exactly once: {old!r}")
        source = source.replace(old, new)
    namespace: dict = {"__name__": "ci_skip_variant", "__file__": str(CI_SKIP_PY)}
    exec(compile(source, "ci_skip_variant", "exec"), namespace)  # noqa: S102 - our own source
    return types.SimpleNamespace(**namespace)


def check_decisions(m) -> None:
    """Every rule of ci_skip.decide, stated as an invariant over any copy of the module."""
    units = sorted(m.UNITS)
    assert set(units) == set(m.UNITS) and units, "the map names no unit"
    assert not set(m.UNITS) & set(m.ALWAYS_RUN), "a job is both skippable and always-run"
    assert set(m.ALWAYS_RUN) == EXPECTED_ALWAYS_RUN, f"ALWAYS_RUN changed: {sorted(m.ALWAYS_RUN)}"
    assert RULED_ALWAYS_RUN <= set(m.ALWAYS_RUN), "an owner-ruled always-run job left the set"
    for unit in units:
        # Rule 1: only a pull request or a queue entry may skip.
        for event in ("push", "", "workflow_dispatch", "schedule"):
            run, _ = m.decide(unit, event, ["ansible/roles/base/tasks/main.yml"])
            assert run, f"{unit} skipped on event {event!r}"
        for event in ("pull_request", "merge_group"):
            # Rules 3 and 4: an unreadable or empty diff runs.
            assert m.decide(unit, event, None)[0], f"{unit} skipped when the diff could not be read"
            assert m.decide(unit, event, [])[0], f"{unit} skipped on an empty diff"
            # Rule 5: a path outside every zone runs, alone or beside harmless ones.
            for path in UNMAPPED:
                assert m.decide(unit, event, [path])[0], f"{unit} skipped for unmapped {path}"
                assert m.decide(unit, event, [READ_BY_NONE[0], path])[0], f"{unit} skipped beside unmapped {path}"
            assert m.decide(unit, event, [READ_BY_NONE[0], ""])[0], f"{unit} skipped for an empty path"
            # Rule 6: a read path or a universal path runs; everything else skips.
            for path, readers in READERS.items():
                run, _ = m.decide(unit, event, [path])
                assert run == (unit in readers), f"{unit} on {path}: run={run}, readers={sorted(readers)}"
                run, _ = m.decide(unit, event, [READ_BY_NONE[0], path])
                assert run == (unit in readers), f"{unit} on a mixed diff with {path}: run={run}"
            for path in UNIVERSAL_PATHS:
                assert m.decide(unit, event, [path])[0], f"{unit} skipped though {path} changed"
            # Rule 7: only a fully mapped diff that misses every read skips.
            assert not m.decide(unit, event, READ_BY_NONE)[0], f"{unit} ran for paths nothing reads"
            assert not m.decide(unit, event, ["ansible/roles/x/tasks/main.yml"])[0], f"{unit} ran for an ansible-only diff"
    # Rule 2: an always-run or unknown job runs whatever the diff.
    for unit in sorted(m.ALWAYS_RUN) + ["no-such-job", ""]:
        for event in ("pull_request", "merge_group"):
            assert m.decide(unit, event, ["ansible/roles/base/tasks/main.yml"])[0], f"{unit!r} skipped"
            assert m.decide(unit, event, READ_BY_NONE)[0], f"{unit!r} skipped on a harmless diff"


# ---- ci.yml -----------------------------------------------------------------------------------------------------

TOP_DIRS = sorted({*(p.name for p in ROOT.iterdir() if p.is_dir() and p.name not in {".git", "node_modules"}), *(z.rstrip("/") for z in ci_skip.ZONES)})
ROOT_FILES = sorted(p.name for p in ROOT.iterdir() if p.is_file() and not p.name.startswith(".git"))
DIR_TOKEN = re.compile(r"(?<![A-Za-z0-9_.-])((?:" + "|".join(re.escape(d) for d in TOP_DIRS) + r")/[A-Za-z0-9_./*-]*)")
FILE_TOKEN = re.compile(r"(?<![A-Za-z0-9_./$-])(" + "|".join(re.escape(f) for f in ROOT_FILES) + r")(?![A-Za-z0-9_-])")
WORKDIR = re.compile(r"^\s*working-directory:\s*(\S+)\s*$", re.M)


def step_field(step_text: str, pattern: str) -> str | None:
    found = re.search(pattern, step_text, re.M)
    return found.group(1).strip() if found else None


def step_if(step_text: str) -> str | None:
    return step_field(step_text, r"^        if: (.*)$")


def non_comment(text: str) -> str:
    return "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))


def covered(path: str, reads: tuple[str, ...], universal: tuple[str, ...] = ()) -> bool:
    """A path a step names is fine when the map reads it, or when changing it runs every job anyway."""
    return any(ci_skip.under(path, prefix) or path == prefix.rstrip("/") for prefix in (*reads, *universal))


def check_workflow(text: str, m) -> None:
    """The shape every skippable job must have, and that every other job has none of it."""
    names = job_names(text)
    classified = set(m.UNITS) | set(m.ALWAYS_RUN)
    for key in sorted(classified):
        assert key in names, f"{key} is in the path map but is not a job of ci.yml"
        assert job_if(job_block(text, key)) is None, f"{key} has a job-level `if:` that could skip its required check"
    reachable = [k for k in names if job_if(job_block(text, k)) is None]
    unclassified = [k for k in reachable if k not in classified]
    assert not unclassified, f"jobs on pull_request/merge_group in neither UNITS nor ALWAYS_RUN: {unclassified}"

    by_name = {}
    for key in names:
        named = re.search(r"^    name: (.*?)[ \t]*$", job_block(text, key), re.M)
        if named:
            by_name[named.group(1)] = key
    for context in [n for n, f in REQUIRED.items() if f == "ci.yml"]:
        assert context in by_name, f"required check {context!r} has no job"
        assert by_name[context] in classified, f"required check {context!r} is a job in neither set"

    for key in names:
        block = job_block(text, key)
        mentions = [token for token in ("ci-skip", "steps.skip") if token in non_comment(block)]
        if key not in m.UNITS:
            assert not mentions, f"{key} must not use the skip machinery but mentions {mentions}"
            continue
        steps = step_blocks(block)
        assert len(steps) >= 3, f"{key} has too few steps"
        assert steps[0][0] == "Checkout", f"{key}: the first step must be Checkout"
        decide = steps[1][1]
        assert step_field(decide, r"^        uses: (.*)$") == SKIP_USES, f"{key}: step 2 must be the ci-skip action"
        assert step_field(decide, r"^        id: (.*)$") == "skip", f"{key}: the ci-skip step must have id skip"
        assert step_field(decide, r"^          unit: (.*)$") == key, f"{key}: `unit` must be this job's own key"
        assert step_if(decide) is None, f"{key}: the ci-skip step must always run"
        assert sum(SKIP_USES in non_comment(t) for _, t in steps) == 1, f"{key}: exactly one ci-skip step"
        for name, step_text in steps[2:]:
            assert len(re.findall(r"^        if: ", step_text, re.M)) == 1, f"{key}: step {name!r} must carry exactly one `if:`"
            assert step_if(step_text) in GUARDS, f"{key}: step {name!r} is not guarded exactly as {GUARDS}, got {step_if(step_text)!r}"
        assert "continue-on-error" not in non_comment(block), f"{key}: continue-on-error would hide a failure"


def check_reads_named(text: str, m) -> None:
    """Every repository path a skippable job's steps name must be one its map entry reads."""
    for key, reads in m.UNITS.items():
        block = job_block(text, key)
        head = block.split("\n    steps:\n", 1)[0]
        body = [t for _, t in step_blocks(block)[2:]]
        lines = non_comment("\n".join([head, *body])).replace("${PWD}/", "").replace("$PWD/", "")
        found = set(DIR_TOKEN.findall(lines)) | set(FILE_TOKEN.findall(lines)) | set(WORKDIR.findall(head))
        for token in sorted(found):
            path = token.split("*", 1)[0]
            if path in (".", "", "$GITHUB_WORKSPACE"):
                continue
            assert covered(path, reads, m.UNIVERSAL), f"{key} names {token!r}, which its entry in UNITS does not read {reads}"


def mutate_workflow(text: str, job: str, old: str, new: str, count: int = 1) -> str:
    block = job_block(text, job)
    assert block.count(old) >= 1, f"mutation target not in {job}: {old!r}"
    return text.replace(block, block.replace(old, new, count))


def add_after_checkout(text: str, job: str, step_yaml: str) -> str:
    block = job_block(text, job)
    marker = "          persist-credentials: false\n"
    assert marker in block
    return text.replace(block, block.replace(marker, marker + step_yaml, 1))


class RealCodeTests(unittest.TestCase):
    """The shipped code and workflow satisfy every invariant the mutants below must break."""

    def test_the_decision_rules_hold(self):
        check_decisions(ci_skip)

    def test_every_workflow_job_is_classified_and_shaped(self):
        check_workflow(CI_YML.read_text(encoding="utf-8"), ci_skip)

    def test_every_path_a_skippable_job_names_is_in_its_map_entry(self):
        check_reads_named(CI_YML.read_text(encoding="utf-8"), ci_skip)

    def test_always_run_is_exactly_the_six_jobs_and_includes_the_two_ruled(self):
        self.assertEqual(EXPECTED_ALWAYS_RUN, set(ci_skip.ALWAYS_RUN))
        self.assertTrue(RULED_ALWAYS_RUN <= set(ci_skip.ALWAYS_RUN))
        self.assertFalse(set(ci_skip.UNITS) & set(ci_skip.ALWAYS_RUN))

    def test_the_two_python_steps_that_read_a_tree_run_under_the_trace(self):
        text = CI_YML.read_text(encoding="utf-8")
        monitoring = job_block(text, "monitoring-config-validate")
        mail = job_block(text, "mail-provision-checks")
        self.assertIn(
            "run: python3 scripts/trace_reads.py --unit monitoring-config-validate -- -m unittest discover -s hetzner/monitoring",
            monitoring,
        )
        self.assertIn(
            "run: python3 scripts/trace_reads.py --unit mail-provision-checks -- -m unittest discover -s mail/provision",
            mail,
        )

    def test_every_mapped_path_exists_and_sits_in_a_zone(self):
        for unit, reads in ci_skip.UNITS.items():
            for prefix in reads:
                with self.subTest(unit=unit, prefix=prefix):
                    self.assertTrue((ROOT / prefix).exists(), f"{prefix} is mapped but absent")
                    self.assertTrue(ci_skip.in_any(prefix, ci_skip.ZONES))
        for path in ci_skip.UNIVERSAL:
            with self.subTest(universal=path):
                self.assertTrue((ROOT / path).exists(), f"{path} is universal but absent")

    def test_the_cleanup_steps_still_run_after_a_failure(self):
        text = CI_YML.read_text(encoding="utf-8")
        steps = dict(step_blocks(job_block(text, "monitoring-config-validate")))
        for name in ("Remove the rendered ntfy config", "Remove the rendered Alertmanager config"):
            self.assertEqual(f"always() && {GUARD}", step_if(steps[name]))


class MutantTests(unittest.TestCase):
    """Each deliberate break must be caught by the checker the real code passes."""

    def assert_decisions_catch(self, old: str, new: str):
        check_decisions(ci_skip)  # control case: the real module passes
        with self.assertRaises(AssertionError):
            check_decisions(load_variant(old, new))

    def assert_workflow_catches(self, mutated: str, m=ci_skip):
        check_workflow(CI_YML.read_text(encoding="utf-8"), m)  # control case
        with self.assertRaises(AssertionError):
            check_workflow(mutated, m)

    def test_a_if_an_unmapped_path_no_longer_fails_open(self):
        self.assert_decisions_catch("not in_any(path, ZONES)", "False")

    def test_b_an_empty_diff_skips(self):
        self.assert_decisions_catch('return True, "the diff is empty"', 'return False, "the diff is empty"')

    def test_c_a_diff_error_skips(self):
        self.assert_decisions_catch(
            'return True, "the changed paths could not be read"', 'return False, "the changed paths could not be read"'
        )

    def test_d_monitoring_loses_its_own_directory(self):
        self.assert_decisions_catch('("hetzner/monitoring/", "hetzner/RUNBOOK-monitoring.md")', '("hetzner/RUNBOOK-monitoring.md",)')

    def test_e_an_always_run_job_appears_in_the_map(self):
        self.assert_decisions_catch('"mail-typecheck": ("mail/",),', '"mail-typecheck": ("mail/",),\n    "scripts-tests": ("scripts/",),')

    def test_f_a_step_guard_is_written_equals_true(self):
        text = CI_YML.read_text(encoding="utf-8")
        mutated = mutate_workflow(text, "monitoring-config-validate", "if: steps.skip.outputs.run != 'false'", "if: steps.skip.outputs.run == 'true'")
        self.assert_workflow_catches(mutated)

    def test_g_a_job_names_another_jobs_key(self):
        text = CI_YML.read_text(encoding="utf-8")
        mutated = mutate_workflow(text, "monitoring-config-validate", "unit: monitoring-config-validate", "unit: edge-config-validate")
        self.assert_workflow_catches(mutated)

    def test_h_a_skip_step_is_added_to_an_always_run_job(self):
        text = CI_YML.read_text(encoding="utf-8")
        step = "\n      - name: Decide\n        id: skip\n        uses: ./.github/actions/ci-skip\n        with:\n          unit: scripts-tests\n"
        self.assert_workflow_catches(add_after_checkout(text, "scripts-tests", step))

    def test_i_a_job_level_if_is_added_to_a_skippable_job(self):
        text = CI_YML.read_text(encoding="utf-8")
        mutated = mutate_workflow(
            text, "edge-config-validate", "    timeout-minutes: 15\n", "    timeout-minutes: 15\n    if: github.event_name == 'pull_request'\n"
        )
        self.assert_workflow_catches(mutated)

    def test_j_a_step_is_left_unguarded(self):
        text = CI_YML.read_text(encoding="utf-8")
        mutated = mutate_workflow(text, "nextcloud1-config-validate", "        if: steps.skip.outputs.run != 'false'\n", "")
        self.assert_workflow_catches(mutated)

    def test_k_a_new_job_is_in_neither_set(self):
        text = CI_YML.read_text(encoding="utf-8")
        extra = "  brand-new-check:\n    name: Brand new\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: true\n\n"
        mutated = text.replace("  scripts-tests:\n", extra + "  scripts-tests:\n", 1)
        self.assertNotEqual(text, mutated)
        self.assert_workflow_catches(mutated)

    def test_l_the_always_run_set_loses_a_job(self):
        check_decisions(ci_skip)
        variant = load_variant('        "typecheck",\n', "")
        with self.assertRaises(AssertionError):
            check_decisions(variant)
        with self.assertRaises(AssertionError):
            check_workflow(CI_YML.read_text(encoding="utf-8"), variant)

    def test_m_the_event_rule_is_dropped(self):
        self.assert_decisions_catch("if event not in EVENTS:", "if False:")

    def test_n_the_universal_list_forgets_ci_yml(self):
        self.assert_decisions_catch('    ".github/workflows/ci.yml",\n', "")

    def test_o_a_step_reads_a_path_outside_its_map(self):
        text = CI_YML.read_text(encoding="utf-8")
        check_reads_named(text, ci_skip)  # control case
        mutated = mutate_workflow(
            text,
            "monitoring-config-validate",
            "run: docker compose -f hetzner/monitoring/stack/compose.yml config -q",
            "run: docker compose -f ansible/roles/x/compose.yml config -q",
        )
        with self.assertRaises(AssertionError):
            check_reads_named(mutated, ci_skip)

    def test_p_a_step_reads_a_root_level_file(self):
        text = CI_YML.read_text(encoding="utf-8")
        mutated = mutate_workflow(text, "edge-config-validate", "docker build --tag edge-caddy-ci:validate hetzner/edge", "cat sites.ts && docker build --tag edge-caddy-ci:validate hetzner/edge")
        with self.assertRaises(AssertionError):
            check_reads_named(mutated, ci_skip)

    def test_q_the_diff_command_is_pinned(self):
        # A diff against only the head would list nothing for a clean tree: the rule that an
        # empty diff runs is what stands between that and a skip, so the real command is pinned.
        source = CI_SKIP_PY.read_text(encoding="utf-8")
        self.assertIn('["diff", "--name-only", "-z", "--no-renames", base, head]', source)


# ---- behaviour of the script around decide() -------------------------------------------------------------------


def done(returncode: int = 0, stdout: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout, b"")


class Scripted:
    """A runner that answers git calls from a table keyed by the git subcommand."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append(command[1:])
        answer = self.answers.get(command[1], done(0))
        if isinstance(answer, Exception):
            raise answer
        return answer(command) if callable(answer) else answer


class ChangedFilesTests(unittest.TestCase):
    def test_a_good_diff_is_split_on_nul(self):
        runner = Scripted({"diff": done(0, b"ansible/a.yml\0mail/index.ts\0")})
        self.assertEqual(["ansible/a.yml", "mail/index.ts"], ci_skip.changed_files(SHA_A, SHA_B, runner))

    def test_a_path_with_a_newline_stays_one_path(self):
        runner = Scripted({"diff": done(0, b"ansible/x\nrun=false\0")})
        self.assertEqual(["ansible/x\nrun=false"], ci_skip.changed_files(SHA_A, SHA_B, runner))

    def test_missing_or_malformed_shas_cannot_be_read(self):
        runner = Scripted({})
        for base, head in [(None, SHA_B), (SHA_A, None), ("", SHA_B), ("--output=x", SHA_B), (SHA_A, "HEAD"), ("abc", SHA_B)]:
            with self.subTest(base=base, head=head):
                self.assertIsNone(ci_skip.changed_files(base, head, runner))
        self.assertEqual([], runner.calls, "no git command may run for a value that is not a sha")

    def test_an_absent_head_cannot_be_read(self):
        runner = Scripted({"cat-file": done(1)})
        self.assertIsNone(ci_skip.changed_files(SHA_A, SHA_B, runner))

    def test_a_failed_fetch_cannot_be_read(self):
        present = iter([done(0), done(1), done(1)])
        runner = Scripted({"cat-file": lambda _: next(present), "fetch": done(128)})
        self.assertIsNone(ci_skip.changed_files(SHA_A, SHA_B, runner))

    def test_a_fetch_that_leaves_the_base_absent_cannot_be_read(self):
        present = iter([done(0), done(1), done(1)])
        runner = Scripted({"cat-file": lambda _: next(present), "fetch": done(0)})
        self.assertIsNone(ci_skip.changed_files(SHA_A, SHA_B, runner))

    def test_a_failed_diff_cannot_be_read(self):
        runner = Scripted({"diff": done(128)})
        self.assertIsNone(ci_skip.changed_files(SHA_A, SHA_B, runner))

    def test_a_runner_that_raises_cannot_be_read(self):
        for error in (subprocess.TimeoutExpired("git", 1), OSError("no git"), ValueError("x")):
            with self.subTest(error=type(error).__name__):
                runner = Scripted({"diff": error, "cat-file": error})
                self.assertIsNone(ci_skip.changed_files(SHA_A, SHA_B, runner))

    def test_the_base_is_fetched_anonymously_and_shallow_when_absent(self):
        present = iter([done(0), done(1), done(0)])
        runner = Scripted({"cat-file": lambda _: next(present), "fetch": done(0), "diff": done(0, b"mail/a\0")})
        self.assertEqual(["mail/a"], ci_skip.changed_files(SHA_A, SHA_B, runner))
        fetch = [c for c in runner.calls if c[0] == "fetch"]
        self.assertEqual([["fetch", "--no-tags", "--depth=1", "--quiet", "origin", SHA_A]], fetch)


def clean_git_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_TERMINAL_PROMPT": "0"})
    return env


def real_runner(command, **kwargs):
    return subprocess.run(command, env=clean_git_env(), **kwargs)


def git_in(directory: str, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=directory, env=clean_git_env(), capture_output=True, text=True, check=True)
    return result.stdout.strip()


class RealGitTests(unittest.TestCase):
    """The depth-1 checkout plus one depth-1 fetch of the base, against a real repository."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = pathlib.Path(self.tmp.name)
        self.origin = str(base / "origin")
        os.mkdir(self.origin)
        git_in(self.origin, "init", "--quiet", "-b", "main")
        git_in(self.origin, "config", "user.email", "t@example.invalid")
        git_in(self.origin, "config", "user.name", "t")
        git_in(self.origin, "config", "commit.gpgsign", "false")
        git_in(self.origin, "config", "uploadpack.allowAnySHA1InWant", "true")
        for path, content in (("ansible/a.yml", "1"), ("mail/index.ts", "1"), ("README.md", "1")):
            full = pathlib.Path(self.origin, path)
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(content)
        git_in(self.origin, "add", ".")
        git_in(self.origin, "commit", "--quiet", "-m", "base")
        self.base_sha = git_in(self.origin, "rev-parse", "HEAD")
        pathlib.Path(self.origin, "ansible/a.yml").write_text("2")
        pathlib.Path(self.origin, "ansible/b.yml").write_text("1")
        git_in(self.origin, "add", ".")
        git_in(self.origin, "commit", "--quiet", "-m", "change")
        self.head_sha = git_in(self.origin, "rev-parse", "HEAD")
        self.clone = str(base / "clone")
        git_in(self.tmp.name, "clone", "--quiet", "--depth=1", f"file://{self.origin}", self.clone)

    def test_a_shallow_clone_reads_the_diff_by_fetching_only_the_base(self):
        self.assertNotEqual("", git_in(self.clone, "rev-parse", "HEAD"))
        absent = subprocess.run(
            ["git", "cat-file", "-e", f"{self.base_sha}^{{commit}}"], cwd=self.clone, env=clean_git_env(), capture_output=True
        )
        self.assertNotEqual(0, absent.returncode, "the clone must start without the base commit")
        changed = ci_skip.changed_files(self.base_sha, self.head_sha, real_runner, cwd=self.clone)
        self.assertEqual(["ansible/a.yml", "ansible/b.yml"], sorted(changed))
        self.assertEqual(
            (False, "no changed path is one this job reads"),
            ci_skip.decide("monitoring-config-validate", "pull_request", changed),
        )

    def test_an_unknown_base_cannot_be_read_and_so_runs(self):
        changed = ci_skip.changed_files("c" * 40, self.head_sha, real_runner, cwd=self.clone)
        self.assertIsNone(changed)
        self.assertTrue(ci_skip.decide("edge-config-validate", "pull_request", changed)[0])


class MainTests(unittest.TestCase):
    def run_main(self, unit, environ, runner=None):
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = ci_skip.main(["--unit", unit], environ=environ, runner=runner or Scripted({}))
        self.assertEqual(0, code)
        lines = out.getvalue().splitlines()
        return dict(line.split("=", 1) for line in lines), lines

    def test_it_prints_exactly_two_output_lines(self):
        runner = Scripted({"diff": done(0, b"ansible/a.yml\0")})
        env = {"EVENT_NAME": "pull_request", "BASE_SHA": SHA_A, "HEAD_SHA": SHA_B}
        values, lines = self.run_main("edge-config-validate", env, runner)
        self.assertEqual("false", values["run"])
        self.assertEqual(["run", "reason"], [line.split("=", 1)[0] for line in lines])

    def test_a_push_runs_without_touching_git(self):
        runner = Scripted({})
        values, _ = self.run_main("edge-config-validate", {"EVENT_NAME": "push", "BASE_SHA": SHA_A, "HEAD_SHA": SHA_B}, runner)
        self.assertEqual("true", values["run"])
        self.assertEqual([], runner.calls)

    def test_an_always_run_job_runs_without_touching_git(self):
        runner = Scripted({})
        values, _ = self.run_main("scripts-tests", {"EVENT_NAME": "pull_request", "BASE_SHA": SHA_A, "HEAD_SHA": SHA_B}, runner)
        self.assertEqual("true", values["run"])
        self.assertEqual([], runner.calls)

    def test_missing_environment_runs(self):
        values, _ = self.run_main("edge-config-validate", {})
        self.assertEqual("true", values["run"])

    def test_a_crash_inside_the_decision_runs(self):
        def boom(command, **kwargs):
            raise RuntimeError("unexpected")

        # changed_files swallows runner errors, so make decide itself fail.
        original = ci_skip.decide
        ci_skip.decide = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            values, _ = self.run_main("edge-config-validate", {"EVENT_NAME": "pull_request"}, boom)
        finally:
            ci_skip.decide = original
        self.assertEqual("true", values["run"])

    def test_a_path_name_can_never_reach_the_output(self):
        # A file named like an output line must not let a pull request write one.
        evil = b"ansible/x\nrun=false\n\0"
        runner = Scripted({"diff": done(0, evil)})
        env = {"EVENT_NAME": "pull_request", "BASE_SHA": SHA_A, "HEAD_SHA": SHA_B}
        values, lines = self.run_main("edge-config-validate", env, runner)
        self.assertEqual(2, len(lines))
        self.assertEqual("false", values["run"])
        for reason in (ci_skip.decide("edge-config-validate", "pull_request", ["a\nrun=false"])[1],):
            self.assertNotIn("\n", ci_skip.one_line(reason))
        self.assertNotIn("\n", ci_skip.one_line("x\nrun=false\r\ny"))

    def test_the_action_calls_the_script_and_widens_when_it_cannot_run(self):
        action = (ROOT / ".github" / "actions" / "ci-skip" / "action.yml").read_text(encoding="utf-8")
        self.assertIn('python3 scripts/ci_skip.py --unit "$UNIT"', action)
        self.assertIn('|| echo "run=true" >> "$GITHUB_OUTPUT"', action)
        # CI-2: nothing is interpolated into the run body.
        run_body = action.split("run: |", 1)[1]
        self.assertNotIn("${{", run_body)
        for name in ("UNIT", "EVENT_NAME", "BASE_SHA", "HEAD_SHA"):
            self.assertRegex(action, rf"(?m)^        {name}: \$\{{\{{ ")


if __name__ == "__main__":
    unittest.main()
