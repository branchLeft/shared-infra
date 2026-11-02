"""Tests for the choice of Ansible shards (ci_select.py).

A shard wrongly left out is a gate that passes without running, so these tests are written
from that side: each rule is shown to run what it must, on the real tree, and the controls
show that a run which should be narrow is narrow.
"""

from __future__ import annotations

import importlib.util
import io
import json
import re
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path

import ci_select

ROOT = Path(__file__).resolve().parents[2]
CI_SELECT = Path(ci_select.__file__).resolve()
LIST_SHARDS = ROOT / "ansible" / "harness" / "list_shards.py"
# A file of the checks folder, as the shard job names it in a line of its own script.
CHECKS_FILE = re.compile(r"ansible/checks/[A-Za-z0-9_.-]+")
# The three checks files named one by one in EVERY_SHARD. Only the first two are shard inputs;
# check_pins.py is no shard's input, and stays every-shard as the issue asks.
SHARD_READS = (
    "ansible/checks/ci_select.py",
    "ansible/checks/check_pins.py",
    "ansible/checks/pip-requirements.txt",
)


def real_shards() -> list[dict[str, str]]:
    """Return the shards of the real tree, listed by the program the workflow runs.

    Raises:
        AssertionError: list_shards.py cannot be loaded.
    """
    spec = importlib.util.spec_from_file_location("list_shards_under_test", LIST_SHARDS)
    if spec is None or spec.loader is None:
        message = "list_shards.py cannot be loaded"
        raise AssertionError(message)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    listed: list[dict[str, str]] = module.shards(ROOT)
    return listed


def paths_of(shards: list[dict[str, str]]) -> set[str]:
    """Return the directories the shards run over."""
    return {shard["path"] for shard in shards}


class SelectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.shards = real_shards()

    def pull_request(self, *changed: str) -> list[dict[str, str]]:
        return ci_select.select("pull_request", list(changed), self.shards, ROOT)

    def test_the_tree_lists_more_than_one_shard_to_choose_from(self) -> None:
        # A control: with one shard every selection below would pass.
        self.assertGreater(len(paths_of(self.shards)), 10)
        self.assertIn(ci_select.SKELETON, paths_of(self.shards))

    def queue_entry(self, *changed: str) -> list[dict[str, str]]:
        return ci_select.select("merge_group", list(changed), self.shards, ROOT)

    def test_a_merge_queue_entry_that_cannot_say_what_changed_runs_every_shard(self) -> None:
        self.assertEqual(self.shards, ci_select.select("merge_group", None, self.shards, ROOT))

    def test_a_merge_queue_entry_that_changed_a_shared_file_runs_every_shard(self) -> None:
        # The sabotage case: the rule that a shared file runs every shard must hold for the
        # queue's diff as it does for a pull request's. Each of these is read by every role.
        for path in (
            "ansible/harness/run_harness.py",
            "ansible/checks/check_pins.py",
            "ansible/requirements.txt",
            "ansible/requirements.yml",
            "ansible/pyproject.toml",
            ".ansible-lint",
            ".yamllint",
            ".github/workflows/ansible.yml",
            "ansible/ansible.cfg",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.shards, self.queue_entry(path))
                self.assertEqual(self.shards, self.queue_entry("ansible/roles/egress_nat/x", path))

    def test_a_merge_queue_entry_that_changed_one_role_runs_that_role_alone(self) -> None:
        chosen = self.queue_entry("ansible/roles/egress_nat/tasks/main.yml")
        self.assertEqual({"ansible/roles/egress_nat"}, paths_of(chosen))
        self.assertEqual(self.pull_request("ansible/roles/egress_nat/tasks/main.yml"), chosen)

    def test_a_merge_queue_entry_is_narrowed_as_a_pull_request_is(self) -> None:
        # A control that the two events share one set of rules, on every kind of file.
        for changed in (
            ("ansible/patterns/typed_module/library/x.py",),
            ("ansible/role_skeleton/tasks/main.yml.j2",),
            ("ansible/roles/backup_worker/tasks/main.yml",),
            ("hetzner/provision/branchleft-nat.service",),
            ("ansible/playbooks/app1.yml",),
            ("README.md",),
            ("ansible/roles/gone/tasks/main.yml",),
        ):
            with self.subTest(changed=changed):
                self.assertEqual(self.pull_request(*changed), self.queue_entry(*changed))

    def test_a_merge_queue_entry_that_changed_nothing_a_shard_reads_runs_no_shard(self) -> None:
        self.assertEqual([], self.queue_entry("README.md", "hetzner/dns/zone.json"))

    def test_the_weekly_sweep_runs_every_shard_whatever_the_diff_says(self) -> None:
        self.assertEqual(self.shards, ci_select.select("schedule", None, self.shards, ROOT))
        self.assertEqual(self.shards, ci_select.select("schedule", [], self.shards, ROOT))
        self.assertEqual(
            self.shards, ci_select.select("schedule", ["README.md"], self.shards, ROOT)
        )

    def test_a_push_to_main_runs_no_shard(self) -> None:
        self.assertEqual([], ci_select.select("push", ["ansible/harness/x.py"], self.shards, ROOT))

    def test_a_pull_request_that_cannot_say_what_changed_runs_every_shard(self) -> None:
        self.assertEqual(self.shards, ci_select.select("pull_request", None, self.shards, ROOT))

    def test_an_event_nobody_planned_for_runs_every_shard(self) -> None:
        self.assertEqual(self.shards, ci_select.select("workflow_dispatch", [], self.shards, ROOT))

    def test_a_role_change_runs_that_role_alone(self) -> None:
        chosen = self.pull_request("ansible/roles/egress_nat/tasks/main.yml")
        self.assertEqual({"ansible/roles/egress_nat"}, paths_of(chosen))
        every = [s for s in self.shards if s["path"] == "ansible/roles/egress_nat"]
        self.assertEqual(every, chosen)

    def test_a_change_in_every_role_and_pattern_runs_all_of_its_scenarios(self) -> None:
        for path in sorted(paths_of(self.shards) - {ci_select.SKELETON}):
            with self.subTest(unit=path):
                chosen = self.pull_request(f"{path}/README.md")
                own = [s for s in self.shards if s["path"] == path]
                self.assertTrue(set(map(str, own)) <= set(map(str, chosen)))

    def test_a_pattern_change_runs_that_pattern_alone(self) -> None:
        chosen = self.pull_request("ansible/patterns/typed_module/library/x.py")
        self.assertEqual({"ansible/patterns/typed_module"}, paths_of(chosen))

    def test_the_skeleton_change_runs_the_skeleton_alone(self) -> None:
        chosen = self.pull_request("ansible/role_skeleton/tasks/main.yml.j2")
        self.assertEqual({ci_select.SKELETON}, paths_of(chosen))

    def test_the_files_that_decide_every_role_run_every_shard(self) -> None:
        for path in (
            "ansible/harness/run_harness.py",
            "ansible/harness/molecule/x.yml",
            "ansible/checks/check_pins.py",
            "ansible/checks/pip-requirements.txt",
            "ansible/pyproject.toml",
            "ansible/requirements.in",
            "ansible/requirements.txt",
            "ansible/requirements.yml",
            ".ansible-lint",
            ".yamllint",
            ".github/workflows/ansible.yml",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.shards, self.pull_request(path))

    def test_every_entry_that_decides_every_role_is_a_file_the_tree_holds(self) -> None:
        # A control: an entry that names nothing (a renamed file) would run no shard for it.
        for entry in ci_select.EVERY_SHARD:
            with self.subTest(entry=entry):
                self.assertTrue((ROOT / entry).exists(), entry)

    def test_one_such_file_among_role_files_still_runs_every_shard(self) -> None:
        self.assertEqual(
            self.shards,
            self.pull_request("ansible/roles/egress_nat/tasks/main.yml", ".yamllint"),
        )

    def test_a_file_under_ansible_that_no_rule_names_runs_every_shard(self) -> None:
        for path in ("ansible/ansible.cfg", "ansible/roles/README.md", "ansible/new_dir/x.yml"):
            with self.subTest(path=path):
                self.assertEqual(self.shards, self.pull_request(path))

    def test_the_files_only_lint_reads_run_no_shard(self) -> None:
        for path in (
            "ansible/README.md",
            "ansible/inventories/production/hosts.yml",
            "ansible/playbooks/app1.yml",
            "ansible/tools/pull_bootstrap.py",
            "ansible/trust/app1.yml",
            ".github/workflows/ansible-delivery.yml",
            "README.md",
        ):
            with self.subTest(path=path):
                self.assertEqual([], self.pull_request(path))

    def test_every_lint_only_entry_is_a_path_the_tree_holds(self) -> None:
        # A control: the narrowing above is only as good as the paths it names.
        for entry in ci_select.LINT_ONLY:
            with self.subTest(entry=entry):
                self.assertTrue((ROOT / entry).exists(), entry)

    def test_a_role_file_change_still_runs_that_roles_shard(self) -> None:
        # The narrowing the issue says works for roles must keep working, on both events.
        path = "ansible/roles/egress_nat/tasks/main.yml"
        own = [shard for shard in self.shards if shard["path"] == "ansible/roles/egress_nat"]
        self.assertTrue(own, "egress_nat has no shard to test")
        self.assertEqual(own, self.pull_request(path))
        self.assertEqual(own, self.queue_entry(path))

    def test_host_roles_and_playbooks_keep_their_pinned_behaviour(self) -> None:
        # host_roles.yml is read by the lint job's tests, not by a shard, so it selects none.
        # It selected every shard before, only because it sat under ansible/checks/. A playbook
        # selects none, as it did before.
        for path in (
            "ansible/checks/host_roles.yml",
            "ansible/playbooks/app1.yml",
            "ansible/playbooks/edge1.yml",
        ):
            with self.subTest(path=path):
                self.assertEqual([], self.pull_request(path))
        own = [shard for shard in self.shards if shard["path"] == "ansible/roles/egress_nat"]
        chosen = self.pull_request(
            "ansible/roles/egress_nat/tasks/main.yml", "ansible/checks/host_roles.yml"
        )
        self.assertEqual(own, chosen)

    def test_the_three_checks_files_the_shards_read_run_every_shard(self) -> None:
        # A shard that is wrongly left out is a gate that passes without running. Each file is
        # shown alone and beside a role file, on both events.
        for path in SHARD_READS:
            with self.subTest(path=path):
                self.assertEqual(self.shards, self.pull_request(path))
                self.assertEqual(self.shards, self.queue_entry(path))
                self.assertEqual(
                    self.shards, self.pull_request("ansible/roles/egress_nat/tasks/main.yml", path)
                )

    def test_an_unrecognised_ansible_path_outside_checks_runs_every_shard(self) -> None:
        # The folder rule is a path with its slash, so a sibling whose name starts the same way
        # is not in the folder, and runs every shard.
        for path in (
            "ansible/new_dir/x.yml",
            "ansible/ansible.cfg",
            "ansible/roles/README.md",
            "ansible/checks_old/x.py",
            "ansible/checks.py",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.shards, self.pull_request(path))

    def test_the_rest_of_the_checks_folder_runs_no_shard(self) -> None:
        # Every file in ansible/checks/ but the three named above runs the lint job only. The
        # files are listed from the tree, so a file added later is covered too.
        rest = sorted(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "ansible" / "checks").rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        )
        # A control: an empty listing would pass for nothing.
        self.assertGreater(len(rest), len(SHARD_READS))
        for path in [*rest, "ansible/checks/a_file_added_later.py"]:
            if path in SHARD_READS:
                continue
            with self.subTest(path=path):
                self.assertEqual([], self.pull_request(path))

    def test_every_checks_file_the_shard_job_names_runs_every_shard(self) -> None:
        # The fail-open guard: a checks file the shard job starts to read must run every shard,
        # or the selector would under-select without a sign. The shard job is the text from its
        # header to the next job's header; comment lines are not reads.
        workflow = (ROOT / ".github" / "workflows" / "ansible.yml").read_text(encoding="utf-8")
        start = workflow.index("\n  shard:\n")
        end = workflow.index("\n  roles:\n", start)
        named: set[str] = set()
        for line in workflow[start:end].splitlines():
            if not line.lstrip().startswith("#"):
                named.update(CHECKS_FILE.findall(line))
        # A control: the job names its pin, so an empty scan would pass for nothing.
        self.assertIn("ansible/checks/pip-requirements.txt", named)
        for path in sorted(named):
            with self.subTest(path=path):
                self.assertEqual(self.shards, self.pull_request(path))

    def test_a_role_that_another_names_runs_with_it(self) -> None:
        chosen = self.pull_request("ansible/roles/backup_worker/tasks/main.yml")
        self.assertIn("ansible/roles/backup_restore", paths_of(chosen))
        chosen = self.pull_request("ansible/patterns/files_and_units/tasks/main.yml")
        self.assertIn("ansible/patterns/program_and_timer", paths_of(chosen))

    def test_a_role_that_nothing_names_runs_alone(self) -> None:
        # The control of the test above: the closure does not widen a selection that has nothing
        # to add.
        chosen = self.pull_request("ansible/roles/egress_nat/tasks/main.yml")
        self.assertEqual({"ansible/roles/egress_nat"}, paths_of(chosen))

    def test_every_file_a_role_reads_outside_ansible_runs_that_role(self) -> None:
        reads = ci_select.reads_by_path(ROOT)
        self.assertTrue(reads, "the scan found no reads")
        for read, readers in sorted(reads.items()):
            changed = read if (ROOT / read).is_file() else f"{read}/some_file"
            with self.subTest(read=read):
                chosen = paths_of(self.pull_request(changed))
                self.assertLessEqual(readers, chosen)

    def test_the_scan_finds_the_reads_it_is_meant_to_find(self) -> None:
        # A control: an empty scan would make the test above pass.
        reads = ci_select.reads_by_path(ROOT)
        self.assertIn("hetzner/monitoring/stack", reads)
        self.assertIn("hetzner/provision/branchleft-nat.service", reads)
        self.assertIn("hetzner/provision/branchleft-db-tunnel.service", reads)
        # Read through a symlink in files/, not through a path in molecule/ or tests/.
        self.assertIn("hetzner/control-plane/stack", reads)
        self.assertIn("ansible/roles/egress_nat", reads["hetzner/provision/branchleft-nat.service"])

    def test_a_mail_script_the_mx1_stack_role_reads_runs_that_role(self) -> None:
        # A control on the real tree: the role links the compose file and the Caddyfile.
        reads = ci_select.reads_by_path(ROOT)
        for path in ("mail/provision/Caddyfile", "mail/provision/docker-compose.yml"):
            with self.subTest(path=path):
                self.assertIn("ansible/roles/mx1_stack", reads.get(path, set()))
                self.assertIn("ansible/roles/mx1_stack", paths_of(self.pull_request(path)))

    def test_a_file_outside_ansible_that_no_role_reads_runs_no_shard(self) -> None:
        for path in ("hetzner/RUNBOOK-edge.md", "hetzner/dns/zone.json", "mail/README.md"):
            with self.subTest(path=path):
                self.assertEqual([], self.pull_request(path))


class TreeFixtureTest(unittest.TestCase):
    """The selection on a small tree built here, where the right answer is known."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.write("ansible/roles/reader/molecule/default/verify.yml", "src: hetzner/x/y.conf\n")
        self.write("ansible/roles/user/tasks/main.yml", "name: branchleft.reader\n")
        self.write("ansible/roles/loner/tasks/main.yml", "name: nothing\n")
        self.write("ansible/patterns/pat/tasks/main.yml", "name: nothing\n")
        self.write("hetzner/x/y.conf", "x\n")
        self.write("hetzner/x/z.conf", "x\n")
        self.shards = [
            {
                "name": "reader",
                "path": "ansible/roles/reader",
                "scenario": "default",
                "kind": "role",
            },
            {"name": "user", "path": "ansible/roles/user", "scenario": "default", "kind": "role"},
            {"name": "loner", "path": "ansible/roles/loner", "scenario": "default", "kind": "role"},
            {"name": "pat", "path": "ansible/patterns/pat", "scenario": "default", "kind": "role"},
        ]

    def write(self, name: str, text: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def names(self, *changed: str) -> list[str]:
        chosen = ci_select.select("pull_request", list(changed), self.shards, self.root)
        return [shard["name"] for shard in chosen]

    def test_a_read_file_runs_its_reader_and_the_role_that_names_the_reader(self) -> None:
        self.assertEqual(["reader", "user"], self.names("hetzner/x/y.conf"))

    def test_a_file_beside_the_read_one_runs_nothing(self) -> None:
        self.assertEqual([], self.names("hetzner/x/z.conf"))

    def test_a_role_nothing_names_runs_alone(self) -> None:
        self.assertEqual(["loner"], self.names("ansible/roles/loner/tasks/main.yml"))
        self.assertEqual(["pat"], self.names("ansible/patterns/pat/tasks/main.yml"))

    def test_the_role_that_is_named_runs_its_namer_too(self) -> None:
        self.assertEqual(["reader", "user"], self.names("ansible/roles/reader/tasks/main.yml"))

    def test_the_naming_role_does_not_run_the_one_it_names(self) -> None:
        self.assertEqual(["user"], self.names("ansible/roles/user/tasks/main.yml"))

    def test_a_link_into_hetzner_counts_as_a_read(self) -> None:
        link = self.root / "ansible/roles/loner/files/y.conf"
        link.parent.mkdir(parents=True)
        link.symlink_to("../../../../hetzner/x/z.conf")
        self.assertEqual(["loner"], self.names("hetzner/x/z.conf"))

    def test_a_literal_mail_path_and_a_link_into_mail_count_as_reads(self) -> None:
        self.write("ansible/roles/mailer/molecule/default/verify.yml", "src: mail/provision/x.sh\n")
        self.write("mail/provision/x.sh", "x\n")
        self.write("mail/provision/Caddyfile", "x\n")
        self.write("mail/README.md", "x\n")
        self.shards.append(
            {
                "name": "mailer",
                "path": "ansible/roles/mailer",
                "scenario": "default",
                "kind": "role",
            }
        )
        link = self.root / "ansible/roles/mailer/files/Caddyfile"
        link.parent.mkdir(parents=True)
        link.symlink_to("../../../../mail/provision/Caddyfile")
        self.assertEqual(["mailer"], self.names("mail/provision/x.sh"))
        self.assertEqual(["mailer"], self.names("mail/provision/Caddyfile"))
        self.assertEqual([], self.names("mail/README.md"))

    def test_a_deleted_role_selects_nothing_for_itself(self) -> None:
        self.assertEqual([], self.names("ansible/roles/gone/tasks/main.yml"))


class CommandTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.dir = Path(self.directory.name)
        self.matrix = self.dir / "matrix.json"
        include = [
            {"name": "a", "path": "ansible/roles/a", "scenario": "default", "kind": "role"},
            {"name": "b", "path": "ansible/roles/b", "scenario": "default", "kind": "role"},
        ]
        self.matrix.write_text(json.dumps({"include": include}), encoding="utf-8")
        (self.dir / "ansible" / "roles" / "a").mkdir(parents=True)
        (self.dir / "ansible" / "roles" / "b").mkdir(parents=True)

    def run_main(self, *args: str) -> tuple[int, dict[str, str]]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = ci_select.main(
                ["--matrix-file", str(self.matrix), "--root", str(self.dir), *args]
            )
        pairs = [line.split("=", 1) for line in out.getvalue().splitlines()]
        return status, {key: value for key, value in pairs}

    def changed(self, *names: str) -> Path:
        path = self.dir / "changed.z"
        path.write_text("\0".join(names) + "\0", encoding="utf-8")
        return path

    def test_a_narrow_run_prints_its_shards(self) -> None:
        changed = self.changed("ansible/roles/a/tasks/main.yml")
        status, outputs = self.run_main("--event", "pull_request", "--changed-file", str(changed))
        self.assertEqual(0, status)
        self.assertEqual("true", outputs["shards"])
        self.assertEqual(["a"], [s["name"] for s in json.loads(outputs["matrix"])["include"]])

    def test_a_run_with_nothing_to_run_prints_false_and_a_matrix_that_cannot_run(self) -> None:
        changed = self.changed("README.md")
        status, outputs = self.run_main("--event", "pull_request", "--changed-file", str(changed))
        self.assertEqual(0, status)
        self.assertEqual("false", outputs["shards"])
        self.assertEqual([ci_select.NO_SHARD], json.loads(outputs["matrix"])["include"])

    def test_a_missing_changed_file_runs_everything(self) -> None:
        status, outputs = self.run_main("--event", "pull_request")
        self.assertEqual(0, status)
        self.assertEqual("true", outputs["shards"])
        self.assertEqual(2, len(json.loads(outputs["matrix"])["include"]))

    def test_the_merge_queue_runs_the_shards_its_diff_names(self) -> None:
        changed = self.changed("ansible/roles/b/tasks/main.yml")
        status, outputs = self.run_main("--event", "merge_group", "--changed-file", str(changed))
        self.assertEqual(0, status)
        self.assertEqual("true", outputs["shards"])
        self.assertEqual(["b"], [s["name"] for s in json.loads(outputs["matrix"])["include"]])

    def test_the_merge_queue_runs_everything_when_a_shared_file_changed(self) -> None:
        changed = self.changed("ansible/roles/b/tasks/main.yml", "ansible/requirements.txt")
        status, outputs = self.run_main("--event", "merge_group", "--changed-file", str(changed))
        self.assertEqual(0, status)
        self.assertEqual(2, len(json.loads(outputs["matrix"])["include"]))

    def test_the_merge_queue_runs_everything_when_it_could_not_diff(self) -> None:
        status, outputs = self.run_main("--event", "merge_group")
        self.assertEqual(0, status)
        self.assertEqual(2, len(json.loads(outputs["matrix"])["include"]))

    def test_the_weekly_sweep_runs_everything(self) -> None:
        changed = self.changed("README.md")
        status, outputs = self.run_main("--event", "schedule", "--changed-file", str(changed))
        self.assertEqual(0, status)
        self.assertEqual(2, len(json.loads(outputs["matrix"])["include"]))

    def test_a_push_runs_no_shard(self) -> None:
        status, outputs = self.run_main("--event", "push")
        self.assertEqual(0, status)
        self.assertEqual("false", outputs["shards"])

    def test_a_malformed_matrix_is_refused(self) -> None:
        for text in ("", "[]", '{"include": []}', '{"include": [1]}', '{"include": [{"a": 1}]}'):
            with self.subTest(text=text):
                self.matrix.write_text(text, encoding="utf-8")
                status, _ = self.run_main("--event", "pull_request")
                self.assertEqual(1, status)

    def test_the_real_listing_parses(self) -> None:
        listing = json.dumps({"include": real_shards()})
        self.assertIsNotNone(ci_select.parse_matrix(listing))


@dataclass(frozen=True)
class Case:
    """A small tree, the files a pull request changes, and the shards it must run.

    ``expected`` is a list of unit names, or ``None`` for every shard.
    """

    files: dict[str, str]
    changed: tuple[str, ...]
    expected: list[str] | None
    links: dict[str, str] = field(default_factory=dict)


def tree_of(case: Case, root: Path) -> list[dict[str, str]]:
    """Write ``case`` under ``root`` and return one shard per role and pattern in it."""
    for name, text in case.files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for name, target in case.links.items():
        link = root / name
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
    shards = []
    for group in ci_select.GROUPS:
        base = root / "ansible" / group
        for unit in sorted(base.iterdir()) if base.is_dir() else []:
            shards.append(
                {
                    "name": unit.name,
                    "path": f"ansible/{group}/{unit.name}",
                    "scenario": "default",
                    "kind": "role",
                }
            )
    return shards


def chosen_by(module: types.ModuleType, case: Case) -> list[str]:
    """Return the unit names ``module.select`` runs for ``case``, in the order of the shards."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        shards = tree_of(case, root)
        chosen = module.select("pull_request", list(case.changed), shards, root)
        return [shard["name"] for shard in chosen]


def expected_names(case: Case) -> list[str]:
    """Return the names ``case`` expects, with every shard of its tree for ``None``."""
    if case.expected is not None:
        return case.expected
    with tempfile.TemporaryDirectory() as directory:
        return [shard["name"] for shard in tree_of(case, Path(directory))]


def role_file(unit: str, name: str = "tasks/main.yml", group: str = "roles") -> str:
    """Return the repository path of a file in a unit of the small trees."""
    return f"ansible/{group}/{unit}/{name}"


QUIET = "- name: nothing\n  ansible.builtin.debug:\n    msg: nothing\n"
PLAIN = {role_file("a"): QUIET, role_file("c"): QUIET}


def calls(unit_text: str) -> Case:
    """Return a tree where role b holds ``unit_text`` as its tasks, and role a changes."""
    return Case({**PLAIN, role_file("b"): unit_text}, (role_file("a"),), ["a", "b"])


INCLUDE = "- ansible.builtin.include_role:\n    name: %s\n"
INCLUDE_BLOCK = "- name: run a\n  ansible.builtin.include_role:\n    name: a\n    public: true\n"
# A role called by a bare name, which nothing the textual scan looks for names.
BARE_CALLS = {
    "a block include_role": INCLUDE_BLOCK,
    "a block import_role": "- ansible.builtin.import_role:\n    name: a\n",
    "an include_role with no namespace": "- include_role:\n    name: 'a'\n",
    "an inline mapping": "- ansible.builtin.include_role: {name: a, public: true}\n",
    "key=value arguments": "- ansible.builtin.include_role: name=a public=true\n",
    "a name behind a parameter": "- ansible.builtin.include_role:\n    public: true\n    name: a\n",
    "a path": "- ansible.builtin.include_role:\n    name: ../roles/a\n",
}
# A play's roles, or a role's dependencies, by a bare name.
LIST_CALLS = {
    "a bare roles entry": "- hosts: all\n  roles:\n    - a\n",
    "a roles entry at the key's depth": "- hosts: all\n  roles:\n  - a\n",
    "a role: entry": "- hosts: all\n  roles:\n    - role: a\n      vars:\n        x: 1\n",
    "a role: entry after another key": "- hosts: all\n  roles:\n    - tags: [x]\n      role: a\n",
    "a name: entry": "- hosts: all\n  roles:\n    - name: a\n",
    "an inline mapping entry": "- hosts: all\n  roles:\n    - { role: a, tags: x }\n",
    "an inline list": "- hosts: all\n  roles: [a]\n",
    "a quoted entry": "- hosts: all\n  roles:\n    - 'a'\n",
    "a role entry on its own line": "- hosts: all\n  roles:\n    -\n      role: a\n",
}


class StructuredScanTest(unittest.TestCase):
    """The structured scan, on small trees where the right answer is known."""

    def selected(self, case: Case) -> list[str]:
        return chosen_by(ci_select, case)

    def scan(
        self, files: dict[str, str], links: dict[str, str] | None = None
    ) -> ci_select.RoleScan:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        tree_of(Case(files, (), None, links or {}), Path(directory.name))
        return ci_select.scan_references(Path(directory.name))

    def test_a_role_called_by_a_bare_name_runs_with_the_role_it_calls(self) -> None:
        for label, text in BARE_CALLS.items():
            with self.subTest(call=label):
                case = calls(text)
                self.assertEqual(case.expected, self.selected(case))

    def test_a_role_listed_in_roles_or_dependencies_runs_with_the_role_it_lists(self) -> None:
        for label, text in LIST_CALLS.items():
            with self.subTest(call=label):
                case = calls(text)
                self.assertEqual(case.expected, self.selected(case))
        meta = Case(
            {**PLAIN, role_file("b", "meta/main.yml"): "dependencies:\n  - role: a\n"},
            (role_file("a"),),
            ["a", "b"],
        )
        self.assertEqual(meta.expected, self.selected(meta))

    def test_a_role_that_calls_nothing_runs_alone(self) -> None:
        # The control of the two tests above: the same tree with no call narrows to the role.
        case = Case({**PLAIN, role_file("b"): QUIET}, (role_file("a"),), ["a"])
        self.assertEqual(case.expected, self.selected(case))

    def test_every_recognised_form_resolves_with_nothing_left_over(self) -> None:
        for label, text in {**BARE_CALLS, **LIST_CALLS}.items():
            with self.subTest(call=label):
                scan = self.scan({**PLAIN, role_file("b"): text})
                self.assertEqual([], scan.unresolved)
                self.assertEqual({"ansible/roles/b"}, scan.edges["ansible/roles/a"])

    def test_dependencies_that_are_not_a_list_name_no_role(self) -> None:
        # mx1_stack passes ``dependencies: false`` to a module; it is not a role list.
        for value in ("false", "[]", "null"):
            with self.subTest(value=value):
                scan = self.scan({**PLAIN, role_file("b"): f"- x:\n    dependencies: {value}\n"})
                self.assertEqual([], scan.unresolved)

    def test_a_role_name_the_scan_cannot_map_is_unresolved(self) -> None:
        for label, text in {
            "a collection role": "- ansible.builtin.include_role:\n    name: community.general.x\n",
            "a role that is not here": "- ansible.builtin.include_role:\n    name: nothing_here\n",
            "a name with a template tail": INCLUDE % "'a{{ x }}'",
            "a variable nothing defines": INCLUDE % "'{{ who }}'",
            "an include with no name": "- ansible.builtin.include_role:\n    public: true\n",
            "a bare roles entry that is not here": "- hosts: all\n  roles:\n    - elsewhere\n",
            "a roles entry with no role": "- hosts: all\n  roles:\n    - tags: x\n",
            "a templated roles list": "- hosts: all\n  roles: '{{ the_roles }}'\n",
        }.items():
            with self.subTest(call=label):
                scan = self.scan({**PLAIN, role_file("b"): text})
                self.assertEqual(1, len(scan.unresolved), scan.unresolved)
                self.assertTrue(scan.unresolved[0][0].startswith("ansible/roles/b/tasks/main.yml:"))

    def test_a_name_through_a_variable_resolves_when_every_definition_does(self) -> None:
        files = {
            **PLAIN,
            role_file(
                "b"
            ): "- vars:\n    who: a\n  ansible.builtin.include_role:\n    name: '{{ who }}'\n",
        }
        scan = self.scan(files)
        self.assertEqual([], scan.unresolved)
        self.assertEqual({"ansible/roles/b"}, scan.edges["ansible/roles/a"])
        # One definition that cannot be read is enough to leave the name unresolved.
        files[role_file("b", "vars/main.yml")] = "who: '{{ somewhere_else }}'\n"
        self.assertEqual(1, len(self.scan(files).unresolved))

    def test_a_variable_that_names_another_variable_resolves_to_a_limited_depth(self) -> None:
        def chain(length: int) -> dict[str, str]:
            lines = [f"v{n}: '{{{{ v{n + 1} }}}}'" for n in range(length)]
            body = "\n".join([*lines, f"v{length}: a", ""])
            call = "- ansible.builtin.include_role:\n    name: '{{ v0 }}'\n"
            return {**PLAIN, role_file("b"): call, role_file("b", "vars/main.yml"): body}

        self.assertEqual([], self.scan(chain(2)).unresolved)
        # A chain deeper than the limit is left unresolved: a loop must end somewhere.
        self.assertEqual(1, len(self.scan(chain(ci_select.VARIABLE_DEPTH + 1)).unresolved))
        loop = {
            **PLAIN,
            role_file(
                "b"
            ): "x: '{{ y }}'\ny: '{{ x }}'\n- ansible.builtin.include_role:\n    name: '{{ x }}'\n",
        }
        self.assertEqual(1, len(self.scan(loop).unresolved))

    def test_a_playbook_dir_path_resolves_from_the_file_or_any_directory_above_it(self) -> None:
        call = "- ansible.builtin.include_role:\n    name: '{{ playbook_dir }}/%s'\n"
        for label, tail, edge in (
            ("a sibling role", "../../../a", True),
            ("the role itself", "../..", False),
            ("a sibling from a higher playbook", "../../a", True),
        ):
            with self.subTest(path=label):
                files = {**PLAIN, role_file("b", "molecule/default/converge.yml"): call % tail}
                scan = self.scan(files)
                self.assertEqual([], scan.unresolved)
                self.assertEqual(
                    {"ansible/roles/b"} if edge else set(), scan.edges["ansible/roles/a"]
                )
        nowhere = {**PLAIN, role_file("b", "molecule/default/converge.yml"): call % "../../../gone"}
        self.assertEqual(1, len(self.scan(nowhere).unresolved))

    def test_a_name_built_with_a_trailing_unit_name_resolves_to_that_unit(self) -> None:
        call = (
            "- vars:\n    where: '{{ scratch.path ~ \"/%s\" }}'\n"
            "  ansible.builtin.include_role:\n    name: '{{ where }}'\n"
        )
        scan = self.scan({**PLAIN, role_file("b"): call % "a"})
        self.assertEqual([], scan.unresolved)
        self.assertEqual({"ansible/roles/b"}, scan.edges["ansible/roles/a"])
        self.assertEqual(1, len(self.scan({**PLAIN, role_file("b"): call % "gone"}).unresolved))

    def test_a_playbook_imported_from_another_unit_is_an_edge(self) -> None:
        files = {**PLAIN, role_file("a", "molecule/default/prepare.yml"): "- hosts: all\n"}
        imported = "- ansible.builtin.import_playbook: ../../../a/molecule/default/prepare.yml\n"
        scan = self.scan({**files, role_file("b", "molecule/default/converge.yml"): imported})
        self.assertEqual([], scan.unresolved)
        self.assertEqual({"ansible/roles/b"}, scan.edges["ansible/roles/a"])

    def test_a_playbook_imported_from_the_same_unit_is_no_edge(self) -> None:
        files = {
            **PLAIN,
            role_file("b", "molecule/default/prepare.yml"): "- hosts: all\n",
            role_file(
                "b", "molecule/refusals/converge.yml"
            ): "- import_playbook: ../default/prepare.yml\n",
        }
        scan = self.scan(files)
        self.assertEqual([], scan.unresolved)
        self.assertEqual(set(), scan.edges["ansible/roles/b"])

    def test_a_playbook_the_scan_cannot_place_is_unresolved(self) -> None:
        for label, value in {
            "a file that is not there": "missing.yml",
            "a file outside any unit": "../../../../README.md",
            "an absolute path": "/etc/play.yml",
            "a templated path": "'{{ where }}/play.yml'",
        }.items():
            with self.subTest(playbook=label):
                files = {
                    **PLAIN,
                    "README.md": "x\n",
                    role_file("b"): f"- import_playbook: {value}\n",
                }
                self.assertEqual(1, len(self.scan(files).unresolved))

    def test_a_handler_only_another_unit_defines_makes_the_notifier_run_with_it(self) -> None:
        for label, handler in {
            "a handler name": "- name: Restart alpha\n  ansible.builtin.debug:\n",
            "a listen name": "- name: Other\n  listen: Restart alpha\n  ansible.builtin.debug:\n",
            "a listen list": (
                "- name: Other\n  listen:\n    - Restart alpha\n  ansible.builtin.debug:\n"
            ),
        }.items():
            for notify in (
                "notify: Restart alpha",
                "notify:\n    - Restart alpha",
                "notify: [Restart alpha]",
            ):
                with self.subTest(handler=label, notify=notify):
                    text = f"- name: change\n  ansible.builtin.debug:\n  {notify}\n"
                    files = {
                        **PLAIN,
                        role_file("a", "handlers/main.yml"): handler,
                        role_file("b"): text,
                    }
                    case = Case(files, (role_file("a", "handlers/main.yml"),), ["a", "b"])
                    self.assertEqual(case.expected, self.selected(case))
                    self.assertEqual([], self.scan(files).unresolved)

    def test_a_handler_the_notifier_defines_itself_is_no_edge(self) -> None:
        own = "- name: change\n  ansible.builtin.debug:\n  notify: Restart alpha\n"
        files = {
            **PLAIN,
            role_file(
                "a", "handlers/main.yml"
            ): "- name: Restart alpha\n  ansible.builtin.debug:\n",
            role_file("b"): own,
            role_file(
                "b", "handlers/main.yml"
            ): "- name: Restart alpha\n  ansible.builtin.debug:\n",
        }
        case = Case(files, (role_file("a"),), ["a"])
        self.assertEqual(case.expected, self.selected(case))
        self.assertEqual([], self.scan(files).unresolved)

    def test_a_handler_in_a_handlers_block_of_a_playbook_counts_as_defined(self) -> None:
        play = (
            "- hosts: all\n  handlers:\n    - name: Restart alpha\n      ansible.builtin.debug:\n"
        )
        use = "- name: change\n  ansible.builtin.debug:\n  notify: Restart alpha\n"
        files = {
            **PLAIN,
            role_file("b", "molecule/default/converge.yml"): play,
            role_file("b"): use,
        }
        scan = self.scan(files)
        self.assertEqual([], scan.unresolved)
        self.assertEqual(set(), scan.edges["ansible/roles/a"])

    def test_a_handler_nothing_defines_or_a_templated_one_is_unresolved(self) -> None:
        for label, notify in {
            "a handler nothing defines": "notify: Restart gone",
            "a templated handler": "notify: 'Restart {{ which }}'",
            "an inline list left open": "notify: [Restart a",
        }.items():
            with self.subTest(notify=label):
                text = f"- name: change\n  ansible.builtin.debug:\n  {notify}\n"
                scan = self.scan({**PLAIN, role_file("b"): text})
                self.assertEqual(1, len(scan.unresolved), scan.unresolved)

    def test_a_link_into_another_unit_is_an_edge(self) -> None:
        files = {**PLAIN, role_file("a", "files/x"): "x\n"}
        links = {role_file("b", "files/x"): "../../a/files/x"}
        case = Case(files, (role_file("a", "files/x"),), ["a", "b"], links)
        self.assertEqual(case.expected, self.selected(case))
        self.assertEqual([], self.scan(files, links).unresolved)

    def test_a_link_inside_the_unit_or_to_a_file_that_runs_every_shard_is_no_edge(self) -> None:
        files = {**PLAIN, role_file("b", "files/x"): "x\n", "ansible/harness/h.py": "x\n"}
        links = {
            role_file("b", "files/y"): "x",
            role_file("b", "files/h.py"): "../../../harness/h.py",
        }
        scan = self.scan(files, links)
        self.assertEqual([], scan.unresolved)
        self.assertEqual(set(), scan.edges["ansible/roles/a"])

    def test_a_link_to_a_file_that_is_missing_or_that_no_rule_names_is_unresolved(self) -> None:
        for label, target, extra in (
            ("a missing file", "../../a/files/gone", {}),
            ("a lint-only file", "../../../tools/x.py", {"ansible/tools/x.py": "x\n"}),
            ("a file out of the repository", "../../../../../outside", {}),
        ):
            with self.subTest(link=label):
                scan = self.scan({**PLAIN, **extra}, {role_file("b", "files/x"): target})
                self.assertEqual(1, len(scan.unresolved), scan.unresolved)

    def test_a_link_to_a_file_outside_ansible_is_left_to_the_outside_reads(self) -> None:
        files = {**PLAIN, "hetzner/x/y.conf": "x\n"}
        links = {role_file("b", "files/y.conf"): "../../../../hetzner/x/y.conf"}
        self.assertEqual([], self.scan(files, links).unresolved)
        case = Case(files, ("hetzner/x/y.conf",), ["b"], links)
        self.assertEqual(case.expected, self.selected(case))

    def test_an_unresolved_reference_makes_a_role_change_run_every_shard(self) -> None:
        unresolved = "- ansible.builtin.include_role:\n    name: '{{ who }}'\n"
        case = Case({**PLAIN, role_file("b"): unresolved}, (role_file("a"),), None)
        self.assertEqual(["a", "b", "c"], expected_names(case))
        self.assertEqual(expected_names(case), self.selected(case))

    def test_an_unresolved_reference_does_not_widen_a_change_that_runs_no_shard(self) -> None:
        unresolved = "- ansible.builtin.include_role:\n    name: '{{ who }}'\n"
        files = {
            **PLAIN,
            role_file("b"): unresolved,
            "README.md": "x\n",
            "ansible/README.md": "x\n",
        }
        for changed in (("README.md",), ("ansible/README.md",), ()):
            with self.subTest(changed=changed):
                self.assertEqual([], self.selected(Case(files, changed, [])))

    def test_a_file_that_cannot_be_read_is_unresolved(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        tree_of(Case(PLAIN, (), None), root)
        unreadable = root / role_file("a", "tasks/other.yml")
        unreadable.write_text("x\n", encoding="utf-8")
        unreadable.chmod(0)
        self.addCleanup(unreadable.chmod, 0o644)
        if _readable(unreadable):
            self.skipTest("this account reads a file whatever its mode")
        self.assertEqual(1, len(ci_select.unresolved_references(root)))

    def test_a_note_names_the_references_that_forced_every_shard(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        unresolved = "- ansible.builtin.include_role:\n    name: '{{ who }}'\n"
        shards = tree_of(Case({**PLAIN, role_file("b"): unresolved}, (), None), root)
        matrix = root / "matrix.json"
        matrix.write_text(json.dumps({"include": shards}), encoding="utf-8")
        changed = root / "changed.z"
        changed.write_text(role_file("a") + "\0", encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = ci_select.main(
                [
                    "--event",
                    "pull_request",
                    "--matrix-file",
                    str(matrix),
                    "--changed-file",
                    str(changed),
                    "--root",
                    str(root),
                ]
            )
        self.assertEqual(0, status)
        self.assertEqual(3, len(json.loads(out.getvalue().split("matrix=")[1])["include"]))
        self.assertIn("ansible/roles/b/tasks/main.yml:1", err.getvalue())
        self.assertIn("1 role reference(s) cannot be mapped", err.getvalue())


def _readable(path: Path) -> bool:
    """Return whether this account can read ``path`` (it can, as root, whatever the mode)."""
    try:
        path.read_bytes()
    except OSError:
        return False
    return True


class RealTreeScanTest(unittest.TestCase):
    """The structured scan on this repository, where one new templated name must not slip by."""

    def test_no_role_reference_in_the_tree_is_unresolved(self) -> None:
        # One reference the scan cannot place sends every pull request to every shard, which
        # would erase the saving this selection exists for. To fix a failure here, make the
        # name literal, or name it through a variable of the same role with a literal value.
        unresolved = ci_select.unresolved_references(ROOT)
        listing = "\n".join(f"  {where}: {text}" for where, text in unresolved)
        self.assertEqual([], unresolved, "\n" + listing)

    def test_the_scan_reads_the_sites_it_is_meant_to_read(self) -> None:
        # A control: an empty scan would make the test above pass for nothing. The tree holds
        # more than 245 role calls by collection name, and the scan counts those and more.
        scan = ci_select.scan_references(ROOT)
        self.assertGreater(scan.sites, 245)
        call = re.compile(r"include_role|import_role")
        found = sum(
            len(call.findall(path.read_text(encoding="utf-8", errors="ignore")))
            for unit in ci_select.units(ROOT)
            for path in unit.rglob("*.yml")
            if path.is_file()
        )
        self.assertGreater(found, 245)

    def test_the_scan_places_the_templated_names_the_tree_holds(self) -> None:
        # The names written as a variable or a playbook_dir path in two roles' tests.
        edges = ci_select.scan_references(ROOT).edges
        self.assertIn("ansible/roles/monitoring_stack", edges["ansible/roles/ntfy_pager"])
        self.assertIn("ansible/roles/backup_restore", edges["ansible/roles/backup_worker"])

    def test_the_graph_of_the_tree_holds_every_textual_edge(self) -> None:
        text = ci_select.text_references(ROOT)
        joined = ci_select.references(ROOT)
        self.assertTrue(any(text.values()), "the textual scan found no edge")
        for target, named in text.items():
            with self.subTest(target=target):
                self.assertLessEqual(named, joined[target])

    def test_a_handler_change_runs_its_role_and_every_role_that_names_it(self) -> None:
        shards = real_shards()
        changed = "ansible/roles/node_exporter/handlers/main.yml"
        chosen = paths_of(ci_select.select("pull_request", [changed], shards, ROOT))
        expected = {"ansible/roles/node_exporter"} | ci_select.references(ROOT)[
            "ansible/roles/node_exporter"
        ]
        self.assertEqual(expected, chosen)


def load_variant(source: str) -> types.ModuleType:
    """Return ci_select with ``source`` as its text, run as a module of its own."""
    module = types.ModuleType("ci_select_variant")
    module.__file__ = str(CI_SELECT)
    exec(compile(source, str(CI_SELECT), "exec"), module.__dict__)  # noqa: S102
    return module


UNRESOLVED_CASE = Case(
    {**PLAIN, role_file("b"): "- ansible.builtin.include_role:\n    name: '{{ who }}'\n"},
    (role_file("a"),),
    None,
)
HANDLER_CASE = Case(
    {
        **PLAIN,
        role_file("a", "handlers/main.yml"): "- name: Restart alpha\n  ansible.builtin.debug:\n",
        role_file("b"): "- name: change\n  ansible.builtin.debug:\n  notify: Restart alpha\n",
    },
    (role_file("a", "handlers/main.yml"),),
    ["a", "b"],
)
DEPENDENCY_CASE = Case(
    {**PLAIN, role_file("b", "meta/main.yml"): "dependencies:\n  - a\n"},
    (role_file("a"),),
    ["a", "b"],
)
LINK_CASE = Case(
    {**PLAIN, role_file("a", "files/x"): "x\n"},
    (role_file("a", "files/x"),),
    ["a", "b"],
    {role_file("b", "files/x"): "../../a/files/x"},
)


class SabotageTest(unittest.TestCase):
    """Each rule of the structured scan, broken in the source, turns its own case red.

    A selection that wrongly skips a shard is a gate that passes without running, so each rule
    is shown to be the thing that keeps its case right: the real source selects what the case
    expects, and the source with that one rule removed does not.
    """

    def prove(self, marker: str, replacement: str, case: Case, mutant_chooses: list[str]) -> None:
        source = CI_SELECT.read_text(encoding="utf-8")
        # A marker that matched nothing, or twice, would make the mutation a no-op or a mess.
        self.assertEqual(1, source.count(marker), marker)
        self.assertEqual(expected_names(case), chosen_by(load_variant(source), case))
        mutant = load_variant(source.replace(marker, replacement))
        self.assertEqual(mutant_chooses, chosen_by(mutant, case))
        self.assertNotEqual(expected_names(case), chosen_by(mutant, case))

    def test_dropping_the_fail_open_for_an_unresolved_reference_narrows_the_case(self) -> None:
        marker = "        if unresolved_references(root):\n            return None\n"
        self.prove(marker, "", UNRESOLVED_CASE, ["a"])

    def test_dropping_the_handler_edge_narrows_the_case(self) -> None:
        self.prove(
            "        return elsewhere or None\n", "        return {unit}\n", HANDLER_CASE, ["a"]
        )

    def test_dropping_the_roles_and_dependencies_edge_narrows_the_case(self) -> None:
        marker = "        return [self.entry_role(unit, file, entry) for entry in entries]\n"
        self.prove(marker, "        return [{unit} for _ in entries]\n", DEPENDENCY_CASE, ["a"])

    def test_dropping_the_symlink_edge_narrows_the_case(self) -> None:
        marker = "            self.reach(unit, {owner}, relative, inside_root)\n"
        self.prove(marker, "            pass\n", LINK_CASE, ["a"])


if __name__ == "__main__":
    unittest.main()
