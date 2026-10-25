"""Tests for the choice of Ansible shards (ci_select.py).

A shard wrongly left out is a gate that passes without running, so these tests are written
from that side: each rule is shown to run what it must, on the real tree, and the controls
show that a run which should be narrow is narrow.
"""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import ci_select

ROOT = Path(__file__).resolve().parents[2]
LIST_SHARDS = ROOT / "ansible" / "harness" / "list_shards.py"


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

    def test_a_merge_queue_run_runs_every_shard(self) -> None:
        self.assertEqual(self.shards, ci_select.select("merge_group", [], self.shards, ROOT))

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

    def test_a_file_outside_ansible_that_no_role_reads_runs_no_shard(self) -> None:
        for path in ("hetzner/edge/stack/compose.yml", "hetzner/dns/zone.json", "mail/README.md"):
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

    def test_the_merge_queue_runs_everything_whatever_changed(self) -> None:
        changed = self.changed("README.md")
        status, outputs = self.run_main("--event", "merge_group", "--changed-file", str(changed))
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


if __name__ == "__main__":
    unittest.main()
