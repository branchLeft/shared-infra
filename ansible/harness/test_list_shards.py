"""Tests for the shard list the Ansible workflow runs, built from a throwaway tree."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import list_shards


class ShardTests(unittest.TestCase):
    """The list has a shard for every directory and every scenario, and cannot be empty."""

    def make_tree(self, layout: dict[str, list[str] | None]) -> Path:
        """Create ansible/<group>/<name> directories; the value lists a directory's scenarios.

        ``None`` makes a directory with no ``molecule/`` at all.
        """
        base = Path(tempfile.mkdtemp(prefix="shards-test-"))
        self.addCleanup(shutil.rmtree, base, True)
        for relative, scenarios in layout.items():
            directory = base / "ansible" / relative
            directory.mkdir(parents=True)
            for name in scenarios or []:
                (directory / "molecule" / name).mkdir(parents=True)
        return base

    def names(self, base: Path) -> list[str]:
        """Return the shard names for the tree."""
        return [shard["name"] for shard in list_shards.shards(base)]

    def test_a_role_with_one_scenario_has_one_shard_named_by_its_path(self) -> None:
        base = self.make_tree({"roles/alpha": ["default"]})
        self.assertEqual(
            list_shards.shards(base)[0],
            {
                "name": "ansible/roles/alpha",
                "path": "ansible/roles/alpha",
                "scenario": "default",
                "kind": "role",
            },
        )

    def test_each_further_scenario_is_its_own_shard(self) -> None:
        base = self.make_tree({"roles/alpha": ["default", "refusals", "extra"]})
        found = [
            (shard["path"], shard["scenario"])
            for shard in list_shards.shards(base)
            if shard["kind"] == "role"
        ]
        self.assertEqual(
            found,
            [
                ("ansible/roles/alpha", "default"),
                ("ansible/roles/alpha", "extra"),
                ("ansible/roles/alpha", "refusals"),
            ],
        )

    def test_a_directory_with_no_molecule_directory_still_gets_a_default_shard(self) -> None:
        base = self.make_tree({"roles/bare": None, "patterns/also_bare": None})
        self.assertEqual(self.names(base)[:2], ["ansible/roles/bare", "ansible/patterns/also_bare"])

    def test_a_role_with_only_a_second_scenario_still_gets_the_default_shard(self) -> None:
        base = self.make_tree({"roles/alpha": ["refusals"]})
        found = [shard["scenario"] for shard in list_shards.shards(base) if shard["kind"] == "role"]
        self.assertEqual(found, ["default", "refusals"])

    def test_shard_names_are_unique(self) -> None:
        base = self.make_tree(
            {
                "roles/alpha": ["default", "refusals"],
                "roles/beta": ["default", "refusals"],
                "patterns/alpha": ["default", "refusals"],
            }
        )
        names = self.names(base)
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(names), 7)

    def test_the_skeleton_is_the_last_shard_and_is_not_a_role(self) -> None:
        base = self.make_tree({"roles/alpha": ["default"]})
        last = list_shards.shards(base)[-1]
        self.assertEqual(last["kind"], "skeleton")
        self.assertEqual(last["path"], "ansible/role_skeleton")

    def test_hidden_directories_and_plain_files_are_not_shards(self) -> None:
        base = self.make_tree({"roles/alpha": ["default"], "roles/.cache": None})
        (base / "ansible" / "roles" / "README.md").write_text("x", encoding="utf-8")
        (base / "ansible" / "roles" / "alpha" / "molecule" / ".hidden").mkdir()
        (base / "ansible" / "roles" / "alpha" / "molecule" / "notes.md").write_text(
            "x", encoding="utf-8"
        )
        found = [shard["name"] for shard in list_shards.shards(base) if shard["kind"] == "role"]
        self.assertEqual(found, ["ansible/roles/alpha"])

    def test_an_empty_tree_fails_instead_of_listing_only_the_skeleton(self) -> None:
        base = self.make_tree({})
        with self.assertRaises(list_shards.NothingToTestError) as raised:
            list_shards.shards(base)
        self.assertIn("nothing would be tested", str(raised.exception))

    def test_main_exits_non_zero_and_prints_no_matrix_for_an_empty_tree(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = list_shards.main(self.make_tree({}))
        self.assertEqual(status, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("nothing would be tested", err.getvalue())

    def test_main_prints_one_line_of_json_with_the_matrix(self) -> None:
        base = self.make_tree({"roles/alpha": ["default", "refusals"]})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = list_shards.main(base)
        self.assertEqual(status, 0)
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        matrix = json.loads(out.getvalue())
        self.assertEqual(len(matrix["include"]), 3)
        self.assertIn("ansible/roles/alpha (refusals)", err.getvalue())

    def test_the_real_tree_lists_the_refusals_scenario_of_demo1_build(self) -> None:
        shards = list_shards.shards(list_shards.REPO_ROOT)
        pairs = {(shard["path"], shard["scenario"]) for shard in shards}
        self.assertIn(("ansible/roles/demo1_build", "default"), pairs)
        self.assertIn(("ansible/roles/demo1_build", "refusals"), pairs)
        names = [shard["name"] for shard in shards]
        self.assertEqual(len(names), len(set(names)))

    def test_every_scenario_directory_in_the_real_tree_has_a_shard(self) -> None:
        listed = {
            (shard["path"], shard["scenario"])
            for shard in list_shards.shards(list_shards.REPO_ROOT)
        }
        for group in list_shards.GROUPS:
            for directory in list_shards.directories(list_shards.REPO_ROOT / "ansible" / group):
                for scenario in list_shards.directories(directory / "molecule"):
                    self.assertIn((f"ansible/{group}/{directory.name}", scenario.name), listed)


if __name__ == "__main__":
    unittest.main()
