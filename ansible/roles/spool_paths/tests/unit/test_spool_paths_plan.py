"""Tests that hold the derived path list to the descriptors the collector drains.

A path is held to a host only when a descriptor names it and the owner's table says where it is.
The alias is the descriptor's own address. These tests run the planning module's function on
scratch directories and judge what it returns. They touch no host.

Each control a test names was run red on a sabotaged copy and green on the file as shipped (the
pull request records both).
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import cast

import spool_paths_plan as module

MARKER = "# Written by the spool_paths role. Change the role inputs, not this file."
BLOCK = "10.250.0.0/24"
RESERVED = ["10.20.0.0/16"]
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake"


def row(slug: str, **extra: object) -> dict[str, object]:
    """Return a table row for the slug."""
    base: dict[str, object] = {
        "slug": slug,
        "ssh_host": "192.0.2.10",
        "spool_port": 8095,
        "host_key": KEY,
    }
    base.update(extra)
    return base


class Scratch:
    """A scratch descriptor directory and role directory."""

    def __init__(self, test: unittest.TestCase) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="spool-paths-plan-"))
        test.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.descriptors = self.home / "descriptors"
        self.config = self.home / "spool-paths"
        self.descriptors.mkdir()
        self.config.mkdir()

    def descriptor(self, name: str, alias: str, **extra: object) -> Path:
        """Write a descriptor the way the collector role writes one, named for its file."""
        document: dict[str, object] = {
            "slug": name,
            "kind": "demo",
            "appHostIp": alias,
            "expiresAt": None,
        }
        document.update(extra)
        path = self.descriptors / f"{name}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def plan(self, hosts: list[object], block: str = BLOCK) -> dict[str, object]:
        """Return the module's result for the scratch directories."""
        return module.plan(hosts, block, RESERVED, str(self.descriptors), str(self.config), MARKER)


def paths_of(result: dict[str, object]) -> list[dict[str, object]]:
    """Return the paths in a result."""
    return cast("list[dict[str, object]]", result["paths"])


def slugs(result: dict[str, object]) -> list[str]:
    """Return the slugs of the paths in a result."""
    return [str(path["slug"]) for path in paths_of(result)]


class DerivedList(unittest.TestCase):
    """The list of paths is the descriptors that have a table row, and nothing else."""

    # Control: a host no descriptor names gets no path. Red when the table alone decides.
    def test_a_table_row_no_descriptor_names_gets_no_path(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        result = scratch.plan([row("demo1"), row("tenant9")])
        self.assertEqual(slugs(result), ["demo1"])
        self.assertEqual(result["unreached"], ["tenant9"])

    # A host a descriptor names that the owner has not said where to find is left to its own
    # address, and reported.
    def test_a_descriptor_with_no_table_row_gets_no_path(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        scratch.descriptor("app1", "10.20.1.101")
        result = scratch.plan([row("demo1")])
        self.assertEqual(slugs(result), ["demo1"])
        self.assertEqual(result["unlisted"], ["app1"])

    # Control: no descriptor at all means no path, whatever the table holds.
    def test_an_empty_descriptor_directory_gives_no_path(self) -> None:
        scratch = Scratch(self)
        result = scratch.plan([row("demo1"), row("tenant9")])
        self.assertEqual(slugs(result), [])

    def test_a_missing_descriptor_directory_gives_no_path(self) -> None:
        scratch = Scratch(self)
        shutil.rmtree(scratch.descriptors)
        self.assertEqual(slugs(scratch.plan([row("demo1")])), [])

    def test_the_alias_is_the_descriptors_own_address(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.77")
        paths = paths_of(scratch.plan([row("demo1")]))
        self.assertEqual(paths[0]["alias"], "10.250.0.77")

    def test_defaults_are_filled_for_a_row_that_leaves_them_out(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        paths = paths_of(scratch.plan([row("demo1")]))
        self.assertEqual(paths[0]["ssh_port"], 22)
        self.assertEqual(paths[0]["jump"], {})

    def test_a_jump_row_is_carried_with_its_default_port(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("tenant1", "10.250.0.12")
        jump = {"host": "192.0.2.20", "host_key": KEY}
        paths = paths_of(scratch.plan([row("tenant1", jump=jump)]))
        self.assertEqual(paths[0]["jump"], {**jump, "port": 22})

    def test_paths_come_back_in_slug_order(self) -> None:
        scratch = Scratch(self)
        for slug, alias in (("zeta", "10.250.0.3"), ("alpha", "10.250.0.4")):
            scratch.descriptor(slug, alias)
        self.assertEqual(slugs(scratch.plan([row("zeta"), row("alpha")])), ["alpha", "zeta"])


class UnusableDescriptors(unittest.TestCase):
    """A file that is not a usable descriptor names no host."""

    def test_a_descriptor_whose_slug_is_not_its_file_name_is_not_used(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11", slug="other")
        result = scratch.plan([row("demo1")])
        self.assertEqual(slugs(result), [])
        self.assertEqual(result["invalid"], ["demo1.json"])

    def test_a_descriptor_with_a_public_address_is_not_used(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "192.0.2.5")
        self.assertEqual(slugs(scratch.plan([row("demo1")])), [])

    def test_a_descriptor_that_is_not_json_is_not_used(self) -> None:
        scratch = Scratch(self)
        (scratch.descriptors / "demo1.json").write_text("not json", encoding="utf-8")
        self.assertEqual(slugs(scratch.plan([row("demo1")])), [])

    def test_a_linked_descriptor_is_not_used(self) -> None:
        scratch = Scratch(self)
        target = scratch.home / "elsewhere.json"
        target.write_text(
            json.dumps({"slug": "demo1", "appHostIp": "10.250.0.11"}), encoding="utf-8"
        )
        (scratch.descriptors / "demo1.json").symlink_to(target)
        self.assertEqual(slugs(scratch.plan([row("demo1")])), [])

    def test_a_file_that_is_not_a_descriptor_name_is_ignored(self) -> None:
        scratch = Scratch(self)
        (scratch.descriptors / "notes.txt").write_text("a note", encoding="utf-8")
        (scratch.descriptors / ".hidden.json").write_text("{}", encoding="utf-8")
        result = scratch.plan([row("demo1")])
        self.assertEqual((slugs(result), result["invalid"], result["unlisted"]), ([], [], []))


class Aliases(unittest.TestCase):
    """An alias must be a usable address of the owner's block, and must be unique."""

    # Control: the estate's and the tenants network's block is never an alias. Red when the
    # reserved check is dropped.
    def test_an_alias_in_a_reserved_block_is_refused(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.20.1.101")
        with self.assertRaisesRegex(module.Refusal, "demo1: .*outside alias_block"):
            scratch.plan([row("demo1")])
        with self.assertRaisesRegex(module.Refusal, "overlaps a reserved block"):
            scratch.plan([row("demo1")], block="10.0.0.0/8")

    def test_an_alias_outside_the_block_is_refused(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.251.0.5")
        with self.assertRaisesRegex(module.Refusal, "outside alias_block"):
            scratch.plan([row("demo1")])

    def test_two_descriptors_naming_one_address_are_refused(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        scratch.descriptor("tenant1", "10.250.0.11")
        with self.assertRaisesRegex(module.Refusal, "one address"):
            scratch.plan([row("demo1"), row("tenant1")])

    def test_a_path_with_no_block_set_is_refused(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        with self.assertRaisesRegex(module.Refusal, "alias_block is empty"):
            scratch.plan([row("demo1")], block="")

    def test_no_block_is_needed_while_no_path_is_built(self) -> None:
        scratch = Scratch(self)
        self.assertEqual(slugs(scratch.plan([row("demo1")], block="")), [])

    def test_the_networks_own_address_is_refused(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.0")
        with self.assertRaisesRegex(module.Refusal, "network or broadcast"):
            scratch.plan([row("demo1")])

    def test_a_block_that_overlaps_a_reserved_block_is_refused(self) -> None:
        scratch = Scratch(self)
        with self.assertRaisesRegex(module.Refusal, "overlaps"):
            scratch.plan([], block="10.20.5.0/24")

    def test_a_public_block_is_refused(self) -> None:
        scratch = Scratch(self)
        with self.assertRaisesRegex(module.Refusal, "inside 10/8"):
            scratch.plan([], block="192.0.2.0/24")


class TableRows(unittest.TestCase):
    """A malformed row is refused by its place in the list, and no message shows a value."""

    def test_each_malformed_row_is_refused(self) -> None:
        scratch = Scratch(self)
        cases: dict[str, dict[str, object]] = {
            "extra key": row("demo1", note="x"),
            "bad slug": row("Demo_1"),
            "bad host": row("demo1", ssh_host="bad host"),
            "bad port": row("demo1", spool_port=0),
            "boolean port": row("demo1", spool_port=True),
            "bad key": row("demo1", host_key="not a key"),
            "bad ssh port": row("demo1", ssh_port=70000),
            "jump with extra": row("demo1", jump={"host": "a", "host_key": KEY, "user": "x"}),
            "jump without key": row("demo1", jump={"host": "a"}),
            "jump not a mapping": row("demo1", jump="a"),
        }
        for name, bad in cases.items():
            with self.subTest(name), self.assertRaisesRegex(module.Refusal, r"^host 1: "):
                scratch.plan([bad])

    def test_a_row_that_is_not_a_mapping_is_refused(self) -> None:
        scratch = Scratch(self)
        with self.assertRaisesRegex(module.Refusal, "host 2: must be a mapping"):
            scratch.plan([row("demo1"), "demo2"])

    def test_two_rows_with_one_slug_are_refused(self) -> None:
        scratch = Scratch(self)
        with self.assertRaisesRegex(module.Refusal, "share a slug"):
            scratch.plan([row("demo1"), row("demo1")])

    def test_a_refusal_never_shows_a_value(self) -> None:
        scratch = Scratch(self)
        with self.assertRaises(module.Refusal) as caught:
            scratch.plan([row("demo1", ssh_host="bad host", host_key="ssh-ed25519 SECRETBODY!")])
        self.assertNotIn("SECRETBODY", str(caught.exception))
        self.assertNotIn("bad host", str(caught.exception))


class StalePaths(unittest.TestCase):
    """A path a past run wrote that no descriptor names now is reported for teardown."""

    def test_a_marked_file_no_descriptor_names_is_stale(self) -> None:
        scratch = Scratch(self)
        scratch.descriptor("demo1", "10.250.0.11")
        (scratch.config / "demo1.conf").write_text(f"{MARKER}\nHost demo1\n", encoding="utf-8")
        (scratch.config / "gone.conf").write_text(f"{MARKER}\nHost gone\n", encoding="utf-8")
        self.assertEqual(scratch.plan([row("demo1")])["stale"], ["gone"])

    # Control: a file the role did not write is never reported, so never removed.
    def test_a_file_without_the_marker_is_never_stale(self) -> None:
        scratch = Scratch(self)
        (scratch.config / "hand.conf").write_text("Host hand\n", encoding="utf-8")
        (scratch.config / "hand.key").write_text(f"{MARKER}\n", encoding="utf-8")
        self.assertEqual(scratch.plan([])["stale"], [])

    def test_a_linked_file_is_never_stale(self) -> None:
        scratch = Scratch(self)
        target = scratch.home / "target"
        target.write_text(f"{MARKER}\n", encoding="utf-8")
        (scratch.config / "linked.conf").symlink_to(target)
        self.assertEqual(scratch.plan([])["stale"], [])

    def test_a_host_whose_descriptor_is_gone_but_whose_row_stays_is_stale(self) -> None:
        scratch = Scratch(self)
        (scratch.config / "demo1.conf").write_text(f"{MARKER}\n", encoding="utf-8")
        result = scratch.plan([row("demo1")])
        self.assertEqual((slugs(result), result["stale"]), ([], ["demo1"]))


if __name__ == "__main__":
    unittest.main()
