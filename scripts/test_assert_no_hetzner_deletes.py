#!/usr/bin/env python3
"""Unit tests for assert-no-hetzner-deletes.

This gate is the only automated thing standing between a merged plan and the
destruction of mx1 or the platform network, so the failure that matters is
the guard reporting clean over a plan it did not actually understand. Every
test below is aimed at that shape: a URN it mis-parses, an op it waves
through, a directory whose coverage it silently skips, or an error state that
shares an exit code with success.
"""

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest


def _load_module():
    """Import the script by path: its filename has hyphens, so it is not a
    legal module name for a plain import."""
    path = pathlib.Path(__file__).resolve().parent / "assert-no-hetzner-deletes.py"
    spec = importlib.util.spec_from_file_location("assert_no_hetzner_deletes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = _load_module()


_STACK = "urn:pulumi:production::branchleft-mail::"
_URN_MX1 = f"{_STACK}hcloud:index/server:Server::mx1"
_URN_FIREWALL = f"{_STACK}hcloud:index/firewall:Firewall::mail-firewall"
_URN_ROUTE = (
    "urn:pulumi:production::branchleft-hetzner-network::"
    "hcloud:index/networkRoute:NetworkRoute::platform-internet-egress"
)
_URN_CHILD = (
    "urn:pulumi:production::branchleft-hetzner-estate::"
    "branchleft:hetznerHost:Host$hcloud:index/server:Server::edge1-server"
)


def _plan(*steps):
    return {"steps": [{"op": op, "urn": urn} for op, urn in steps]}


class SplitUrnTests(unittest.TestCase):
    def test_plain_urn(self):
        self.assertEqual(
            guard._split_urn(_URN_MX1), ("hcloud:index/server:Server", "mx1")
        )

    def test_parent_chain_resolves_to_leaf_type(self):
        # A component's child carries `<parent>$<type>` in the type segment;
        # protection has to key on the leaf type or every Host child escapes.
        self.assertEqual(
            guard._split_urn(_URN_CHILD), ("hcloud:index/server:Server", "edge1-server")
        )

    def test_non_urn_raises(self):
        with self.assertRaises(ValueError):
            guard._split_urn("urn:pulumi:production")


class DestructiveStepsTests(unittest.TestCase):
    def test_clean_plan_is_empty(self):
        self.assertEqual(
            guard.destructive_steps(_plan(("same", _URN_MX1), ("update", _URN_FIREWALL))),
            [],
        )

    def test_delete_of_protected_type_is_found(self):
        self.assertEqual(
            guard.destructive_steps(_plan(("delete", _URN_MX1))), [("mx1", "delete")]
        )

    def test_every_replace_flavoured_op_is_destructive(self):
        for op in (
            "replace",
            "create-replacement",
            "delete-replaced",
            "read-replacement",
            "discard-replaced",
            "remove-pending-replace",
        ):
            with self.subTest(op=op):
                self.assertEqual(
                    guard.destructive_steps(_plan((op, _URN_MX1))), [("mx1", op)]
                )

    def test_component_child_is_protected_through_parent_chain(self):
        self.assertEqual(
            guard.destructive_steps(_plan(("delete", _URN_CHILD))),
            [("edge1-server", "delete")],
        )

    def test_network_route_is_deliberately_unprotected(self):
        self.assertEqual(guard.destructive_steps(_plan(("delete", _URN_ROUTE))), [])

    def test_missing_steps_raises_instead_of_passing(self):
        # "I found no steps" and "there are no destructive steps" must not
        # share an exit path.
        for bad in ({}, {"steps": "nope"}, {"steps": [{"op": "delete"}]}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    guard.destructive_steps(bad)


class VerifyCoverageTests(unittest.TestCase):
    def _run(self, dirname, source):
        with tempfile.TemporaryDirectory() as root:
            directory = pathlib.Path(root) / dirname
            directory.mkdir()
            (directory / "program.ts").write_text(source, encoding="utf-8")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                result = guard.verify_coverage(str(directory))
            return result, buffer.getvalue()

    def test_mail_with_both_constructors_passes(self):
        result, _ = self._run(
            "mail",
            "new hcloud.Server('mx1', {});\nnew hcloud.Firewall('mail-firewall', {});\n",
        )
        self.assertEqual(result, 0)

    def test_missing_constructor_fails(self):
        result, output = self._run("mail", "new hcloud.Server('mx1', {});\n")
        self.assertEqual(result, 1)
        self.assertIn("hcloud.Firewall", output)

    def test_mention_in_comment_does_not_count(self):
        result, _ = self._run(
            "mail",
            "new hcloud.Server('mx1', {});\n// hcloud.Firewall lives elsewhere now\n",
        )
        self.assertEqual(result, 1)

    def test_unknown_directory_fails_closed(self):
        # A program dir the map has never heard of must fail, not skip: a new
        # Hetzner project added without coverage is exactly the erosion the
        # map exists to catch.
        result, output = self._run("brand-new-stack", "new hcloud.Server('x', {});\n")
        self.assertEqual(result, 1)
        self.assertIn("COVERAGE_BY_DIR", output)

    def test_empty_directory_fails(self):
        with tempfile.TemporaryDirectory() as root:
            directory = pathlib.Path(root) / "mail"
            directory.mkdir()
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                result = guard.verify_coverage(str(directory))
        self.assertEqual(result, 1)

    def test_nonexistent_directory_fails(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = guard.verify_coverage("/nonexistent/path/mail")
        self.assertEqual(result, 1)


class CoverageMapTests(unittest.TestCase):
    def test_real_program_dirs_satisfy_their_own_map(self):
        # The map's fixture claims are only worth anything if the actual
        # committed programs satisfy them. Run coverage against the real
        # directories this script will be pointed at in CI.
        repo_root = pathlib.Path(__file__).resolve().parent.parent
        for dirname in guard.COVERAGE_BY_DIR:
            with self.subTest(dirname=dirname):
                buffer = io.StringIO()
                with contextlib.redirect_stdout(buffer):
                    result = guard.verify_coverage(str(repo_root / dirname))
                self.assertEqual(result, 0, buffer.getvalue())


class MainTests(unittest.TestCase):
    def _main(self, argv):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = guard.main(argv)
        return result, buffer.getvalue()

    def test_self_test_passes(self):
        result, output = self._main(["prog", "--self-test"])
        self.assertEqual(result, 0, output)

    def test_clean_plan_file_exits_zero(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(_plan(("same", _URN_MX1)), handle)
            path = handle.name
        result, _ = self._main(["prog", path])
        self.assertEqual(result, 0)

    def test_destructive_plan_file_exits_one(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(_plan(("delete", _URN_MX1)), handle)
            path = handle.name
        result, output = self._main(["prog", path])
        self.assertEqual(result, 1)
        self.assertIn("mx1", output)

    def test_unreadable_plan_exits_one_not_zero(self):
        result, _ = self._main(["prog", "/nonexistent/preview.json"])
        self.assertEqual(result, 1)

    def test_malformed_json_exits_one(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write("{not json")
            path = handle.name
        result, _ = self._main(["prog", path])
        self.assertEqual(result, 1)

    def test_usage_error_exits_two(self):
        result, _ = self._main(["prog"])
        self.assertEqual(result, 2)


if __name__ == "__main__":
    unittest.main()
