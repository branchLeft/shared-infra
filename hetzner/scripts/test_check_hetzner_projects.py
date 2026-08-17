#!/usr/bin/env python3
"""Unit tests for check-hetzner-projects.

Every fault this checker looks for is silent in production, so the tests are
written the other way round from the usual: each one builds the broken layout
and asserts the checker *notices*, because a checker that has stopped noticing
is indistinguishable from a clean tree.

The three that matter most, in order of what they cost when missed:

* **A shared project `name`.** Two projects over one state file. An apply in
  the second loads the first's checkpoint and plans to delete its resources,
  and it gets part-way through before anyone reads the plan.
* **A `main` that names the package's own entry point.** The same fault as
  omitting `main`, spelled out, so a checker that only tests for absence passes
  the very edit it exists to catch.
* **Reader edge cases.** A trailing comment, a duplicate key or an inline flow
  mapping each make the reader answer confidently and wrongly, which surfaces
  as a failure naming the wrong fault -- worse than no check, because it sends
  someone to fix a thing that is not broken.

The last case builds nothing: it runs the check against this repository's own
`hetzner/` tree, so the tree drifting is itself a test failure rather than
something only CI notices.

No network. No subprocess.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import tempfile
import unittest

BACKEND = "s3://example-state?endpoint=example.invalid&s3ForcePathStyle=true&region=xx1"
OTHER_BACKEND = "gs://example-other-state"


def _load_module():
    path = pathlib.Path(__file__).resolve().parent / "check-hetzner-projects.py"
    spec = importlib.util.spec_from_file_location("check_hetzner_projects", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


chp = _load_module()


def project(
    backend: str | None = BACKEND,
    main: str | None = None,
    name: str | None = "p",
    runtime: str | None = "nodejs",
) -> str:
    lines = []
    if name is not None:
        lines.append(f"name: {name}")
    if runtime is not None:
        lines.append(f"runtime: {runtime}")
    if main is not None:
        lines.append(f"main: {main}")
    if backend is not None:
        lines.extend(["backend:", f"  url: '{backend}'"])
    return "\n".join(lines) + "\n"


class TreeBuilder:
    """A `hetzner/`-shaped tree in a temporary directory."""

    def __init__(self, root: pathlib.Path):
        self.root = root

    def write(self, relative: str, text: str) -> pathlib.Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def sound(self) -> "TreeBuilder":
        """The layout the repository actually has: one package, one project at
        its root, one project in a subdirectory pointing back at a sibling
        program file."""
        self.write("package.json", '{"name": "pkg", "main": "index.ts"}\n')
        self.write("index.ts", "export const a = 1;\n")
        self.write("estate.ts", "export const b = 2;\n")
        self.write("Pulumi.yaml", project(name="network"))
        self.write("estate/Pulumi.yaml", project(name="estate", main="../estate.ts"))
        return self


class SoundTreeTests(unittest.TestCase):
    def test_reports_nothing_for_the_intended_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            self.assertEqual(chp.check(tree.root), [])

    def test_a_root_project_needs_no_main(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            tree = TreeBuilder(root)
            tree.write("package.json", '{"main": "index.ts"}\n')
            tree.write("index.ts", "export const a = 1;\n")
            tree.write("Pulumi.yaml", project())
            self.assertEqual(chp.check(root), [])

    def test_an_empty_tree_is_a_failure_rather_than_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            failures = chp.check(pathlib.Path(tmp))
            self.assertEqual(len(failures), 1)
            self.assertIn("no Pulumi.yaml", failures[0])


class ProjectNameTests(unittest.TestCase):
    def test_two_projects_sharing_a_name_fail(self):
        # The shape a new host stack arrives in: copy estate/ to monitoring/,
        # change `main`, forget `name`. Both then resolve to
        # .pulumi/stacks/estate/<stack>.json.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("monitoring.ts", "export const c = 3;\n")
            tree.write(
                "monitoring/Pulumi.yaml", project(name="estate", main="../monitoring.ts")
            )
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("'estate'", failures[0])
            self.assertIn("share one state file", failures[0])

    def test_a_project_without_a_name_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("estate/Pulumi.yaml", project(name=None, main="../estate.ts"))
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("names no project `name`", failures[0])

    def test_an_unnamed_project_is_not_also_reported_as_a_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("estate/Pulumi.yaml", project(name=None, main="../estate.ts"))
            tree.write("other.ts", "export const d = 4;\n")
            tree.write("other/Pulumi.yaml", project(name=None, main="../other.ts"))
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 2)
            self.assertNotIn("share one state file", " ".join(failures))


class MainTests(unittest.TestCase):
    def test_subdirectory_project_without_main_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("estate/Pulumi.yaml", project(name="estate"))
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("estate/Pulumi.yaml", failures[0])
            self.assertIn("sets no `main`", failures[0])

    def test_main_naming_the_package_entry_point_fails(self):
        # The fault the checker exists for, written out rather than omitted:
        # this project would run the network program on purpose-looking config.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("estate/Pulumi.yaml", project(name="estate", main="../index.ts"))
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("entry point", failures[0])

    def test_the_root_project_may_name_the_entry_point_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("Pulumi.yaml", project(name="network", main="./index.ts"))
            self.assertEqual(chp.check(tree.root), [])

    def test_two_projects_over_one_program_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("second/Pulumi.yaml", project(name="second", main="../estate.ts"))
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("run the same program", failures[0])

    def test_main_pointing_at_a_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("estate/Pulumi.yaml", project(name="estate", main="../typo.ts"))
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("typo.ts", failures[0])
            self.assertIn("not a file", failures[0])

    def test_main_pointing_at_a_directory_is_not_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("estate/Pulumi.yaml", project(name="estate", main="../"))
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("not a file", failures[0])

    def test_a_deeper_project_is_checked_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("stacks/nested/Pulumi.yaml", project(name="nested"))
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("stacks/nested/Pulumi.yaml", failures[0])

    def test_a_package_without_main_defaults_to_index_js(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            tree = TreeBuilder(root)
            tree.write("package.json", '{"name": "pkg"}\n')
            tree.write("index.js", "module.exports = {};\n")
            tree.write("Pulumi.yaml", project(name="network"))
            tree.write("estate/Pulumi.yaml", project(name="estate", main="../index.js"))
            failures = chp.check(root)
            self.assertEqual(len(failures), 1)
            self.assertIn("entry point", failures[0])


class WellFormednessTests(unittest.TestCase):
    def test_a_duplicated_key_fails_rather_than_taking_the_last(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write(
                "estate/Pulumi.yaml",
                "name: estate\nruntime: nodejs\nmain: ../index.ts\nmain: ../estate.ts\n"
                f"backend:\n  url: '{BACKEND}'\n",
            )
            failures = chp.check(tree.root)
            self.assertTrue(any("appears more than once" in f for f in failures))

    def test_a_missing_runtime_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write(
                "estate/Pulumi.yaml", project(name="estate", main="../estate.ts", runtime=None)
            )
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("names no `runtime`", failures[0])

    def test_a_non_node_runtime_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write(
                "estate/Pulumi.yaml",
                project(name="estate", main="../estate.ts", runtime="python"),
            )
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("runtime: python", failures[0])


class BackendTests(unittest.TestCase):
    def test_an_unpinned_project_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write(
                "estate/Pulumi.yaml", project(backend=None, main="../estate.ts", name="estate")
            )
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("pins no backend.url", failures[0])

    def test_two_different_backends_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write(
                "estate/Pulumi.yaml",
                project(backend=OTHER_BACKEND, main="../estate.ts", name="estate"),
            )
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("different backends", failures[0])
            self.assertIn(OTHER_BACKEND, failures[0])

    def test_one_unpinned_project_does_not_also_report_a_backend_mismatch(self):
        # Otherwise the single real fault is reported twice, and the second
        # message names a divergence that does not exist.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write(
                "estate/Pulumi.yaml", project(backend=None, main="../estate.ts", name="estate")
            )
            failures = chp.check(tree.root)
            self.assertNotIn("different backends", " ".join(failures))

    def test_an_inline_flow_backend_names_the_right_fault(self):
        # It IS pinned; the reader just cannot read it. Reporting "pins no
        # backend.url" would send someone to add a key that is already there.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write(
                "estate/Pulumi.yaml",
                f"name: estate\nruntime: nodejs\nmain: ../estate.ts\n"
                f"backend: {{url: '{BACKEND}'}}\n",
            )
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("inline flow mapping", failures[0])
            self.assertNotIn("pins no backend.url", failures[0])


class PackageLayoutTests(unittest.TestCase):
    def test_a_second_package_json_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("estate/package.json", '{"name": "estate"}\n')
            failures = chp.check(tree.root)
            self.assertTrue(any("exactly one package.json" in f for f in failures))

    def test_a_second_package_suppresses_the_main_check(self):
        # With two package roots, "not at the package root" stops identifying
        # the projects that borrow an entry point, so the derived check would
        # report a fault that is not there on top of the one that is.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("estate/package.json", '{"name": "estate"}\n')
            tree.write("estate/Pulumi.yaml", project(name="estate"))
            failures = chp.check(tree.root)
            self.assertEqual(len(failures), 1)
            self.assertIn("exactly one package.json", failures[0])

    def test_no_package_json_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            TreeBuilder(root).write("Pulumi.yaml", project())
            failures = chp.check(root)
            self.assertTrue(any("no package.json" in f for f in failures))

    def test_node_modules_is_not_walked(self):
        # A dependency's own package.json and Pulumi.yaml are not this
        # repository's projects, and there are hundreds of the first.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("node_modules/dep/package.json", '{"name": "dep"}\n')
            tree.write("node_modules/dep/Pulumi.yaml", project(backend=None))
            self.assertEqual(chp.check(tree.root), [])

    def test_sibling_worktrees_are_not_walked(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write(".worktrees/other/package.json", '{"name": "other"}\n')
            tree.write(".worktrees/other/Pulumi.yaml", project(backend=None))
            self.assertEqual(chp.check(tree.root), [])

    def test_a_stray_project_under_dist_is_still_reported(self):
        # This package type-checks with --noEmit and builds nothing, so a
        # Pulumi.yaml under dist/ is a copy somebody left behind rather than
        # build output to ignore.
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("dist/Pulumi.yaml", project(name="estate", backend=None))
            failures = chp.check(tree.root)
            self.assertTrue(any("dist/Pulumi.yaml" in f for f in failures))


class ParsingTests(unittest.TestCase):
    def test_a_commented_out_main_is_not_a_main(self):
        self.assertNotIn("main", chp.read_top_level_scalars("name: p\n# main: ../x.ts\n"))

    def test_a_trailing_comment_is_not_part_of_the_value(self):
        scalars = chp.read_top_level_scalars("main: ../estate.ts # the estate program\n")
        self.assertEqual(scalars["main"], "../estate.ts")

    def test_a_hash_without_leading_whitespace_stays_in_the_value(self):
        # YAML opens a comment only after whitespace, so this is a filename.
        self.assertEqual(chp.strip_scalar("../a#b.ts"), "../a#b.ts")

    def test_a_hash_inside_a_quoted_value_stays(self):
        self.assertEqual(chp.strip_scalar("'s3://b?x=1#frag'"), "s3://b?x=1#frag")

    def test_an_indented_key_is_not_top_level(self):
        self.assertEqual(
            chp.read_top_level_scalars("name: p\nbackend:\n  main: ../x.ts\n"), {"name": "p"}
        )

    def test_duplicate_keys_are_reported_in_order(self):
        self.assertEqual(
            chp.duplicate_top_level_keys("name: a\nname: b\nruntime: nodejs\n"), ["name"]
        )

    def test_backend_url_stops_at_the_next_top_level_key(self):
        text = "backend:\n  poll: 1\nother:\n  url: 'gs://not-the-backend'\n"
        self.assertEqual(chp.read_backend_url(text), (None, None))

    def test_backend_url_is_unquoted(self):
        self.assertEqual(chp.read_backend_url(f"backend:\n  url: '{BACKEND}'\n"), (BACKEND, None))

    def test_absent_backend_block_reads_as_none_with_no_problem(self):
        self.assertEqual(chp.read_backend_url("name: p\nruntime: nodejs\n"), (None, None))


class ExitCodeTests(unittest.TestCase):
    def _run(self, root: pathlib.Path) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = chp.main(["--root", str(root)])
        return code, err.getvalue()

    def test_main_returns_one_and_names_the_fault(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            tree.write("estate/Pulumi.yaml", project(name="estate"))
            code, err = self._run(tree.root)
            self.assertEqual(code, 1)
            self.assertIn("sets no `main`", err)

    def test_main_returns_zero_on_the_intended_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = TreeBuilder(pathlib.Path(tmp)).sound()
            code, err = self._run(tree.root)
            self.assertEqual(code, 0)
            self.assertEqual(err, "")


class ThisRepositoryTests(unittest.TestCase):
    def test_the_real_hetzner_tree_passes(self):
        self.assertEqual(chp.check(chp.DEFAULT_ROOT), [])


if __name__ == "__main__":
    unittest.main()
