#!/usr/bin/python3 -I
"""Unit tests for check-hetzner-host-dist.

The fault this checker exists for is silent: a pull changes hetzner-host/*.ts,
the compiled dist/ still holds the old program, and a preview plans against
code nobody reads. So each test builds the stale layout and asserts the checker
refuses it. A checker that has stopped refusing looks the same as a fresh build.

No network. No subprocess.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import pathlib
import sys
import tempfile
import unittest
from types import ModuleType

SECOND_NS = 10**9
T0 = 1_700_000_000 * SECOND_NS  # the moment of the checkout
BUILT = T0 + 10 * SECOND_NS  # dist written after the checkout
PULLED = T0 + 20 * SECOND_NS  # a source file rewritten by a later pull


def _load_module() -> ModuleType:
    path = pathlib.Path(__file__).resolve().parent / "check-hetzner-host-dist.py"
    spec = importlib.util.spec_from_file_location("check_hetzner_host_dist", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker: ModuleType = _load_module()


def _write(path: pathlib.Path, mtime_ns: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("// fixture\n", encoding="utf-8")
    os.utime(path, ns=(mtime_ns, mtime_ns))


class CheckHetznerHostDist(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.package = pathlib.Path(self._tmp.name) / "hetzner-host"
        self.addCleanup(self._tmp.cleanup)

    def _build_fresh(self) -> None:
        _write(self.package / "host.ts", T0)
        _write(self.package / "index.ts", T0)
        _write(self.package / "dist" / "host.js", BUILT)
        _write(self.package / "dist" / "index.js", BUILT)

    def _run(self) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = checker.main(["--package", str(self.package)])
        return code, err.getvalue()

    def test_fresh_build_passes(self) -> None:
        self._build_fresh()
        code, _ = self._run()
        self.assertEqual(code, 0)

    def test_source_newer_than_dist_refuses_and_names_the_stale_build(self) -> None:
        # The owner's case: a pull rewrote host.ts; dist still holds the old build.
        self._build_fresh()
        _write(self.package / "host.ts", PULLED)
        code, err = self._run()
        self.assertEqual(code, 1)
        self.assertIn("host.ts", err)
        self.assertIn("dist/host.js", err)
        self.assertIn("stale", err)

    def test_missing_entry_point_refuses(self) -> None:
        self._build_fresh()
        (self.package / "dist" / "index.js").unlink()
        code, err = self._run()
        self.assertEqual(code, 1)
        self.assertIn("dist/index.js", err)

    def test_new_source_without_compiled_output_refuses(self) -> None:
        self._build_fresh()
        _write(self.package / "addressPlan.ts", T0)
        code, err = self._run()
        self.assertEqual(code, 1)
        self.assertIn("addressPlan.ts", err)

    def test_test_and_fixture_files_do_not_count_as_source(self) -> None:
        # tsconfig.build.json excludes these, so a newer test file is not stale.
        self._build_fresh()
        _write(self.package / "host.test.ts", PULLED)
        _write(self.package / "enrolment.fixtures.ts", PULLED)
        code, _ = self._run()
        self.assertEqual(code, 0)

    def test_package_with_no_sources_refuses(self) -> None:
        # A checker that finds nothing to compare and exits 0 reports health
        # for a tree it never examined.
        self.package.mkdir(parents=True)
        _write(self.package / "dist" / "index.js", BUILT)
        code, _ = self._run()
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
