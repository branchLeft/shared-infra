#!/usr/bin/python3 -I
"""Refuses a hand preview or apply against a stale compiled @branchleft/hetzner-host.

The stacks link the package with `link:../hetzner-host`, and its entry point is
the compiled dist/index.js. A `git pull` rewrites the .ts sources and leaves
dist/ as it was built, so a stack would plan against a program nobody reads.

    check-hetzner-host-dist.py [--package DIR]

Exits 0 when every non-test source has a compiled output at least as new as the
source, and 1 otherwise, naming each stale pair and the rebuild command. Reads
files only; contacts nothing.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import pathlib
import sys
from collections.abc import Sequence

# hetzner/scripts/ -> hetzner/ -> the repository root, then into the package.
DEFAULT_PACKAGE = pathlib.Path(__file__).resolve().parent.parent.parent / "hetzner-host"
ENTRY_POINT = "dist/index.js"

# The same exclusions tsconfig.build.json applies: tests, fixtures and the
# vitest config are not compiled into dist/, so they never make it stale.
_EXCLUDED_SUFFIXES: tuple[str, ...] = (".test.ts", ".fixtures.ts")
_EXCLUDED_NAMES: frozenset[str] = frozenset({"vitest.config.ts"})
_EXCLUDED_DIRS: frozenset[str] = frozenset({"node_modules", "dist"})

REBUILD_HINT = (
    "Rebuild it from hetzner/ with `pnpm install --frozen-lockfile`, whose "
    "postinstall runs the package build, and then preview again."
)


@dataclasses.dataclass(frozen=True)
class Stale:
    source: str
    output: str
    why: str


def _sources(package: pathlib.Path) -> list[pathlib.Path]:
    """Every .ts file the package build compiles, pruning dependency and output trees."""
    found: list[pathlib.Path] = []
    for dirpath, dirnames, filenames in os.walk(package):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        for name in filenames:
            if not name.endswith(".ts"):
                continue
            if name.endswith(_EXCLUDED_SUFFIXES) or name in _EXCLUDED_NAMES:
                continue
            found.append(pathlib.Path(dirpath, name))
    return sorted(found)


def find_stale(package: pathlib.Path) -> list[Stale]:
    """Every compiled output that is missing or older than its source."""
    entry = package / ENTRY_POINT
    if not entry.is_file():
        return [Stale(source="", output=ENTRY_POINT, why="never built")]
    sources = _sources(package)
    if not sources:
        # Finding nothing to compare and passing would report health for a tree
        # that was never examined.
        return [Stale(source="", output="", why="no source files found")]
    stale: list[Stale] = []
    for src in sources:
        rel = src.relative_to(package)
        out = package / "dist" / rel.with_suffix(".js")
        out_rel = out.relative_to(package).as_posix()
        if not out.is_file():
            stale.append(Stale(rel.as_posix(), out_rel, "no compiled output"))
        elif src.stat().st_mtime_ns > out.stat().st_mtime_ns:
            stale.append(
                Stale(rel.as_posix(), out_rel, "source is newer than the build")
            )
    return stale


def _parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--package", type=pathlib.Path, default=DEFAULT_PACKAGE)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse(argv)
    stale = find_stale(args.package)
    if not stale:
        return 0
    lines = [
        "hetzner-host/dist is a stale build of its source: refusing to preview or apply."
    ]
    for item in stale:
        if item.source:
            lines.append(f"  {item.source} -> {item.output}: {item.why}")
        elif item.output:
            lines.append(f"  {item.output}: {item.why}")
        else:
            lines.append(f"  {item.why}")
    lines.append(REBUILD_HINT)
    print("\n".join(lines), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
