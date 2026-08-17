#!/usr/bin/env python3
"""Structural checks over the Pulumi projects in `hetzner/`.

Every check here guards a failure that presents as success rather than as an
error, which is the only reason a checker exists for something this small.

**A project directory with no `main`, or the wrong `main`, runs a different
program.** The projects here deliberately share one npm package, so a project
in a subdirectory has no `package.json` of its own and Pulumi walks up to the
package root's. It then reads that file's `"main"` and resolves it against the
*package* root, so the subdirectory project runs the package's entry point.
Observed directly against Pulumi v3.255.0: a subdirectory project with no
`main` previewed a create plan for the network program's resources, exited 0,
and reported nothing wrong. Naming that same entry point explicitly is the same
fault with a different spelling, so both are rejected.

**Two projects sharing a `name` share a state file.** A DIY backend stores a
stack at `.pulumi/stacks/<project-name>/<stack>.json`, keyed on the name in
`Pulumi.yaml` and not on the directory. Copy a project directory, change
`main`, forget `name`, and `pulumi up` in the copy loads the original's
checkpoint and plans to delete every resource the original created -- part-way
through which the firewall is already gone.

**A project with no pinned backend is operated against whichever backend the
workstation last logged into.** `pulumi login` is global state on a machine, so
the pin is what keeps `pulumi up` in this directory addressing this estate's
state. Two projects pinning *different* backends is the other half: these
stacks reference each other, and a stack reference resolves inside one backend.

The single-package rule is what the first check depends on, and it carries its
own reason: a provider version is part of every resource's URN, so two packages
pinning `@pulumi/hcloud` differently would put hosts and the network they
attach to behind two provider instances.

    check-hetzner-projects.py [--root DIR]

Exits non-zero, listing every failure. Reads files only; contacts nothing.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

DEFAULT_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Not source, or a second copy of it. `.worktrees` holds sibling checkouts of
# this same repo, whose projects are that checkout's business. `dist` is
# deliberately absent: this package type-checks with `--noEmit` and builds
# nothing, so a `Pulumi.yaml` appearing under one would be a stray copy that
# still needs reporting rather than build output to ignore.
SKIP_DIRS = {".git", ".worktrees", "node_modules", "graphify-out"}

# What `package.json` means by an absent `main`.
NPM_DEFAULT_MAIN = "index.js"

# The only runtime whose module resolution the reasoning above describes.
EXPECTED_RUNTIME = "nodejs"


# --------------------------------------------------------------------------
# Parsing
#
# A real YAML parser is not available: this runs on a bare `python3` with no
# site-packages, the same constraint the other scripts in this repo work under.
#
# The repository's other YAML readers are of the same shape, for the
# same reason. They are **not** shared and have diverged on purpose: that one
# reads Pulumi-generated `Pulumi.<stack>.yaml` files, this one reads hand-written
# `Pulumi.yaml` files and therefore has to cope with trailing comments,
# duplicate keys and inline flow mappings that a machine-written file never
# contains. Changing one does not imply changing the other, but a bug found in
# either is worth looking for in the other.
#
# Both are readers for their own files, not YAML parsers, and both say so
# rather than pretending otherwise.
# --------------------------------------------------------------------------

_TRAILING_COMMENT = re.compile(r"\s#")


def strip_scalar(value: str) -> str:
    """A scalar's value, without its quotes or its trailing comment.

    YAML requires whitespace before a `#` for it to open a comment, so
    `main: ../a#b.ts` is a filename and `main: ../a.ts # note` is not.
    """
    value = value.strip()
    if value[:1] in ("'", '"'):
        closing = value.find(value[0], 1)
        # An unterminated quote is left alone: the checks downstream report it
        # as a value that does not resolve, which is what it is.
        return value[1:closing] if closing != -1 else value
    match = _TRAILING_COMMENT.search(value)
    return value[: match.start()].strip() if match else value


def read_top_level_entries(text: str) -> list[tuple[str, str]]:
    """Every top-level `key: value` pair, in order, duplicates included.

    Order and duplicates are both kept because a repeated key is a fault to
    report rather than something to silently resolve -- YAML says the last one
    wins, and a reader that agrees hides the ambiguity it should surface.
    """
    entries: list[tuple[str, str]] = []
    for line in text.splitlines():
        if not line or line[0].isspace() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        value = strip_scalar(value)
        # A bare `key:` opens a block and `>`/`|` open a folded scalar. Neither
        # is a value, and reporting one as an empty string would read as a
        # configured-but-blank setting rather than as an absent one.
        if not value or value in (">", "|", ">-", "|-"):
            continue
        entries.append((key.strip(), value))
    return entries


def read_top_level_scalars(text: str) -> dict[str, str]:
    return dict(read_top_level_entries(text))


def duplicate_top_level_keys(text: str) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for key, _ in read_top_level_entries(text):
        if key in seen and key not in duplicates:
            duplicates.append(key)
        seen.add(key)
    return sorted(duplicates)


def read_backend_url(text: str) -> tuple[str | None, str | None]:
    """`(url, problem)` for a `Pulumi.yaml`'s `backend: url:`.

    `problem` is set for a shape this reader cannot answer for, so the caller
    reports "not readable" rather than "not pinned" -- naming the wrong fault
    sends someone to add a key that is already there.
    """
    in_backend = False
    for line in text.splitlines():
        if line.startswith("backend:"):
            inline = strip_scalar(line.partition(":")[2])
            if inline:
                return None, (
                    f"`backend:` is an inline flow mapping ({inline!r}), which this "
                    f"reader does not parse. Write it as an indented block."
                )
            in_backend = True
            continue
        if in_backend:
            if line and not line[0].isspace():
                break
            stripped = line.strip()
            if stripped.startswith("url:"):
                return strip_scalar(stripped[len("url:") :]), None
    return None, None


def find(root: pathlib.Path, filename: str) -> list[pathlib.Path]:
    """Every `filename` under `root`, skipping the directories above."""
    hits = []
    for path in sorted(root.rglob(filename)):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        hits.append(path)
    return hits


def package_entry_point(package_json: pathlib.Path) -> pathlib.Path:
    """Where Pulumi resolves a project that names no `main` of its own."""
    try:
        main = json.loads(package_json.read_text()).get("main") or NPM_DEFAULT_MAIN
    except (OSError, ValueError):
        main = NPM_DEFAULT_MAIN
    return (package_json.parent / main).resolve()


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def check_single_package(root: pathlib.Path, packages: list[pathlib.Path]) -> list[str]:
    if len(packages) == 1 and packages[0].parent == root:
        return []
    if not packages:
        return [f"no package.json under {root}: the Pulumi projects here have no SDK to resolve"]
    listed = ", ".join(str(p.relative_to(root)) for p in packages)
    return [
        f"expected exactly one package.json, at the root of {root}; found {len(packages)}: "
        f"{listed}. Every Pulumi project here shares one node_modules so that one "
        f"@pulumi/hcloud version appears in every URN. Adding a package means deciding "
        f"how the two provider versions stay equal, which is not a decision a second "
        f"package.json makes on its own."
    ]


def check_wellformed(projects: dict[pathlib.Path, str]) -> list[str]:
    failures = []
    for path, text in projects.items():
        for key in duplicate_top_level_keys(text):
            failures.append(
                f"{path}: `{key}` appears more than once at the top level. YAML takes the "
                f"last, which is rarely the one that was read while editing."
            )
        runtime = read_top_level_scalars(text).get("runtime")
        if runtime is None:
            failures.append(f"{path}: names no `runtime`")
        elif runtime != EXPECTED_RUNTIME:
            failures.append(
                f"{path}: `runtime: {runtime}`. Everything this checker asserts about "
                f"entry points is Node module resolution, and none of it holds for "
                f"another runtime."
            )
    return failures


def check_names(projects: dict[pathlib.Path, str]) -> list[str]:
    failures = []
    names: dict[str, list[pathlib.Path]] = {}
    for path, text in projects.items():
        name = read_top_level_scalars(text).get("name")
        if name is None:
            failures.append(f"{path}: names no project `name`")
            continue
        names.setdefault(name, []).append(path)
    for name, paths in sorted(names.items()):
        if len(paths) > 1:
            listed = ", ".join(str(p) for p in paths)
            failures.append(
                f"project name {name!r} is used by {len(paths)} projects ({listed}). A DIY "
                f"backend keys a stack's state on the project name and not on the "
                f"directory, so these share one state file: an apply in one loads the "
                f"other's checkpoint and plans to delete everything in it."
            )
    return failures


def check_backends(projects: dict[pathlib.Path, str]) -> list[str]:
    failures = []
    urls: dict[str, list[pathlib.Path]] = {}
    for path, text in projects.items():
        url, problem = read_backend_url(text)
        if problem is not None:
            failures.append(f"{path}: {problem}")
            continue
        if url is None:
            failures.append(
                f"{path}: pins no backend.url, so it is operated against whichever "
                f"backend `pulumi login` last selected on the machine"
            )
            continue
        urls.setdefault(url, []).append(path)
    if len(urls) > 1:
        rendered = "; ".join(
            f"{url} ({', '.join(str(p) for p in paths)})" for url, paths in sorted(urls.items())
        )
        failures.append(
            f"projects pin {len(urls)} different backends, and a stack reference "
            f"resolves inside one backend only: {rendered}"
        )
    return failures


def check_main(
    root: pathlib.Path, projects: dict[pathlib.Path, str], entry_point: pathlib.Path
) -> list[str]:
    failures = []
    targets: dict[pathlib.Path, list[pathlib.Path]] = {}

    for path, text in projects.items():
        main = read_top_level_scalars(text).get("main")
        at_package_root = path.parent == root

        if main is None:
            if at_package_root:
                targets.setdefault(entry_point, []).append(path)
            else:
                failures.append(
                    f"{path}: sets no `main`. This project has no package.json of its "
                    f"own, so Pulumi resolves the package root's `main` against the "
                    f"package root and silently runs {entry_point} instead. It does not "
                    f"error."
                )
            continue

        target = (path.parent / main).resolve()
        if not target.is_file():
            failures.append(f"{path}: `main: {main}` resolves to {target}, which is not a file")
            continue
        if not at_package_root and target == entry_point:
            failures.append(
                f"{path}: `main: {main}` names the package's own entry point "
                f"({entry_point}). That is the program the root project already runs, so "
                f"this project would run it a second time -- the same fault as omitting "
                f"`main`, spelled out."
            )
            continue
        targets.setdefault(target, []).append(path)

    for target, paths in sorted(targets.items()):
        if len(paths) > 1:
            listed = ", ".join(str(p) for p in paths)
            failures.append(
                f"{len(paths)} projects run the same program {target} ({listed}). Two "
                f"projects over one program create the same resources twice, in two "
                f"stacks that each believe they own them."
            )
    return failures


def check(root: pathlib.Path) -> list[str]:
    projects = {path: path.read_text() for path in find(root, "Pulumi.yaml")}
    if not projects:
        return [f"no Pulumi.yaml under {root}"]
    packages = find(root, "package.json")

    package_failures = check_single_package(root, packages)
    failures = (
        package_failures
        + check_wellformed(projects)
        + check_names(projects)
        + check_backends(projects)
    )
    # The `main` checks identify a borrowed entry point as "not at the package
    # root, resolving to the package's own main", which only means anything
    # while there is one package root. With the layout already broken they
    # would report a fault that is not there on top of the one that is.
    if not package_failures:
        failures += check_main(root, projects, package_entry_point(packages[0]))
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(DEFAULT_ROOT))
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root).resolve()
    failures = check(root)
    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    print(f"{len(find(root, 'Pulumi.yaml'))} Pulumi project(s) under {root}: layout is sound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
