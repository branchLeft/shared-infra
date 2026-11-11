#!/usr/bin/env python3
"""Run a Python command and fail if it reads a repository path its CI job's map does not name.

    python3 scripts/trace_reads.py --unit monitoring-config-validate -- \
        -m unittest discover -s hetzner/monitoring -p 'test_*.py' -v

Everything after `--` is what `python3` would be given. The command runs under
an audit hook that watches `open`, `os.listdir`, `os.scandir` and any `git
ls-files` it starts. A path inside the repository (the working directory) but
outside `ci_skip.UNITS[unit]` is a violation: the command still runs to the
end, then this exits 1 and names each path once. The allowed set is imported
from ci_skip.py, never copied. Limits and the reason it runs inside the job are
in ci_skip.md.
"""

from __future__ import annotations

import argparse
import os
import runpy
import sys

import ci_skip

OPENING_EVENTS = ("open", "os.listdir", "os.scandir")


def relative_to_repo(path: object, repo: str) -> str | None:
    """The repo-relative form of a path event argument, or None when it is not a repo path."""
    if isinstance(path, os.PathLike):
        path = os.fspath(path)
    if isinstance(path, bytes):
        path = os.fsdecode(path)
    if not isinstance(path, str) or not path:
        return None  # a file descriptor, or the current directory's default
    if path.startswith("<") and path.endswith(">"):
        return None  # a pseudo-file name such as "<unknown>", never on disk
    # Relative to the directory the command is in now: a test may have changed it.
    absolute = os.path.realpath(os.path.join(os.getcwd(), path))
    if not os.path.isabs(path) and not os.path.lexists(absolute):
        # shutil.rmtree opens entries relative to a directory descriptor, which an
        # audit event does not carry, so a bare name is attributable only when it
        # exists beside the working directory. Limit noted in ci_skip.md.
        return None
    if absolute == repo:
        return ""
    if not absolute.startswith(repo + os.sep):
        return None
    return absolute[len(repo) + 1 :].replace(os.sep, "/")


def is_allowed(relative: str, reads: tuple[str, ...]) -> bool:
    """True when the path is something the map names, or inside a directory it names.

    A directory above a named path is not allowed: listing it reads the names of
    its other entries, which the map does not cover.
    """
    return any(ci_skip.under(relative, prefix) or relative == prefix.rstrip("/") for prefix in reads)


class Tracer:
    def __init__(self, unit: str, repo: str) -> None:
        self.reads = ci_skip.UNITS[unit]
        self.repo = repo
        self.violations: dict[str, str] = {}

    def __call__(self, event: str, args: tuple) -> None:
        if event in OPENING_EVENTS and args:
            relative = relative_to_repo(args[0], self.repo)
            if relative is not None and not is_allowed(relative, self.reads):
                self.violations.setdefault(relative, event)
        elif event == "subprocess.Popen" and len(args) > 1 and isinstance(args[1], (list, tuple)):
            words = [str(word) for word in args[1]]
            if "ls-files" in words and any(os.path.basename(word) == "git" for word in words[:1]):
                self.violations.setdefault("git ls-files", event)


def run(unit: str, python_args: list[str], repo: str | None = None) -> int:
    repo = os.path.realpath(repo or os.getcwd())
    tracer = Tracer(unit, repo)
    code = 0
    # The command must not find its modules in scripts/ just because this file lives there.
    here = os.path.dirname(os.path.realpath(__file__))
    sys.path[:] = [entry for entry in sys.path if os.path.realpath(entry or ".") != here]
    sys.addaudithook(tracer)
    saved_argv = sys.argv
    try:
        if python_args[:1] == ["-m"] and len(python_args) > 1:
            sys.argv = [python_args[1], *python_args[2:]]
            runpy.run_module(python_args[1], run_name="__main__", alter_sys=True)
        elif python_args:
            sys.argv = python_args
            runpy.run_path(python_args[0], run_name="__main__")
    except SystemExit as stop:
        code = stop.code if isinstance(stop.code, int) else (0 if stop.code is None else 1)
    finally:
        sys.argv = saved_argv
    if tracer.violations:
        print(f"trace_reads: {unit} read outside its map in ci_skip.UNITS:", file=sys.stderr)
        for path, event in sorted(tracer.violations.items()):
            print(f"  {path}  ({event})", file=sys.stderr)
        return 1
    return code


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    split = argv.index("--") if "--" in argv else len(argv)
    own, python_args = argv[:split], argv[split + 1 :]
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--unit", required=True, choices=sorted(ci_skip.UNITS))
    args = parser.parse_args(own)
    if not python_args:
        parser.error("give the python command after --")
    return run(args.unit, python_args)


if __name__ == "__main__":
    sys.exit(main())
