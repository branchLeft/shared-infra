#!/usr/bin/env python3
"""Run promtool rule-test files as parallel shards of their test groups.

`promtool test rules FILE` runs every test group in FILE one after another, and
the alert-rule suite is long enough that the serial run takes over ten minutes.
This script reads each hand-written test file, splits its `tests:` list at the
group boundaries (`  - interval:` lines), writes N shard files that each carry
the file's header unchanged and a balanced share of the groups, and runs one
`promtool test rules` process per shard concurrently.

Nothing about a test changes: every group is copied byte for byte, and the
script refuses to run unless the shards together contain exactly the groups
of the source file, each once. The number of groups and of `eval_time`
entries it ran is printed, so a lost case shows up in the CI log.

The rule file the tests read (`rule_files:`, relative to the test file) is
copied into the work directory at the same relative path, so the test headers
need no change.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

GROUP_START = re.compile(r"^  - interval:")
TESTS_KEY = re.compile(r"^tests:\s*$")
EVAL_TIME = re.compile(r"^\s*- eval_time:", re.MULTILINE)
EVAL_TIME_VALUE = re.compile(r"^\s*- eval_time:\s*(\S+)\s*$", re.MULTILINE)
DURATION = re.compile(r"(\d+[hms])+")
DURATION_PART = re.compile(r"(\d+)([hms])")
RULE_FILES_ENTRY = re.compile(r"^\s*-\s*(\S+)\s*$")

PROMTOOL_IMAGE_DEFAULT = ""


@dataclasses.dataclass(frozen=True)
class Split:
    """A test file cut into its header and its test groups."""

    header: str
    groups: tuple[str, ...]
    rule_files: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class ShardResult:
    name: str
    returncode: int
    seconds: float
    output: str


def split_test_file(text: str) -> Split:
    """Cut `text` at its group boundaries.

    The header is everything up to and including `tests:`, plus any comment or
    blank lines before the first group. Each group runs from its
    `  - interval:` line to the next one, so a comment written above a group
    travels with the group before it, which is harmless in YAML.
    """
    lines = text.splitlines(keepends=True)
    tests_at = [i for i, line in enumerate(lines) if TESTS_KEY.match(line)]
    if len(tests_at) != 1:
        raise ValueError(f"expected exactly one top-level 'tests:' key, found {len(tests_at)}")
    cut = tests_at[0]
    header_parts = [line for line in lines[: cut + 1]]
    groups: list[list[str]] = []
    for line in lines[cut + 1 :]:
        if GROUP_START.match(line):
            groups.append([line])
        elif groups:
            if line.strip() and not line.startswith((" ", "#", "\t")):
                raise ValueError(f"top-level content inside 'tests:' is not supported: {line!r}")
            groups[-1].append(line)
        elif line.strip() and not line.lstrip().startswith("#"):
            raise ValueError(f"content before the first test group is not supported: {line!r}")
        else:
            header_parts.append(line)
    if not groups:
        raise ValueError("no test groups found")
    rule_files = tuple(
        m.group(1)
        for line in lines[:cut]
        if (m := RULE_FILES_ENTRY.match(line)) and not line.lstrip().startswith("#")
    )
    return Split(
        header="".join(header_parts),
        groups=tuple("".join(group) for group in groups),
        rule_files=rule_files,
    )


def duration_seconds(text: str) -> int:
    """Read a promtool duration such as `30s`, `98m`, `1h30m` or `624h`."""
    if not DURATION.fullmatch(text):
        raise ValueError(f"unsupported duration: {text!r}")
    units = {"h": 3600, "m": 60, "s": 1}
    return sum(int(n) * units[u] for n, u in DURATION_PART.findall(text))


def group_cost(group: str) -> int:
    """Promtool's time for a group is proportional to the rule evaluations it runs.

    Each evaluation covers the whole rule file, so a group's cost is the sum of
    its `eval_time` windows, in seconds, divided by the file's evaluation
    interval. The divisor is the same for every group, so it is left out.
    """
    return sum(duration_seconds(m.group(1)) for m in EVAL_TIME_VALUE.finditer(group))


def balance(groups: tuple[str, ...], shards: int) -> list[list[int]]:
    """Assign group indexes to `shards` buckets, heaviest first, greedily."""
    weights = [group_cost(group) for group in groups]
    order = sorted(range(len(groups)), key=lambda i: (-weights[i], i))
    buckets: list[list[int]] = [[] for _ in range(shards)]
    loads = [0] * shards
    for index in order:
        target = min(range(shards), key=lambda b: (loads[b], b))
        buckets[target].append(index)
        loads[target] += weights[index]
    for bucket in buckets:
        bucket.sort()
    return buckets


def write_shards(split: Split, work: Path, name: str, shards: int) -> list[Path]:
    """Write shard files for one test file into `work` and return their paths."""
    paths: list[Path] = []
    for number, indexes in enumerate(balance(split.groups, shards)):
        if not indexes:
            continue
        body = split.header + "".join(split.groups[i] for i in indexes)
        path = work / f"{name}.shard{number}.yml"
        path.write_text(body, encoding="utf-8")
        paths.append(path)
    return paths


def check_partition(split: Split, shard_texts: list[str]) -> tuple[int, int]:
    """Prove the shards hold exactly the source groups, each once.

    Returns the number of groups and of `eval_time` entries across the shards.
    """
    source = sorted(split.groups)
    shard_groups: list[str] = []
    for text in shard_texts:
        shard = split_test_file(text)
        if shard.header != split.header:
            raise AssertionError("a shard's header differs from the source header")
        shard_groups.extend(shard.groups)
    if sorted(shard_groups) != source:
        raise AssertionError("the shards do not hold exactly the source test groups")
    eval_entries = sum(len(EVAL_TIME.findall(group)) for group in shard_groups)
    return len(shard_groups), eval_entries


def copy_rule_files(source_dir: Path, rule_files: tuple[str, ...], work: Path) -> None:
    """Copy each rule file the tests read to the same relative path in `work`."""
    for rel in rule_files:
        src = (source_dir / rel).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"rule file named by the test file is missing: {src}")
        dst = work / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o644)


def promtool_command(image: str, work: Path, shard: Path) -> list[str]:
    """The command that runs one shard, locally or in the pinned image."""
    if not image:
        return ["promtool", "test", "rules", shard.name]
    return [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{work}:/etc/prometheus-tests:ro",
        "--workdir",
        "/etc/prometheus-tests",
        "--entrypoint",
        "/bin/promtool",
        image,
        "test",
        "rules",
        shard.name,
    ]


def run_shard(image: str, work: Path, shard: Path) -> ShardResult:
    started = time.monotonic()
    proc = subprocess.run(
        promtool_command(image, work, shard),
        cwd=work,
        capture_output=True,
        text=True,
        check=False,
    )
    return ShardResult(
        name=shard.name,
        returncode=proc.returncode,
        seconds=time.monotonic() - started,
        output=proc.stdout + proc.stderr,
    )


def run_file(path: Path, image: str, shards: int, jobs: int) -> bool:
    """Shard one test file, run the shards, and report. True when all pass."""
    text = path.read_text(encoding="utf-8")
    split = split_test_file(text)
    with tempfile.TemporaryDirectory(prefix="promtool-shards-") as tmp:
        work = Path(tmp)
        # mkdtemp makes this 0700. The pinned image runs promtool as a non-root
        # user, which must be able to read the bind mount.
        os.chmod(work, 0o755)
        copy_rule_files(path.parent, split.rule_files, work)
        shard_paths = write_shards(split, work, path.stem, shards)
        for shard in shard_paths:
            os.chmod(shard, 0o644)
        groups, evals = check_partition(
            split, [p.read_text(encoding="utf-8") for p in shard_paths]
        )
        print(f"{path.name}: {groups} test groups, {evals} eval_time cases, {len(shard_paths)} shards")
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(lambda p: run_shard(image, work, p), shard_paths))
        wall = time.monotonic() - started
    failed = [r for r in results if r.returncode != 0]
    for result in results:
        status = "ok" if result.returncode == 0 else f"FAILED exit {result.returncode}"
        print(f"  {result.name}: {status} in {result.seconds:.1f}s")
    for result in failed:
        print(f"--- {result.name} output ---")
        print(result.output)
    print(f"{path.name}: wall {wall:.1f}s with {jobs} jobs")
    return not failed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", type=Path, help="promtool test files to run")
    parser.add_argument("--shards", type=int, default=4, help="shards per file")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 2, help="concurrent promtool runs")
    parser.add_argument(
        "--image",
        default=PROMTOOL_IMAGE_DEFAULT,
        help="run promtool in this image; empty runs promtool from PATH",
    )
    args = parser.parse_args(argv)
    if args.shards < 1 or args.jobs < 1:
        parser.error("--shards and --jobs must be at least 1")
    ok = True
    for path in args.files:
        ok = run_file(path, args.image, args.shards, args.jobs) and ok
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
