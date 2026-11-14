#!/usr/bin/env python3
"""Report every pinned ghost-platform consumer whose pinned files differ from ghost-platform main.

A host role here fetches programs from ghost-platform at one pinned commit and holds each to
a digest. That is exact, and it is also silent: a fix merged to ghost-platform reaches the
host only when someone bumps the pin, and nothing said when no one did. This check compares
each file a role pins at the pin with the same file at main. The rules, the registry and the
alert route are in check_ghost_pin_lag.md.

Usage:
    check_ghost_pin_lag.py [--summary FILE] [--main-ref REF]

Exit status:
    0  every pinned file is the same at main (EXIT_CURRENT)
    1  at least one pinned file differs from main, or is gone from it (EXIT_LAG)
    2  the check could not run: a pin or a source could not be read, or GitHub could not be
       reached (EXIT_ERROR). Kept apart from 1 so the log says which happened.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TextIO

import yaml

EXIT_CURRENT = 0
EXIT_LAG = 1
EXIT_ERROR = 2

ROOT = pathlib.Path(__file__).resolve().parent.parent
REGISTRY = pathlib.Path(__file__).resolve().parent / "ghost_pin_consumers.json"
USER_AGENT = "branchleft-shared-infra-ghost-pin-lag-check"
FETCH_TIMEOUT_SECONDS = 20
FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
SHAPES = ("strings", "keys", "path_field")

# (ref, repository path) to the file's bytes, or None when the file does not exist at that ref.
Fetch = Callable[[str, str], "bytes | None"]


class CheckError(Exception):
    """The check could not be completed, which is not the same as a finding."""


@dataclass(frozen=True)
class Consumer:
    """One role that fetches from ghost-platform at a pin."""

    name: str
    host: str
    pin: str
    paths: tuple[str, ...]


@dataclass(frozen=True)
class Lag:
    """One pinned file that differs from main; kind is `changed` or `removed`."""

    consumer: str
    path: str
    kind: str


def read_yaml(root: pathlib.Path, relative: str) -> Mapping[str, Any]:
    """Parse a role's variables file; a file that is not a mapping is refused."""
    path = root / relative
    try:
        loaded = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise CheckError(f"cannot read {relative}: {exc}") from exc
    if not isinstance(loaded, Mapping):
        raise CheckError(f"{relative} is not a mapping")
    return loaded


def values_of(
    loaded: Mapping[str, Any], relative: str, source: Mapping[str, Any]
) -> list[str]:
    """The names one registry source selects from a parsed file, before any prefix."""
    key = source["key"]
    if key not in loaded:
        raise CheckError(f"{relative} holds no key {key}")
    held = loaded[key]
    shape = source.get("shape")
    if (
        shape == "strings"
        and isinstance(held, list)
        and all(isinstance(v, str) for v in held)
    ):
        return list(held)
    if (
        shape == "keys"
        and isinstance(held, Mapping)
        and all(isinstance(k, str) for k in held)
    ):
        return list(held)
    if shape == "path_field" and isinstance(held, list):
        names = [
            entry.get("path") if isinstance(entry, Mapping) else None for entry in held
        ]
        if all(isinstance(n, str) for n in names):
            return [n for n in names if isinstance(n, str)]
    if shape not in SHAPES:
        raise CheckError(f"{relative}: key {key} names the unknown shape {shape!r}")
    raise CheckError(f"{relative}: key {key} does not hold the {shape} shape")


def pin_of(root: pathlib.Path, commit: Mapping[str, Any]) -> str:
    """The full 40-character commit a role pins; anything shorter or looser is refused."""
    loaded = read_yaml(root, commit["file"])
    pin = loaded.get(commit["key"])
    if not isinstance(pin, str) or not FULL_COMMIT.fullmatch(pin):
        raise CheckError(
            f"{commit['file']}: {commit['key']} is not a full lower-case 40-character commit"
        )
    return pin


def load_consumers(root: pathlib.Path, registry: pathlib.Path) -> list[Consumer]:
    """Resolve the registry against the role files under root into one Consumer per role."""
    try:
        spec = json.loads(registry.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckError(f"cannot read the registry {registry.name}: {exc}") from exc
    consumers: list[Consumer] = []
    try:
        for entry in spec["consumers"]:
            paths: list[str] = []
            for source in entry["sources"]:
                if "path" in source:
                    paths.append(source["path"])
                    continue
                loaded = read_yaml(root, source["file"])
                paths.extend(
                    source["prefix"] + name
                    for name in values_of(loaded, source["file"], source)
                )
            if not paths:
                raise CheckError(f"{entry['name']} resolves to no path")
            consumers.append(
                Consumer(
                    entry["name"],
                    entry["host"],
                    pin_of(root, entry["commit"]),
                    tuple(paths),
                )
            )
    except (KeyError, TypeError) as exc:
        raise CheckError(f"the registry {registry.name} is malformed: {exc!r}") from exc
    return consumers


def raw_url(repository: str, ref: str, path: str) -> str:
    """Where GitHub serves one file at one ref."""
    return f"https://raw.githubusercontent.com/{repository}/{ref}/{urllib.parse.quote(path)}"


def github_fetch(repository: str) -> Fetch:
    """A Fetch that reads public files from GitHub; a 404 is None and any other failure stops the check."""

    def fetch(ref: str, path: str) -> bytes | None:
        request = urllib.request.Request(
            raw_url(repository, ref, path), headers={"User-Agent": USER_AGENT}
        )
        try:
            with urllib.request.urlopen(
                request, timeout=FETCH_TIMEOUT_SECONDS
            ) as response:
                return bytes(response.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise CheckError(f"GitHub answered {exc.code} for {path} at {ref}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise CheckError(f"could not read {path} at {ref}: {exc}") from exc

    return fetch


def find_lag(consumers: Sequence[Consumer], fetch: Fetch, main_ref: str) -> list[Lag]:
    """Every file whose bytes at the pin differ from its bytes at main_ref, in registry order."""
    cache: dict[tuple[str, str], str | None] = {}

    def digest(ref: str, path: str) -> str | None:
        if (ref, path) not in cache:
            body = fetch(ref, path)
            cache[(ref, path)] = (
                None if body is None else hashlib.sha256(body).hexdigest()
            )
        return cache[(ref, path)]

    lags: list[Lag] = []
    for consumer in consumers:
        for path in consumer.paths:
            pinned = digest(consumer.pin, path)
            if pinned is None:
                raise CheckError(
                    f"{consumer.name}: {path} does not exist at its own pin {consumer.pin[:12]}"
                )
            current = digest(main_ref, path)
            if current is None:
                lags.append(Lag(consumer.name, path, "removed"))
            elif current != pinned:
                lags.append(Lag(consumer.name, path, "changed"))
    return lags


def render(consumers: Sequence[Consumer], lags: Sequence[Lag], main_ref: str) -> str:
    """The report, in Markdown so it reads the same in a log and in a step summary."""
    if not lags:
        lines = [
            f"Every pinned ghost-platform file is current with {main_ref} ({len(consumers)} roles checked)."
        ]
        return "\n".join(lines) + "\n"
    lines = [f"Pinned ghost-platform files that differ from {main_ref}:", ""]
    for consumer in consumers:
        mine = [lag for lag in lags if lag.consumer == consumer.name]
        if not mine:
            continue
        lines.append(
            f"- {consumer.name} (host {consumer.host}), pinned at {consumer.pin[:12]}"
        )
        lines.extend(f"  - {lag.path}: {lag.kind} on {main_ref}" for lag in mine)
    lines += [
        "",
        "Bump the pin and its digests in the role, or confirm the difference is meant to wait.",
    ]
    return "\n".join(lines) + "\n"


def run(
    root: pathlib.Path,
    registry: pathlib.Path,
    fetch: Fetch,
    main_ref: str,
    summary: pathlib.Path | None,
    out: TextIO,
) -> int:
    """Run the whole check, print the report, and return the exit status."""
    try:
        consumers = load_consumers(root, registry)
        lags = find_lag(consumers, fetch, main_ref)
    except CheckError as exc:
        out.write(f"The check could not run: {exc}\n")
        return EXIT_ERROR
    report = render(consumers, lags, main_ref)
    out.write(report)
    if summary is not None:
        with summary.open("a") as handle:
            handle.write(report)
    return EXIT_LAG if lags else EXIT_CURRENT


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--summary", type=pathlib.Path, help="a file to append the report to"
    )
    parser.add_argument(
        "--main-ref", default="main", help="the ref the pins are compared with"
    )
    args = parser.parse_args(argv)
    try:
        repository = json.loads(REGISTRY.read_text())["repository"]
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        sys.stdout.write(f"The check could not run: cannot read the registry: {exc}\n")
        return EXIT_ERROR
    return run(
        ROOT,
        REGISTRY,
        github_fetch(repository),
        args.main_ref,
        args.summary,
        sys.stdout,
    )


if __name__ == "__main__":
    sys.exit(main())
