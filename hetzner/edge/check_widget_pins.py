#!/usr/bin/env python3
"""Fail when the edge image's /bl-assets/ widget files drift from ghost-platform's pins.

The edge Dockerfile names one commit of branchLeft/ghost-platform
(WIDGET_SOURCE_COMMIT), seven ADD lines carrying sha256 sums, and that commit's
widgets/pins.json carries one row per file with a sha384 digest and a byte
count. This check fetches the same bytes the image build fetches, from that
commit, and fails unless all of these agree:

- the ADD file names are exactly the file names the pins' servedPath values name;
- each ADD sha256 equals the sha256 of the fetched bytes;
- each pins row's sha384 and bytes equal the fetched bytes.

Run from CI with no arguments. The tests in test_check_widget_pins.py use the
same functions with fetched bytes supplied in memory.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

RAW_BASE = "https://raw.githubusercontent.com/branchLeft/ghost-platform"
ADD_LINE = re.compile(
    r"^ADD --checksum=sha256:([0-9a-f]{64}) --chmod=0644 \$\{WIDGET_BASE_URL\}/(\S+) (\S+)$",
    re.MULTILINE,
)
COMMIT_LINE = re.compile(r"^ARG WIDGET_SOURCE_COMMIT=([0-9a-f]{40})$", re.MULTILINE)
DEFAULT_DOCKERFILE = Path(__file__).resolve().parent / "Dockerfile"


@dataclass(frozen=True)
class DockerfilePins:
    commit: str
    sha256_by_name: dict[str, str]


@dataclass(frozen=True)
class BundlePin:
    sha384: str
    size: int


def parse_dockerfile(text: str) -> DockerfilePins:
    commit_match = COMMIT_LINE.search(text)
    if commit_match is None:
        raise ValueError("Dockerfile has no `ARG WIDGET_SOURCE_COMMIT=<40 hex>` line")
    adds = [line for line in text.splitlines() if line.startswith("ADD ")]
    sha256_by_name: dict[str, str] = {}
    for line in adds:
        match = ADD_LINE.match(line)
        if match is None:
            raise ValueError(f"unrecognised widget ADD line: {line}")
        digest, source, destination = match.group(1), match.group(2), match.group(3)
        if not destination.startswith("/srv/bl-assets/") or destination.rsplit("/", 1)[1] != source:
            raise ValueError(f"widget ADD destination does not match its source: {line}")
        if source in sha256_by_name:
            raise ValueError(f"widget file named twice: {source}")
        sha256_by_name[source] = digest
    return DockerfilePins(commit=commit_match.group(1), sha256_by_name=sha256_by_name)


def parse_pins(text: str) -> dict[str, BundlePin]:
    manifest = json.loads(text)
    pins: dict[str, BundlePin] = {}
    for bundle in manifest["bundles"]:
        name = bundle["servedPath"].rsplit("/", 1)[1]
        if name in pins:
            raise ValueError(f"pins.json names {name} twice")
        pins[name] = BundlePin(sha384=bundle["sha384"], size=int(bundle["bytes"]))
    return pins


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha384_sri(data: bytes) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode("ascii")


def check(dockerfile_text: str, pins_text: str, fetch_bytes: Callable[[str, str], bytes]) -> list[str]:
    """Return every drift found; an empty list means the edge and the pins agree.

    fetch_bytes(commit, name) returns the bytes of widgets/dist/<name> at commit.
    """
    dockerfile = parse_dockerfile(dockerfile_text)
    pins = parse_pins(pins_text)
    problems: list[str] = []

    if set(dockerfile.sha256_by_name) != set(pins):
        only_edge = sorted(set(dockerfile.sha256_by_name) - set(pins))
        only_pins = sorted(set(pins) - set(dockerfile.sha256_by_name))
        problems.append(
            f"file list differs: only in edge Dockerfile {only_edge}, only in pins.json {only_pins}"
        )

    for name in sorted(set(dockerfile.sha256_by_name) & set(pins)):
        data = fetch_bytes(dockerfile.commit, name)
        actual256 = sha256_hex(data)
        if actual256 != dockerfile.sha256_by_name[name]:
            problems.append(
                f"{name}: edge Dockerfile sha256 {dockerfile.sha256_by_name[name]} "
                f"is not the sha256 of {dockerfile.commit}'s bytes ({actual256})"
            )
        pin = pins[name]
        actual384 = sha384_sri(data)
        if actual384 != pin.sha384:
            problems.append(
                f"{name}: pins.json sha384 {pin.sha384} is not {dockerfile.commit}'s bytes ({actual384})"
            )
        if len(data) != pin.size:
            problems.append(
                f"{name}: pins.json bytes {pin.size} is not {dockerfile.commit}'s size ({len(data)})"
            )
    return problems


def fetch_from_github(commit: str, name: str) -> bytes:
    url = f"{RAW_BASE}/{commit}/widgets/dist/{name}"
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https host
        return response.read()


def fetch_pins_from_github(commit: str) -> str:
    url = f"{RAW_BASE}/{commit}/widgets/pins.json"
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https host
        return response.read().decode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dockerfile", type=Path, default=DEFAULT_DOCKERFILE)
    args = parser.parse_args(argv)

    dockerfile_text = args.dockerfile.read_text(encoding="utf-8")
    commit = parse_dockerfile(dockerfile_text).commit
    pins_text = fetch_pins_from_github(commit)
    problems = check(dockerfile_text, pins_text, lambda _commit, name: fetch_from_github(commit, name))
    if problems:
        print(f"FAILED: edge widget files drift from ghost-platform {commit} pins:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"OK: the edge's seven widget files match ghost-platform {commit} pins")
    return 0


if __name__ == "__main__":
    sys.exit(main())
