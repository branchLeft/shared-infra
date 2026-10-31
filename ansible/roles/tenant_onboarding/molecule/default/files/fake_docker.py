#!/usr/bin/env python3
"""A stand-in for the docker command, for the tenant_onboarding Molecule scenario only.

The tenant volume program calls three subcommands: volume ls (with an optional name
filter), volume create, and volume inspect with a Mountpoint format. This keeps the
volumes in one JSON file and gives each a directory as its mountpoint, so the program's
ownership and mode calls land on real files. It is not a container runtime and runs no
container.
"""

from __future__ import annotations

import json
import os
import re
import sys

STATE = "/var/lib/fake-docker/volumes.json"
MOUNTS = "/var/lib/fake-docker/mounts"


def load() -> dict[str, dict[str, str]]:
    try:
        with open(STATE, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return {}


def save(volumes: dict[str, dict[str, str]]) -> None:
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE, "w", encoding="utf-8") as handle:
        json.dump(volumes, handle, sort_keys=True)


def ls(args: list[str]) -> int:
    pattern = None
    if "--filter" in args:
        value = args[args.index("--filter") + 1]
        if not value.startswith("name="):
            sys.stderr.write(f"fake docker: unsupported filter {value}\n")
            return 1
        pattern = re.compile(value[len("name=") :])
    for name in sorted(load()):
        if pattern is None or pattern.search(name):
            print(name)
    return 0


def create(name: str) -> int:
    volumes = load()
    if name in volumes:
        sys.stderr.write(f"fake docker: volume {name} already exists\n")
        return 1
    mountpoint = os.path.join(MOUNTS, name)
    os.makedirs(mountpoint, mode=0o755, exist_ok=True)
    volumes[name] = {"mountpoint": mountpoint}
    save(volumes)
    print(name)
    return 0


def inspect(name: str, args: list[str]) -> int:
    volumes = load()
    if name not in volumes:
        sys.stderr.write(f"fake docker: no such volume {name}\n")
        return 1
    if args[:1] == ["--format"] and args[1:2] == ["{{json .Mountpoint}}"]:
        print(json.dumps(volumes[name]["mountpoint"]))
        return 0
    sys.stderr.write("fake docker: unsupported inspect format\n")
    return 1


def main(argv: list[str]) -> int:
    if argv[:2] == ["volume", "ls"]:
        return ls(argv[2:])
    if argv[:2] == ["volume", "create"] and len(argv) == 3:
        return create(argv[2])
    if argv[:2] == ["volume", "inspect"] and len(argv) >= 3:
        return inspect(argv[2], argv[3:])
    sys.stderr.write(f"fake docker: unsupported command {' '.join(argv)}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
