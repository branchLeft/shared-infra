#!/usr/bin/python3 -I
"""Test stand-in for the one `docker` call the deploy wrapper makes before it pins an image.

The wrapper renders the stack's Compose model with `docker compose config --format json`
and holds every image in it to the attestation rule. The test host has no Docker, so this
prints the same model: the stack's `compose.yml` in the current directory, as JSON. It reads
no override file because the role writes none. Every other `docker` call fails, as it would
with no daemon, so nothing here pretends a container exists.
"""

import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if argv[1:3] != ["compose", "--profile"] or "config" not in argv or "--no-interpolate" not in argv:
        print("stand-in docker: only `compose config --no-interpolate` is supported", file=sys.stderr)
        return 1
    try:
        import yaml
    except ImportError:
        print("stand-in docker: PyYAML is not installed on the test host", file=sys.stderr)
        return 3
    model = yaml.safe_load(Path("compose.yml").read_text(encoding="utf-8"))
    json.dump(model, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
