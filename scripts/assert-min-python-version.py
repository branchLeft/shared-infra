#!/usr/bin/env python3
"""Refuse to run a Python test suite under an interpreter too old to import it.

Narrative, usage notes and rationale: see `assert-min-python-version.md` next to this file.
"""

from __future__ import annotations

import argparse
import sys


def parse_min_version(spec: str) -> tuple[int, int]:
    """Parse 'MAJOR.MINOR' into a (major, minor) int tuple.

    Raises ValueError on anything else -- including a patch component, which
    this check never needs: nothing here compares below minor granularity.
    """
    parts = spec.split(".")
    if len(parts) != 2:
        raise ValueError(f"expected 'MAJOR.MINOR', got {spec!r}")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise ValueError(f"expected 'MAJOR.MINOR', got {spec!r}") from exc
    return (major, minor)


def check(
    min_version: tuple[int, int],
    actual: tuple[int, int, int],
    suite: str | None,
    executable: str,
) -> str | None:
    """Return an explanatory error message if actual < min_version, else None."""
    if actual[:2] >= min_version:
        return None
    where = f" for {suite}" if suite else ""
    actual_str = ".".join(str(part) for part in actual)
    floor_str = ".".join(str(part) for part in min_version)
    return (
        f"assert-min-python-version: interpreter too old{where}: "
        f"this is Python {actual_str} ({executable}), but this suite needs "
        f">= {floor_str}.\n"
        "unittest discover does not refuse to run under an old interpreter --\n"
        "it imports every module, turns the one that cannot parse into a\n"
        "single synthetic failing test, and keeps going, so the reported\n"
        "count is smaller than the real suite and reads like an unrelated\n"
        "pre-existing failure rather than a wrong interpreter.\n"
        f"Re-run with a newer interpreter on PATH (`python3 --version` must "
        f"show >= {floor_str})."
    )


def _self_test() -> None:
    assert parse_min_version("3.10") == (3, 10)
    for bad in ("3", "3.10.1", "x.y", "", "3."):
        try:
            parse_min_version(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {bad!r}")

    # Healthy case: at or above the floor never produces a message.
    assert check((3, 10), (3, 10, 0), None, "/usr/bin/python3") is None
    assert check((3, 10), (3, 14, 6), "hetzner/provision", "/opt/homebrew/bin/python3") is None

    # Unhealthy case: below the floor names the suite, the actual version
    # and the executable.
    msg = check((3, 10), (3, 9, 6), "hetzner/provision", "/usr/bin/python3")
    assert msg is not None
    assert "3.9.6" in msg
    assert "3.10" in msg
    assert "hetzner/provision" in msg
    assert "/usr/bin/python3" in msg

    # No suite label still produces a usable message.
    msg_no_suite = check((3, 10), (3, 9, 6), None, "/usr/bin/python3")
    assert msg_no_suite is not None
    assert " for " not in msg_no_suite.split("\n", 1)[0]

    print("assert-min-python-version: self-test OK")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "min_version", nargs="?", help="version floor as MAJOR.MINOR, e.g. 3.10"
    )
    parser.add_argument(
        "--suite", default=None, help="suite label to name in the failure message"
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        _self_test()
        return 0

    if not args.min_version:
        parser.error("min_version is required unless --self-test is given")
        return 2  # pragma: no cover - argparse exits the process above

    try:
        min_version = parse_min_version(args.min_version)
    except ValueError as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - argparse exits the process above

    actual = sys.version_info[:3]
    message = check(min_version, actual, args.suite, sys.executable)
    if message is not None:
        print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
