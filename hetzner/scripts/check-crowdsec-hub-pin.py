#!/usr/bin/env python3
"""Detect when the pinned CrowdSec image is no longer upstream's newest release.

Usage:
    check-crowdsec-hub-pin.py
    check-crowdsec-hub-pin.py --pinned-version v1.7.7

`hetzner/edge/stack/crowdsec/config.yaml.local` pins `cscli.hub_branch:
master` so a container start never depends on `version.crowdsec.net` being
reachable. Upstream's own `chooseBranch` only returns `master` for an
unpinned agent while the running version is upstream's newest release; once
a newer release ships, the unpinned choice becomes the version branch and
our pin keeps saying `master`, which then serves hub content authored for a
newer agent to this one. Nothing in this repository changes when that
happens -- the trigger is an upstream release -- so this is a scheduled,
independent check rather than a gate on any pull request: it must be able to
fail on its own without blocking anyone's merge, and a pull request here
must never depend on this endpoint being reachable.

This mirrors `chooseBranch`'s own three-way compare, not an approximation of
it: the pin is stale exactly when an unpinned cscli at the pinned version
would no longer choose `master`.

Exit status:
    0  the pin is still correct (pinned version is upstream's newest, or
       ahead of it -- a pre-release image compared against a stable "latest")
    1  the pin is stale: upstream has shipped something newer than the
       pinned image, so the master branch is now built for a newer agent
    2  the check itself could not run: the image pin could not be found or
       parsed, or upstream's version endpoint could not be read -- kept
       distinct from 1 so a failed run's log says which one happened
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request

COMPOSE_PATH = (
    pathlib.Path(__file__).resolve().parent.parent / "edge" / "stack" / "compose.yml"
)
LATEST_URL = "https://version.crowdsec.net/latest"

_IMAGE_PATTERN = re.compile(
    r"image:\s*docker\.io/crowdsecurity/crowdsec:(v[0-9][^\s@]*)@"
)


class CheckError(Exception):
    """The check could not be completed -- distinct from a positive stale finding."""


def pinned_version(compose_text: str) -> str:
    """The crowdsec image tag pinned in a compose.yml's text.

    Raises rather than returning a fallback: a pin this cannot find -- or
    finds more than one distinct value for -- is a reason to stop, not a
    reason to report "not stale" about nothing. Comment lines are skipped
    before matching, so a commented-out previous pin left above the live
    line can never silently win an unanchored search.
    """
    matches = {
        found.group(1)
        for line in compose_text.splitlines()
        if not line.strip().startswith("#")
        for found in [_IMAGE_PATTERN.search(line)]
        if found
    }
    if not matches:
        raise CheckError(
            "no crowdsec image pin found matching "
            f"{_IMAGE_PATTERN.pattern!r} in the compose file"
        )
    if len(matches) > 1:
        raise CheckError(
            f"more than one crowdsec image pin found: {sorted(matches)} -- "
            "ambiguous, refusing to guess which one is live"
        )
    return next(iter(matches))


def _parse_release(version: str) -> tuple[tuple[int, ...], str]:
    """(numeric release tuple, prerelease suffix) from a 'vX.Y.Z[-rcN]' tag."""
    body = version[1:] if version.startswith("v") else version
    release, _, prerelease = body.partition("-")
    try:
        parts = tuple(int(part) for part in release.split("."))
    except ValueError as exc:
        raise CheckError(f"cannot parse version {version!r} as semver") from exc
    if not parts:
        raise CheckError(f"cannot parse version {version!r} as semver")
    return parts, prerelease


_PRERELEASE_RUN = re.compile(r"\d+|\D+")


def _prerelease_key(prerelease: str) -> tuple:
    """A natural-sort key for a prerelease suffix: alternating digit and
    non-digit runs, digit runs compared by value rather than by byte.

    Without this, 'rc10' sorts before 'rc2' the same way 'v1.7.10' would sort
    before 'v1.7.8' as a plain string -- the exact trap the release-triple
    comparison below exists to avoid, left unfixed for the suffix.
    """
    return tuple(
        (0, int(run)) if run.isdigit() else (1, run)
        for run in _PRERELEASE_RUN.findall(prerelease)
    )


def compare(a: str, b: str) -> int:
    """-1/0/1 for the release triple exactly as `chooseBranch`'s own
    `semver.Compare` would: numeric release components, and a release
    outranking a prerelease of the same X.Y.Z. Prerelease-vs-prerelease
    ordering (an 'rc2' against an 'rc10') is this script's own natural,
    digit-aware comparison -- not a verified match for
    `golang.org/x/mod/semver`'s own algorithm, which this script does not
    read. Neither CrowdSec's tag scheme nor this repository's pinned image
    exercises that path today: compose.yml only ever pins a GA release, and
    an upstream release candidate never becomes `version.crowdsec.net/latest`
    while it is still a candidate.

    Comparing the numeric release components as ints, not the tag as a
    string, is load-bearing: 'v1.7.10' sorts before 'v1.7.8' as a string but
    is the newer release. A release also outranks a prerelease of the same
    X.Y.Z, matching semver precedence -- so a pinned pre-release build never
    reads as "behind" the stable tag it precedes.
    """
    a_release, a_pre = _parse_release(a)
    b_release, b_pre = _parse_release(b)
    if a_release != b_release:
        return -1 if a_release < b_release else 1
    if a_pre == b_pre:
        return 0
    if a_pre == "":
        return 1
    if b_pre == "":
        return -1
    a_key, b_key = _prerelease_key(a_pre), _prerelease_key(b_pre)
    return -1 if a_key < b_key else 1


def is_pin_stale(pinned: str, latest: str) -> bool:
    """True exactly when an unpinned cscli at `pinned` would no longer choose
    `master` -- i.e. upstream's `latest` is newer than the pinned version."""
    return compare(pinned, latest) < 0


def _parse_latest_payload(raw: bytes) -> str:
    """The release name from `version.crowdsec.net/latest`'s JSON body.

    e.g. `{"name":"v1.7.8", "tag_name":"v1.7.8", "published_at":"..."}`.
    Cross-checked against `tag_name` when the response carries one: the two
    have never been observed to differ, and a response where they do reads
    as a schema change rather than a release, so it is treated as
    unparsable rather than silently trusted on `name` alone.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CheckError(f"latest-release endpoint did not return JSON: {exc}") from exc
    name = data.get("name") if isinstance(data, dict) else None
    if not isinstance(name, str) or not name:
        raise CheckError(f"latest-release response has no usable 'name' field: {data!r}")
    tag_name = data.get("tag_name") if isinstance(data, dict) else None
    if isinstance(tag_name, str) and tag_name and tag_name != name:
        raise CheckError(
            f"latest-release response disagrees with itself: name={name!r} "
            f"tag_name={tag_name!r}"
        )
    return name


def _fetch_latest_release(url: str = LATEST_URL) -> str:
    """Thin, mechanical wrapper around urllib -- the parsing this depends on
    is `_parse_latest_payload`, tested on its own without a network call.

    The endpoint 403s urllib's default `Python-urllib/x.y` User-Agent
    outright (verified live), so a request without one fails every time,
    indistinguishably from an outage -- any other User-Agent string clears it.
    """
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "branchleft-shared-infra-crowdsec-hub-pin-check",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise CheckError(f"could not reach {url}: {exc}") from exc
    return _parse_latest_payload(raw)


def report(pinned: str, latest: str) -> int:
    """Print the finding and return the exit status for it. Pure given its
    two version strings, so the message and the exit code are tested
    together rather than the code alone."""
    if is_pin_stale(pinned, latest):
        print(
            "::error::hetzner/edge/stack/compose.yml pins crowdsec "
            f"{pinned}, but upstream's newest release is {latest}. "
            "config.yaml.local's `cscli.hub_branch: master` pin is now "
            "wrong -- an unpinned cscli at this version would no longer "
            "choose master, so the pinned agent is pulling hub content "
            "built for a newer release. Bump the crowdsec image digest in "
            "compose.yml to the new release; that is also what makes the "
            "master pin correct again."
        )
        return 1
    print(
        f"OK: crowdsec {pinned} is still upstream's newest ({latest}); "
        "the master pin holds."
    )
    return 0


def _read_compose_text() -> str:
    """compose.yml's text, with a missing or unreadable file reported the
    same way as any other check failure -- exit 2, not an uncaught
    `OSError` that a caller could mistake for exit 1's positive finding."""
    try:
        return COMPOSE_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise CheckError(f"cannot read {COMPOSE_PATH}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pinned-version",
        help="Check this version instead of reading it from compose.yml.",
    )
    args = parser.parse_args(argv)

    # report() is inside this try, not after it: is_pin_stale() -> compare()
    # -> _parse_release() can itself raise CheckError, on either an
    # --pinned-version override this script did not validate or a
    # latest-release name that _parse_latest_payload accepted as "a
    # non-empty string" without confirming it parses as semver. Either one
    # must land on exit 2, never fall through to exit 1's "the pin is stale"
    # claim about a version nothing has actually understood.
    try:
        pinned = args.pinned_version or pinned_version(_read_compose_text())
        latest = _fetch_latest_release()
        return report(pinned, latest)
    except CheckError as exc:
        print(f"::error::{exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
