#!/usr/bin/python3 -I
"""Test stand-in for the volume program the tenant onboarding role installs. It keeps the
same two interfaces the role uses, `--list-claims` and `--uid N SLUG`, and the same
register format (one slug=uid line per claim), and records each call.
"""

import sys
from pathlib import Path

CLAIMS = Path("/etc/branchleft/tenant-uids")
STATE = Path("/var/lib/standin")


def list_claims() -> int:
    for claim in sorted(CLAIMS.iterdir()):
        if claim.name.startswith(".") or not claim.is_file():
            continue
        uid = claim.read_text(encoding="utf-8").rstrip("\n")
        print(f"{claim.name}={uid}")
    return 0


def claim(uid: str, slug: str) -> int:
    with (STATE / "volume.log").open("a", encoding="utf-8") as log:
        log.write(f"{slug} {uid}\n")
    (CLAIMS / slug).write_text(f"{uid}\n", encoding="utf-8")
    return 0


def main(argv: list[str]) -> int:
    CLAIMS.mkdir(parents=True, exist_ok=True)
    STATE.mkdir(parents=True, exist_ok=True)
    if len(argv) >= 2 and argv[1] == "--list-claims":
        return list_claims()
    if len(argv) < 4:
        print("usage: standin-volume-program --list-claims | --uid N SLUG", file=sys.stderr)
        return 2
    return claim(uid=argv[2], slug=argv[3])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
