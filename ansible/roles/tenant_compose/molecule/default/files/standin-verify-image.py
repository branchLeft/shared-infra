#!/usr/bin/python3 -I
"""Test stand-in for the host's image verifier, which the deploy wrapper runs before it
writes a pin. It takes the verifier's arguments (registry/name@digest, the repository, the
signing workflow, --bundle-from-oci), records each call, and passes only an image listed in
the file `attested`, as the real verifier passes only an image whose attestation it finds.
"""

import sys
from pathlib import Path

STATE = Path("/var/lib/standin")


def main(argv: list[str]) -> int:
    if len(argv) != 5 or argv[4] != "--bundle-from-oci":
        print("usage: standin-verify-image IMAGE REPO SIGNER --bundle-from-oci", file=sys.stderr)
        return 2
    image, signer = argv[1], argv[3]
    STATE.mkdir(parents=True, exist_ok=True)
    attested = (STATE / "attested").read_text(encoding="utf-8").splitlines()
    verdict = "pass" if image in attested else "fail"
    with (STATE / "verify.log").open("a", encoding="utf-8") as log:
        log.write(f"{image} signer={signer} {verdict}\n")
    if verdict == "fail":
        print(f"stand-in: no attestation found for {image}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
