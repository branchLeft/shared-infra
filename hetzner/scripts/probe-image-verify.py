#!/usr/bin/python3 -I
"""Host proof that the deploy wrapper refuses an unsigned or wrong-identity image.

Run as root on a wrapper host. Usage, output and what each line proves are in
probe-image-verify.md beside this file. Read-only: it deploys nothing and writes nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from types import ModuleType
from typing import Any

WRAPPER_PATH = "/usr/local/sbin/branchleft-deploy"

# A digest nobody published: the sha256 of a fixed string. An image of a registered name at this
# digest has no attestation anywhere, which is what an unsigned or locally built image looks like
# to the verifier (it reads the attestation from the registry by digest).
UNSIGNED_DIGEST = hashlib.sha256(b"branchleft-probe-image-verify-unsigned").hexdigest()

# The wrapper's own words for "the verifier ran and said no". Its other refusals (verifier missing,
# host asked for a credential) are a host fault, not a refusal of the image, and must not pass.
REFUSAL_MARKER = "is not attested by"
LOGIN_MARKER = "gh auth login"

Run = Callable[..., Any]


@dataclass(frozen=True)
class Result:
    name: str
    passed: bool
    detail: str

    def line(self) -> str:
        return f"{'PASS' if self.passed else 'FAIL'} {self.name}: {self.detail}"


def load_wrapper(path: str) -> ModuleType:
    """Import the installed wrapper by path, so the probe exercises the code the host runs."""
    loader = importlib.machinery.SourceFileLoader("branchleft_deploy_installed", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def canonical(wrapper: ModuleType, image: str) -> tuple[str, str]:
    """The register name and the digest, however the image was spelled."""
    return wrapper.attested_name(image), image.partition("@")[2]


def accepted_check(wrapper: ModuleType, image: str, run: Run) -> Result:
    name = "real-image-accepted"
    try:
        verified = wrapper.verify_attestation(image, run=run)
    except wrapper.DeployError as error:
        return Result(name, False, f"refused: {error}")
    if verified is not True:
        return Result(
            name,
            False,
            "the image is not in the wrapper's register, so it is not verified",
        )
    return Result(name, True, f"{image} verified")


def unsigned_check(wrapper: ModuleType, image: str, run: Run) -> Result:
    name = "unsigned-image-refused"
    unsigned = f"{canonical(wrapper, image)[0]}@sha256:{UNSIGNED_DIGEST}"
    try:
        wrapper.verify_attestation(unsigned, run=run)
    except wrapper.DeployError as error:
        message = str(error)
        if REFUSAL_MARKER in message and LOGIN_MARKER not in message:
            return Result(name, True, f"refused {unsigned}")
        return Result(
            name, False, f"refused for a host fault, not for the image: {message}"
        )
    return Result(name, False, f"ACCEPTED {unsigned}")


def wrong_identity_check(wrapper: ModuleType, image: str, run: Run) -> Result:
    name = "wrong-identity-refused"
    registered, digest = canonical(wrapper, image)
    right = wrapper.ATTESTED_IMAGES.get(registered)
    others = sorted(set(wrapper.ATTESTED_IMAGES.values()) - {right})
    if right is None or not others:
        return Result(
            name, False, "needs a registered image and a second registered signer"
        )
    try:
        result = run(
            [
                wrapper.VERIFIER,
                f"{registered}@{digest}",
                wrapper.ATTESTED_REPO,
                others[0],
                "--bundle-from-oci",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=wrapper.verifier_env(),
            stdin=subprocess.DEVNULL,
        )
    except OSError as error:
        return Result(name, False, f"could not run the verifier: {error}")
    if result.returncode == 0:
        return Result(name, False, f"ACCEPTED {image} as signed by {others[0]}")
    if LOGIN_MARKER in (result.stderr or ""):
        return Result(
            name, False, "refused for a host fault (credential), not for the identity"
        )
    return Result(name, True, f"refused {image} as signed by {others[0]}")


def run_probe(
    wrapper: ModuleType, image: str, run: Run = subprocess.run
) -> list[Result]:
    """The real image must be accepted first: without it a refusal could be any host fault."""
    control = accepted_check(wrapper, image, run)
    if not control.passed:
        return [control]
    return [
        control,
        unsigned_check(wrapper, image, run),
        wrong_identity_check(wrapper, image, run),
    ]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--accepted-image",
        required=True,
        help="a published, attested image, name@sha256:digest",
    )
    parser.add_argument("--wrapper", default=WRAPPER_PATH)
    args = parser.parse_args(argv[1:])
    if os.geteuid() != 0:
        print(
            "FAIL not-root: the verifier's home is root-only, so run this as root",
            file=sys.stderr,
        )
        return 2
    results = run_probe(load_wrapper(args.wrapper), args.accepted_image)
    for result in results:
        print(result.line())
    return 0 if len(results) == 3 and all(r.passed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
