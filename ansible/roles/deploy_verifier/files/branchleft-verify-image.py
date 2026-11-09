#!/usr/bin/python3 -I
"""Verify that an image was attested by the expected workflow of this repo, on refs/heads/main.

Fail closed: exit 0 only when gh verified an attestation for exactly that digest, signer and
ref. This is the Python port of the bash program it replaces, with the same usage, exit codes,
refusals and messages. Usage, identities and rationale: scripts/verify-image-attestation.md.

VERIFY_PLAIN_ERRORS=1 prints refusals as plain text, not ::error:: annotations.

Exit codes: 0 verified; 1 refused, or gh did not verify; 2 usage.
No shell is run: gh is started from an argument list, with the environment built here.
"""

import os
import re
import subprocess
import sys

# gh refuses to start without a non-empty token, even on --bundle-from-oci. This fixed value is
# not a credential; see the gate below.
PLACEHOLDER = "placeholder-not-a-credential"
BUNDLE_FLAG = "--bundle-from-oci"
SOURCE_REF = "refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
# A bound on the gh call. The bash program had none; a verify that never returns refuses the deploy.
GH_TIMEOUT_SECONDS = 300

# The digest is what the attestation is bound to. A tag can move after it is checked, so a
# tag-form reference verifies nothing about what a host pulls. fullmatch, not a line match: a
# value with a newline in it is refused whole.
IMAGE_RE = re.compile(
    r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}"
)
REPO_RE = re.compile(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+")


def main(argv):
    program = argv[0]
    if os.environ.get("VERIFY_PLAIN_ERRORS", "0") == "1":
        err = "error: "
    else:
        err = "::error::"

    args = argv[1:]
    if len(args) not in (3, 4):
        return usage(program)
    image_ref, repo, signer = args[0], args[1], args[2]
    bundle = False
    if len(args) == 4:
        if args[3] != BUNDLE_FLAG:
            print(f"{err}unknown option: {args[3]}", file=sys.stderr)
            return usage(program)
        bundle = True

    if not IMAGE_RE.fullmatch(image_ref):
        print(
            f"{err}refusing '{image_ref}': an image must be named by digest "
            "(registry/name@sha256:<64 hex>), in lower case",
            file=sys.stderr,
        )
        return 1

    if not REPO_RE.fullmatch(repo):
        print(f"{err}refusing '{repo}': expected owner/repo", file=sys.stderr)
        return 1

    # The signer must be a workflow file inside that same repository.
    prefix = f"{repo}/.github/workflows/"
    if not (signer.startswith(prefix) and len(signer) > len(prefix)):
        print(
            f"{err}refusing '{signer}': expected {repo}/.github/workflows/<file>",
            file=sys.stderr,
        )
        return 1

    # The verifier's environment is the caller's, plus the placeholder on the bundle path only,
    # and only when neither GH_TOKEN nor GITHUB_TOKEN holds a value. Without the flag gh calls the
    # API and needs a real token, so that path refuses here instead. The placeholder is never
    # printed. Name and value are held apart: the plan's secret scan reads a name and a value on one
    # line as a credential.
    env = dict(os.environ)
    no_token = not env.get("GH_TOKEN", "") and not env.get("GITHUB_TOKEN", "")
    if bundle:
        if no_token:
            env["GH_TOKEN"] = PLACEHOLDER
    elif no_token:
        print(
            f"{err}refusing: verifying without --bundle-from-oci needs the GitHub API, so "
            "GH_TOKEN or GITHUB_TOKEN must hold a real token and neither is set",
            file=sys.stderr,
        )
        return 1

    command = [
        "gh",
        "attestation",
        "verify",
        f"oci://{image_ref}",
        "--repo",
        repo,
        "--signer-workflow",
        signer,
        "--source-ref",
        SOURCE_REF,
        "--cert-oidc-issuer",
        ISSUER,
        "--deny-self-hosted-runners",
    ]
    if bundle:
        command.append(BUNDLE_FLAG)

    # A gh that cannot be started, or that runs past the timeout, is a refusal like any other.
    try:
        completed = subprocess.run(
            command, env=env, check=False, timeout=GH_TIMEOUT_SECONDS
        )
        verified = completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        verified = False
    if not verified:
        print(
            f"{err}no valid attestation for {image_ref} from {signer} on refs/heads/main",
            file=sys.stderr,
        )
        return 1

    print(f"verified: {image_ref} was attested by {signer} on refs/heads/main")
    return 0


def usage(program):
    print(
        f"usage: {program} <registry/name@sha256:64hex> <owner/repo> "
        "<owner/repo/.github/workflows/file.yml> [--bundle-from-oci]",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
