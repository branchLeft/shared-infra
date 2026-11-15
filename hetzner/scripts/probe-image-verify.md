# probe-image-verify

Host proof that the deploy wrapper refuses an unsigned image and an image signed by the wrong
workflow. Narrative for `probe-image-verify.py`; the script's docstring points here. It replaces
checks 2 and 3 of "Live checks, in order, after the apply" in `hetzner/provision/branchleft_deploy.md`
with a run that prints a verdict per line and exits non-zero on any failure.

## Usage

Run as root on a wrapper host (`app1`, `ops1`, and `app-t1` once it is enrolled), with the host's own
Python and no checkout:

    sudo /usr/bin/python3 -I probe-image-verify.py --accepted-image ghcr.io/branchleft/ghost-tenant@sha256:DIGEST

`DIGEST` is a published, attested image of a name in the wrapper's register (`ATTESTED_IMAGES`).
The probe is read-only: it deploys nothing, writes no pin and starts no container.

## What each line proves

The probe imports the installed `/usr/local/sbin/branchleft-deploy` and calls its own
`verify_attestation`, so it exercises the code the host runs, with the wrapper's own verifier
environment. No constant is copied.

- `real-image-accepted`: the control. The given image verifies. If this fails, nothing else is run,
  because a refusal could then be any host fault (verifier missing, no network, credential asked for).
- `unsigned-image-refused`: the same registered name at a digest nobody published. The verifier reads
  the attestation from the registry by digest, so this is what an unsigned or locally built image
  looks like to it. It passes only on the wrapper's own refusal ("is not attested by"); a refusal for
  a missing verifier or a credential request is a FAIL.
- `wrong-identity-refused`: the real digest asked of the verifier with the other registered workflow
  as signer. A good attestation from the wrong identity must be refused.

Exit 0 means all three passed. Exit 1 means a check failed, 2 means not run as root.

## Limits

It proves the verifier and the wrapper's refusal on that host. It does not run `branchleft-deploy`
for a stack, so it does not show a pin file left unchanged; the wrapper's tests do that.
