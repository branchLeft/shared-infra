# render_shim_env.py: rationale

The narrative for `render_shim_env.py`, kept beside it so the code file stays
within the CMT-3 comment-block limit.

## Why it re-renders idempotently

Re-rendering is idempotent by construction: the same secret in always produces
the same file out. It is safe to repeat. The file is written atomically, so a
crash or disk-full mid-write can never leave a truncated or half-written env
file for docker compose to read.

## What the env holds depends on the image

Each shim image reads its own set of variables. `shim-env-contracts.json`,
beside this file, is the one home of that table. It maps each pinned image
digest to a contract: the secret's label in `SERVICE_CREDENTIALS_PATH` and the
exact env lines, with `{secret}` marking where the secret goes.

The script reads the single digest out of the compose file compose itself reads
(`SHIM_COMPOSE_PATH`) and renders that digest's contract. Today the one listed
digest is the `smtp-delivery` contract, which renders `SMTP_PASS` from
`blog-shim-bulk-submission`. The `drain` contract renders `SHIM_DRAIN_TOKEN`
from `shim-drain-token`, and no digest selects it yet.

A digest the table does not list is refused, with nothing written. The env of an
image nobody described is a guess, and a wrong guess stops the container at
start or runs it unauthenticated.

## Two secrets, two kinds

- An SMTP submission credential (`mint=false`) is created by
  `62-provision-shim-submission-credential.sh` on Stalwart. This script only
  reads it and never writes the credentials file. A missing label refuses and
  says to run 62 first.
- A drain token (`mint=true`) has no remote system to create it on. It is
  generated locally on first use (`secrets.token_urlsafe`, matching
  `rotate_admin_credential.py`'s own generation) and recorded in the same flat
  `label:secret` file. A re-run reuses it rather than minting a new one, which
  would lock out whatever already holds the old one.

## Refusals

- An empty recorded secret is refused for both kinds: a line of `label:` with no
  value. The rendered env would carry a bare `SMTP_PASS=` or
  `SHIM_DRAIN_TOKEN=`, so the image would start with a blank credential. This is
  the same refusal `mx1_stack_envfile.py` makes. It happens before anything is
  written, and the env file already on disk is left as it was.
- A malformed credentials line (no `:`) fails loudly, through the same error path
  as every other provisioning script.

## Secrets never printed

The script never prints a secret, or any string containing it, to stdout or
stderr. Its only writes are the mode-600 env file and, for a drain token, the
mode-600 credentials file. Error messages name a digest, a file or a label, never
a value.
