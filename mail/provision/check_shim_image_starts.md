# check_shim_image_starts.py: rationale

The narrative for `check_shim_image_starts.py`, kept beside it so the code file
stays within the CMT-3 comment-block limit.

## What it proves

The environment file `render_shim_env.py` renders for the image digest pinned in
`shim-compose.yml` is one that image can start with, and the container answers
the compose file's own healthcheck. The renderer once drifted from the image it
was meant to feed: `main` rendered a drain-token
environment while the compose file pinned an image whose config loader requires
`SMTP_HOST`. Nothing noticed, because no test ever started the image.

## How it is bounded

- CI only. It is never run on a host, and it touches no host: no ssh, no
  ansible, no docker against anything but the runner's own daemon.
- `docker run --network none`. Nothing in the container can reach mx1 or any
  SMTP server. The pinned image does not open an SMTP connection at start, so a
  start needs no reachable mail server.
- The credential is the fixed placeholder `PLACEHOLDER-NOT-A-SECRET`, written
  to a temporary credentials file. No real secret is read or written.
- Health is judged by `docker exec` of the healthcheck script taken from
  `shim-compose.yml` (through `shim_healthcheck_script` in
  `test_shim_compose_healthcheck.py`, so there is one copy). That is stricter than
  a published port, and works with no network.
- The data directory is opened to mode 0777, not chowned. The image runs as
  uid 1000 and the GitHub runner is not that user. `63-deploy-mailgun-shim.sh`
  chowns the real directory on the host for the same reason.

## The control

`--expect-smtp-host-missing` runs the same flow and inverts the expectation: the
container must stop, its log must name the missing `SMTP_HOST`, and it must hold
none of `SQLITE_CANTOPEN`, `EACCES` or `EPERM`. A mount or permission failure
therefore cannot pass for the stale-environment failure. Without
`SHIM_RENDERER`, the control environment is the `drain` contract's output, the
very file `main` rendered before the fix. With it, the named program renders the
environment instead (in the normal run it is also the renderer under test,
default `render_shim_env.py`).

Every failure prints a `CONTROL-REASON:` line (`smtp-host-missing`,
`mount-or-permission`, `other`) so a red run shows which fault it was.

## What it cannot show

It runs the pinned image against a placeholder SMTP credential and no network, so
it says nothing about whether Stalwart accepts the real credential, or whether
mail leaves mx1. It also cannot show what is running on mx1 now: that is a
host-observable fact, read on the host by the owner.

## Why it is not `test_*`

`mail-provision-checks` runs `unittest discover -p 'test_*.py'`, which would
either need docker on every run or skip it. This check has its own CI job,
`shim-image-starts`, which is not in `mail-plan`'s `needs`, so a registry outage
blocks no deploy.
