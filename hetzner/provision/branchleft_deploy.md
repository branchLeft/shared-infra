# branchleft_deploy.py

Narrative moved out of `branchleft_deploy.py` under the CMT-3 gate (comment
blocks of 11 lines or more). Each section is cited from a one-line pointer
in the code, by its heading.

## Module overview

Installed as /usr/local/sbin/branchleft-deploy and reachable from CI as the
deploy account's single sudo-permitted command. It is the whole of that
account's privilege, so it validates its own arguments rather than relying on
a sudoers pattern to do it -- a wildcard in a sudoers command matches spaces,
which makes any pattern-based restriction argument injection waiting to
happen.

Three rules it exists to enforce:

- **Only digest-pinned references.** A tag is a mutable pointer, so a stack
  deployed by tag has no answer to "what is running", and a restart months
  later can silently change the image. The refusal is here rather than in CI
  because CI is not the only caller.
- **The image file is not the secrets file.** This writes
  /etc/branchleft/<stack>.image.env and nothing else. Stack secrets live in
  /etc/branchleft/<stack>.env, which no automated path may rewrite; both are
  loaded by the systemd unit.
- **A restarted service has a health signal.** `docker compose up --wait`
  only reports a rollback-worthy failure for a service that declares a
  healthcheck; without one a crash loop is transiently `running`, so a bad
  deploy is not detected below at all. A gap this script does not already
  know about (`KNOWN_UNHEALTHCHECKED_SERVICES`) refuses the deploy rather
  than restart into a rollback that cannot fire; a known one only warns.

On a failed restart, the previous digest is restored and the unit restarted
again only when the pinned image's own container did not come up -- so a
deploy whose image genuinely will not run leaves the host on the last image
that worked rather than on a file describing one that does not. A failed
restart whose pinned image _did_ come up (some other service's healthcheck
is what tripped `--wait`) leaves the pin alone and fails loudly instead:
rewriting it would restart the whole stack onto an older image over a
failure the image was not responsible for, which is not reversible for a
stack whose data does not survive that cleanly. The health-signal refusal
above is a separate, earlier exception: it fires before any of this, so the
stack is left running whatever it already was.

Two calling conventions, and the difference between them is which principal
chooses the stack:

    branchleft-deploy <stack> <image@sha256:...>

The unscoped form. The caller names any stack on the host, so possession of
a key that can reach it is authority over every stack on that host. It is
what the platform's own repositories use.

    branchleft-deploy --slot <stack>            # image read from stdin

The scoped form. The stack name is not an argument the caller supplies: it
is fixed in the `command=` of the authorized_keys entry the presented key
authenticated against, which only root can write
(`provision_deploy_slot.py`). The caller supplies the image and nothing
else, so a key issued for one stack cannot address another, and there is no
name for this script to cross-check because there is no name from the
caller to distrust.

The image arrives on stdin rather than in SSH_ORIGINAL_COMMAND because a
forced command discards the client's argv, leaving those two as the only
channels. Carrying it in the environment would need sudo's env_reset opened
for that variable, which means editing the sudoers grant on every live host
in order to add a control; stdin needs no change to any privileged file,
and does not leave a caller-controlled string in a root process's
environment where a later reader could find it.

## DEPLOY_LOCK_TIMEOUT

Bounded against what the lock actually wraps, not a round number: the
guarded sequence runs `systemctl restart` on a `Type=oneshot` unit whose
`TimeoutStartSec=600` (branchleft-compose@.service) makes that single call
block for up to ten minutes on a legitimate slow pull-plus-health-wait, and
a failed restart's rollback path runs a _second_ such restart under the
same lock acquisition -- so a single ordinary (non-buggy) deploy that fails
once and rolls back can legitimately hold this lock for close to 2x600s.
1260s is that worst case (1200s) plus a margin for the discriminator
`docker ps` call and the `logger` call that sit between the two restarts.
Anything shorter would report a slow-but-healthy holder as if it had hung,
which is the false-positive this timeout exists to avoid, not to produce.

## stack_deploy_lock

Scoped per (host, stack) rather than per host or globally: `config_dir` is
already host-local (`/etc/branchleft` on that machine alone), and the lock
file lives inside it named for this stack, so two deploys to _different_
stacks on the same host never contend -- the routine case on the edge
host, where per-tenant image bumps are frequent and unrelated to each
other. A global lock would serialise those for no reason; a lock scoped
any wider than one stack would fix nothing the issue actually reported,
which was one stack's own pin being interleaved.

`flock(2)` is the primitive, not a PID file or a marker this code writes
and checks: the lock lives in the kernel against the open file
description, not in the file's bytes, so it is released the moment every
fd referencing it closes -- on a clean exit, an uncaught exception, or a
signal including SIGKILL, with no cleanup code of this process's own
needing to run for that to happen. It is also not persisted across a
reboot: the lock file itself (empty, just a namespace to flock against)
can survive one, but the lock state is in-kernel and gone with it, so a
host that rebooted mid-deploy comes back with no lock held by anyone --
never a wedged one waiting to be cleared by hand.

Held-lock behaviour is a bounded wait, not an immediate failure or an
indefinite block: polls for up to `timeout` seconds (default
`DEPLOY_LOCK_TIMEOUT`, sized against the restart unit's own
`TimeoutStartSec` -- see that constant's comment) using non-blocking
`flock` attempts rather than a single blocking call, so the caller sees
the reason precisely instead of the wait itself, and can still be given a
deterministic clock and sleep for testing. An ordinary overlap (two
deploys landing moments apart, or one deploy's own legitimate slow pull
and health-wait) quietly clears within that window; the operator only
sees a message at all once contention has outlasted the whole of it --
which the message below does not read as evidence of a hang, because at
a timeout sized for the slowest legitimate case, an alive-but-slow holder
is at least as likely as a genuinely stuck one.

## strip_yaml_comments

Trailing comments are cut as well as whole lines: `image: foo@sha256:...

# was ${IMAGE}` otherwise reads as a live pin reference while the service

below it runs a hardcoded digest, which is exactly the state being guarded
against.

Quoting is not tracked. The only question asked of the result is whether an
IMAGE reference is live configuration or commentary, and a `#` inside a
quoted scalar ahead of one would be pathological in a Compose file.

## ComposeParseError

The parser below is a regex over indentation, not a YAML parse, so a shape
it does not recognise -- a YAML anchor on the service header, an inline
mapping, a different nesting depth -- looks identical to "this service has
no healthcheck key yet". Raising rather than skipping keeps that ambiguity
from being read as a clean bill of health; `deploy()` below treats it as
"could not determine" rather than "found a gap", which is the only choice
that does not risk refusing a deploy the Compose file itself would start
without any trouble.

## healthcheck_states

Regex rather than a YAML parse to keep this module stdlib-only, matching how
the image-pin half above reads the same files. Module-level, like
`resolves_image_from_env`, so the repository-wide contract test for the
stacks this repository commits and the deploy-time check below for whatever
stack is about to be restarted -- committed here or not -- cannot drift into
disagreeing about what a health signal is.

Shapes it cannot classify raise `ComposeParseError`. The one gap it cannot
raise on is a top-level key it fails to recognise at all, which would end
the `services:` section early and leave the rest of the file unread.

## health_signal_gaps

`refused` is empty exactly when the deploy should proceed with no gap this
script does not already know about; anything in it is new since the last
review of `KNOWN_UNHEALTHCHECKED_SERVICES` and stops the deploy. `warned`
lists the accepted gaps so a deploy that proceeds still says so, loudly,
every time.

Propagates `ComposeParseError` rather than swallowing it: `deploy()` below
is the one that decides a shape this cannot read is reported as "could not
determine" rather than as a gap.

## pinned_image_is_up

This is the discriminator a rollback decision needs and the restart's exit
code alone cannot give: `systemctl restart` reports one bit for the whole
stack, so a `docker compose up -d --wait` that times out on one service's
healthcheck looks identical to one where the pinned image itself never
started. Filtering `docker ps` by the compose project label and the exact
image reference finds the specific container this pin is responsible for
without needing to parse the compose file for which service name owns
it -- the same reference this script already validated and wrote is what
Compose reports back verbatim as that container's image.

`--all` is required, not cosmetic: a container whose image never came up
at all -- the case that should still trigger a rollback -- exited before
this runs and would otherwise not appear, reading as "no evidence against
the image" instead of the evidence it actually is.

Returns `None`, not `False`, when the check itself could not be run --
`docker` missing, the daemon unreachable, an unexpected filter error.
Callers must not treat the two the same: `False` is positive evidence the
image is at fault, grounds to roll back a pin nothing else can safely
undo; `None` is no evidence at all, and guessing "at fault" from an
absence of information is exactly the conflation this function exists to
remove.

## deploy() rollback decision

"The restart failed" and "the new image is why" are not the same fact:
`docker compose up -d --wait` fails the whole restart if any service's
healthcheck does not pass in time, including one that has nothing to do
with the image this call pinned. Rewriting the pin back to `previous`
restarts every container in the stack onto an older image, which is not
reversible for one whose data survives no such restart cleanly -- a
database that already upgraded its on-disk format under the new image
cannot be talked back down. So a rollback only happens on positive
evidence the pinned image itself is the problem; anything else fails
loudly with the pin left exactly as this call wrote it, for an operator
to resolve deliberately rather than have it guessed at.

## LOCK_TIMEOUT_ENV_VAR

Not a new argv flag: the two calling conventions above are validated by
exact argv length precisely so the sudoers grant can name this binary with
no wildcard (see the module docstring) -- adding a `--lock-timeout` flag
would widen that shape for every caller, including the CI deploy account,
for a knob only an operator diagnosing contention needs. An environment
variable read here instead reaches a direct invocation (an operator running
this script by hand, as the RUNBOOK does) with zero change to argv parsing.
It does NOT reach the CI deploy account's sudo invocation: sudo's env_reset
strips it unless the sudoers drop-in adds it to env_keep, which is a
separate, deliberate change to a privileged file, not a side effect of
this one.
