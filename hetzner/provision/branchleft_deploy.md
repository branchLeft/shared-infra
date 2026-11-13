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

## verify_attestation and ATTESTED_IMAGES

An image this host deploys is checked for its build attestation before the
lock, the pin write or any restart. `ATTESTED_IMAGES` is the register: each
attested image name and the one workflow whose attestation it must carry, both
under `branchLeft/ghost-platform`. The check runs `VERIFIER`, the host copy of
ghost-platform's `scripts/verify-image-attestation.sh`, always with
`--bundle-from-oci`, and any non-zero exit refuses the deploy.

It fails closed. A missing verifier, an unknown digest, an unsigned image and
an image signed by another workflow are all refused, and each refusal leaves
the pin file and the running stack as they were. There is no argument,
environment variable or stack setting that skips it.

An image name outside the register is refused, not passed unverified, unless
`UNATTESTED_STACK_IMAGES` names it for that stack. That table is the reviewed
exemption list: each stack that pins through this wrapper today, with the one
image name it runs and no workflow attests yet (`website`, `publicpress-website`,
`edge`, `db`, `dbt1`). It is keyed by stack as well as by name, so an exemption
does not open the other stacks: a tenant slot key cannot pin the edge image, and
cannot pin `attacker.example/evil@sha256:...`. A registered image deploys on any
stack. Exempt images skip the verifier; adding an entry is a reviewed diff, and
the way to remove one is to register the image in `ATTESTED_IMAGES`. A new stack
or image is refused until one of the two tables names it.

The register is looked up by registry host and path alone (`attested_name`). A
tag or a registry port on the reference is a spelling, not another image: the
host pulls the digest, so `name:tag@sha256:...` and `host:443/name@sha256:...`
are verified exactly as `name@sha256:...` is, and the verifier is given the
register name and the digest.

The rollback restore is not re-verified. It returns to the pin that last ran,
and blocking it could leave the host with nothing running.

The vendored copy is pinned by sha256 in `test_branchleft_deploy.py`. Change
the copy and that constant in one change, and take the bytes only from
ghost-platform's script.

### The verifier runs with no credential

`verify_attestation` runs the verifier with a fixed environment, `verifier_env()`,
and nothing inherited from the host. `PATH` names the pinned gh directory and
then `/usr/bin:/bin`. `HOME`, `GH_CONFIG_DIR` and `XDG_CONFIG_HOME` point at an
empty, root-only directory, so root's own `~/.config/gh` cannot become an
ambient credential. Neither `GH_TOKEN` nor `GITHUB_TOKEN` is passed, whatever
the host holds. `DOCKER_CONFIG` is passed, and names the registry read key's
directory (next section). `test_branchleft_deploy.py` pins the exact dictionary.

The design is fail-closed. The host holds no GitHub API credential; it holds a
registry read key, reached only through `DOCKER_CONFIG`. A registered
image is deployed only when gh verifies its attestation with no API credential.
When gh says it needs a credential, the deploy is refused with "the host verifier needs
GitHub credentials this host does not hold; the deploy is refused". Nothing in
the code falls back to an unverified deploy.

### The registry read key

A private image's attestation is read from the registry, so the host needs a
key the registry accepts. The key is a classic token with only `read:packages`,
owned by a reader account, kept as a docker config in
`/etc/branchleft/registry/docker/config.json` (directory `root:root` 0700, file
`root:root` 0600), with an auth entry for `ghcr.io` and for no other registry.
The owner places it. Nothing in this repository writes, fetches or prints it.

Three things name that one directory, and
`test_the_registry_key_directory_is_one_path_in_wrapper_unit_and_role` holds
them to one path:

- `REGISTRY_DOCKER_CONFIG` in `branchleft_deploy.py`, handed to the verifier as
  `DOCKER_CONFIG` in `verifier_env()`.
- `Environment=DOCKER_CONFIG=...` in `branchleft-compose@.service`, for the pull.
- `deploy_verifier_registry_docker_dir` in the `deploy_verifier` role, which
  only checks the directory and the file (modes, owner, one registry, no
  credential helper) and refuses a wrong one. It is applied on `app1`, `db1`,
  `dbt1`, `edge1` and `ops1`.

An absent directory is anonymous access. The verifier and the pull still work
for a public image, and the role reports the absence without refusing. When the
registry will not serve a registered image (its words: unauthorised, denied,
authentication required), `verify_attestation` refuses before the lock, the
compose read and the pin write, and the message names the registry read key and
its directory. A refusal for any other reason keeps the "is not attested by"
message. gh's login refusal outranks both.

**gh's local token gate, and the placeholder.** gh refuses to start without a
non-empty token (`gh auth login`), even on `--bundle-from-oci`, where it makes no
GitHub API call. Observed on a hosted runner (gh 2.103.3, every token variable
unset, no gh credentials file), in
[ghost-platform run 42427972700](https://github.com/branchLeft/ghost-platform/actions/runs/42427972700)
without a token (gh stopped in about 0.03 s with "verification needs a GitHub
token") and
[run 42428728854](https://github.com/branchLeft/ghost-platform/actions/runs/42428728854)
with `GH_TOKEN` set to the literal `placeholder-not-a-credential`: the real tenant
digest verified, a forged control was refused for its identity, and a `GH_DEBUG=api`
log showed 22 requests, all to `tuf-repo-cdn.sigstore.dev` and `tuf-repo.github.com`,
none to `api.github.com`, and no `Authorization` header. So on this path gh's gate
needs only a non-empty value.

`branchleft-verify-image` therefore sets `GH_TOKEN` to that fixed constant, for its
gh call only, when `--bundle-from-oci` is given and neither `GH_TOKEN` nor
`GITHUB_TOKEN` holds a value. A real token already set is left alone. Without
`--bundle-from-oci` gh needs the API and a real token, so the verifier refuses there
with a message that names the two variables and sets no placeholder. The constant is
not a credential and is never printed, read from a file or read from a credential
store. `verifier_env()` still carries no token, and the placeholder is added inside
the verifier, so the wrapper's pinned environment is unchanged.

The honest limit: this shows gh's local gate is satisfied, not that the host is
authenticated to GitHub's API. Verification is cryptographic, against the Sigstore trust root (TUF)
and the signer identity, digest and `refs/heads/main`, and is not account-based.
**A host credential is still not the fallback**: if the placeholder stops working,
the registered deploys stay refused and the next step is a tokenless sigstore
verifier. gh writes its TUF cache and a device id under the verifier's `HOME`
(`.cache/gh`, `.local/state/gh`) and no `config.yml` or `hosts.yml`, so the role's
credential-file refusal does not trip on a second apply; the directory is empty only
until the first check.

### Installing the verifier and gh

The `deploy_verifier` role installs the verifier from `hetzner/provision/`, and
the gh release named in its `vars/main.yml`, with its tarball digest checked at
download. The role is applied on `edge1`, `app1`, `ops1` and `db1`, before the
first role that runs this wrapper. A host whose wrapper came from the hand-run
`30-install-deploy-tooling.sh` and not from a role has no verifier until the
role runs there. Such a host refuses every registered image and still deploys
unregistered ones.

### Live checks, in order, after the apply

The apply downloads gh from github.com, so each wrapper host must reach GitHub
at apply. The first check gates the rest.

1. `gh --version` on each host shows 2.103.3.
2. `branchleft-verify-image` on `app1`, with the fixed environment and no
   token, accepts `ghcr.io/branchleft/ghost-tenant@sha256:0d8ddc21a9e51237e1d709614973f7b418d9a0c69e0933e4301281ee90481ae4`.
   If it refuses for want of a credential, stop: the placeholder above is not working.
3. The same verifier refuses a locally built, unsigned image of the same name.
4. Repeat 2 and 3 on `ops1`, `edge1` and `db1`.

Until check 2 passes, a tenant deploy that lands is refused, which is the
intended failure.

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
