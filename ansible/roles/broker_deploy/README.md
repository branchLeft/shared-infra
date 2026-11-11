# broker_deploy

This role installs the demo host's broker on a host and runs it, in place of the
broker runbook's hand install: the pinned Node runtime, the broker account, the state
directories, one pinned release of the broker's bundle with the current link pointing at
it, the public half of the request-signing key, the environment file and the systemd
unit. It enables and starts the unit, restarts it when what it runs changed, and waits for
the broker's status answer.

The release is the one the broker's release workflow builds in CI and signs with a
build attestation. The role carries that release's tarball, held to a sha256 pinned in
reviewed code, and fetches nothing: see "How the release arrives".

It is built from the `monitoring_stack` role and the patterns under `ansible/patterns/`.

## What it changes on a host

| Path                                              | Owner       | Mode                  | Source                                                                       |
| ------------------------------------------------- | ----------- | --------------------- | ---------------------------------------------------------------------------- |
| `/opt/branchleft/broker/node/` (the Node runtime) | root        | 0755                  | Node tarball, checked against its published sha256                           |
| `broker` account                                  | system      | no login shell        | none                                                                         |
| `/etc/branchleft/`                                | root        | 0755                  | none                                                                         |
| `/var/lib/branchleft/`                            | root        | 0755                  | none                                                                         |
| `/var/lib/branchleft/broker-slots/`               | broker      | 0755                  | none                                                                         |
| `/var/lib/branchleft/broker-slots/admin-keys/`    | broker      | 0700                  | none                                                                         |
| `/opt/branchleft/broker/releases/<version>/`      | root        | dirs 0755, files 0644 | the pinned release tarball, `broker_deploy_release_dir`                      |
| `/opt/branchleft/broker/current` (link)           | root        | link                  | the release directory                                                        |
| `/etc/branchleft/broker-verify-key.bin`           | root:broker | 0640                  | `broker_deploy_verify_key_src`                                               |
| `/etc/branchleft/broker.env`                      | root        | 0600                  | `templates/broker.env.j2`, the shipped template with the slots-file line set |
| `/etc/sudoers.d/branchleft-slot`                  | root        | 0440                  | `templates/branchleft-slot.sudoers.j2`, one literal line per invocation      |
| `/etc/systemd/system/branchleft-broker.service`   | root        | 0644                  | `files/branchleft-broker.service`                                            |

After the role the unit is loaded, enabled and active, and the broker answers
`GET /status/0` on the loopback address.

## How the release arrives

The broker's release workflow packs the bundle into a deterministic tarball
`broker-bundle-VERSION.tar.gz`, attests it, and publishes it as a release. The demo host
reaches no network place but its package mirrors, and its commit arrives signed, so the
role takes the tarball from its own `files/releases/` directory, in the commit, and not
from the release page.

Two controls stand between the tarball and the host. Before the role writes anything,
`tasks/_release_pin.yml` hashes the file where the role runs and refuses it unless it is a
plain file whose sha256 equals the pin for its version in `broker_deploy_release_pins`.
The pin is reviewed code, so a release is chosen by a reviewed change and not by a tag. And
a tarball is added to `files/releases/` only after the release's attestation has been
verified against the broker's release workflow, as the broker's runbook describes; the
role does not verify an attestation, and a pin proves the bytes did not change since it was
chosen, not that CI built them.

A version is unpacked into its own directory under `releases/` and the `current` link is
swapped to it. A directory that already holds `broker.mjs` is not unpacked again, so a
release is never replaced and a damaged one is not repaired in place. A new version is a
new directory, and the old one stays for a rollback by pinning the old version.

## Starting and restarting

The role enables the unit and starts it. It restarts the broker, once, when the unpacked
release, the current link, the verify key, the environment file or the unit changed in the
same run (`broker_deploy_inputs_changed`, set in `tasks/main.yml` and read in
`tasks/_run.yml`). A run that changes none of them leaves the process alone. A broker that
is stopped or failed is started by the enable-and-start task on the next run. Last, the
role asks `GET http://127.0.0.1:8090/status/0` until it answers 200 with slot `0`, and fails
the run when it does not, so a unit that starts and dies is not reported as converged.

Check mode names the start or restart in a plan with a task that runs `true` and reports
changed. It skips three things, each for a stated reason: the unpack (the module needs its
destination to exist), the start of a unit that is not on the host yet (the module would
fail to find it), and the status request (a plan starts nothing).

## The sudoers boundary

The broker account may run the slot wrapper as root for a fixed list of
invocations and nothing else: for each slot in `broker_deploy_slot_names`, a
reset, and a start, a stop and an email-batches check for each of the colours
`a` and `b`; and one load of `image.tar` in `broker_deploy_image_stage_dir`.
Every line is a literal command, because a wildcard in a sudoers command matches
spaces and would let an extra argument reach the wrapper as root.

The file is written to a temporary file, checked with `visudo -csf`, and only
then moved over the old one, so a grant visudo refuses never replaces a good one.
Check mode skips that check (the module runs it only on a real write), so a plan
shows the file as changed and a refusal shows at the live apply.

The role holds the slot table twice: here, as `broker_deploy_slot_names`, and in
the wrapper's own generator on the host. Nothing in this repository compares
them, so changing the number of slots means changing both.

## Inputs

The one input with no default must be given:

- `broker_deploy_verify_key_src`: a path on the controller to the 32-byte public
  key.

The release is `broker_deploy_release_version` (default the pinned `0.1.0`), its digest is
in `broker_deploy_release_pins`, and the tarballs are in `broker_deploy_release_dir`.

[`meta/argument_specs.yml`](meta/argument_specs.yml) documents all of them. None
of them is a secret. The private half of the key never reaches the role.

## Requirements on the host

- `xz` (the Node tarball is unpacked with it).
- systemd, to load the unit.
- `sudo`, which provides `visudo`, to check the grant.

## Steps the role does not take

These stay with an owner, as the runbook already says:

- Cutting a release: that is the broker's release workflow, on a signed tag.
- Adding a release tarball to `files/releases/` and its pin, after the attestation was
  verified. A pin for a version whose tarball is not in the directory stops the role.
- Making the request-signing key pair, and saving the private half in the
  owner's password manager.
- Installing the slot wrapper program itself, which the sudoers grant names.
  The grant is installed here; the wrapper comes from the host build.

## Tests

The Molecule scenario in `molecule/default` runs the role in a systemd container
against a stand-in release tarball, packed from `molecule/default/files/bundle`, and a
zero-filled 32-byte key. Neither is a broker artefact: the stand-in entry point only
answers the status request. A test-only drop-in (`prepare.yml`) lifts the unit's sandbox,
which an unprivileged container cannot provide, so the sandboxed start is not proven
here. `verify.yml` reads the result back, and compares the unit and the verify key with
their sources. It checks the unpacked release's owner and modes, that the unit is
enabled and active, that the broker answers its status request, and that the start step
leaves the process alone when nothing changed and replaces it when the release changed. It checks the
environment file's owner, mode, slots-file line and that `LISTEN_HOST` is unset,
but not every line of it.

The unit tests in `tests/unit` run the pin check and the release tasks with
`ansible-playbook` on the machine that runs them, in a scratch directory with every path
moved into it: a tarball that is not the pinned one, is missing, is a link, or has a
version or a pin of the wrong shape is refused before anything is written, a plan unpacks
nothing, an apply unpacks and links once, and the next run and the next plan change
nothing. The unpack tests need GNU tar, which the unarchive module requires, and skip on a
machine that has another tar (macOS); the shards run on Linux, where none is skipped. A
contract test holds the pins' shape, the stand-in tarball to its pin and its source, the
readiness port to the environment file's, and the pin check ahead of any write.

It checks the sudoers grant: root-owned 0440, accepted by `visudo -csf`, exactly
the 50 literal invocation lines of the default slot table, and listed by
`sudo -l` for the broker account with no unrestricted grant. It also runs the
role's sudoers install with a line that is not sudoers syntax and expects the
install to stop at visudo's refusal and leave the good grant untouched.

The admin keys directory is the broker's to replace, because the broker owns the
slots directory above it. The role reads it without following a link and refuses a
link or a non-directory there (`tasks/_admin_keys_dir.yml`), in a plan as well as an
apply, and the file task does not follow a link either. A file task that followed
one would change the owner and mode of its target, as root: a link to
`/etc/sudoers.d` would become the broker's, mode 0700. `verify.yml` runs that step
alone, first on the real directory, which it must accept, then on a link to a root
directory of mode 0711, which it must refuse with the role's own message and leave
as it found it, and then on a regular file in the directory's place, which it must
refuse with the same message and leave as it found it. The file is the half of the
check that the link does not reach: the file module refuses a file too, but with
its own words ("already exists as a file"), and the case matches the role's.

The Node unpack is skipped in check mode: `unarchive` needs its destination to
exist even then, and on a host the role has not touched the directory and the
download are only reported, not made.

## Known limits

- The Node runtime is still downloaded from nodejs.org, so a host whose egress allows
  the package mirrors only cannot run this role until the runtime has another source.
- The verify key has no source in a pushed commit yet: `broker_deploy_verify_key_src` is
  a path the caller supplies.
- The attestation is not verified by the role, only the pinned digest (see "How the
  release arrives").
- The sandboxed start of the unit is proven by the broker's own boot test, not by this
  role's container test.
