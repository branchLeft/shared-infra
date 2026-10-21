# broker_deploy

This role installs the demo host's broker on a host, the way the broker runbook
does by hand: the pinned Node runtime, the broker account, the state
directories, one release of the built bundle with the current link pointing at
it, the public half of the request-signing key, the environment file and the
systemd unit. It installs the unit without starting it.

It is the first of the broker's roles. It is built from the `monitoring_stack`
role and the patterns under `ansible/patterns/`.

## What it changes on a host

| Path                                              | Owner       | Mode                  | Source                                                                       |
| ------------------------------------------------- | ----------- | --------------------- | ---------------------------------------------------------------------------- |
| `/opt/branchleft/broker/node/` (the Node runtime) | root        | 0755                  | Node tarball, checked against its published sha256                           |
| `broker` account                                  | system      | no login shell        | none                                                                         |
| `/etc/branchleft/`                                | root        | 0755                  | none                                                                         |
| `/var/lib/branchleft/`                            | root        | 0755                  | none                                                                         |
| `/var/lib/branchleft/broker-slots/`               | broker      | 0755                  | none                                                                         |
| `/var/lib/branchleft/broker-slots/admin-keys/`    | broker      | 0700                  | none                                                                         |
| `/opt/branchleft/broker/releases/<release>/`      | root        | dirs 0755, files 0644 | `broker_deploy_bundle_src`                                                   |
| `/opt/branchleft/broker/current` (link)           | root        | link                  | the release directory                                                        |
| `/etc/branchleft/broker-verify-key.bin`           | root:broker | 0640                  | `broker_deploy_verify_key_src`                                               |
| `/etc/branchleft/broker.env`                      | root        | 0600                  | `templates/broker.env.j2`, the shipped template with the slots-file line set |
| `/etc/sudoers.d/branchleft-slot`                  | root        | 0440                  | `templates/branchleft-slot.sudoers.j2`, one literal line per invocation      |
| `/etc/systemd/system/branchleft-broker.service`   | root        | 0644                  | `files/branchleft-broker.service`                                            |

The unit is loaded, disabled and inactive after the role. Nothing enables or
starts it.

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

The three inputs with no default must be given:

- `broker_deploy_release`: the release directory name.
- `broker_deploy_bundle_src`: a path on the controller to the built bundle.
- `broker_deploy_verify_key_src`: a path on the controller to the 32-byte public
  key.

[`meta/argument_specs.yml`](meta/argument_specs.yml) documents all of them. None
of them is a secret. The private half of the key never reaches the role.

## Requirements on the host

- `xz` (the Node tarball is unpacked with it).
- systemd, to load the unit.
- `sudo`, which provides `visudo`, to check the grant.

## Steps the role does not take

These stay with an owner, as the runbook already says:

- Building the bundle on a workstation, and choosing the release name.
- Making the request-signing key pair, and saving the private half in the
  owner's password manager.
- Starting the broker. That needs an owner ruling and is the runbook's B-7 step.
- Installing the slot wrapper program itself, which the sudoers grant names.
  The grant is installed here; the wrapper comes from the host build.

## Tests

The Molecule scenario in `molecule/default` runs the role in a systemd container
against a stand-in bundle and a zero-filled 32-byte key. Neither is a broker
artefact: they only prove where files land. `verify.yml` reads the result back,
and compares the unit and the verify key with their sources. It checks the
environment file's owner, mode, slots-file line and that `LISTEN_HOST` is unset,
but not every line of it.

It checks the sudoers grant: root-owned 0440, accepted by `visudo -csf`, exactly
the 50 literal invocation lines of the default slot table, and listed by
`sudo -l` for the broker account with no unrestricted grant. It also runs the
role's sudoers install with a line that is not sudoers syntax and expects the
install to stop at visudo's refusal and leave the good grant untouched.

The Node unpack is skipped in check mode: `unarchive` needs its destination to
exist even then, and on a host the role has not touched the directory and the
download are only reported, not made.
