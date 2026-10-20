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
| `/etc/systemd/system/branchleft-broker.service`   | root        | 0644                  | `files/branchleft-broker.service`                                            |

The unit is loaded, disabled and inactive after the role. Nothing enables or
starts it.

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

## Steps the role does not take

These stay with an owner, as the runbook already says:

- Building the bundle on a workstation, and choosing the release name.
- Making the request-signing key pair, and saving the private half in the
  owner's password manager.
- Starting the broker. That needs an owner ruling and is the runbook's B-7 step.
- The sudoers boundary and the slot wrapper (the runbook's A-5 step, from the
  host build). They are not in this role's scope.

## Tests

The Molecule scenario in `molecule/default` runs the role in a systemd container
against a stand-in bundle and a zero-filled 32-byte key. Neither is a broker
artefact: they only prove where files land. `verify.yml` reads the result back,
and compares the unit and the verify key with their sources. It checks the
environment file's owner, mode, slots-file line and that `LISTEN_HOST` is unset,
but not every line of it.
