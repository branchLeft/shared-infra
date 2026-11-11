# spool_path_account

This role is the far end of the path `ops1` uses to reach a host's mail spool. It gives `ops1` one
unprivileged account on this host, with one key, and the key can do one thing: open a connection to the
spool's drain port on this host's loopback address. It cannot run a command, open another port, or be
used from another address. The role opens no port of its own and adds no firewall rule, because the path
rides the host's existing ssh.

The `spool_paths` role on `ops1` is the other end. It holds the key and dials this host.

This README is written for a maintainer who is new to the repository. It follows the order the standard
sets for a role README (ANS-14).

## What the role does, and what it does not

Inert until the owner has placed both input files (The owner's files). With neither present the role
removes what it wrote and changes nothing else. With both, in this order, and it stops at the first
refusal:

1. **Inputs.** Checks the directory above the inputs and the inputs directory (root's, `0700`), that each
   input is a regular file, root's, `0600` and not a link, and the shape of each: one IPv4 address, and
   one `ssh-ed25519` key line. A message names the problem and never a value.
2. **The drain port.** Reads, with `ss`, where the spool's drain port listens on this host and refuses
   unless it listens on the loopback address and nowhere else. This is the control the whole design rests
   on, and it is read before the account gets a key, so a wildcard or public bind stops the run with
   nothing opened.
3. **The account.** Makes `spoolpath`, a system account with no shell (`nologin`), no password and no home.
   It refuses an existing account that has a login shell and never changes one.
4. **The key.** Writes one line to a root-owned key file: `restrict`, `port-forwarding`, a `permitopen` of
   the drain port on the loopback address, `from` the owner's address, a forced command of `nologin`, and
   the key. The key's comment is dropped.
5. **The sshd settings.** Writes a drop-in whose `Match User` block reads that key file, allows only
   public-key authentication and local forwarding to that one port, and turns off everything else:
   gateway ports, agent and stream-local forwarding, X11, a terminal, a tunnel, the user's rc file, with
   `ForceCommand` of `nologin`. Once both files are written, `sshd -t` checks the whole
   configuration. If sshd refuses it, both files are removed and the run stops, so the account is left
   unable to log in. sshd is reloaded when either file changed.

What it does not do, each on purpose:

- It does not write, show or log an input. The key file holds the address, so its task hides its result
  and its diff.
- It does not remove the account. Removing an account is not the role's to do; clearing the inputs takes
  down the key file and the sshd settings, which is what makes the account unable to log in.
- It does not start, change or configure the spool. The spool's own role does, and a test holds the port
  the two agree on.

## The owner's files

In `/etc/branchleft/spool-path-account`, a directory the owner makes (root's, `0700`), two files, each a
regular file, root's, `0600`:

| File           | Meaning                                                                       |
| -------------- | ----------------------------------------------------------------------------- |
| `from_address` | The address this host sees the path arrive from. One IPv4 address             |
| `public_key`   | The public half of the key `ops1` holds for this host, one `ssh-ed25519` line |

The address is not the same on every host. On a host with a public interface the path arrives from the
estate gateway's address, and that address is shared by everything behind the gateway, so it does not tie
the key to `ops1`: what stops another host using the key is that the private half exists only on `ops1`,
root-owned. On a private-only host behind a jump host it is the jump host's private address.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the one input and Ansible checks it when
the role starts. Neither a secret nor an address is an input.

| Variable                        | Default | Meaning                                                                 |
| ------------------------------- | ------- | ----------------------------------------------------------------------- |
| `spool_path_account_spool_port` | `8095`  | The port the spool's drain listener is bound to on this host's loopback |

The paths, the account name and the sshd settings are constants in `vars/main.yml`, not inputs.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with OpenSSH (`/usr/sbin/sshd`, `/etc/ssh/sshd_config.d`), the `ssh` service, `ss`
  and `getent`.
- The spool already running and publishing its drain port on the loopback address only. On the demo host
  the spool role runs before this one.

## What it changes on a host

| Path                                                   | Owner | Mode   | What                                    |
| ------------------------------------------------------ | ----- | ------ | --------------------------------------- |
| `/etc/ssh/branchleft-spool-path`                       | root  | `0755` | The directory of the account's key file |
| `/etc/ssh/branchleft-spool-path/authorized_keys`       | root  | `0644` | The one key line                        |
| `/etc/ssh/sshd_config.d/42-branchleft-spool-path.conf` | root  | `0644` | The account's sshd settings             |

It also makes the `spoolpath` account and reloads sshd. It names, and never writes, the two input files.

## How to test it

From the repository root, with the pinned tools installed as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/spool_path_account
```

The role has unit tests. From `ansible/roles/spool_path_account`:

```text
PYTHONPATH=files:library python -m unittest discover -b -s tests/unit -p 'test_*.py'
```

- The listener check is held to what `ss` prints: a loopback bind passes, a wildcard, public or IPv6 bind
  is named, no listener is not a pass, and a port that only ends the same digits is not matched.
- The role's own input and write tasks run with Ansible against a scratch tree: inert with no input, the
  key line exactly as designed, a second run changing nothing, no input value in the run's output at the
  highest verbosity, and each refusal (one input only, a bad address, a bad key, an input anyone can read,
  an open directory, a link, a parent others can write) writing nothing.
- A real `sshd -T` reads the rendered drop-in for the account and reports the confinement, and for another
  user reports none of it. A real sshd on a loopback port, using the rendered key line, lets the key open
  the drain port and refuses it any other, refuses it from another address, and does not run a command.

The Molecule `default` scenario converges twice on a systemd container with stand-ins for `sshd`, the
`ssh` service and the spool's loopback listener, with both owner inputs placed as made-up values. It checks
the files, owners and modes, the key line, that the account has no login shell, the sshd settings, that sshd
was asked to check the whole configuration, and that no input value is in the run's log. It needs Docker.
The scenario passes under the harness; the unit tests above run the real `sshd`.

## How it is delivered

Delivery is the gated workflow only (ANS-17): a plan in check mode, the `ansible-hosts` approval, and for
`demo1` a signed bundle sent to it (it never fetches). Nothing here applies the role by hand and nobody
reads or carries a key. Wiring the role to a host is the owner's merge, because the lists it edits are
owner-merged paths (`ansible/checks/host_roles.yml`, `.github/CODEOWNERS`). The first apply after that
merge changes nothing until the owner has placed both input files.

## How to change it safely

- A change to the key line or the sshd settings changes what `ops1` can do on this host, so it gets the
  deep review and the owner's merge.
- Never add an option to the key line that widens it, a second `permitopen`, a shell, or a `from` that is
  a pattern. The tests name each.
- Keep `spool_path_account_spool_port` equal to the spool role's drain port and `spool_path_account_user`
  equal to the account `spool_paths` dials. `ansible/checks/test_spool_paths_agree.py` holds both pairs.

## Named limits

- **The `from` address does not tie the key to `ops1`.** It binds the gateway, which is shared. The private
  key's custody on `ops1` is what does.
- **The read-back is of the listener, not of the firewall.** The role does not read the host's firewall; it
  adds none, and the existing rules are the owner's.
- **`sshd -t` does not run in check mode.** A plan shows a bad file as a change and it fails only at apply.
- **A refused configuration removes the key.** The rollback takes out a previously good key file too, so
  the account is closed until the next good run. It never leaves a half-written, accepted state.
- **The account stays when the inputs are cleared.** Its key file is gone, so it cannot log in.
- **The test platform has stand-ins for `sshd` and the `ssh` service.** It proves files, owners, modes and
  the order; the unit tests prove the settings and the key line against a real sshd.

## Clauses this role exercises

ANS-7 (defaults mirror the spec), ANS-9 (no shell), ANS-10 (check mode), ANS-11 (idempotence), ANS-12 (no
role imports another), ANS-14 (this README), ANS-15 (a container test), ANS-16 (no value in a message) and
ANS-17 (the gated pull).
