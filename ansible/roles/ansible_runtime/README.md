# ansible_runtime

Installs on a host the pinned `ansible-core`, built from this repository's
hash-locked `ansible/requirements.txt`, so that the host's trigger can run a
signed playbook of this repository on the host itself.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

The host's trigger (`pull_trigger`) runs `ansible-playbook` at an absolute path.
This role puts one there. It:

1. Installs the packages `python3` and `python3-venv`.
2. Copies the lock file to the host, named by a fingerprint of its text.
3. Makes a virtual environment for that lock and installs the lock into it with
   hash checking required, so that every package must match a hash in the lock
   and a package the lock does not name is refused.
4. Writes a marker in the environment when the install finished.
5. Points the `ansible-playbook` link at that environment, last, so a failed
   install leaves the previous environment in service.

Each lock gets its own environment beside the old one. A bump of the lock builds
a new environment; the `ansible-playbook` that is running the bump keeps its own
packages and is never upgraded under itself. The role never removes an old
environment.

It does not install the trigger (`pull_trigger` does), manage users, SSH keys or
services, or hold any secret. It does not install the collections separately:
they arrive inside the pinned `ansible` package (`ansible/README.md`).

## Interface

The variables, their types and defaults are in `meta/argument_specs.yml`, and
the same defaults are in `defaults/main.yml`.

| Variable                           | Meaning                                                                                              |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `ansible_runtime_requirements_src` | Required. Path, on the machine that runs the role, of the lock file (`ansible/requirements.txt`).    |
| `ansible_runtime_root`             | Directory that holds the environments (default `/opt/ansible-runtime`).                              |
| `ansible_runtime_link`             | The `ansible-playbook` link (default `/usr/local/bin/ansible-playbook`, the trigger's default path). |

No variable is a secret.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version.
- No collections beyond `ansible.builtin`.
- Target system: Debian 13 (apt, and Python 3.13, which is above the floor
  ansible-core sets for the machine that runs it), with a route to the Python
  package index and about 400 MB free for each environment.

## What it changes on a host

- The packages `python3` and `python3-venv`.
- `/opt/ansible-runtime/` (root, 0755), and in it `requirements-<fingerprint>.txt`
  (root, 0644) and `venv-<fingerprint>/` (the environment, owned by root).
- `venv-<fingerprint>/.installed-from-lock`: the marker (root, 0644).
- `/usr/local/bin/ansible-playbook`: a link into the environment.

No services, ports or users.

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes, one command runs lint, yamllint, the interface checks and the
container test:

```text
python3 ansible/harness/run_harness.py ansible/roles/ansible_runtime
```

Run it with the Python of the virtual environment that holds the pinned tools.
The test installs the repository's real lock into a Debian 13 container, so it
needs a route to the Python package index and takes minutes. `verify.yml`
asserts, and each line names what it proves:

- the directory is root-owned with mode 0755;
- the link points into the environment named by this lock;
- `ansible-playbook` run through the link reports the pinned ansible-core;
- `pip check` is clean;
- nothing under the directory is owned by another account or writable by others
  (the trigger runs these tools as root and does not vet them);
- a lock with a wrong hash is refused, and a lock with no hash at all is
  refused, and neither moves the link.

The second refusal is the one the `--require-hashes` flag alone holds: pip turns
hash checking on by itself when any line carries a hash, but a lock with no hash
at all installs unchecked without the flag.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by running
`ansible-playbook` by hand. The one exception is the one-time root bootstrap of a
host that has no trigger yet, which the owner runs by hand: its command is in the
owner's runbook for `edge1`, and the playbook is
`ansible/playbooks/edge1.yml`. After that bootstrap the gated pull applies the
role from the signed checkout.

## Named limits

- **The lock is trusted at the level its hashes give.** A hash proves the bytes
  match the lock, not that PyPI's maintainers published them honestly. A bump is
  reviewed, not trusted (`ansible/README.md`, "What this does not prove").
- **Old environments stay.** Each bump leaves the previous environment on the
  disk. Removing one is by hand, after the new one is in service. Nothing
  removes the environment the running playbook uses.
- **The fingerprint names the lock text.** The file lookup trims trailing
  whitespace before the hash, so a change only to trailing whitespace of the
  lock is not a new environment.
- **The first install reaches the Python package index** from the host, and a
  host with no route to it fails at the install task, before the link moves.

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together.
2. Keep every task able to run under `--check --diff`. The install and
   environment tasks are command tasks, which check mode skips on its own; the
   copy of the lock and the link report the change.
3. Keep the order: the link moves last.
4. A control is changed only with its proof: weaken it in a copy, see the named
   assertion in `verify.yml` fail, restore it, see it pass.
5. Run the harness command above before opening a pull request.
