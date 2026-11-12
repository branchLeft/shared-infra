# deploy_slot_keys

This role makes the deploy account's per-stack SSH keys exactly a declared list. Each
**slot** is one public key that may run one stack's deploy command and nothing else: its
`authorized_keys` line carries a forced command that names the stack, so a tenant's CI key
cannot deploy another tenant's stack, open a shell, copy a file or forward a port. The role
installs the existing slot program from `hetzner/provision/` and calls it through one typed
module, so the rules about what a slot is stay in the program and the role only decides
which slots the host holds.

This README is written for a maintainer who is new to the repository. It follows the
order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

- Installs `hetzner/provision/provision_deploy_slot.py` as root-owned
  `/usr/local/sbin/branchleft-provision-deploy-slot`.
- Calls the module `deploy_slot_keys_reconcile`, which loads that installed program and
  makes the host's slots exactly the declared list: it grants a slot that is missing,
  rotates a slot whose key changed, and revokes a slot that is no longer declared.
- Reads `authorized_keys` back after the change and compares every managed line with a
  shape the module pins for itself. If the program has drifted and renders a line the
  module does not expect, the run restores the file it started from and fails.

The slot program's own rules apply and the role does not weaken them: one key holds one
slot; the key's comment is discarded; the `/home/deploy` tree belongs to root and is not
writable by the account; a register of slots is kept in `/etc/branchleft/deploy-slots/`;
and a stack that already exists on the host is refused unless the entry adopts it.

The role does not make a key pair. A person mints the private half, which goes to the
tenant repository's production environment secret; the role only ever sees the public
half. It does not install the deploy wrapper or the sudoers grant (those belong to
`deploy_tooling`, which must have run first), and it does not create the `deploy` account.
On a host enrolled by first-boot configuration there is no such account, and the module
fails closed there rather than make one.

An empty list means "not declared". It changes nothing and never revokes every slot, so a
host that is handed a list that failed to load keeps the slots it has.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the one input, and Ansible
checks it when the role starts. It has no default (ANS-7): a host that is not told its
slots is not given any.

| Variable                 | Default        | Meaning                                                                         |
| ------------------------ | -------------- | ------------------------------------------------------------------------------- |
| `deploy_slot_keys_slots` | none, required | The exact list of slots. Each entry has `stack`, `public_key`, `adopt_existing` |

Each entry:

- `stack`: lowercase letters, digits and hyphens, starting with a letter, 32 characters at
  most. It is written into the forced command, so the program validates it before
  anything is written.
- `public_key`: one OpenSSH public key on one line. Hidden from logs (`no_log`).
- `adopt_existing`: `false` unless the stack already runs on the host and the entry takes
  it over.

The list holds tenant stack names and public keys, which are private. It is supplied at
run time (on a pulled host, from the host's own root-only inputs file through the `host_inputs`
loader, which is the only route there) and is never committed to this
repository (ANS-16). Everything else the role uses is fixed in
[`vars/main.yml`](vars/main.yml) and in the module, and an inventory value does not
change it.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` in
  `meta/main.yml` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Python 3, a `deploy` account, `sudo`, and the deploy wrapper at
  `/usr/local/sbin/branchleft-deploy` (installed by `deploy_tooling`).
- `openssh-server` reads the account's `authorized_keys`; the role does not manage it.

## What it changes on a host

- `/usr/local/sbin/branchleft-provision-deploy-slot` (`root:root`, `0755`): the slot
  program.
- `/home/deploy/.ssh/authorized_keys` (`root:deploy`, `0640`): the host-level line the host
  already had, kept first and untouched, then one line per slot.
- `/home/deploy` and `/home/deploy/.ssh` (`root:deploy`, `0750`): owned by root so the
  account cannot rewrite its own keys.
- `/etc/branchleft/deploy-slots/<stack>.pub` (`root:root`, `0600`) under a `0700`
  directory: the register of which key holds which slot.

A slot's line has this shape, and the module pins it independently of the program:

```text
restrict,command="/usr/bin/sudo -n /usr/local/sbin/branchleft-deploy --slot STACK" TYPE BLOB branchleft-slot:STACK
```

`restrict` turns off the pty, port forwarding, agent forwarding and X11 for the key, and
the forced command replaces whatever command the client asked for.

## How to run its test

From the repository root, with the pinned tools installed as `ansible/README.md`
describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/deploy_slot_keys
```

The harness runs lint, yamllint, a fresh-state check-mode run, converge, a second
converge that must change nothing, verify, a configured-state check-mode run that must
show no change, Molecule's own check action and destroy. It needs Docker on the machine
and creates one container. The container has no network, runs a real `sshd` of its own on
a high local port, and never touches a host.

The module and the checks that bind it to the rest of the repository have unit tests: from
`ansible/roles/deploy_slot_keys` run
`PYTHONPATH=library python -m unittest discover -s tests/unit`, and from the repository
root run `python -m unittest discover -s ansible/checks`. CI runs all of them.

## How it is delivered

Delivery to a host is the gated workflow only (ANS-17): a plan job in check mode, the
approval of the protected environment, a pull of that exact commit on the host, and a
second run that must report zero changes. Nothing in this repository applies the role by
hand. The role is listed for `app1` in `ansible/checks/host_roles.yml` and applied by
`ansible/playbooks/app1.yml`, last, after `deploy_tooling` (the slot program needs the wrapper
that role installs). The slot list for a real host is supplied at run time: the owner records it
in the host's `/etc/branchleft/host-inputs.json` under `deploy_slot_keys_slots`, and the
`host_inputs` loader sets it, so the pull has no extra variable. The loader refuses an empty
list, so app1's pull stops until the file holds at least one slot. How the owner records a
tenant's key and what to check on the host afterwards is in the private ghost-platform-docs
repository, not here.

## How to change it safely

- A change to the module, to the role's tasks or to anything under this directory is the
  owner's to merge (`.github/CODEOWNERS`), because the file the role writes decides who
  may run a deploy as root.
- A change to the slot program in `hetzner/provision/` must change the module's pins in the
  same pull request. `ansible/checks/test_deploy_slot_keys_single_home.py` fails when a
  constant the program writes with is not pinned, or differs from its pin.
- Never copy or link the program into this directory. The same test fails on a file with
  the program's name, on a file with its bytes under another name, and on any link.
- Never name the deploy wrapper's path in a task. Only `deploy_tooling` installs it, and
  `test_deploy_tooling_single_owner.py` fails a task that does. The module holds the path
  as a pin and the single-home test holds that pin to the `deploy_tooling` variable.

## Why each part is the way it is

- **The program is installed first, then loaded by the module.** The rules stay in one
  file with its own tests. The module refuses a program that is not root's, is a link,
  or sits under a directory that an account other than root can write, because it runs
  the program as root.
- **The module pins its own oracle.** If the module trusted the program to judge its own
  output, a drifted program would pass its own test. The module therefore checks every
  managed line, before the write (the plan) and after it (the read-back), against the
  pinned shape. A failed read-back restores `authorized_keys` as it was.
- **It validates every entry before it reads the host.** A refusal names a rule and a
  position in the list ("slot entry number 2: key-already-installed") and nothing else.
  It never names a stack, a key or a fingerprint, because the log of a plan is not private.
- **Exact-set semantics with an empty list meaning "not declared".** The role revokes what
  is not listed, so a list that arrived empty by mistake must not wipe the host.
- **Check mode plans, and writes nothing.** The module task is skipped only while the
  copy of the program above it would change, because a plan made by a program that is not
  yet installed would be a plan made by nothing.
- **`failed_when: false` on the module task**, followed by an assertion on `msg`. A hidden
  failure would otherwise show only "the output has been hidden"; the message is a rule and
  a position, which is safe to print.

## What the test proves

The unit tests load the real program with a fake file system and cover each
of these, for the privilege boundary in particular:

- A stack name that is empty, upper-case, too long, or carries a space, a `;`, `$()`, a
  backtick, a newline or a quote is refused before anything is written.
- A public key with options in front of it, a second line, or an unknown type is refused;
  a key declared for two stacks, or equal to the host-level key, is refused.
- A program whose constants differ from the pins, or that renders another slot's command,
  fails closed (the mutated-program read-back test is the control for the read-back).
- A program path that is not root's, or is under a group-writable directory, is refused.
- The result and the failure message carry counts and rule names, never a stack or a key.

The Molecule scenario starts a real `sshd`, grants four slots (one adopted), and then:

- connects with each slot key and asks for another stack's command, a shell, a command
  chain with `;`, `&&`, a newline, a pipe, a redirect, `$()` and backticks, a pty, the
  `sftp` subsystem and `scp` in both protocols. A stand-in for the wrapper records what it
  was given; the test requires that it was given exactly the stack's own argument and that
  no marker file a hostile command would make exists;
- asks a slot key for a local port forward (`ssh -W`) to the scenario's own `sshd`, which is
  listening, and requires that `sshd` logged `refused local port forward`, that no
  `SSH-2.0-` banner came back and that the client failed. A key that could forward would be
  served the banner and `sshd` would log nothing;
- asks a slot key for a remote port forward (`ssh -N -R` with `ExitOnForwardFailure=yes`)
  and requires the client's `remote port forwarding failed` error and a non-zero exit. `sshd`
  logs no line for a refused remote forward, so the client's error, which that option raises
  only when `sshd` answers the request with a failure, is the evidence. A key that could
  forward would leave the client running until `timeout` killed it, which the test names as
  its own failure. Neither forward case covers `-A`, `-X` or Unix-socket forwards: `restrict`
  turns those off too, and they are pinned only by the exact `restrict,` line;
- proves the host-level key still works as the account, before and after a rotation;
- proves the account cannot write `/home/deploy`, its `.ssh`, `authorized_keys` or a file
  in it, with `/tmp` as the control that the check can say yes;
- refuses six bad lists with the exact message and an unchanged host, and runs a list that
  would rotate one slot and revoke the rest in check mode, with an unchanged host;
- rotates, revokes and puts the host back, requiring the exact set each time;
- scans the controller's Ansible log, run at verbosity 1, for a canary stack name and the
  key bodies that were declared, and requires none of them, with the converge's own
  output present as the control that the scan reads something.

## Named limits

- The Molecule container is not a Hetzner host. It proves the file shapes and the forced
  command at `sshd`'s level; it does not prove the deploy wrapper's own behaviour, which
  `hetzner/provision/test_branchleft_deploy.py` covers, and it uses a stand-in for it.
- The role cannot judge a key added to `authorized_keys` by hand. Only lines with the
  `branchleft-slot:` marker are the role's; every other line is kept verbatim and in order,
  ahead of the slots, and nothing here reports it. A person who adds an unmarked line to
  this file has added a way in that nothing here checks.
- The host-level line is simply an unmarked line. The host's first-boot configuration owns
  it and the role does not judge it.
- An enrolled (pull) host has no `deploy` account, so the module fails closed there. Using
  the role on such a host needs a decision about the account first.

## Clauses this role exercises

ANS-2 and ANS-9 (a typed module, no shell), ANS-7 (no default for the input), ANS-10 (check
mode), ANS-11 (idempotence), ANS-12 (no role imports another), ANS-14 (this README),
ANS-15 (a container test), ANS-16 (`no_log` and `diff: false` where a value passes) and
ANS-17 (the gated pull).
