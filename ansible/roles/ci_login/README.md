# ci_login

Keeps a host's pipeline account in place: the `ansible-ci` account the CI workflows log
in as, its sudoers file, and its two forced-command key lines. It exists so that a
rebuilt edge1 does not need the hand steps again.

## What the role does, and what it does not

- **Account.** If `ansible-ci` is absent the role creates it: a system account with a
  home, the real shell `/bin/bash` and no password argument, so its password field is
  locked (`!`). If the account exists the role never modifies it. It only reads it back
  and refuses the run when the shell is `nologin` or `false`, or when the password field
  holds anything that does not start with `*` or `!` (a hash). A hand-made account with
  `*` passes and reports no change.
- **Sudoers.** `/etc/sudoers.d/ansible-ci`, owner root, mode `0440`, checked by `visudo -csf`
  before it replaces anything, holding exactly two lines: the `env_keep` line that keeps
  `SSH_ORIGINAL_COMMAND` through sudo for the trigger program, and a `NOPASSWD` grant of
  `/usr/local/sbin/pull-trigger --mode apply` and `--mode check`, nothing else.
- **Keys, only when `ci_login_manage_keys` is true.** The account's `authorized_keys` becomes
  exactly two lines, one per mode:
  `restrict,command="sudo /usr/local/sbin/pull-trigger --mode apply" KEY` and the same with
  `--mode check`. The role refuses an empty list, a list that is not one `apply` and one
  `check` entry, a key that is not one plausible public key, and one key given for both modes.
  With the flag false the role does not read, check or touch the keys, whatever the list holds.

It does not install `sudo`, an SSH server or the trigger program (`pull_trigger` does), edit
`/etc/sudoers` or `sshd_config`, set a password, or remove anything.

## The accepted risk: no source address limit

The key lines carry no `from=` option. GitHub's runners have no fixed address, so the owner
accepted this on the ruling at
https://github.com/branchLeft/workspace/issues/2339#issuecomment-6492257550 ("any address,
two commands only"). What bounds a stolen key is the forced command, `restrict`, and a
sudoers grant of the two trigger modes. Unlike the `sudoers_and_keys` pattern, which refuses a
forced command with no source address, this role has no `from_addresses` option, and the
pins test (`ansible/checks/test_ci_login_pins.py`) fails if a `from` option appears in the
key template or the interface, so the missing limit stays visible.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the two variables and
[`defaults/main.yml`](defaults/main.yml) holds the same defaults:

| Variable               | Default | Meaning                                                                                 |
| ---------------------- | ------- | --------------------------------------------------------------------------------------- |
| `ci_login_manage_keys` | `false` | `false`: the keys are untouched. `true`: the keys become the list.                      |
| `ci_login_keys`        | `[]`    | `{key, mode}` entries, `mode` one of `apply`, `check`. Read only when the flag is true. |

The account name, the sudoers file name, the trigger program path, the two sudoers lines and
the key shapes are constants in [`vars/main.yml`](vars/main.yml), so an inventory cannot change
them. The program path is the one `pull_trigger` owns, held equal by the pins test; the key
shapes are the `sudoers_and_keys` pattern's, held equal by the same test.

Where the values come from on edge1: `ansible/owner_vars/edge1.yml`, loaded by
`ansible/playbooks/edge1.yml`. That file is the owner's alone and is shipped with the flag
`false` and an empty list, so merging the role changes nothing about the keys until the owner
fills it. The public keys are not secrets, but every task that handles them sets `no_log: true`
and `diff: false` (ANS-16), and the test scans the log for them. The sudoers task is the
exception on purpose: a sudoers file holds command paths, not secrets, so it shows its diff in
the plan, and `test_ci_login_pins.py` fails if `no_log` or `diff: false` returns on it.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `ansible.posix` from the pinned
  `ansible` package, for `authorized_key`.
- Target: a Debian-family host with `sudo` (the role calls `/usr/sbin/visudo`), `getent`
  and Python 3. The test image is Debian 13, the release the production hosts run.

## What it changes on a host

- The account `ansible-ci` and its home, only when the account is absent.
- `/etc/sudoers.d/ansible-ci`.
- With the flag true: `<home>/.ssh` (mode `0700`) and `<home>/.ssh/authorized_keys` (mode `0600`).

No service, port or firewall rule, and `/etc/sudoers` is never opened.

## How to test it

From the repository root, with Docker running and the tools installed as `ansible/README.md`
describes (the harness runs in CI, never against a host):

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ci_login
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ci_login --scenario hand_made
```

- `default` starts from a host with no account. It proves the role creates the account with a
  locked password, a real shell and a home; writes the sudoers file and the two key lines
  exactly; removes a key it was not given; refuses a usable password, a `nologin` shell, an
  empty or wrong-sized list, a repeated key and a malformed key (with every line-break
  character); leaves the keys alone with the flag false; and keeps every key out of the log.
- `hand_made` starts from the state edge1 is in today: a `*` account, the sudoers file and
  two key lines written by hand. It proves the role changes none of them with the flag false,
  that the flag true with the same keys rewrites nothing, and that other keys do rewrite the
  file.

Each refusal has its own case in the verify play, which names the task it expects to stop
the run. The missing source limit has a red-then-green test in `test_ci_login_pins.py`.

## How it is delivered

Only through the gated workflow (ANS-17): the role is on edge1's list in
`ansible/checks/host_roles.yml` and applied by `ansible/playbooks/edge1.yml`. The plan job
shows edge1's check-mode diff first. The owner reads the sudoers diff there, line by line; the
key tasks hide their content (`no_log`, `diff: false`), so for those the owner reads only
whether each would change. The first run is the proof that the hand-made
account, sudoers file and (once the flag is on) key lines already match: the role is expected
to report no change.

## Named limits

- **The hand state was not read.** It exists on edge1 only. The sudoers text comes from the
  `pull_trigger` README, and the key lines use `restrict`, the form that README documents, where
  the `sudoers_and_keys` pattern writes four separate options. If the first gated plan shows a
  difference, the role's text wins over the hand-made file unless the owner says otherwise.
- **Check mode skips `validate`.** A sudoers file `visudo` would refuse looks like an ordinary
  change in the plan; the container test runs the real check.
- **Check mode on a host with no account** cannot write keys (the key module needs the
  account), so it stops after the checks; the real run creates the account first.
- **A key body is checked for shape, not for being the right key.** A one-character typo in a
  body of the right length is a different valid key and would lock the pipeline out.
- **`restrict,command=` is reviewed, not tested.** The image has no SSH server, so the test
  reads the written lines with `ssh-keygen -l` but does not log in.
- **The grant is two commands, but the key holder chooses the request text** the trigger
  program receives; the program judges it (see its README).

## How to change it safely

Change the tasks, the argument spec, the defaults and the molecule plays together, run both
scenarios, and break the control you touched to see its test fail. Do not add a `from`
option without an owner ruling that replaces the one above, and update the pins test with it.
Do not manage `ansible-ci`'s keys from another role: `exclusive: true` would remove each
other's keys.
