# ci_step_login

Keeps a host's step account in place: the `control-plane-step` account that the gated step
workflow logs in as, its sudoers file, and its one forced-command key line. It is the host half
of a step request (the `pull_trigger` README, "Step requests"); the workflow that sends the
request is `ansible-gated-step.yml` in `branchLeft/github-workflows`.

## What the role does, and what it does not

- **Account.** If `control-plane-step` is absent the role creates it: a system account with a
  home, the real shell `/bin/bash` and no password argument, so its password field is locked
  (`!`). If the account exists the role never modifies it. It only reads it back and refuses the
  run when the shell is `nologin` or `false`, or when the password field holds anything that
  does not start with `*` or `!` (a hash).
- **Sudoers.** `/etc/sudoers.d/control-plane-step`, owner root, mode `0440`, checked by
  `visudo -csf` before it replaces anything, holding exactly two lines: the `env_keep` line that
  keeps `SSH_ORIGINAL_COMMAND` through sudo for the trigger program, and one `NOPASSWD` grant of
  `/usr/local/sbin/pull-trigger --mode step`. sudo matches a command that has arguments
  exactly, so `--mode apply`, `--mode check`, `--config` and a trailing word are all refused.
- **Key.** The account's `authorized_keys` becomes exactly one line:
  `restrict,from="ADDRESSES",command="sudo /usr/local/sbin/pull-trigger --mode step" KEY`.
  The role refuses a key that is not one ed25519 public key on one line, an empty list of source
  addresses, and an address that is not a dotted IPv4 address or a range from `/24` to `/32`.

The step id and its word are not in the key line or the sudoers file: they travel in the request,
and the program judges them against the host's step allow-list (`pull_trigger_steps` in
`owner_vars/ops1.yml`). So this account can ask for a step the allow-list names and nothing else,
and a new step is a change to the program and the allow-list, not to this role.

It does not install `sudo`, an SSH server or the trigger program (`pull_trigger` does), edit
`/etc/sudoers` or `sshd_config`, set a password, or remove anything. It never touches the
pipeline account `ansible-ci`, which holds the apply and check keys and never this one.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the two inputs. Both are required
and neither has a default, so a run without them stops before any task:

| Variable             | Meaning                                                                                  |
| -------------------- | ---------------------------------------------------------------------------------------- |
| `ci_step_login_key`  | The step key's public half: one ed25519 public key, one line, no options.                |
| `ci_step_login_from` | The source addresses of the `from` option: IPv4 addresses or ranges from `/24` to `/32`. |

The account name, the sudoers file name, the program path, the two sudoers lines, the key options
and the key and address shapes are constants in [`vars/main.yml`](vars/main.yml), so an inventory
cannot change them. The program path is the one `pull_trigger` owns and the key shape is the
`sudoers_and_keys` pattern's; the pins test (`ansible/checks/test_ci_step_login_pins.py`) holds
both equal.

Where the values come from on ops1: `ansible/owner_vars/ops1.yml`, loaded by
`ansible/playbooks/ops1.yml`. That file is the owner's alone. The key is public. Every task that
handles it sets `no_log: true` and `diff: false` (ANS-16), and the test scans the log for it. The
sudoers task is the exception on purpose: it shows its diff in the plan, and the pins test fails
if `no_log` or `diff: false` returns on it.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `ansible.posix` from the pinned `ansible`
  package, for `authorized_key`.
- Target: a Debian-family host with `sudo` (the role calls `/usr/sbin/visudo`), `getent` and
  Python 3. The test image is Debian 13, the release the production hosts run.

## What it changes on a host

- The account `control-plane-step` and its home, only when the account is absent.
- `/etc/sudoers.d/control-plane-step`.
- `<home>/.ssh` (mode `0700`) and `<home>/.ssh/authorized_keys` (mode `0600`).

No service, port or firewall rule, and `/etc/sudoers` is never opened.

## Why the source address is pinned

A key with a forced command must say where it may connect from (the `sudoers_and_keys` pattern
refuses one that does not). ops1 has no public address: the step is sent through the edge1 jump
host, so ops1's sshd sees the jump host's private address as the source. The address is the
owner's value in `owner_vars/ops1.yml` and is not a runner address. The pipeline account's keys
carry no `from` because GitHub's runners have no fixed address; that does not apply here. If the
value is wrong the key is refused at connection and no step runs: it fails closed.

## How to test it

From the repository root, with Docker running and the tools installed as `ansible/README.md`
describes (the harness runs in CI, never against a host):

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ci_step_login
```

The `default` scenario starts from a host with no account. It proves the role creates the
account with a locked password, a real shell and a home; writes the sudoers file and the one key
line exactly; removes a key it was not given; keeps every key out of the log; and refuses an
empty or malformed key (with every line-break character), an empty or wide or wildcard source
address, a usable password and a `nologin` shell. It also runs a stand-in for the trigger program
through `sudo` as the step account: the step mode runs as root with the request text kept, and
`--mode apply`, `--mode check`, `--config`, an added word, a repeated mode, no argument at all and
another program are each refused.

Each refusal has its own case in the verify play, which names the task it expects to stop the
run. The constants, the sudoers lines and the key template are also pinned offline by
`ansible/checks/test_ci_step_login_pins.py`, each shown red on a sabotaged copy.

## How it is delivered

Only through the gated workflow (ANS-17): the role is on ops1's list in
`ansible/checks/host_roles.yml` and applied by `ansible/playbooks/ops1.yml`. The plan job shows
ops1's check-mode diff first. The owner reads the sudoers diff there, line by line; the key task
hides its content (`no_log`, `diff: false`), so for it the owner reads only whether it would
change. The owner's key line, to compare against what lands, is in the pull request.

## Named limits

- **`restrict,command=` is reviewed, not tested.** The image has no SSH server, so the test reads
  the written line with `ssh-keygen -l` but does not log in, and the `from` option is not
  exercised. The sudo half is exercised.
- **Check mode skips `validate`.** A sudoers file `visudo` would refuse looks like an ordinary
  change in the plan; the container test runs the real check.
- **Check mode on a host with no account** cannot write keys (the key module needs the account),
  so it stops after the checks; the real run creates the account first.
- **A key body is checked for shape, not for being the right key.** A one-character typo in a
  body of the right length is a different valid key and would lock the step route out.
- **The key holder chooses the request text** the trigger program receives; the program judges
  it (the `pull_trigger` README), and so does the environment approval in the workflow.
- **The account is made once.** A hand-made account is judged, never changed.

## How to change it safely

Change the tasks, the argument spec and the molecule plays together, run the scenario, and break
the control you touched to see its test fail. Do not widen the sudoers grant, drop an option
from the key template or accept a wider address range without an owner ruling, and update the
pins test with it. Do not manage this account's keys from another role: `exclusive: true` would
remove each other's keys.
