# ring_controller_host

This role makes the host side of the ring controller on `ops1`: a service account of its own, two
OpenSSH keys generated on the host (the ledger-signing key and the push key), a bundle installed by
digest when a digest is given, a service unit and a timer, and an environment file of public
values. It prints the public half of each key with its fingerprint, so the people who must trust
them can be told which keys to trust.

**The unit and the timer are inert until the bundle digest input is set.** With the digest empty the
role installs both unit files, holds the timer disabled and stopped, installs no bundle and points
nothing at one. Setting the digest is the one step that turns the controller on.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

The ring controller is a program that takes one release step on each tick of a timer, reads a
ledger, signs what it writes to it and pushes it. This role puts the host in the state the program
needs and installs the program the owner has named by digest. It does not build the program, does
not run it by hand, and has no agent in the loop: the unit has no model key and its `PATH` holds no
agent program.

The role:

1. Checks, and never makes or changes, `/etc/branchleft`, `/opt/branchleft` and
   `/var/lib/branchleft`: each must be a real directory that is root's and that group and others
   cannot write. It also checks that `/usr/bin/ssh-keygen` is a root-owned regular file that only
   root can change. It does not install OpenSSH.
2. Makes the system account and group `ring-controller` (no login shell, no home directory). The
   controller is not run as root: `ops1` holds other roles' root-only files and the owner's own
   data, and an account of its own cannot read them.
3. Makes the directories it owns: `/etc/branchleft/ring-controller` (config), the release
   directories under `/opt/branchleft/ring-controller`, and the state directory
   `/var/lib/branchleft/ring-controller`, which is the account's and closed to everyone else.
4. Calls one module, `ring_controller_host_keys`, which generates the two key pairs if they are
   absent and leaves existing ones exactly as they are (see "How the keys are made").
5. Prints the two public halves and their fingerprints in two `debug` tasks. That is the recorded,
   non-secret output of the first apply.
6. Writes the known-hosts file the push pins its remote with.
7. When a digest is set: downloads the bundle held to that digest, unpacks it into a release
   directory named by the digest, requires `bin/ring-controller` to be a root-owned executable
   that no one else can write, and only then points `current` at the release.
8. Writes the environment file, installs the two units, reloads systemd, and holds the timer on
   or off by the digest.

It does not create the ledger, the push remote or its host key (those are the owner's inputs), does
not install or configure OpenSSH, does not put the public halves anywhere (the owner copies them
from the apply's output), does not escrow the private keys, and does not rotate them. To rotate, a
person removes both files of a key and the next apply generates a new one; the role refuses to do
that by itself when a private key has gone and its public half is still there.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the five inputs. All are public
values and none is a secret, so none needs a `host_inputs` entry. All default to empty, and an empty
value is valid: the role then does what it can without it. The owner's values live in
`ansible/owner_vars/ops1.yml`, a file only the owner merges.

| Variable                                  | Default | Meaning                                                                       |
| ----------------------------------------- | ------- | ----------------------------------------------------------------------------- |
| `ring_controller_host_bundle_sha256`      | empty   | The SHA-256 of the bundle, 64 lowercase hex digits. Empty keeps the timer off |
| `ring_controller_host_bundle_url`         | empty   | The https URL the bundle is fetched from, with no credential in it            |
| `ring_controller_host_ledger_url`         | empty   | The https URL of the ledger the controller reads                              |
| `ring_controller_host_ledger_push_remote` | empty   | The push remote, `ssh://git@HOST/ORG/REPO.git`                                |
| `ring_controller_host_push_known_hosts`   | empty   | One known_hosts line (host, key type, key) for the push remote                |

Each is checked by its own task before anything changes, and a refusal names the input and never
its value. A set digest needs the other four: a controller started with no ledger to read, nowhere to
push or no host key to pin would run half configured, so the role names the missing one and stops.
The shapes are patterns in `vars/main.yml`; none admits a space, a quote, a backslash, a dollar
sign or a hash, so each value is one plain word in the environment file.

The paths, names, modes and the account are constants in `vars/main.yml`, not inputs: an inventory
value cannot move them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Python 3.13. The module runs `ssh-keygen` from OpenSSH and needs no
  cryptography library.
- OpenSSH's `ssh-keygen` at `/usr/bin/ssh-keygen`, `/etc/branchleft` made by `host_inputs`, and
  the other two parents made by the roles that run before this one on `ops1`.
- Only `ops1` may apply it. That is the owner's list (`ansible/checks/host_roles.yml`, rule R9); a
  test inside the role would be no control, because under the pull inventory the host's name is
  `localhost`.

## What it changes on a host

| Path                                                       | Owner             | Mode   | What                                      |
| ---------------------------------------------------------- | ----------------- | ------ | ----------------------------------------- |
| `ring-controller` (account and group)                      | system            |        | No login, no home                         |
| `/etc/branchleft/ring-controller`                          | root              | `0755` | Config directory                          |
| `/etc/branchleft/ring-controller/keys`                     | `ring-controller` | `0700` | Holds the two key pairs and nothing else  |
| `/etc/branchleft/ring-controller/keys/ledger-signing`      | `ring-controller` | `0600` | The ledger-signing private key (ed25519)  |
| `/etc/branchleft/ring-controller/keys/push`                | `ring-controller` | `0600` | The push private key (ed25519)            |
| `/etc/branchleft/ring-controller/keys/*.pub`               | `ring-controller` | `0644` | The public halves                         |
| `/etc/branchleft/ring-controller/known_hosts`              | root              | `0644` | The pinned host key line, or empty        |
| `/etc/branchleft/ring-controller/ring-controller.env`      | root              | `0644` | Public values, an exact list of six names |
| `/var/lib/branchleft/ring-controller`                      | `ring-controller` | `0700` | State directory                           |
| `/opt/branchleft/ring-controller`, `releases`              | root              | `0755` | Base and releases directories             |
| `/opt/branchleft/ring-controller/releases/<sha256>`        | root              | `0755` | One release, only when a digest is set    |
| `/opt/branchleft/ring-controller/current`                  | root              | link   | To the release, only when a digest is set |
| `/etc/systemd/system/ring-controller.service` and `.timer` | root              | `0644` | The two units                             |

Nothing else. A canary test holds that nothing outside these paths changes.

## The reserved path of the promotion record

The controller keeps its own signed, hash-chained record of each promotion. That record is a
separate piece of work and this role does not build, make, write or read it. The role only fixes
where it will live, so that the controller and the host agree on one path before either exists. The
constant is `ring_controller_host_promotion_record_dir` in `vars/main.yml`, and its value is
`/var/lib/branchleft/ring-controller/promotion-record`.

The path is a subdirectory of the state directory, so it is the service account's and closed to
everyone else (`0700`), and it is inside the one path the unit may write (`ReadWritePaths`). The
controller derives it from `RING_CONTROLLER_STATE_DIR`, so it is not in the environment file and
no task names it. The directory does not exist after an apply; the controller makes it the first
time it writes a record. A test holds all four facts: under the state directory, inside the unit's
writable path, named by no task, absent from the environment file.

## How the keys are made

The module runs `ssh-keygen` by argument list with an empty environment, no terminal, no standard
input and no standard error, so what `ssh-keygen` says about a key is never kept. It generates each
key into a temporary name in the `0700` directory and publishes it by a hard link to the final
name. A link fails if the name exists, so an existing key is never replaced, and a crash leaves at
worst an orphan temporary file, never part of a key at the final name. The public half is derived
from the private key by `ssh-keygen -y`, and the module never reads the private bytes itself.

An existing key is accepted only if it is a regular file with one link, of modest size, with no group
or other permission bit, and `ssh-keygen` can derive a public half from it. A key readable by anyone
else may already be known to them, so a wide mode is **refused**, not corrected. A refusal is a fixed
code and a path:

| Code                 | Meaning                                                                       |
| -------------------- | ----------------------------------------------------------------------------- |
| `E-ARGS`             | The directory is not an absolute, normal path, or a name is malformed         |
| `E-OWNER-UNKNOWN`    | The host has no such account or group                                         |
| `E-PARENT`           | The parent of the key directory is missing, a link, not root's or writable    |
| `E-DIR`              | The directory path is a link, a file, or cannot be made or opened             |
| `E-DIR-FOREIGN`      | The directory holds a file the role does not own                              |
| `E-TEMP-NOT-A-FILE`  | A temporary name is held by a link or a directory                             |
| `E-KEYGEN-BINARY`    | `ssh-keygen` is missing, not a regular file, not root's or writable by others |
| `E-KEYGEN`           | `ssh-keygen` failed to make a key                                             |
| `E-KEY-OPEN`         | The key cannot be opened (a link in its place, for one)                       |
| `E-KEY-NOT-REGULAR`  | The key is a directory, a pipe or another special file                        |
| `E-KEY-LINKED`       | The key has more than one hard link                                           |
| `E-KEY-SIZE`         | The key file is too big (it is not read)                                      |
| `E-KEY-MODE-WIDE`    | The key has a group or other permission bit (it is not given to `ssh-keygen`) |
| `E-KEY-FORM`         | `ssh-keygen` cannot derive a public half from it                              |
| `E-KEY-LOST`         | A public half is present and its private key is gone                          |
| `E-PUB`              | The public name is held by something a rename cannot replace                  |
| `E-IO`, `E-INTERNAL` | An operating-system error (errno name only) or any other error (type name)    |

A key that is lost is refused and not made again: a new key would change what others trust, which is
the owner's act. A narrower mode or another owner is adopted: the module sets the owner and mode
through the open file's descriptor and never touches the bytes.

## How the private keys stay out of every log

The private key is made and judged inside the module's process and never leaves it. It is never a
return value, a task variable, a command-line argument, an environment variable, a file the
controller reads, or part of a message. The task that calls the module has `no_log: true` and
`diff: false` (ANS-16). The role has no lookup, `slurp`, `pipe`, `command`, `shell` or `stat` of a
private key; the unit tests read the tasks and fail on any of them. The text of a refusal is read
out by an `assert` after the hidden task, so a stop shows its code and path although the task is
hidden.

The environment file holds six names, an exact list: the ledger URL, the push remote, the paths of
the two identity files, the known-hosts file and the state directory. It holds no key and no token,
and the unit file does not name a model key or an agent program. The list of names the controller
refuses to run with lives with the controller, which refuses at its own start; the role does not
restate it, so there is one home for it.

## How to test it

From the repository root, with the pinned tools installed as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ring_controller_host
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ring_controller_host --scenario bundle
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ring_controller_host --scenario refusals
```

The module and the units have unit tests. From `ansible/roles/ring_controller_host`:

```text
PYTHONPATH=files:library python -m unittest discover -b -s tests/unit -p 'test_*.py'
```

The Molecule `default` scenario applies the role with no digest and converges twice (the second must
change nothing). It checks the keys' owner and mode, that the public halves printed are the files'
and that a rerun leaves the private bytes alone, that the unit's environment holds exactly the six
names, no name ending in `_API_KEY` and nothing starting `ANTHROPIC_`, that `PATH` finds no `claude`
(with a control that finds one when it is planted), that the timer is disabled and stopped, and that
files of other roles are exactly as they were. It runs at verbosity 3 and scans the controller's
log and every file the run left there for the keys' text, after showing the scan can find a
key-shaped control text. The `bundle` scenario fetches two stand-in bundles over `file://` and
checks the digest pin (a wrong digest stops at the download), the program check, the link, the
timer turning on and off with the digest, and the environment file. The `refusals` scenario puts the host in each
bad state or gives each bad input, and requires the role's exact message, no value in it, and no
change to any path it writes.

The sabotage controls, each red when its guard is removed: `test_existing_key_is_never_overwritten`
(the guard that leaves an existing key alone), the mode tests for the key module (a wider mode
constant), the log scan (a key task without `no_log`), the environment test (a model key name in the
template), the unit test of `get_url` with its `checksum` (the inert-until-digest and digest-pin
guard), `test_check_host_roles.py` (the role on any host but `ops1`), the canary comparison, and
`test_codeowners.py` (the owner line).

## How it is delivered

Delivery is the gated workflow only (ANS-17): a plan in check mode, the `ansible-hosts` approval, a
pull of that exact commit on the host, and a second run that must report zero changes. Nothing
here applies the role by hand, and nobody generates, reads or carries a private key.

Wiring the role to `ops1` is the owner's merge, because the lists it edits are owner-merged paths
(`ansible/checks/host_roles.yml`, `ansible/playbooks/ops1.yml`, `ansible/owner_vars/ops1.yml`,
`.github/CODEOWNERS`). Until the owner's apply nothing runs the role.

On a fresh host the plan (check mode) shows the keys as "would create" and cannot show the public
halves, which exist only after the apply. The first apply prints both public halves with their
fingerprints; the second run reports no change and prints the same values. Those values are what the
owner gives the ledger host (the push key) and the readers of the ledger (the signing key); the
role does not place them anywhere.

## How to change it safely

- A change to the module or the tasks is a change to how a private key is made on the host, so it
  gets the deep review a key-handling role gets, and the owner's: the role's directory is owned in
  `.github/CODEOWNERS` by the owner, and `test_codeowners.py` mirrors that line.
- The environment names and the layout `bin/ring-controller` inside the bundle are the contract with
  the controller's own bundle. A change to either is a change to both sides, in step.
- Keep the module's names and modes equal to `vars/main.yml`; a unit test holds them together.
- The module must keep a private key out of every output. Do not add a return value that depends on
  one, and do not put a lookup, a `slurp` or a `stat` of a private key in a task.
- Do not add a model key, a token or an agent program's directory to the unit's environment or
  `PATH`.

## Named limits

- **The account owns the key directory.** The service account must be able to read its private keys,
  so it owns the `0700` directory they are in and can rename or replace the entries. It cannot reach
  anything of root's. A key the account itself replaces is not detected until the next apply
  judges it.
- **Check mode on a fresh host shows less.** With no account or config directory yet, the tasks that
  need them are skipped and the plan prints "not yet made" for the public halves. A download is not
  made in check mode, so the bundle tasks cannot show what a digest would fetch.
- **A wrong digest leaves an empty release directory.** The download stops at the checksum, before
  anything is unpacked and before `current` moves, but the directory named by that digest was made
  first. It holds nothing and is harmless.
- **`current` is not removed when the digest is cleared.** Clearing the digest holds the timer off;
  it does not delete the last release or unlink it. Removing a release is a person's act.
- **The environment names and the bundle layout are a proposal until the bundle exists.** They are
  the contract with the controller's bundle and are fixed here so that both sides build to one
  text.
- **One host key line.** The known-hosts input is one line; a remote with two host key types needs
  the role to take a list, which is a change to the interface.
- **The test platform is a container.** It proves the files, owners, modes, the units' text and
  systemd's view of the timer; it does not prove that the controller runs, which is its own test
  and the first real tick.

## Clauses this role exercises

ANS-2 and ANS-9 (a typed module, no shell), ANS-7 (defaults mirror the spec), ANS-10 (check mode),
ANS-11 (idempotence), ANS-12 (no role imports another), ANS-14 (this README), ANS-15 (a container
test), ANS-16 (`no_log` and `diff: false` where a key passes) and ANS-17 (the gated pull).
