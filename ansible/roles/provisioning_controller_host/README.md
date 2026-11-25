# provisioning_controller_host

This role makes the host side of the tenant provisioning controller on `ops1`: a service account of
its own, an SSH key made on the host that never leaves it, the approval trigger (a path unit and a
timer that run the controller's executor for every recorded approval that has not completed), the
controller's configuration, and the demo tenant's register entry. It prints the key's public half so
the people who must trust it can be told which key to trust.

**The units are inert until the bundle digest input is set.** With the digest empty the role installs
all three unit files, holds them disabled and stopped, and installs no bundle. Setting the digest
(and the route inputs it needs, below) is the one step that turns the trigger on. Nothing here
depends on the controller's bundle being published: the role installs, and the service waits for its
inputs.

This README follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

The provisioning controller (ghost-platform `services/provisioning-controller`) takes one approval
from a ledger and runs the steps that make a tenant: it reaches the tenant host over SSH through two
jump hosts, and calls three small programs for the steps that have no product code of their own.
This role puts `ops1` in the state the controller needs. It does not build the controller, does not
run it by hand, and has no agent in the loop. It does not give the key any network reach: the
per-key jump lists are separate work. It does not make the ledger (the approval portal writes it), the
secrets file or the stack file (the controller's own inputs), and it does not rotate the key.

The role:

1. Checks, and never makes or changes, `/etc/branchleft`, `/opt/branchleft` and
   `/var/lib/branchleft`: each must be a real directory that is root's and that group and others
   cannot write.
2. Makes the system account and group `provisioning-controller` (no login shell, no home).
3. Makes the directories it owns: the config directory (root's), the release directories, and the
   state, inputs and escrow directories (the account's, mode `0700`).
4. Calls one module, `provisioning_controller_host_ssh_key`, which generates the SSH key if it is
   absent and leaves an existing one exactly as it is (see "How the key is made").
5. Writes the key's public half, which the module returns, to `ssh.pub` (root's, `0444`) and prints
   it in a `debug` task, which is the recorded, non-secret output of the first apply.
6. When a digest is set: downloads the bundle held to that digest, unpacks it into a release
   directory named by the digest, requires `bin/provisioning-controller` to be a root-owned
   executable, and only then points `current` at the release.
7. Installs the pass program and the steps program, `config.json`, `register.json`, `ssh_config`
   and `known_hosts`, then the three units, and holds the path and timer on or off by the digest.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares eight inputs, all public values (no
secret, so no `host_inputs` entry). All default to empty. The owner's values live in
`ansible/owner_vars/ops1.yml`, a file only the owner merges.

| Variable (prefix `provisioning_controller_host_`) | Meaning                                                          |
| ------------------------------------------------- | ---------------------------------------------------------------- |
| `bundle_sha256`                                   | SHA-256 of the controller bundle, 64 lowercase hex. Empty = off  |
| `bundle_url`                                      | The https URL the bundle is fetched from, with no credential     |
| `edge1_jump_user`, `edget_jump_user`              | The user to log in as on the two jump hosts                      |
| `edge1_host_key`, `edget_host_key`                | Pinned ssh-ed25519 host key of each jump host                    |
| `app_t1_host_key`, `db_t1_host_key`               | Pinned ssh-ed25519 host key of the tenant app and database hosts |

The six route inputs are all set or all empty: some but not all stops the run, naming the input and
never its value. A digest needs all six (a bundle that could not reach the tenant host would have
nothing to run for). Each input has its own check, and the patterns are in `vars/main.yml`. The
paths, names, modes and addresses are constants in `vars/main.yml`, not inputs.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; no collection beyond `ansible.builtin`.
- Debian 13 with Python 3.13 and systemd 247 or later (`LoadCredential=`). The key module derives the
  public half itself and needs no cryptography library and no OpenSSH.
- `/etc/branchleft` made by `host_inputs`, and the other two parents by the roles before this one.
- Only `ops1` may apply it, by the owner's host-role list (rule R9).

## What it changes on a host

| Path                                                               | Owner                     | Mode   | What                                        |
| ------------------------------------------------------------------ | ------------------------- | ------ | ------------------------------------------- |
| `provisioning-controller` (account and group)                      | system                    |        | No login, no home                           |
| `/etc/branchleft/provisioning-controller`                          | root                      | `0755` | Config directory                            |
| `.../ssh`                                                          | root                      | `0700` | Holds the key and nothing else              |
| `.../ssh/id_ed25519`                                               | root                      | `0400` | The private key (Ed25519, OpenSSH)          |
| `.../ssh.pub`                                                      | root                      | `0444` | The public half, one `authorized_keys` line |
| `.../config.json`                                                  | `provisioning-controller` | `0600` | The run configuration                       |
| `.../register.json`                                                | `provisioning-controller` | `0644` | The demo tenant's register entry            |
| `.../ssh_config`, `.../known_hosts`                                | root                      | `0644` | Only with the route inputs set              |
| `/var/lib/branchleft/provisioning-controller`, `inputs`, `escrow`  | `provisioning-controller` | `0700` | State, the controller's inputs, escrow      |
| `/opt/branchleft/provisioning-controller`, `releases`              | root                      | `0755` | Base and releases directories               |
| `.../provisioning-controller-pass`, `-steps`                       | root                      | `0755` | The two programs this role ships            |
| `.../releases/<sha256>`, `.../current`                             | root                      | link   | Only when a digest is set                   |
| `/etc/systemd/system/provisioning-controller.{service,path,timer}` | root                      | `0644` | The three units                             |

Nothing else. A canary test holds that no path outside these changes.

## The approval trigger

The controller's executor takes one approval id per run. The ledger of approvals is
`approvals.json` in the state directory (the portal writes it); the executor writes `run-state.jsonl`
beside it and records `run-complete` for an approval that has finished.

`provisioning-controller.service` is a oneshot that runs the pass program
(`provisioning-controller-pass`). The pass reads the ledger and the state file, and runs the executor
once for every approval id that has no `run-complete` record. It runs nothing for a complete
approval, and refuses (naming a code and a path, never content) a ledger or state file that is a
link, not a regular file, too big, writable by others or damaged. The path unit
`provisioning-controller.path` starts the service when `approvals.json` changes, and the timer
(two minutes after boot, then ten minutes after each run ends) picks up a run that stopped part way
or an approval written while the unit was off. A service run is the account's, never root's, with
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome` and `PrivateTmp`; the one writable path is
the state directory, and `PATH` is fixed.

A missing bundle is not an error: the service has `ConditionPathExists` on the bundle program, so
before the first digest a trigger does nothing.

## The three controller steps

Three steps the controller dispatches to command hosts have no program in the controller. The controller's
builder asked this role to decide how `ops1` provides each, in no-touch form:

- `confirm-register-assignment`: provided by `provisioning-controller-steps`, a small typed program
  the role installs. It reads the delivered register and answers the step's inputs: exit 0 when the
  slot's entry exists once with the same port, uid, bucket and folder; exit 3 (permanent) otherwise,
  and also when another entry holds the same port, uid, bucket, folder or state folder. A refused
  register is a bad assignment and is never retried.
- `escrow-stack-passphrase`: provided by the same program. It makes one 43-character random
  passphrase per `STACK_PASSPHRASE_<slot>` name, writes it to a `0600` file in the escrow directory
  (the account's, `0700`), prints nothing, and never makes it again when the file exists (a file
  that is not fit, wide, empty or a link, is refused and left alone). The passphrase never leaves
  the host and no person sees it. Taking it from the escrow into the tenant's stack is a later
  step of the controller.
- `create-owner-account`: **needs product code in ghost-platform**, since the account is made inside
  the tenant's Ghost, and no host program can do it. Until it
  lands the step has no program and a run stops there; this role leaves it unconfigured on purpose
  rather than wiring a stand-in that would report success.

## How the key is made

The module generates 32 random bytes and writes them as an OpenSSH `ssh-ed25519` private key in the
format `ssh` reads. It writes into a temporary name in the `0700` directory, created `O_EXCL` and
`O_NOFOLLOW` with mode `0400` at once through a directory file descriptor, so no moment exists at
which the file is readable by anyone but root, whatever the umask. It syncs the file and publishes
it by a hard link to the final name. A link fails if the name exists, so an existing key is never
replaced, and a crash leaves at worst an orphan temporary file or a whole key with a second name
(mended by the next run), never part of a key at the final name.

The public half is derived inside the module (RFC 8032, section 5.1.5, in pure Python) and returned
as one `ssh-ed25519` line. The module never writes it: the role writes it from the result, so the
role never reads the private file. The unit tests check the derivation against the RFC's vectors and
against the pinned `cryptography` package, and `ssh-keygen -y` of a generated key matches the line.

An existing key is accepted only if it is a regular file with one link (or one more for its own
leftover temporary name), of modest size, owned by root, with no group or other permission bit and
holding exactly the key the module would write. A key another account owns or that others can read
may already be known to them, so it is **refused** before it is read, not corrected. A mode narrower
than `0400` is adopted. A key that is lost (the public file is there and the key is not) is refused
and not made again, because a new key would change what others trust, which is the owner's act. A
refusal is a fixed code and a path (`E-KEY-MODE-WIDE`, `E-KEY-OWNER`, `E-KEY-LOST`, `E-DIR-FOREIGN`,
`E-KEY-LINKED`, `E-KEY-FORM`, `E-PUB-MISMATCH` and others, listed in the module's header).

## How the key reaches the controller, and how it never leaves

The key stays root's, mode `0400`, and the account never opens it. The service unit has one
`LoadCredential=` line naming the key file; systemd, which is root, hands the process a private copy
for that run only, in a directory the account can read and which is gone when the run ends. The
controller's `sshEntry.keyFile` is that runtime path. No sudoers entry, helper program or second
daemon is added.

The private key is made and judged inside the module's process. It is never a return value, a task
variable, a command-line argument, an environment variable or a message. The key task has
`no_log: true` and `diff: false` (ANS-16). The role has no `slurp`, `fetch`, `command`, `shell`,
`pipe`, `lookup` or `copy` that names the key, and no other task names its path: the unit tests read
the tasks and fail on any. The text of a refusal is read by an `assert` after the hidden task, so a
stop shows its code and path although the task is hidden.

`LoadCredential=` reads as a credential assignment to the plan-diff secret scan and cannot be
reworded, so the service unit's diff is hidden (a list in `vars/main.yml`, a task with `diff: false`
and a test that holds the split). The path and timer diffs are shown.

The SSH client file names the key for the two jump addresses only, so the key is never offered to the
tenant hosts. The network reach of the key (what it may log in to) is separate work.

## How to test it

From the repository root, with the pinned tools installed as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/provisioning_controller_host
.venv/bin/python ansible/harness/run_harness.py ansible/roles/provisioning_controller_host --scenario bundle
.venv/bin/python ansible/harness/run_harness.py ansible/roles/provisioning_controller_host --scenario refusals
```

The unit tests, from `ansible/roles/provisioning_controller_host`:

```text
PYTHONPATH=files:library python -m unittest discover -b -s tests/unit -p 'test_*.py'
```

- `default`: no inputs. Checks owners and modes (key `0400` alone in a `0700` directory), that the
  account cannot read the key on disk, the public line against the printed log, that a rerun changes
  nothing and keeps the key's inode, that the units are installed and disabled, and the on-instance
  scan: the key's body searched for over `/`, where the only hit must be the key path, with a planted
  decoy as the control that the search can find a key.
- `bundle`: a stand-in executor bundle. A wrong digest fails and leaves no link, no enablement; a
  non-executable program is refused; the good bundle with all six route inputs links, installs
  the config and known hosts, and enables the path and timer. It runs the pass as the account over a
  ledger of three approvals (one complete, one stuck): the complete one is never run, and the stuck
  one is run again on the next pass. It runs the steps program: register exit codes, escrow mode.
- `refusals`: each bad state (key lost, wide mode, other owner, link, hard link, not a key, a foreign
  file, a writable parent) and each bad input, with the exact message, no value in it, and no change
  to any path.

The container cannot give systemd's sandbox its namespaces, so the Molecule pass runs as the account
through `runuser`, and the units are judged as installed and enabled; the unit text is held by the
unit tests.

## How it is delivered

Delivery is the gated workflow only (ANS-17): a plan in check mode, the `ansible-hosts` approval, a
pull of that exact commit on the host, and a second run that must report zero changes. Nobody
generates, reads or carries a private key.

Wiring the role to `ops1` is owner-merged and is its own change (R9, R10, R11): the host-role list
(`ansible/checks/host_roles/ops1.yml`), `ansible/playbooks/ops1.yml`, `ansible/owner_vars/ops1.yml`,
the enrolment check, and `.github/CODEOWNERS` plus `KEY_ROLE_PATHS` in `checks/test_codeowners.py`
(a role that makes a key is owner-owned). The controller bundle's publish workflow in ghost-platform
is a separate piece of work: the owner's digest and URL come from it.

On a fresh host the plan cannot show the public half, which exists only after the apply. The first
apply writes `ssh.pub` and prints the line in a task named "Record the public half of the ssh key"; registering it at the jump hosts is separate work.

## Why a bundle by digest

The controller could instead run as a portal-apps container image. The role installs a bundle held
to a SHA-256 beside the host because the executor must run as the account on the host, read a
credential systemd gives it, and write the ledger's files directly; a container would need the key
and the ledger mounted into it. The release directory is named by the digest, and `current` moves
only after the program is checked, so a rollback is a digest change.

## How to change it safely

- A change to the module, the unit or the tasks changes how a private key is made and handed over, so
  it gets the deep review a key-handling role gets, and the owner's.
- The config keys, the program names and the layout `bin/provisioning-controller` in the bundle are
  the contract with the controller. A unit test holds the config's keys to the ones the controller
  accepts. Change both sides in step.
- Keep the module's names and modes equal to `vars/main.yml`; a unit test holds them together.
- Do not add a return value, task or log line that depends on the private key.

## Named limits

- **The key is root's, and only systemd hands it on.** A person with root on `ops1` can read it.
- **Check mode on a fresh host shows less.** With no account or directory yet, the tasks that need
  them are skipped, and a download is not made.
- **A wrong digest leaves an empty release directory.** The download stops at the checksum before
  anything is unpacked and before `current` moves.
- **Clearing the digest holds the units off; it does not remove the last release.**
- **`create-owner-account` has no program** until the owner-account issue lands, so a full run stops at that step.
- **The key reaches no host yet** and the ledger is written by the approval portal: until both exist the
  service has nothing to run.
- **The test platform is a container.** It does not prove that systemd hands the controller the key
  at a tick, which is the first real tick.

## Clauses this role exercises

ANS-2 and ANS-9 (typed modules, no shell), ANS-7 (defaults mirror the spec), ANS-10 (check mode),
ANS-11 (idempotence), ANS-12 (no role imports another), ANS-14 (this README), ANS-15 (a container
test), ANS-16 (`no_log` and `diff: false` where a key passes) and ANS-17 (the gated pull).
