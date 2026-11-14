# ring_controller_host

This role makes the host side of the ring controller on `ops1`: a service account of its own, the
controller's record-signing key (generated on the host, root's, mode `0400`), a bundle installed by
digest when a digest is given, a service unit and a timer, and an environment file of public
values. It writes the key's public half to a world-readable file and prints it, so the people who
must trust it can be told which key to trust.

**The unit and the timer are inert until the bundle digest input is set.** With the digest empty the
role installs both unit files, holds the timer disabled and stopped, installs no bundle and points
nothing at one. Setting the digest is the one step that turns the controller on.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

The ring controller is a program that takes one release step on each tick of a timer and keeps its
own signed, hash-chained log of every slot it promotes. This role puts the host in the state the
program needs and installs the program the owner has named by digest. It does not build the
program, does not run it by hand, and has no agent in the loop: the unit has no model key and its
`PATH` holds no agent program. It holds no push key, no push remote and no pinned host key: the
controller pushes nothing, and the log lives on the host.

The role:

1. Checks, and never makes or changes, `/etc/branchleft`, `/opt/branchleft` and
   `/var/lib/branchleft`: each must be a real directory that is root's and that group and others
   cannot write.
2. Makes the system account and group `ring-controller` (no login shell, no home directory). The
   controller is not run as root: `ops1` holds other roles' root-only files and the owner's own
   data, and an account of its own cannot read them.
3. Makes the directories it owns: `/etc/branchleft/ring-controller` (config), the release
   directories under `/opt/branchleft/ring-controller`, and the state directory
   `/var/lib/branchleft/ring-controller`, which is the account's and closed to everyone else.
4. Calls one module, `ring_controller_host_record_key`, which generates the record-signing key if
   it is absent and leaves an existing one exactly as it is (see "How the key is made").
5. Writes the key's public half, which the module returns, to `record-signing.pub` (root's, mode
   `0444`) and prints it in a `debug` task. That is the recorded, non-secret output of the first
   apply.
6. When a digest is set: downloads the bundle held to that digest, unpacks it into a release
   directory named by the digest, requires `bin/ring-controller` to be a root-owned executable
   that no one else can write, and only then points `current` at the release.
7. Writes the environment file, installs the two units, reloads systemd, and holds the timer on
   or off by the digest.

It does not put the public half anywhere else (the owner copies it from
the apply's output and commits it, see "How it is delivered"), does not escrow the private key,
and does not rotate it. To rotate, a person removes the key file and the public file and the next
apply generates a new key; the role refuses to do that by itself when the key has gone and the
public file is still there.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the two inputs. Both are public
values and neither is a secret, so neither needs a `host_inputs` entry. Both default to empty, and an empty
value is valid: the role then does what it can without it. The owner's values live in
`ansible/owner_vars/ops1.yml`, a file only the owner merges.

| Variable                             | Default | Meaning                                                                       |
| ------------------------------------ | ------- | ----------------------------------------------------------------------------- |
| `ring_controller_host_bundle_sha256` | empty   | The SHA-256 of the bundle, 64 lowercase hex digits. Empty keeps the timer off |
| `ring_controller_host_bundle_url`    | empty   | The https URL the bundle is fetched from, with no credential in it            |

Each is checked by its own task before anything changes, and a refusal names the input and never
its value. A set digest needs the bundle URL: a bundle with nowhere to fetch it from cannot be run, so the
role names the missing one and stops. The shapes
are patterns in `vars/main.yml`; none admits a space, a quote, a backslash, a dollar sign or a
hash, so each value is one plain word in the environment file.

The role used to take two more inputs, for a push remote and for a pinned host key, and used to make
a push key. They are gone. A third, `ring_controller_host_ledger_url`, is gone too: the controller
reads nothing from its environment, so no name for it is written to the environment file. The role's
first task refuses the old name, even when it is empty, naming the input and never a value, so an
`owner_vars` file that still sets it stops the run before anything changes; the owner-vars check
refuses it as well. Ansible refuses an input that is not in the spec only when it is passed
as a role parameter (a `roles:` entry's own keys); a play variable or an `owner_vars` value is
never read against the spec, so the owner-vars check (rule R10 in `ansible/checks`) is what
refuses an old input in `owner_vars/ops1.yml`. A unit test holds the spec to exactly the two names
above, and another holds the old names out of the spec, the defaults, the patterns, the template and
the check's allowed keys.

The paths, names, modes and the account are constants in `vars/main.yml`, not inputs: an inventory
value cannot move them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Python 3.13 and systemd 247 or later (it has `LoadCredential=`, and Debian 13
  ships 257). The module derives the public half itself and needs no cryptography library and no
  OpenSSH.
- `/etc/branchleft` made by `host_inputs`, and the other two parents made by the roles that run
  before this one on `ops1`.
- Only `ops1` may apply it. That is the owner's list (`ansible/checks/host_roles.yml`, rule R9); a
  test inside the role would be no control, because under the pull inventory the host's name is
  `localhost`.

## What it changes on a host

| Path                                                                | Owner             | Mode   | What                                      |
| ------------------------------------------------------------------- | ----------------- | ------ | ----------------------------------------- |
| `ring-controller` (account and group)                               | system            |        | No login, no home                         |
| `/etc/branchleft/ring-controller`                                   | root              | `0755` | Config directory                          |
| `/etc/branchleft/ring-controller/record-signing`                    | root              | `0700` | Holds the key and nothing else            |
| `/etc/branchleft/ring-controller/record-signing/record-signing.key` | root              | `0400` | The record-signing private key (Ed25519)  |
| `/etc/branchleft/ring-controller/record-signing.pub`                | root              | `0444` | The public half, as an SPKI PEM           |
| `/etc/branchleft/ring-controller/ring-controller.env`               | root              | `0644` | Public values, an exact list of 3 names   |
| `/var/lib/branchleft/ring-controller`                               | `ring-controller` | `0700` | State directory                           |
| `/opt/branchleft/ring-controller`, `releases`                       | root              | `0755` | Base and releases directories             |
| `/opt/branchleft/ring-controller/releases/<sha256>`                 | root              | `0755` | One release, only when a digest is set    |
| `/opt/branchleft/ring-controller/current`                           | root              | link   | To the release, only when a digest is set |
| `/etc/systemd/system/ring-controller.service` and `.timer`          | root              | `0644` | The two units                             |

Nothing else. A canary test holds that nothing outside these paths changes.

## How the key is made

The module generates the key as 32 random bytes and writes them as a PKCS8 PEM (the form
`node:crypto` reads; RFC 8410), one 64-character line. It writes the key into a temporary name in
the `0700` directory, created `O_EXCL` and `O_NOFOLLOW` with the mode `0400` at once, so no
moment exists at which the file is readable by anyone but root, whatever the umask. It syncs the
file and publishes it by a hard link to the final name. A link fails if the name exists, so an
existing key is never replaced, and a crash leaves at worst an orphan temporary file or a whole key
with a second name (mended by the next run, below), never part of a key at the final name. The directory is made with the mode `0700` in the same call.

The public half is derived inside the module (RFC 8032, section 5.1.5, in pure Python) and returned
as an SPKI PEM. The module never writes it: the role writes it from the result, so the role never
reads the private file. The unit tests check the derivation against the RFC's vectors and, for
200 seeds, against the pinned `cryptography` package, and check that the library reads the
module's PEM as the same key.

An existing key is accepted only if it is a regular file with one link (or one more for its own
leftover temporary name, below), of modest size, owned by
root, with no group or other permission bit, and holding exactly the canonical PEM of one Ed25519
key. A key another account owns, or one readable by anyone else, may already be known to them, so
it is **refused** before it is read, not corrected. A mode narrower than `0400` is adopted: the
module sets `0400` through the open file's descriptor and never touches the bytes. A refusal is a
fixed code and a path:

| Code                 | Meaning                                                                           |
| -------------------- | --------------------------------------------------------------------------------- |
| `E-ARGS`             | A path is not absolute and normal, or the public file is inside the key directory |
| `E-NOT-ROOT`         | The module is not running as root                                                 |
| `E-PARENT`           | The parent of the key directory is missing, a link, not root's or writable        |
| `E-DIR`              | The directory path is a link, a file, or cannot be made or opened                 |
| `E-DIR-OWNER`        | The directory is not root's                                                       |
| `E-DIR-FOREIGN`      | The directory holds a file the role does not own                                  |
| `E-TEMP-NOT-A-FILE`  | A temporary name is held by a link or a directory                                 |
| `E-KEY-OPEN`         | The key cannot be opened (a link in its place, for one)                           |
| `E-KEY-NOT-REGULAR`  | The key is a directory, a pipe or another special file                            |
| `E-KEY-LINKED`       | The key has a hard link that is not one of its own leftover temporary names       |
| `E-KEY-SIZE`         | The key file is too big (it is not read)                                          |
| `E-KEY-OWNER`        | The key is not root's (it is not read)                                            |
| `E-KEY-MODE-WIDE`    | The key has a group or other permission bit (it is not read)                      |
| `E-KEY-FORM`         | The text is not the canonical PEM of one Ed25519 key                              |
| `E-PUB-MISMATCH`     | The public file is not exactly the half derived from this key                     |
| `E-KEY-LOST`         | The public file is there and the key, or its directory, has gone                  |
| `E-IO`, `E-INTERNAL` | An operating-system error (errno name only) or any other error (type name)        |

A key that is lost is refused and not made again: a new key would change what others trust, which
is the owner's act.

**A run that stopped between the link and the unlink.** The key is published by a hard link from its
temporary name, and the temporary name is removed after. A run that dies between the two leaves the
key with two names. The next apply mends that itself, and only that: the extra name must be a
temporary name in the key's own directory that is the very same file as the key (same device and
inode), and the key must have no other link. A link made anywhere else, a copy under the temporary
name, or a third name is still refused as `E-KEY-LINKED`. When the public file is already there it
must also be exactly the half derived from the key, a regular file and not a link; if it is
anything else the run is refused as `E-PUB-MISMATCH` and the key is left with both names, so a
substituted pair is never accepted. A public file that is absent is not a mismatch, because the
role writes it from the module's result after the key is made. The mend removes the extra name
only, never the key, and the key's inode, bytes, mode and owner are unchanged. Check mode plans the
mend and runs the same comparison. The public file is compared only while a key has two names; a
mismatch at any other time is not looked for by this module.

## How the key reaches the controller

The key stays root's, mode `0400`, in a root-only directory, and the controller account never opens
it. The service unit has one `LoadCredential=` line naming the key file. systemd, which is root,
reads the file when it starts the service and gives the process a private copy in the directory its
`CREDENTIALS_DIRECTORY` names, readable by the service account for that run only and gone when it
ends. The controller reads the key from there, under the name in
`RING_CONTROLLER_RECORD_SIGNING_KEY_NAME`. No sudoers entry, helper program or second daemon is
added, and the environment file holds the key's name and the public file's path, never the key.

The line is a directive whose name the plan's secret scan reads as a credential assignment, and it
cannot be reworded. The plan therefore does not show the service unit's diff (a hidden list in
`vars/main.yml`, a task with `diff: false` and a test that holds the split), and the timer's diff is
shown. Read the service unit from the commit.

## How the private key stays out of every log

The private key is made and judged inside the module's process and never leaves it. It is never a
return value, a task variable, a command-line argument, an environment variable, a file the
controller reads from the disk, or part of a message. The task that calls the module has
`no_log: true` and `diff: false` (ANS-16). The role has no lookup, `slurp`, `pipe`, `command`,
`shell` or `stat` of the private key, and no other task names its path; the unit tests read the
tasks and fail on any of them. The text of a refusal is read out by an `assert` after the hidden
task, so a stop shows its code and path although the task is hidden.

The environment file holds three names, an exact list: the key's name under the
credentials directory, the path of the public file and the state directory. It holds no key and no
token, and the unit file does not name a model key or an agent program. The list of names the
controller refuses to run with lives with the controller, which refuses at its own start; the role
does not restate it, so there is one home for it.

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
change nothing). It checks the key's owner and mode (root, `0400`, alone in a `0700` root directory),
that the service account cannot read the key on disk while root can (a control on the probe), that
the unit holds the `LoadCredential=` line (systemd's status output does not list it), that the
public half printed is the file's and is one SPKI key, that a rerun leaves the private file alone, that the unit's
environment holds exactly the three names, no name ending in `_API_KEY` and nothing starting
`ANTHROPIC_`, that `PATH` finds no `claude` (with a control that finds one when it is planted), that
the timer is disabled and stopped, and that files of other roles are exactly as they were. It runs
at verbosity 3 and scans the controller's log and every file the run left there for the key's text,
after showing the scan can find a key-shaped control text. The `bundle` scenario fetches two stand-in
bundles over `file://` and checks the digest pin (a wrong digest stops at the download), the program
check, the link, the timer turning on and off with the digest, and the environment file. The
`refusals` scenario puts the host in each bad state or gives each bad input, and requires the role's
exact message, no value in it, and no change to any path it writes.

The sabotage controls, each red when its guard is removed: `test_existing_key_is_never_overwritten`
(the guard that leaves an existing key alone), `test_a_new_key_is_root_only_0400_in_a_0700_directory`
and `test_the_key_is_never_wider_than_0400_at_any_moment` (the creation mode and the mode-safe
open), `test_a_key_another_account_owns_is_refused_before_it_is_read` (root-only),
`test_a_key_that_has_gone_is_not_made_again_while_its_public_half_is_there` (the lost-key refusal),
`test_the_two_name_key_of_a_crash_is_mended` (the allowance for the key's own extra name),
`test_a_public_file_that_is_not_the_derived_half_stops_the_mend` (the comparison) and
`test_an_extra_name_for_another_file_is_not_a_mend` (the same-file test),
`test_the_key_reaches_the_account_by_one_systemd_load_and_nothing_else` (the credential wiring in the
unit file), `test_an_old_push_input_is_refused_by_the_argument_spec_as_ansible_reads_it` and
`test_no_shipped_file_names_a_retired_push_input_or_key_tool` (the removed inputs),
the log scan (a key task without `no_log`), the environment test (a model key name in the
template), the unit test of `get_url` with its `checksum` (the inert-until-digest and digest-pin
guard), `test_check_host_roles.py` (the role on any host but `ops1`), the canary comparison, and
`test_codeowners.py` (the owner line).

## How it is delivered

Delivery is the gated workflow only (ANS-17): a plan in check mode, the `ansible-hosts` approval, a
pull of that exact commit on the host, and a second run that must report zero changes. Nothing
here applies the role by hand, and nobody generates, reads or carries a private key.

The lists that wire the role to `ops1` are owner-merged paths (`ansible/checks/host_roles.yml`,
`ansible/playbooks/ops1.yml`, `ansible/owner_vars/ops1.yml`, `.github/CODEOWNERS`).

On a fresh host the plan (check mode) shows the key as "would create" and cannot show the public
half, which exists only after the apply. The first apply writes `record-signing.pub` and prints the
half in a task named "Record the public half of the record-signing key"; the second run reports no
change and prints the same text. The public half cannot be known before the key exists, so
committing it is an owner step that follows the first apply: the owner reads it from the apply's
output (or reads `record-signing.pub` on `ops1`) and commits it, which is how it reaches every
host that verifies a signed record. The role does not place it anywhere else.

## How to change it safely

- A change to the module, the unit or the tasks is a change to how a private key is made and handed
  over on the host, so it gets the deep review a key-handling role gets, and the owner's: the role's directory is owned in
  `.github/CODEOWNERS` by the owner, and `test_codeowners.py` mirrors that line.
- The environment names and the layout `bin/ring-controller` inside the bundle are the contract with
  the controller's own bundle. A change to either is a change to both sides, in step.
- Keep the module's names and modes equal to `vars/main.yml`; a unit test holds them together.
- The module must keep a private key out of every output. Do not add a return value that depends on
  one, and do not put a lookup, a `slurp` or a `stat` of a private key in a task.
- Do not add a model key, a token or an agent program's directory to the unit's environment or
  `PATH`.

## Named limits

- **The key is root's, and only systemd hands it on.** The service account never opens the file.
  A person with root on `ops1` can read it, as with every root-only file there.
- **Check mode on a fresh host shows less.** With no account or config directory yet, the tasks that
  need them are skipped and the plan prints "not yet made" for the public half. A download is not
  made in check mode, so the bundle tasks cannot show what a digest would fetch.
- **A wrong digest leaves an empty release directory.** The download stops at the checksum, before
  anything is unpacked and before `current` moves, but the directory named by that digest was made
  first. It holds nothing and is harmless.
- **`current` is not removed when the digest is cleared.** Clearing the digest holds the timer off;
  it does not delete the last release or unlink it. Removing a release is a person's act.
- **The environment names and the bundle layout are a proposal until the bundle exists.** They are
  the contract with the controller's bundle and are fixed here so that both sides build to one
  text.
- **The test platform is a container.** It proves the files, owners, modes, the units' text and
  systemd's view of the timer and of the credential line; it does not prove that systemd hands the
  controller the key at a tick, which is the first real tick.
- **A file left behind by the earlier version of this role is not removed.** If the earlier version
  was ever applied, its `keys` directory (two OpenSSH keys, one for signing and one for
  pushing, the account's) and its pinned host-key file are still on the host, unused. Removing them is a
  person's act; nothing reads them.

## Clauses this role exercises

ANS-2 and ANS-9 (a typed module, no shell), ANS-7 (defaults mirror the spec), ANS-10 (check mode),
ANS-11 (idempotence), ANS-12 (no role imports another), ANS-14 (this README), ANS-15 (a container
test), ANS-16 (`no_log` and `diff: false` where a key passes) and ANS-17 (the gated pull).
