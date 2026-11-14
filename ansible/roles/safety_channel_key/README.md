# safety_channel_key

This role makes the request-signing key of the content-safety service on the host that runs
it: it generates the key the first time, on the host, and never again, and it prints the matching
public half so the other end of the verdict channel can be told which key to trust.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

The safety service signs every request it sends to a host with an Ed25519 key, in the
`x-broker-signature` header. The key is the **base64 text of 32 random bytes**, in a file the
service reads (`channel.signingKeyFile` in `branchLeft/content-safety`). The service refuses a
file that group or others can read, and a text that is not the canonical base64 of exactly 32
bytes. Hosts hold only the public half, which is not a secret. The key is not a signature on a
verdict: it signs requests, and the service owns it.

The role calls one module, `safety_channel_key`, which:

1. Checks that `/etc/branchleft` exists, is a real directory, is root's and cannot be written by
   group or others. It does not make that directory (`host_inputs` does, R11).
2. Makes `/etc/branchleft/content-safety` (mode `0700`, owned by the key's owner) if it is absent.
3. Leaves an existing, valid key exactly as it is. It generates a key only when the key file is
   absent.
4. Writes the public half beside it and returns it. The apply prints it in one `debug` task, which
   is the recorded, non-secret output of the first apply.

It does not install, start or configure the safety service (that is a
separate work item), does not
create the account the service runs as, does not place the public half in the host end of the
channel, does not escrow or back up the key (losing it costs a regenerate and a re-pin, so there is no
copy to keep), and does not rotate it. To rotate, a person removes the key file on the host and
the next apply generates a new one.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the two inputs and Ansible checks
them when the role starts. Neither is a secret and neither needs a `host_inputs` entry.

| Variable                   | Default | Meaning                                                           |
| -------------------------- | ------- | ----------------------------------------------------------------- |
| `safety_channel_key_owner` | `root`  | The account that owns the directory, the key and the public file. |
| `safety_channel_key_group` | `root`  | The group that owns them.                                         |

The default is `root:root` until the safety service has a definition that names the account it
runs as. A service that does not run as root cannot read a root-owned `0400` key, so a later
change sets the owner to that account, and the next apply **adopts** the existing key: it sets the
owner and the mode and never touches the bytes.

The directory, the file names and the modes are constants, not inputs (`vars/main.yml` and the
module hold them, and a unit test holds the two equal): an inventory value cannot move them.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with Python 3.13, which is all the module needs. It derives the public half
  itself (RFC 8032, section 5.1.5), so the host needs no cryptography library.
- `/etc/branchleft` made by `host_inputs`, which goes first on `ops1`.
- The account and group named by the inputs exist on the host.

## What it changes on a host

| Path                                                 | Owner     | Mode   | What                                    |
| ---------------------------------------------------- | --------- | ------ | --------------------------------------- |
| `/etc/branchleft/content-safety`                     | key owner | `0700` | The directory that holds both files     |
| `/etc/branchleft/content-safety/channel-signing.key` | key owner | `0400` | The key: base64 of 32 bytes, no newline |
| `/etc/branchleft/content-safety/channel-signing.pub` | key owner | `0444` | The public half, base64 and a newline   |

Nothing else: no service, port, unit or package. The directory holds only those two names. A leftover temporary file from an interrupted run
(`.channel-signing.key.tmp-<16 hex>`, `.channel-signing.pub.tmp-<16 hex>`) is removed at the start
of the next run and counted in `temp_cleaned`; any other file in the directory is refused.

## How the key is made

The module writes the key to a temporary file in the same `0700` directory (created `O_EXCL` and
`O_NOFOLLOW`, mode `0400`), syncs it, and publishes it with a hard link to the final name. A link
fails if the name exists, so an existing key is never replaced, and a crash leaves at worst an
orphan temporary file, never part of a key at the final name. If another writer publishes first,
its key stands and is judged like any existing key.

An existing key is accepted only if it is a regular file with one link, at most 64 bytes, and holds
the canonical base64 of exactly 32 bytes with no whitespace. Its mode is checked first, and a mode
with any group or other bit is **refused**, not corrected: such a key may already be known to
someone. A different owner, or a mode with no group or other bit (`0600`, say), is **adopted**:
the module sets the owner and sets the mode to `0400`, through the open file's descriptor, and
reports a change. Everything else is refused, and a refusal is a fixed code and the path:

| Code                 | Meaning                                                                             |
| -------------------- | ----------------------------------------------------------------------------------- |
| `E-ARGS`             | The directory is not an absolute, normal path, or a name is malformed               |
| `E-OWNER-UNKNOWN`    | The host has no such account or group                                               |
| `E-PARENT`           | The parent is missing, a link, not root's or writable by others                     |
| `E-DIR`              | The directory path is a link, a file, or cannot be made or opened                   |
| `E-DIR-FOREIGN`      | The directory holds a file the role does not own                                    |
| `E-TEMP-NOT-A-FILE`  | A temporary name is held by a link or a directory                                   |
| `E-KEY-OPEN`         | The key cannot be opened (a link in its place, for one)                             |
| `E-KEY-NOT-REGULAR`  | The key is a directory, a pipe or another special file                              |
| `E-KEY-LINKED`       | The key has more than one hard link                                                 |
| `E-KEY-SIZE`         | The key file is bigger than 64 bytes (it is not read)                               |
| `E-KEY-MODE-WIDE`    | The key has a group or other permission bit (it is not read)                        |
| `E-KEY-FORM`         | The text is not the canonical base64 of 32 bytes                                    |
| `E-PUB`              | The public name is held by something a rename cannot replace                        |
| `E-IO`, `E-INTERNAL` | An operating-system error (errno name only) or any other error (its type name only) |

The public half is rewritten, and reported as `public_changed` once, when its file is missing,
differs, or has another owner or mode. It is not a secret and is replaced by a rename, so a link
in its place is replaced, not followed.

## How the seed is kept out of every log

The seed is read and written inside the module's process and nowhere else. It is never a return
value, a task variable, a command-line argument, an environment variable, a file the controller
reads, or any part of a message. The task that calls the module has `no_log: true` and
`diff: false` (ANS-16). The role has no lookup, query, pipe, `slurp` or `stat` of the key, and no
shell, command or script; the unit tests read the tasks and fail on any of them. The text of a
refusal is read out by an `assert` after the hidden task, as `deploy_slot_keys` does, so a stop
shows its code and path although the task is hidden.

## How to test it

From the repository root, with the pinned tools installed as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/safety_channel_key
.venv/bin/python ansible/harness/run_harness.py ansible/roles/safety_channel_key --scenario refusals
```

The module has unit tests. From `ansible/roles/safety_channel_key`:

```text
PYTHONPATH=files:library python -m unittest discover -b -s tests/unit -p 'test_*.py'
```

The unit tests cover the derivation against the RFC 8032 vectors and the pinned `cryptography`
package, the create, adopt and refuse paths, the interrupted create and the lost race, check mode,
and the absence of the seed from every return, refusal and print. The sabotage control is
`test_existing_key_is_never_overwritten`: if the guard that leaves an existing key alone is
removed, it fails.

The Molecule `default` scenario converges twice (the second must change nothing), checks the
files' owner and mode, that the key is 44 characters decoding to 32 bytes, that the public file
equals what the apply printed, that a rerun leaves the key's bytes alone, and the adopt path
(another owner, back to root, and a `0600` mode back to `0400`) with the bytes unchanged. It
runs at verbosity 3 and scans the controller's log and every file the run left there for the
key's text and for the form `slurp` prints it in, after showing the scan can find a key-shaped
control text. The `refusals` scenario puts the host in each bad state and requires the role's
exact message and an untouched key.

## How it is delivered

Delivery is the gated workflow only (ANS-17): a plan in check mode, the `ansible-hosts` approval,
a pull of that exact commit on the host, and a second run that must report zero changes. Nothing
here applies the role by hand, and nobody generates, reads or carries the key.

Wiring the role to `ops1` is the owner's merge, because the lists it edits are owner-merged paths
(`ansible/checks/host_roles.yml`, `ansible/playbooks/ops1.yml`, `.github/CODEOWNERS`). Until that
merge nothing applies the role.

On a fresh host the plan (check mode) shows the key as "would create" and cannot show the public
half, which exists only after the apply. The first apply creates the key and prints
`Channel signing public half (base64): ...`; the second run reports no change and prints the same
value. That value is what the host end of the channel pins; the role does not place it there.

## How to change it safely

- A change to the module or the tasks is a change to how a key is made on the control host, so it
  gets the deep review a key-handling role gets, and the owner's. The owner's wiring merge adds the
  role to `.github/CODEOWNERS` as the other key-making roles are.
- Keep the three pins equal: the module's `KEY_NAME`, `PUB_NAME` and modes, `vars/main.yml`, and the
  path the safety service is configured with. The unit test holds the first two together. A future
  role that installs the service pins its own copy of the key path with a test, as `ci_login` does
  for the jump account, and does not import this role (ANS-12).
- The module must keep the key out of every output. Do not add a return value that depends on the
  seed, and do not put a lookup, a `slurp` or a `stat` of the key in a task.
- To change the owner, set the two inputs. Do not edit the key.

## Named limits

- **Not constant-time.** The public half is derived in pure Python with big-integer arithmetic.
  It runs once on the host, as root, with no one timing it, and the seed is already in the file
  beside it. The unit tests check the result against the RFC and a library, not the timing.
- **The seed lives in process memory until the process ends.** Python cannot wipe a `bytes`
  object. The process is the module's, short-lived, and run as root on the host that holds the
  file anyway.
- **The reader is more lenient than the writer.** The service trims whitespace around the text; the
  module refuses it, so every key this role accepts is canonical and a hand-made key with a trailing
  newline is refused, not adopted. A person who made such a key replaces it by removing the file.
- **No directory fsync is promised against a power loss between the link and the sync.** The module
  syncs the file before it links it and syncs the directory after; a power loss in between can lose
  the link, and the next run then generates a key again. It cannot produce a part of a key.
- **Ownership of the directory is the key owner's.** Under a non-root owner the directory is
  owned by that account, so that the account can enter it; root can always enter it.
- **A key the module did not make but that is valid is accepted.** The role cannot tell a
  generated key from a hand-made one; both are left alone.
- **Check mode on a fresh host shows only "would create".** The public half cannot be known before
  the key exists, so the plan prints "not yet made".
- **The test platform is a container.** It proves the files, owners and modes, and the log; it does
  not prove that the safety service accepts the key. That is the service's own test of the same
  text, and the first real run of the channel.

## Clauses this role exercises

ANS-2 and ANS-9 (a typed module, no shell), ANS-7 (defaults mirror the spec), ANS-10 (check mode),
ANS-11 (idempotence), ANS-12 (no role imports another), ANS-14 (this README), ANS-15 (a container
test), ANS-16 (`no_log` and `diff: false` where a value passes) and ANS-17 (the gated pull).
