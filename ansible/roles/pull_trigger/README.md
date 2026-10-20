# pull_trigger

Installs on a host the one program that applies an exact, signed commit of this
repository's `main` to that host, and nothing else.

This README is written for a maintainer who is new to the repository. It follows
the order the standard sets for a role README (ANS-14).

**Status: built on the gated pull (ANS-17).** The design assumes the host pulls,
after the deployment gate, an exact commit it verifies itself. If the owner
decides on a gated push instead, this role is not the shape that decision needs
and the work is discarded, not adapted.

## What the role does, and what it does not

The role installs `pull-trigger`, a single typed Python program, at
`/usr/local/sbin/pull-trigger`, with its configuration in
`/etc/pull-trigger/config.json` and two private directories (state and log). It
installs the four programs the trigger runs (`git`, `gpg`, `gpgconf`, `ssh-keygen`),
from the packages `git`, `gpg`, `gpgconf` and `openssh-client`.

The program is meant to be the only thing a CI key can run. A CI job holds an SSH
key whose `authorized_keys` line is restricted to this one command (see "How a
caller uses it"). The caller sends one 40-digit commit id and a mode, `apply` or
`check`. The program then:

1. Reads its configuration and makes its state and log directories, then
   validates the request before it touches the repository: the whole text is one
   commit of exactly 40 lowercase hex digits. A ref name, abbreviation, option,
   uppercase digit, whitespace, newline, second word or empty text is refused. No
   shell is used anywhere; every command is an argument list.
2. Checks that the host's configured playbook is on the playbook allowlist, then
   takes a single-flight lock. A second request while one runs is refused at
   once, not queued.
3. Fetches `main`, and only `main`, from the configured read-only remote into a
   root-owned bare cache. The host holds no credential that can write to the
   repository.
4. Refuses the commit unless it is an ancestor of the fetched tip of `main`. A
   commit that only another branch holds is never fetched; a commit that `main`
   has since moved away from is refused by the ancestor test.
5. Refuses a commit older than the last one applied on this host (the rollback
   floor).
6. Verifies the commit's signature with a throwaway keyring built from the
   allowlisted public keys. Unsigned, bad signature, and signed by a key not on
   the allowlist are three different refusals.
7. Checks that the host's playbook, taken from configuration and never from the
   caller, is a regular file in that commit. Checks out exactly that commit into
   a fresh root-owned directory (never in place), and checks again, on the disk,
   that no part of the playbook's path is a link and that its real path lies
   inside `ansible/playbooks/` of the checkout.
8. Runs `ansible-playbook` on that checkout for this host only (`-i localhost,
--connection local`), with `--check --diff` in check mode. It prints one
   summary line on standard output and sets a distinct exit status.

It does not run the second pass that proves the apply left nothing to change: the
apply workflow asks for a second request of the same commit (ANS-17) and reads
the exit status (0 means nothing more to change). It does not manage users, SSH
keys or sudoers (the `sudoers_and_keys` pattern does), install `ansible-playbook`
(the host must have one at `pull_trigger_ansible_playbook`), decide which
playbook a host runs beyond the one configured value, or hold any private key.

## Interface

The variables, their types, choices and defaults are in `meta/argument_specs.yml`
and the same defaults are in `defaults/main.yml`. Ansible checks them when the
role starts.

| Variable                        | Meaning                                                                                                     |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `pull_trigger_remote_url`       | The read-only remote: an `https://` or `file://` URL, no credential in it.                                  |
| `pull_trigger_signers`          | Non-empty list of `{format, key}`: `ssh` (one public key line) or `openpgp` (an armoured public key block). |
| `pull_trigger_playbooks`        | The playbook allowlist: plain relative paths under `ansible/playbooks/`.                                    |
| `pull_trigger_playbook`         | The one playbook this host runs; must be on the allowlist.                                                  |
| `pull_trigger_ansible_playbook` | Absolute path of `ansible-playbook` (default `/usr/local/bin/ansible-playbook`).                            |
| `pull_trigger_timeout_seconds`  | Time after which a playbook run is stopped (default 3600).                                                  |
| `pull_trigger_keep_runs`        | How many runs' output files to keep (default 50).                                                           |

No variable is a secret. The signers are public keys, and the configuration is
world-readable by design, so the role leaves the diff of the configuration
visible and sets no `no_log`. The program accepts an SSH signer only as one public
key line of a known key type, and an OpenPGP signer only as a block that opens
with the public key header and closes with its footer, so an SSH private key and
an armoured private key block are refused. It does not read the inside of an
OpenPGP block: a secret key whose header was changed to "PUBLIC KEY BLOCK" would
be accepted, and the configuration is world-readable. Keeping a private key out
of the variable is the caller's job, and the Molecule test asserts only that
the installed configuration of the test holds none. If a later
variable ever holds a secret, it must get `no_log: true` and `diff: false` on
every task that handles it (ANS-16).

The state directory is capped at 60 characters, because the GnuPG agent's socket
lives beneath it and a Unix socket path has a short limit.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`, for the
  role itself; the role's `min_ansible_version` is that version.
- No collections beyond `ansible.builtin`.
- Target system: Debian (the role installs packages with `apt`), Python 3.13 (the
  Debian 13 release), and an `ansible-playbook` on the host for the program to run.

## What it changes on a host

- Installs the packages `git`, `gpg`, `gpgconf` and `openssh-client`
  (`tasks/packages.yml`).
- `/usr/local/sbin/pull-trigger`: the program, owner root, mode 0755.
- `/etc/pull-trigger/` (root, 0755) and `config.json` in it (root, 0644).
- `/var/lib/pull-trigger/` (root, 0700): the cache, work directories, the
  rollback floor (`last-applied`), the lock and the `current` link, all made by
  the program on its first run.
- `/var/log/pull-trigger/` (root, 0700): `pull-trigger.log` (one line per run)
  and `runs/` (the playbook output of each run, newest `keep_runs` kept).

No services, ports or users, and no change to SSH. Wiring the forced command
into `authorized_keys` is the job of the `sudoers_and_keys` pattern.

## How a caller uses it

The `authorized_keys` line for the CI key (placeholder values; the pattern
writes it):

```text
restrict,from="ALLOWED_CIDR",command="/usr/local/sbin/pull-trigger --mode apply" ssh-ed25519 PUBLIC_KEY_PLACEHOLDER ci-apply
```

and a second key with `--mode check` for the plan job. The mode is fixed on the
`command=` side, so the caller cannot change it. What the caller types is the
whole content of `SSH_ORIGINAL_COMMAND`, and it must be the commit alone. For
a person on the host, the commit may instead be one positional word, and not both.

```text
ssh CI_USER@HOST 0123456789abcdef0123456789abcdef01234567
```

### Becoming root

The program must run as root (it refuses a state directory it does not own). Two
routes are supported:

- **The CI key is in root's own `authorized_keys`**, with the `command=` above.
  SSH then starts the program as root and hands it `SSH_ORIGINAL_COMMAND`. This
  route is not tested in the harness, which has no SSH server. It also depends on
  the host's SSH daemon letting root in by key: `PermitRootLogin` must be
  `prohibit-password` or `forced-commands-only`. With `no`, which is common, the key
  is refused before the command runs, and this role does not change the daemon's
  configuration.
- **The CI key belongs to a non-root account and the `command=` runs `sudo`.** On
  Debian 13, sudo drops `SSH_ORIGINAL_COMMAND`, so the program would see no
  request and answer exit 20 `bad-request`. Keep the variable for this one
  program only, and allow exactly the two argument lists:

  ```text
  Defaults!/usr/local/sbin/pull-trigger env_keep += "SSH_ORIGINAL_COMMAND"
  CI_USER ALL=(root) NOPASSWD: /usr/local/sbin/pull-trigger --mode apply, /usr/local/sbin/pull-trigger --mode check
  ```

  The `command=` is then `sudo /usr/local/sbin/pull-trigger --mode apply`. The
  harness proves this route in `verify.yml`: it writes that fragment, checks it with
  `visudo`, asks for a check as a non-root account through `sudo`, and sees that
  another argument list (`--config`) is refused and that without the `env_keep`
  line the answer is exit 20. It does not run an SSH server, so the `command=`
  text and the key restrictions are not tested. Writing the fragment and the
  `authorized_keys` line belongs to the `sudoers_and_keys` pattern.

The summary line on standard output has fixed fields; nothing the caller typed is
copied into it or into the log:

```text
pull-trigger verdict=applied exit=10 reason=ok mode=apply commit=<40 hex> playbook=<path> changed=1
```

The playbook's own output is relayed on standard error and kept in `runs/`.

### Exit codes

| Exit | Verdict        | Meaning                                                                                                                        |
| ---- | -------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| 0    | `unchanged`    | The playbook ran and reported zero changes.                                                                                    |
| 10   | `applied`      | An apply ran and reported changes.                                                                                             |
| 11   | `would-change` | Check mode ran and reports that an apply would change something.                                                               |
| 20   | `refused`      | Refused before any change. See the reasons below.                                                                              |
| 21   | `busy`         | Another trigger holds the lock. Nothing was run. Ask again later.                                                              |
| 30   | `failed`       | The playbook started and failed (`playbook-failed`, `no-recap`, `interrupted`).                                                |
| 31   | `timed-out`    | The playbook ran past `pull_trigger_timeout_seconds` and was stopped.                                                          |
| 40   | `error`        | Invalid or unsafe configuration or state, a missing tool, a failed git command, or `io-error` or `internal-error` (see below). |

The `reason` field of exit 20 is one of `bad-request`, `not-on-main`, `rollback`,
`unsigned`, `bad-signature`, `signer-not-allowed`, `playbook-not-allowed`.

Exit 40 usually means the playbook was never reached, but `io-error` and
`internal-error` can also follow a playbook that ran to its end (for example a full
disk while the log is written). A caller that gets exit 40 on an apply must read
the log on the host before deciding that nothing was applied.

The apply workflow's second run: after exit 10, ask for the same commit again.
Exit 0 means the apply left nothing to change (a clean second run, which
runs the playbook again and changes nothing); exit 10 on the second run is a
failure of idempotence for the workflow to report. The program never decides that
itself, and a repeated request is never skipped as "already done".

## The playbook allowlist and what the checkout is

- The allowlist is in the configuration, root-owned. Every entry is a relative
  path, already normalised (no `.`, `..`, doubled or trailing slash), under
  `ansible/playbooks/`, of plain name parts, ending in `.yml` or `.yaml`. An
  entry that is anything else makes the whole configuration invalid (exit 40).
- The host's playbook is one configured value. The caller supplies no path.
  If it is not on the allowlist the request is refused (`playbook-not-allowed`).
- Two independent checks keep a link out. In the commit the playbook must be a
  regular file (read from the commit's tree with `ls-tree`, so a symbolic link or
  a missing file is refused). On the disk, after the checkout, no part of the
  playbook's path (`ansible`, `ansible/playbooks`, or the file) may be a link, and
  its real path, resolved from the checkout's own resolved root, must lie inside
  the checkout's `ansible/playbooks/`. Each check alone refuses a link at
  `ansible/playbooks`; the harness deletes each in turn and proves it (see "How to
  test it"). The on-disk check runs before the rollback floor is written.
- The checkout is made from the commit's tree with `read-tree` and
  `checkout-index` into a new directory; it holds the files and no `.git`. A failed
  checkout removes the half-made directory. An apply replaces `current` with a
  link to the new directory only after the rollback floor is written, then removes
  the previous directory.
- The program runs `ansible-playbook` on the verified local checkout, and not
  `ansible-pull`. `ansible-pull` would fetch the repository itself, by branch or by
  a ref, after the verification, so what it ran could differ from what was
  verified. Running on the checkout this program made means the playbook file that
  runs is the file that was signed. That claim stops at the playbook file and its
  path: the program checks no other path, so a link elsewhere in the signed tree
  (in a role, an include or a template) can make the playbook read or run a file of
  the host. The signed tree is trusted for what it contains. A repository's
  `ansible.cfg` under `ansible/` is read from the checkout.

## Refusals leave the host untouched

All of the refusals above happen before a work directory is promoted or the
rollback floor changes. The cache may be updated by a fetch (a cache is not what
the host runs). The scenario takes a description of the marker the playbooks
write, the floor, the `current` link, every file in the checkout (owner, mode, size,
modification time, hash) before and after each refusal and asserts the two are
equal. A failed or timed-out apply is different: it does run, so the rollback floor
is raised when the apply starts. A commit older than a failed apply is therefore
refused as `rollback`, and the way forward after a failed apply is a newer commit.
A TERM or INT that has arrived by the time the checkout is done ends the run as
`interrupted` with the floor where it was. One that arrives after the floor was
written raises the floor even if the playbook never got to do anything, and the
way forward is again a newer commit.

## Taking over by hand

Two states stop every request until a person acts. Both are fail-closed, and a
unit test makes each of them.

- **A damaged rollback floor.** If `/var/lib/pull-trigger/last-applied` does not hold
  exactly one 40-digit commit id, every request ends as exit 40 `state-unsafe`
  and nothing runs. The commit last applied is the start of the name of the
  directory that `/var/lib/pull-trigger/current` links to. Check it against the
  history of `main`, then write that id and a newline into `last-applied` (root, mode
  0600). Removing the file instead also clears the error, but the host then accepts
  any signed commit of `main` once, with no floor to refuse an older one.
- **A rewritten `main`.** If history on `main` was rewritten so that the commit
  last applied is no longer an ancestor of the tip, a request for the new tip ends
  as exit 20 `rollback`, because it does not descend from the floor. If the cache
  has also lost the floor commit (for example `repo.git` was removed), the answer is
  exit 40 `git-failed` instead, because git cannot compare the two. In both cases
  the program refuses until the floor is moved by a person who has checked that
  the new history is the intended one: write an id from the new history, one that
  is already applied or that is older than anything to be applied, into
  `last-applied`, or remove the file as above.

## Named limits

- **Signer key handling.** The production signer of a merge is the hosting
  platform's own signing key. Which key goes on the allowlist, how it is
  obtained and how a rotation is made are decisions for the owner. The program
  checks the signature with the keys it is given and requires the verifying
  key's fingerprint to be on the allowlist (git reports a good SSH signature by
  an unlisted key as only "untrusted", so the fingerprint is compared as well). It
  does not fetch or refresh keys, and it does not check expiry of an SSH key
  (SSH keys have none). The code refuses a signature by an OpenPGP key that is
  expired or revoked in the configured block as `bad-signature`, but no test
  makes such a key, so that behaviour is stated here and not proven.
- **Replay.** The commit is the whole request and a commit stays valid while it is
  an ancestor of `main` and newer than the floor. A recorded request can be sent
  again and will run the playbook again; it can never run anything but a
  signed, allowlisted commit of `main`, and never an older one than the last
  applied. A second request of the applied commit changes nothing. It cannot be
  made impossible, because ANS-17 requires that a request can be repeated.
- **Lock semantics.** The lock is `flock` on a file in the state directory. The
  kernel drops it when the holder ends, however it ends, so a dead holder cannot
  wedge the host and there is no stale-lock cleanup. A second request is
  refused with exit 21; it does not wait. Local callers who bypass the program are
  not covered.
- **The first run needs the network** to reach the remote, and a remote that is
  down is exit 40, not a refusal.
- **A root-owned configuration is trusted.** The program refuses a configuration
  or directory that is not owned by the user that runs it or that others can write
  to, but anyone who can write as root can change what it does.
- **The playbook is what is trusted.** The program makes sure that the signed
  playbook is the one that runs. It does not judge what the playbook does.

The eight limits found at review of the first version, each with its state:

- **(a) Output goes to the caller.** The playbook's output, and its `--diff` in
  check mode, are relayed on standard error to the caller, so they reach the CI
  job's log, which is public. Only `no_log: true` and `diff: false` on a task
  that handles a secret (ANS-16) keep a secret out of it.
- **(b) The playbook's tools are not vetted.** `ansible-playbook` and its Python
  environment run as root, and the program does not check their owner or mode.
  Whoever can write to them can run code as root.
- **(c) Closed, and tested.** The program starts with `-I` in its shebang, so a
  `PYTHON*` variable or a file beside it cannot change what it imports. A unit test
  starts a copy with the flags of its own first line, with a module planted beside it
  and another on `PYTHONPATH`, and fails if either is imported; it first starts the
  copy without the flags to show that both would be. The harness runs the installed
  program through its shebang.
- **(d) A killed trigger leaves its playbook running.** If the trigger is killed
  with SIGKILL, its playbook keeps running in its own session while the lock is
  free (the lock's file descriptor is close-on-exec), and the next request's sweep
  of the work directories can remove the checkout that playbook is using.
- **(e) No directory fsync.** The floor and `current` are renamed into place
  without a sync of the directory, so a power loss can roll the floor back by one
  apply.
- **(f) The host playbook must target `all` or `localhost`.** Because of
  `-i localhost,` the playbook gets no inventory variables, and a playbook that
  targets a group ends as exit 30 `no-recap` after the floor was raised.
- **(g) Only the playbook path is checked.** See "The playbook allowlist and what
  the checkout is": the signed-bytes claim is limited to the playbook file.
- **(h) `gpg.x509.program` is not pinned.** Git runs in a fixed environment with
  the global and system configuration switched off, and none of the caller's `GIT_*`
  variables are passed on (a unit test sets hostile ones). The program pins
  `gpg.program` and `gpg.ssh.program` and leaves the x509 one at git's default.
  This is a speculative limit; no known path reaches it, since the program never
  asks git to verify an x509 signature.

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes, one command runs lint, yamllint, the interface checks and the
container test (the harness refuses a remote Docker engine):

```text
python3 ansible/harness/run_harness.py ansible/roles/pull_trigger
```

Run it with the Python of the virtual environment that holds the pinned tools.
The scenario builds, inside the container, a throwaway bare remote, throwaway
SSH and OpenPGP keys and a signed history (`molecule/default/files/make_fixtures.py`:
good commits, one by an unlisted SSH key, one by an unlisted OpenPGP key, an
unsigned commit, a commit whose message was changed after signing, a commit with
no playbook, a commit whose playbook is a link, one with a playbook that fails, and a
branch that is not `main`). The only step that reaches outside the container is
the refresh of the package index, once, in `prepare.yml`. Every assertion in
`molecule/default/verify.yml` names the behaviour it proves, so a failing line says
which control broke:

- the wrapper, its directories, the configuration, the state and log directories are
  root-owned, not writable by others, and have the documented modes;
- check mode reports a change and changes nothing;
- a good commit applies exactly once; the checkout is exactly the commit, with no
  `.git`; a second request is a clean second run;
- an OpenPGP-signed commit applies;
- each refusal, with its reason, leaving the host byte for byte unchanged: a commit not
  on `main`, a commit only another branch holds, unsigned, a non-allowlisted SSH key,
  a non-allowlisted OpenPGP key, a changed message, an older commit, a commit with no
  playbook, a playbook that is a link, a playbook off the allowlist, a playbook that
  climbs out of `ansible/playbooks/`, an allowlist that does, a configuration
  anyone can write to;
- malformed requests (short hex, uppercase, a ref name, an option, two words, a
  commit and a command, a newline, a leading space, nothing) each refused, and no text
  from a caller run;
- a newer commit applies and only its checkout is kept;
- a commit that main has moved away from since it was cached is refused;
- a signed commit in which `ansible/playbooks` is a link, to a directory inside the
  tree and to one outside it, or in which the playbook file is itself a link, is
  refused with the program as installed, and still
  refused when a copy of the program has either of the two link checks deleted (the
  other one refuses, and its own message is asserted);
- a non-root account that may run the program only through `sudo`: with the
  `env_keep` line the request arrives, with another argument list sudo refuses,
  and without the line the answer is exit 20;
- a failing playbook is exit 30 and still raises the rollback floor;
- two overlapping triggers: the second is exit 21 and the playbook ran once;
- a run past its limit is stopped, exit 31;
- the unit tests run again on Debian 13 (see below).

The harness runs the role twice, so the second converge must report no change
(the fixtures are made once, in `prepare.yml`).

The unit tests (`tests/unit/test_pull_trigger.py`) use the standard library only,
and make real git repositories with real SSH and OpenPGP signatures. They include a
table of hostile requests and seeded property tests of the argument validator. They
need `gpg` and `gpgconf` and fail, not skip, on a machine without them. A commit
signed under an SSH namespace other than `git` is refused, but not because of the
`namespaces="git"` option on the allowed-signers line: git verifies under `-n git`
itself, and removing the option leaves that test green. The option stays as a
second layer and is not counted as a control. The
type check and lint of the program, from `ansible/`, with the virtual environment's tools:

```text
PYTHONPATH=roles/pull_trigger/files:roles/pull_trigger/tests/unit python -m unittest discover -b -s roles/pull_trigger/tests/unit -p "test_*.py"
mypy --config-file roles/pull_trigger/pyproject.toml roles/pull_trigger/files/pull_trigger.py
ruff check roles/pull_trigger
```

CI runs the harness over every role, and the harness's `verify.yml` runs this
role's unit tests again inside the Debian 13 container. CI runs neither mypy nor
ruff over the role's Python, so run those two commands before opening a pull
request. They are the reason this role has its own `pyproject.toml`.

### The test base image (a third-party image, trusted by digest)

The scenario uses the same image as the `sudoers_and_keys` pattern, for the same
reasons, and `ansible/patterns/sudoers_and_keys/README.md` ("The test base image")
describes the image, its source and its limits. In short:
`geerlingguy/docker-debian13-ansible`, referenced as `name:latest@sha256:<digest>`
(CON-3), is Debian 13 with Python and `ansible-playbook` in it. The digest is the
pin and the tag is informational. The scenario needs no systemd, so it sets
`command: sleep infinity`, no cgroup mount, no cgroup namespace mode, no tmpfs, no
`privileged` and no capabilities. The image declares `/sys/fs/cgroup` as a volume, so
the platform sets `keep_volumes: false`, or every run would leave an unlabelled
volume behind. Named limit: the image is trusted by its digest and by review, not
built here.

## How it is delivered

A role reaches a host only through the gated workflow (ANS-17), never by running
`ansible-playbook` by hand. The program is the host's half of that: the workflow
holds a key that can run only this command, the deployment gate approves a merge
commit, and the host verifies the commit again by itself. Nothing applies this role
to a host yet.

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together: the spec
   and the defaults must agree.
2. Change the program, its configuration check, its `Why` sentences and the
   exit-code table in this README together. Every sentence a refusal can give is
   fixed text in the `Why` enumeration, so that no text from a caller reaches a log;
   keep it that way.
3. Keep every task able to run under `--check --diff`, and keep the role idempotent.
4. A control is changed only with its proof: weaken the control in a copy, see the
   named assertion in `verify.yml` or the unit test fail, restore it, see it pass.
   Removing a refusal removes a line of the list in "How to test it".
5. Run the harness and the three commands in "How to test it" before opening a
   pull request.
