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
   hash checking required and wheels only (`--only-binary=:all:`), so that every
   package must match a hash in the lock, a package the lock does not name is
   refused, and nothing is built from source. The wheels-only flag is part of the
   control: pip does not hash-check the build dependencies of a source build, so
   without it a lock entry with no wheel for the host's interpreter would run, as
   root, a build backend fetched from the index with no hash. With it, such an
   entry fails the install and the host stays as it was. The Molecule test
   installs the repository's real lock with the flag on, on the production Debian
   release.
4. Writes a marker in the environment when the install finished.
5. Points the `ansible-playbook` link at that environment, last, so a failed
   install leaves the previous environment in service.

Each lock gets its own environment beside the old one. A bump of the lock builds
a new environment; the `ansible-playbook` that is running the bump keeps its own
packages and is never upgraded under itself. The role never removes an old
environment.

## One program, two callers

Steps 2 to 5 are done by one typed Python program, `files/install_runtime.py`,
and by nothing else. The role runs it, and so does the first-boot document of a
new host (`hetzner-host`, "Enrolment"), which downloads it and the lock, checks
each against a SHA-256 recorded at a commit of `main`, and runs it. There is no
second copy of the install logic to drift.

The program, in order: checks the lock against the SHA-256 it was given;
refuses a lock with a line that carries no hash, or with any option, or that
pip could read in another encoding (see "How the lock is read"); computes the fingerprint (the
SHA-256 of the lock text without trailing whitespace, first sixteen hex digits,
which is the role's own expression, held equal by a golden value in the unit
tests and in the Molecule verify); refuses a fingerprint other than the one the
caller expects; opens the lock without following a link; refuses an
environments directory that is a link, not the caller's own or writable by
others; builds the environment with a scrubbed process environment (no pip
variable of the caller reaches the install); installs with hash checking required and wheels only; checks that
`ansible-playbook` is an executable file in the environment; writes the marker
last; and, only when asked with `--link`, replaces the `ansible-playbook` link
atomically. Every failure exits 1, writes one line `install_runtime: <reason>` on
stderr and prints nothing on stdout, so a failed first boot leaves the host
un-enrolled and the owner installs by hand. It never falls back to an engine that
is not the locked one.

The role's own link task stays last in `tasks/main.yml`, so the role is the one
place that decides the link moves.

### How the lock is read

The program refuses a lock that pip would run with an option such as
`--index-url`, so it has to read the lock as pip does. It follows pip's
`join_lines` (in pip's `req_file.py`) rule for rule: a line continues the one
before when its raw text ends in a backslash (a space after the backslash ends
it), and a comment-only line ends a continuation. One rule is stricter than pip
on purpose: pip strips a trailing comment from a joined line, and the program
does not, so a `#` on a requirement line is refused, never skipped. A
requirement line is a name, an exact version, an optional marker and `--hash`
options, separated by the space character only (pip splits on nothing wider).

It also refuses a lock that starts with a byte-order mark, or has a `coding:`
or `coding=` declaration in a comment on its first two lines, because pip
would read such a lock in another encoding (a utf-7 lock can hide an option in
what this program reads as a comment). The repository's lock has neither.

`ansible/checks/check_pins.py` loads the reader, the encoding check and the
allowed marker characters from `files/install_runtime.py` by path and keeps no
copy of them. The patterns it matches a pin with (`REQUIREMENT`, `VERSION`) are
its own. `install_runtime.py` is owner-reviewed in `.github/CODEOWNERS`
because the gate reads it. The parity with pip is tested against pip's own
code in `ansible/checks/test_lock_reader_parity.py`. It asks one pip only: the
version pinned, with its wheel hash, in `ansible/checks/pip-requirements.txt`.
It refuses any other pip and names both versions in the failure message.
`ansible/checks/README.md` holds the pin and the steps to change it.

The parity table is therefore proven against that pinned pip and no other. The
host does not run that pip. `install_runtime.py` makes the environment with
`python -m venv`, and the pip it installs with is the one `ensurepip` bundles
with the host's Python, which the lock does not pin and nothing here tests. What
holds the host's install is not that pip's version: it is the lock's SHA-256, which
the program checks against the record built from reviewed `main` (`--lock-sha256`),
and `--require-hashes --only-binary=:all:`, so every file pip installs is a wheel
checked against a hash in the lock.

A run that dies part-way recovers by being run again. The environment is made
when its `bin/pip` is not executable, and pip is the last thing `python -m venv`
puts down, so a venv that failed after `bin/python` and before pip is cleared and
made again (`--clear`, only when the directory already exists); one that has pip
only runs pip again. Nothing needs removing by hand.

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
- `/opt/ansible-runtime/` (root, 0755), and in it `install_runtime.py` (the install
  program, root, 0755), `requirements-<fingerprint>.txt` (root, 0644) and
  `venv-<fingerprint>/` (the environment, owned by root).
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

## The first pull after the install moved into the program

`edge1` already runs this role under the pull, so the merge of the change that
moved the install into `files/install_runtime.py` reaches it on its first gated
pull, and `edge1` runs the pull that delivers it. That is a live change, so the
pull is read back (the approver reads it, or the owner at the gate, with the
non-mutating diagnostics the registry grants for `edge1` and no other command).
This is what a correct first pull shows for this role's tasks:

- The program is placed: `/opt/ansible-runtime/install_runtime.py` exists, root,
  0755, and the task that places it reports changed once.
- The install is skipped, not run: the marker
  `venv-<fingerprint>/.installed-from-lock` the old role wrote is already there
  for the same lock, so the `creates` form skips the command. `/opt/ansible-runtime/`
  holds the same single `venv-<fingerprint>` it held before, and no second one.
- The link is unchanged: `/usr/local/bin/ansible-playbook` still resolves into that
  same `venv-<fingerprint>`.
- The next pull reports no change for this role's tasks (and `changed=0` for the
  play when nothing else moved), so nothing the role does is a change the second time.

A first pull that builds a second `venv-<fingerprint>`, moves the link, or fails
at the program is not correct: the lock's fingerprint differed from the marker's,
or the program refused: it exits 1, writes one line `install_runtime: <reason>` on
stderr and prints nothing on stdout, so the reason says which.

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
   assertion in `verify.yml` or the named unit test fail, restore it, see it
   pass. The program's unit tests (`tests/unit`) run in CI with mypy strict and
   ruff (`.github/workflows/ansible.yml`, "Check each role's own program").
5. Run the harness command above before opening a pull request.

## Notes kept from install_runtime.py

These notes were cut from `files/install_runtime.py` when its comment blocks went below the
CMT-3 limit. The program keeps a one-line pointer where each note was, and the constraints in
each block are still in the code.

### What the program does, and why it runs alone

Two callers run this one program. The `ansible_runtime` role runs it on a host that is already
under the pull, and the first-boot document of a new host runs it before any Ansible exists
there. Both therefore get the same checks and the same steps, in the same order:

1. read the lock without following a link, and refuse it unless its SHA-256 is the one the caller
   was given;
2. refuse a lock in which any requirement has no SHA-256 hash, or which carries anything but
   pinned, hashed requirements, or which pip could read in an encoding other than UTF-8;
3. name the environment by a fingerprint of the lock text;
4. build `venv-<fingerprint>` and install the lock into it with hash checking required and wheels
   only (`--only-binary=:all:`);
5. write the marker that the install finished, then, only when asked, move the
   `ansible-playbook` link.

A failure at any step leaves the link where it was. It never installs an engine that the lock
does not name. Every file pip installs is a wheel whose hash the lock lists: pip is told to build
nothing, because pip does not hash-check the build dependencies of a source build, so a package
with no wheel for the host's interpreter fails the install (the host stays un-enrolled) and is
never built.

The paths and the fingerprint are the ones the role has always used, so the role's environments
do not change.

### The requirement pattern

One pinned requirement: a name, optional extras, an exact version, an optional environment
marker, then one or more hashes and nothing else on the line. The separators are the space
character and nothing wider, because pip splits a line into its requirement and its options on
`" "` alone (`break_args_options` in pip's `req_file.py`): a tab before `--hash` would leave the
hash inside the requirement as pip reads it. The marker is written only from a positive set of
characters (letters, digits, `_`, `.`, quotes, space, `=`, `!`, `<`, `>`, `(`, `)`), the set
`MARKER_CHARS` names here, and `check_pins` reads it from this file. That set holds no `-` and no
`;` at all, so no option such as `--index-url` or `-i` can sit in the marker, however it is
spaced or nested. It is a set to allow, not a list of forms to refuse.

Why a pattern and not a maintained parser: this runs under the host's own interpreter with `-I`
before any package is installed, so only the standard library exists (the maintained parser,
`packaging.requirements`, is a package, and pip's vendored copy is not a supported import). It is
also not the control. The lock's SHA-256 comes from a record built from reviewed main, and pip's
own `--require-hashes` (always passed) is the maintained refusal of an unpinned or unhashed
requirement and checks each requirement's downloaded file against its hash. That covers every
installed file only because `--only-binary=:all:` is passed with it: pip does not hash-check the
build dependencies of a source build, and with wheels only there is no build. This pattern only
refuses early, with a reason of this program's own, and leaves nothing behind.

### logical_lines

Returns the lock's requirement lines as pip joins them, each with the line it starts on.

The joining follows pip's `join_lines` (pip's `req_file.py`) rule for rule, so that a line pip
reads as an option is an option here too: a line continues the one before when its raw text ends
in a backslash, tested before any strip, so a space after the backslash ends it; and a
comment-only line ends a continuation.

One rule is deliberately stricter than pip. After joining, pip strips a trailing comment from the
line (`ignore_comments`); this does not, so a comment that sits on a requirement leaves a `#` in
the line, which is not a requirement and is refused where pip would skip it. That fails closed,
and the repository's lock has no such line. A comment-only line that starts a line (not a
continuation) is dropped, as pip drops it.

The function is the lock reader for both callers: `ansible/checks/check_pins.py` loads it from
this file. It reads text, so the caller first refuses an encoding pip could choose differently
(`check_lock_encoding`).

### check_lock_encoding

Refuses a lock that pip could read in an encoding other than UTF-8. pip chooses the encoding of a
requirements file from a byte-order mark, then from a `coding:` declaration in a comment on one of
the first two lines (`_decode_req_file` in pip's `req_file.py`), and the rest of this program
reads UTF-8. A lock with either could show this program a comment and pip an option, as a
`# -*- coding: utf-7 -*-` lock does. Both are refused whatever encoding they name; the
repository's lock has neither.

### check_lock_options

Refuses an option on any physical line of the lock other than an exact `--hash=sha256:<64 hex>`
token. It runs first and on the raw lines, as `str.splitlines` gives them and before anything is
joined: a token that starts with `-` is an option to pip, so no reading of continuations, comments
or odd line breaks can carry one past it. A comment-only line is skipped, as pip skips it (the
lock's `# via -r requirements.in` lines are comments). It is stricter than pip on purpose: a
`--hash` with a backslash stuck to it, or an option after a `#` on a requirement line, is refused.
The refusal is `LOCK_UNHASHED` and its detail is the token.

### check_lock_is_hashed

pip's own hash checking is the control that matters, and it stays on. This refuses first, before
anything is made, so that a lock with no hash at all, or with an option that could point pip
somewhere else, fails with a reason of this program's own and leaves nothing behind.
