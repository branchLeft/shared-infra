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
   validates the request before it touches the repository: with `--mode apply` or
   `--mode check` the whole text is one commit of exactly 40 lowercase hex digits. A
   ref name, abbreviation, option, uppercase digit, whitespace, newline, second word
   or empty text is refused. With `--mode step` it is that commit, one step id and one
   word (see "Step requests"). No shell is used anywhere; every command is an
   argument list.
2. Checks that the host's configured playbook is on the playbook allowlist and, for a
   step, that the step is on the step allow-list and the word is its word, then
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
--connection local`), with `--check --diff` in check mode and, for a step, with
   `--tags TAG -e control_plane_db_step=ID` set by the program from its own
   allow-list. It prints one summary line on standard output and sets a distinct
   exit status.

It does not run the second pass that proves the apply left nothing to change: the
apply workflow asks for a second request of the same commit (ANS-17) and reads
the exit status (0 means nothing more to change). It does not manage users, SSH
keys or sudoers (the `sudoers_and_keys` pattern does), install `ansible-playbook`
(the host must have one at `pull_trigger_ansible_playbook`), decide which
playbook a host runs beyond the one configured value, or hold any private key.

**A step request** is a second kind of request, on a key of its own (see "Step
requests"). It names the same commit and also one routine step of a role that the host
playbook keeps behind the `never` tag, with a typed confirmation word. It goes through
every check above and then runs the same playbook with only that step's tag. A
host with no entry in its step allow-list refuses every step request.

## Interface

The variables, their types, choices and defaults are in `meta/argument_specs.yml`
and the same defaults are in `defaults/main.yml`. Ansible checks them when the
role starts.

| Variable                        | Meaning                                                                                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `pull_trigger_remote_url`       | The read-only remote: an `https://` or `file://` URL, no credential in it.                                   |
| `pull_trigger_signers`          | Non-empty list of `{format, key}`: `ssh` (one public key line) or `openpgp` (an armoured public key block).  |
| `pull_trigger_playbooks`        | The playbook allowlist: plain relative paths under `ansible/playbooks/`.                                     |
| `pull_trigger_playbook`         | The one playbook this host runs; must be on the allowlist.                                                   |
| `pull_trigger_ansible_playbook` | Absolute path of `ansible-playbook` (default `/usr/local/bin/ansible-playbook`).                             |
| `pull_trigger_timeout_seconds`  | Time after which a playbook run is stopped (default 3600).                                                   |
| `pull_trigger_keep_runs`        | How many runs' output files to keep (default 50).                                                            |
| `pull_trigger_steps`            | The step allow-list: a list of `{id, tag, word}` (default empty, which allows no step). See "Step requests". |
| `pull_trigger_floor_seed`       | A commit id written to the rollback floor only if the host has none (default empty). See "Push receiver".    |

No variable is a secret. The signers are public keys, and the configuration is
world-readable by design, so the role leaves the diff of the configuration
visible and sets no `no_log`. The step words are in the same public file and are
typing guards, not secrets (see "Step requests"). The program accepts an SSH signer only as one public
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
  the program on its first run. On a bundle host also the `spool` and `quarantine`
  directories, empty between requests, and a floor written by the role itself from
  `pull_trigger_floor_seed` if there is none (never replaced if there is one).
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

and a second key with `--mode check` for the plan job. A third key, with `--mode step`,
exists only for a host that has step entries (see "Step requests"). The mode is fixed
on the `command=` side, so the caller cannot change it. What the caller types is the
whole content of `SSH_ORIGINAL_COMMAND`, and under the apply and check keys it must be
the commit alone. For a person on the host, the commit may instead be one positional
word, and not both.

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
  program only, and allow exactly the argument lists (the third, for `--mode step`, is
  on a separate account and in the step section below; the apply account never has it):

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

The line of an apply and of a check is byte for byte what it was before step requests
existed: the workflow that reads it matches the whole line. A step request adds one
last field, and only it does:

```text
pull-trigger verdict=applied exit=10 reason=ok mode=step commit=<40 hex> playbook=<path> changed=1 step=migrate
```

The playbook's own output is relayed on standard error and kept in `runs/`.

### Step requests

A step request is for a routine, named task that a role keeps behind the `never`
tag: the first three are the control plane's database steps `migrate`, `identity` and
`provision`. It is a second request kind and not a second program: it passes every
check of an apply (the commit is an ancestor of `main`, newer than the floor, signed by
an allowlisted key, with the playbook a regular file in it) and then runs the same
playbook with `--tags TAG -e control_plane_db_step=ID`, so a task that has none of the
selected tags does not run. The tag selects; it does not isolate. Ansible still gathers
facts when the play does, and it runs every task tagged `always` (and every task in a
play or role that gives `always`), whatever `--tags` says. A step is therefore the step's
tasks **plus** the play's fact gathering and its `always` tasks, and a role that keeps
a `never`-tagged step must tag nothing `always` that a step run should not repeat. The
program cannot see inside the playbook, so this is a rule for the role's author and the
reviewer of the role, and the first-run evidence rule below is written to match it. A plain
apply and a check never pass either option, so a `never` step cannot run from them (a
unit test and the harness both show it).

**The interface, exactly.**

| Part               | Value                                                                                                    |
| ------------------ | -------------------------------------------------------------------------------------------------------- |
| Mode               | `--mode step`, a third value of `--mode` beside `apply` and `check`. It is fixed on the `command=` side. |
| Request text       | `<40 lowercase hex commit> <STEP_ID> <WORD>` in `SSH_ORIGINAL_COMMAND`, separated by single spaces only. |
| `STEP_ID`          | `[a-z][a-z0-9_]{0,31}`, and it must also be on the host's step allow-list.                               |
| `WORD`             | `[A-Z0-9-]{4,32}`, compared exactly with the allow-list's word for that step.                            |
| By hand            | Three positional words after `--mode step`: the commit, the id, the word.                                |
| Summary and log    | `mode=step` and a last field `step=ID` (or `step=-` when the id was not found on the allow-list).        |
| Refusals (exit 20) | `bad-request` (the shape), `step-mode-only`, `step-not-allowed`, `confirm-mismatch`.                     |

The step key's two lines (placeholder values; the `sudoers_and_keys` pattern writes
them), alongside the apply key's and the plan key's:

```text
restrict,from="ALLOWED_CIDR",command="sudo /usr/local/sbin/pull-trigger --mode step" ssh-ed25519 PUBLIC_KEY_PLACEHOLDER control-plane-step
Defaults!/usr/local/sbin/pull-trigger env_keep += "SSH_ORIGINAL_COMMAND"
STEP_USER ALL=(root) NOPASSWD: /usr/local/sbin/pull-trigger --mode step
```

The step id is not in the `command=` text or in the sudoers line: it travels in the
request, so the sudoers argument list is one fixed list and does not copy the
allow-list. The plain apply key's account has no `--mode step` list, and the program
refuses a step request under `--mode apply` or `--mode check` as `step-mode-only`, so
a step needs both the step key and the step account. The harness proves the sudo
half: it writes these lines, checks them with `visudo`, runs a step through the step
account, and sees sudo refuse the same step for the plain account and refuse `--mode
apply`, `--mode check` and `--config` for the step account. It does not run an SSH
server, so the `command=` text and the key restrictions are **reviewed, not tested**.

**The allow-list.** `pull_trigger_steps` is a list of `{id, tag, word}`. The program
holds a **closed list of step ids** in its own code (`migrate`, `identity`,
`provision`). The configuration may name some of them and can add none: an entry whose
id is any other word is `invalid-config` (exit 40) and stops every request, whatever
the word is. This is deliberate. A list of names to refuse could not name a surface
that does not exist yet, and every name not on it would pass. Break-glass access (the
four-hour support-access tool) is therefore not a step and cannot become one by editing
a variable: not by a new id, and not by pointing a listed id at its tasks, because the
tag that decides what runs is bound to the id (below). A new routine step is a change to
this root program, reviewed by the owner.
Each entry is checked when the configuration loads:

- exactly the three fields, all text; an unknown, missing or empty field is refused;
- `id` is on the closed list; two entries with the same id are refused;
- `tag` is exactly `control_plane_db_` followed by the entry's own id, so the id the
  owner approves and the tag that selects the tasks cannot differ. An entry that pairs
  an id with any other tag (another step's tag, a break-glass tag, a mistyped tag) is
  `invalid-config` (exit 40) and stops every request. The field is kept so that the
  inventory states plainly what runs; the program checks it and does not trust it.
  `--tags` takes comma lists and the special tags `all`, `always`, `never`, `tagged`
  and `untagged`, and a tag is playbook-wide, so a free-form tag could run the whole
  playbook or another role's tasks. None of those equals this form;
- `word` is `[A-Z0-9-]{4,32}`.

**The word is a typing guard and not a secret.** It sits in the world-readable
configuration of a public repository (the inventory file for the host). The person who
adds an entry chooses it and the owner reads it in that pull request; at dispatch the
person dispatching reads it from the same inventory file, and types it into the workflow's
`confirm` input. What stops a step is the protected environment whose only reviewer is
the owner, not the word. The word catches a wrong step or a wrong host and nothing more.

**What "the owner's typed confirmation" means here.** Ruling 2B lets a routine step run
on the owner's typed confirmation. GitHub gives that no single home: the word is typed by
whoever **dispatches** the workflow (`confirm` is a `workflow_dispatch` input), and an
environment approval is a button that takes no text. So the sender is built to this
reading, stated here so it is not left to be guessed: the owner dispatches every step
run himself and types the word at dispatch; the sender refuses a step dispatch whose
actor is not the owner's account; and the owner's approval of the environment is a
second, separate act. The word is then a slip guard on the owner's own typing, and the
control is that both acts are the owner's. The owner can relax this to "the approval
alone is the confirmation", in which case the sender drops the actor check and keeps the
word as a slip guard. Nothing in this program changes either way: it compares the word
with the allow-list and cannot know who typed it. That is why the actor check is in the
sender and not here.

**Order of refusal.** After the request is parsed, the program checks the playbook
allowlist, then the step (on the list, then the word), and only then takes the lock,
fetches, reads the floor and checks out. A refused step touches none of those.

**The floor is the apply's floor, unchanged.** A step request needs a commit that is
newer than or equal to the last one applied, as an apply does, and when the playbook
starts the floor is raised to that commit, as it is for an apply and for a failed
apply. Two consequences follow, and both are stated here so that nobody finds them
out later:

- a step that failed can be asked for again on the same commit (the floor accepts
  the commit that set it), and the role's own markers, not the floor, stop a second
  success;
- a step that ran on commit C raises the floor to C, so a plain apply of an older commit
  that had not been applied yet is then refused `rollback`. The way forward is a newer
  commit.

**What the approver sees (ANS-17).** A check-mode run cannot show a step: a step is
never run in check mode, the program refuses it there, and the plan job's check-mode
play does not see a `never`-tagged task. So the plan for a step is not a diff. It is the
three things the delivery workflow prints before the protected environment pauses: the
commit, the step id, and the committed input the step compares (the image digest for
`migrate`, a hash of the rendered tenant configuration for `identity`). The program's
summary line then names the step it ran (`step=ID`), so a bare commit sent by mistake
is not read as a step. The amendment that says this in the standard is open for review
in the standards repository, and the workflow that prints the three lines is its own
change in the workflows repository.

**What the owner does on a host, once.** None of this is done by the role or by an
agent. It is listed so that the owner's steps are in one place:

1. Make the step key pair, and put the private half in the `control-plane-step`
   environment's secret. The public half goes in the host's `authorized_keys`, on the
   step account, with the line above.
2. Add the step account and its sudoers lines (above) through the `sudoers_and_keys`
   pattern, and add the host's known-hosts entry to the environment.
3. Create the GitHub environment `control-plane-step` with the owner as its only
   required reviewer, and with deployment limited to the `main` branch. These are
   settings of the environment and cannot be tested from the repository.
4. Add the step entries to the host's inventory file, in a reviewed pull request.

Wiring a host is not done by this role or by its pull request. Adding the
`control_plane` and `control_plane_db` roles to `playbooks/ops1.yml`, setting
`pull_trigger_steps` for ops1, and writing the shared-infra caller of the reusable
`ansible-gated-apply.yml` with the github-workflows tag it pins, are one ticket,
[ISSUE branchLeft/workspace#2531](https://github.com/branchLeft/workspace/issues/2531).
The ops1 enrolment ticket (branchLeft/workspace#2340) does not do them. Until that ticket
is done the default empty list allows no step on any host. The first live run also waits
on [ISSUE branchLeft/workspace#2483](https://github.com/branchLeft/workspace/issues/2483)
(the signer ops1 trusts) and [ISSUE branchLeft/workspace#2338](https://github.com/branchLeft/workspace/issues/2338)
(the reusable workflow in a form a caller can use).

When a step is run live, the evidence is the workflow run, the host's summary line with
`mode=step` and `step=ID` that reports `verdict=applied` with a change count above zero on
the first live run of that step, a second run of the same step that reports no change, and
the deployment's review record showing that the owner approved that run in that
environment (the environment is the only control here that is not public).

The change count above zero is part of the evidence on purpose. The program cannot tell
from a run that reported no change whether the step's tasks were idempotent and already
done, or were never selected (no task carries the tag, or every task was skipped), and
a summary of `verdict=unchanged` is the same line in both cases. A first run that
reports no change is therefore not evidence that the step ran: find out why before
counting it. Only the first run of a step on a host has to change something; the
second is meant to report none. A change count is also reached by an `always`-tagged task
that changed something (see the top of this section), so read the run's output for the
step's own named tasks changing, not the count alone.

### Push receiver (the bundle source)

A host that has no route to the remote cannot pull, so one host, `demo1`, takes its
commit pushed to it instead. It is the same program and the same checks, with a second
way to get the commit: the caller sends a full-history git bundle on standard input and
the program unpacks it into a throwaway repository instead of fetching `main`. The way
the commit arrives is a root-owned configuration value, `source` (`remote`, the
default, or `bundle`). The role writes the key only for a host named in
`pull_trigger_bundle_hosts` (a constant of the role, `demo1` only), matched against the
play's `enrolled_host`; every other host's configuration file is byte for byte what it
was, and a unit test and the default scenario both show it has no `source` key. A host
with the bundle source never fetches, and a host with the remote source never reads
standard input.

The request is the whole of `SSH_ORIGINAL_COMMAND`, three words:

```text
apply 0123456789abcdef0123456789abcdef01234567 ansible/playbooks/demo1.yml
```

The first word is `apply` or `check` and must equal the mode fixed on the key's
`command=` side; a different word is refused as `mode-mismatch` before anything is read
from standard input, so a key that may only check cannot be made to apply. The third
word must be the host's configured playbook, which must be on the allowlist
(`playbook-not-allowed` otherwise). The step mode is not offered on this source.

The order of the checks on this source, each before the next and none after a change:

1. The request has exactly the three words, and the first equals the key's mode.
2. The playbook equals the configured one and is allowlisted.
3. Standard input is read, with a limit of 200 MiB and a deadline of 300 seconds,
   into a root-owned spool file. The deadline is a monotonic clock read in a `select`
   loop, so a sender that stops sending cannot hold the program: it ends the request as
   `bad-bundle`. The single-flight lock is taken only after the read, so a stalled
   upload never makes another request answer `busy`.
4. The spool is admitted in a quarantine repository: the header must be a git bundle
   header, `git bundle verify` must pass (a bundle that needs history it does not carry
   is refused), the objects are fetched from the file into the quarantine, an explicit
   `git fsck --strict` runs over them (so the object check does not depend on the git
   version), and the bundle's `HEAD` must be exactly the requested commit. Any failure
   is `bad-bundle`, with its own sentence on standard error. Nothing in the quarantine
   is trusted until the next steps pass, and the quarantine and the spool are removed
   whatever the outcome.
5. The signature, the allowlist of signers, the floor and the playbook are checked by
   the same code as the pull route, over the quarantine in place of the cache.
6. Checkout from the quarantine, then the run, as for a pull.

Two checks differ from the pull route, and both are stated here because they are the
point of this source:

- **The floor reads "equal or descends".** The pushed commit must equal the floor or
  descend from it, which is the pull rule. Strictly newer would refuse the apply
  workflow's mandatory second pass of the same commit (it must report 0 `unchanged`)
  and the nightly drift check of the live commit. A host with no floor at all refuses
  every request as `no-floor` (exit 20, and nothing is checked out): the role writes the
  floor once, from `pull_trigger_floor_seed`, only if the file is absent, and never
  moves one that exists. The seed is a reviewed commit id in the host's playbook.
- **There is no "ancestor of `main`" test.** The host has no `main` to compare with.
  A commit signed by an allowlisted key and descending from the floor is accepted
  whether or not it is on `main`. The signer on the host is the hosting platform's web
  signing key, and that key also signs commits made in the web interface on branches
  other than `main`. This is the named limit of the owner's ruling
  (the check is "signed by that key, not older than the floor, playbook allowlisted"):
  a non-`main` commit that descends from the floor is applied, and a later `main`
  commit that does not descend from it is then refused as `rollback`. The way out is the
  floor reset in the operator runbook (in `ghost-platform-docs`), which a person runs.
  The unit tests and the push scenario both run this case.

The summary line has the same fixed fields as the pull route, with its own prefix and
with `changed` always a digit on this source, so the workflow that reads it can match
the whole line:

```text
push-receiver verdict=applied exit=10 reason=ok mode=apply commit=<40 hex> playbook=<path> changed=1
```

A refusal that happens before a commit could be named prints `commit=-`; a unit test
matches every line that names a commit against the judge expression the pushing
workflow uses. The line is printed even when the sender has already hung up: a write
that fails on a closed standard output or error is dropped, the line is still written to
the log, and the exit status is returned.

To read the result on the host, one command prints the floor and the last verdict and
nothing that changes between runs (no time):

```bash
sudo sh -c 'printf "floor=%s\n" "$(cat /var/lib/pull-trigger/last-applied)"; \
  tail -n 1 /var/log/pull-trigger/pull-trigger.log | grep -oE "(verdict|exit|changed)=[a-z0-9-]+" | paste -sd" " -'
```

After a first apply it prints the commit as `floor=<40 hex>` and then
`verdict=applied exit=10 changed=1`; after the second pass of the same commit,
`verdict=unchanged exit=0 changed=0`. A unit test compares this block with the command
the push scenario runs, so the two cannot differ.

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
`unsigned`, `bad-signature`, `signer-not-allowed`, `playbook-not-allowed`, and for
step requests `step-mode-only` (a step with `--mode apply` or `--mode check`),
`step-not-allowed` (the id is not on the host's allow-list, which may be empty) and
`confirm-mismatch` (the word is not that step's word). On the bundle source (see "Push
receiver") there are three more: `mode-mismatch` (the request's mode word is not the key's),
`no-floor` (the host has no rollback floor) and `bad-bundle` (standard input is not a
bundle that stands alone, passes the object check and has the requested commit as its
`HEAD`, or it was too large or too slow); a refusal of the bundle source also prints
`changed=0`.

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

All of the refusals above, and the three step refusals, happen before a work directory
is promoted or the rollback floor changes. The cache may be updated by a fetch (a cache is not what
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
- **The push receiver accepts a commit that is not on `main`.** It checks the signer, the
  floor and the playbook, and has no `main` to compare with (see "Push receiver"). A commit
  made in the web interface on another branch and signed by the same key is applied if it
  descends from the floor. This is the owner's ruling, and the floor reset is a person's
  step in the operator runbook.
- **The floor of a bundle host is a seed.** The first floor comes from
  `pull_trigger_floor_seed`, a commit id chosen when the host is enrolled; the receiver
  refuses everything before then. A wrong seed that is newer than the commits to be pushed
  refuses them as `rollback`.
- **The push scenario cuts the container off the network, not off loopback.** It shows the
  receiver needs no network; it does not show what a host's firewall allows. The size limit
  (200 MiB) and the deadline (300 s) are constants of the program, not settings.
- **A read of standard input holds the connection.** A sender that dribbles bytes is cut at
  the deadline, but until then the SSH session is open and the spool holds what was sent.
  The spool and the quarantine are swept at the start of the next request.

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
- step requests: no plain apply or check ever runs a step; a step request runs only the
  tagged task with the id the program validated, each of the three steps on its own
  word, and a second request of a step reports no change; each step refusal (not on the
  list, an empty list, a wrong word, another step's word, a step under `--mode apply` or
  `--mode check`, the step mode with a bare commit, a commit older than the floor, an
  unsigned, unlisted-key, tampered or off-`main` commit, and the hostile shapes) leaves
  the host and the step markers byte for byte as they were; a configuration that names
  a step the program cannot run, one whose tag is `all` and one that pairs a step's id with
  another step's tag, stops every request; the
  step account may run a step only through its one sudo argument list and the apply
  account may not;
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

The push receiver has a scenario of its own, `molecule/push/`, run with
`python3 ansible/harness/run_harness.py ansible/roles/pull_trigger --scenario push`
(CI runs every scenario). It converges the role with `enrolled_host: demo1` and a floor seed,
then, in `prepare.yml` and before the role runs, removes the container from every Docker
network, so everything after the package refresh runs with no network at all. A control
connect from the container must fail. It then sends real bundles to the installed program on
standard input: a check and an apply, the second pass of the same commit (`unchanged`), a later
commit, a signed commit that is not on `main` (applied, and the named limit shown by running
it), then a `main` commit that does not descend from it (refused as `rollback`). It sends the
refusals (a mode word that is not the key's, a playbook that is not the configured one, no
floor, a commit older than the floor or not descending from it, an unrelated history, a truncated bundle, junk, a bundle that is not stand-alone,
a bundle whose `HEAD` is another commit, an unsigned, tampered or unlisted-key commit) and
checks each leaves the host and the spool as they were. Then the ten red cases of P1 to P10
run against copies of the program, and a seed copy with `force: true` shows the floor seed's
guard. The read-the-result command above is run for the first apply and the second pass and
its output is compared with the documented text.

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

A role is meant to reach a host only through the gated workflow (ANS-17), never by running
`ansible-playbook` by hand. The program is the host's half of that: the workflow
holds a key that can run only this command, the deployment gate (ANS-17) is the planned approval of a merge
commit: its reusable workflow exists in `branchLeft/github-workflows`, but nothing in this repo calls it yet, and the host verifies the commit again by itself. `edge1` is the first host: its
bootstrap and its playbook are `playbooks/edge1.yml`, and the signer it trusts is the one in `trust/edge1.yml`, loaded by that playbook through `vars_files`. The remote and the playbook derivation are in `playbooks/includes/pull_trigger_common.yml`.

### The controls of a step request, and how each is shown to fail

Every control below was broken on purpose in a copy, seen to fail by the named test,
restored, and seen to pass. A new step id, a change to the closed list or to the order of
the refusals is a change to a root program, and the owner reviews it.

| Control                                                                   | Broken by                                                | Fails in                                                                      |
| ------------------------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------- |
| A1 a step must be on the allow-list                                       | removing the not-listed refusal                          | `test_a_step_that_is_not_on_the_allow_list...`, harness refusal cases         |
| A2 the word must be that step's word                                      | skipping the word comparison                             | `test_a_wrong_confirmation_word...`, `test_the_word_of_one_step...`           |
| A3 the request shape is exact                                             | accepting a trailing token                               | `test_every_hostile_step_request...`, the random request test                 |
| A4 a plain request passes no tag                                          | passing a tag when the request has no step               | `test_a_plain_apply_and_a_check_pass_no_tag...`, harness plain-request check  |
| A5 a step is refused before the lock and the fetch                        | moving the step check after the fetch                    | `test_a_step_refusal_comes_before_the_lock_the_fetch_and_the_floor`           |
| A6 the step list is closed in the program                                 | dropping the closed-list test on a configured id         | `test_a_name_that_is_not_one_of_the_programs_steps...`, harness `break-glass` |
| A7 a check request cannot carry a step                                    | letting `--mode check` carry one                         | `test_a_check_request_that_carries_a_step...`, harness refusal case           |
| A8 an apply request cannot carry a step                                   | letting `--mode apply` carry one                         | `test_an_apply_request_that_carries_a_step...`, harness refusal case          |
| A9 the plain account has no step argument list                            | adding `--mode step` to the plain account's sudoers line | harness sudo block                                                            |
| A10 a step on a commit older than the floor is refused                    | skipping the floor test for a step                       | `test_a_step_on_a_commit_older_than_the_floor...`, harness refusal case       |
| A11 a step's tag is its own id's tag and no other                         | accepting any tag with the prefix, not the id's own      | `test_an_id_paired_with_any_tag_but_its_own_is_refused`, harness `tag-all`    |
| A12 two entries cannot share an id                                        | removing the duplicate test                              | `test_every_invalid_step_entry_is_refused`                                    |
| A13 the line of an apply and a check has no step field                    | always adding the step field                             | `test_the_summary_of_a_step_ends_with_the_step...`, harness refusal check     |
| A14 what the caller typed in a step request is never logged               | logging the typed id before it is found on the list      | `test_what_the_caller_typed_in_a_step_request...`                             |
| A15 the step mode with a bare commit is refused, not run as a plain apply | removing the no-step test for `--mode step`              | `test_a_bare_commit_with_the_step_mode...`, harness refusal case              |
| A16 the spec's step ids are the program's step ids                        | adding an id to the spec's `choices` only                | `test_the_spec_lists_exactly_the_step_ids_the_program_holds`                  |

The `command=` text and the key restrictions of the step key are reviewed, not tested
(no SSH server in the harness). A9 proves the sudo lines in this README, not the file
the `sudoers_and_keys` pattern writes on a host.

### The controls of the push receiver, and how each is shown to fail

Each control below has a unit test that names it and, for P1 to P10, a red case in the push
scenario that CI runs. The scenario works on Debian 13 with the program as installed: it
copies the program, changes one check with a replacement that must match, and runs a request
that the installed program refuses. The copy must answer the red way (the refusal is gone) and
the installed program must still give the refusal, which is the green side.

| Control                                              | Broken by                                       | Fails in                                                                           |
| ---------------------------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------- |
| P1 the request's mode word must equal the key's      | removing the comparison                         | `test_request_mode_word_must_equal_key_mode`, scenario `no-mode-compare`           |
| P2 a host with no floor applies nothing              | removing the no-floor refusal                   | `test_a_host_with_no_floor_applies_nothing...`, scenario `no-floor-test`           |
| P3 a commit older than the floor is refused          | removing the floor comparison                   | `test_a_commit_older_than_the_floor...`, scenario `no-floor-compare`               |
| P4 the signature is checked on a pushed commit       | removing the signature check                    | `test_an_unsigned_commit_is_refused`, scenario `no-signature-check`                |
| P5 the request's playbook must be the configured one | removing the comparison                         | `test_the_playbook_in_the_request...`, scenario `no-playbook-compare`              |
| P6 the bundle's HEAD must be the requested commit    | removing the HEAD test                          | `test_a_bundle_whose_head_is_not...`, scenario `no-head-test`                      |
| P7 the objects are checked with `fsck --strict`      | removing the explicit check                     | `test_an_object_that_fails_git_s_object_check...`, scenario `no-object-check`      |
| P8 standard input is limited in bytes                | removing the limit                              | `test_a_bundle_over_the_byte_limit...`, scenario `no-byte-limit`                   |
| P9 standard input is read against a deadline         | a blocking read in place of the `select` loop   | `test_a_stalled_stream_ends_at_the_deadline...`, scenario `blocking-read`          |
| P10 the quarantine takes nothing over the network    | allowing `https` in the quarantine's git        | `test_the_quarantine_may_use_the_file_transport...`, scenario `fetches-over-https` |
| P11 the floor seed never moves an existing floor     | `force: true` on the seed copy                  | the push scenario's seed check                                                     |
| P12 the receiver needs no network                    | none: the container has no network when it runs | the push scenario's control connect, which must fail                               |

The playbook-link, checkout and lock controls are those of the pull route and are shown
by the default scenario and in "How to test it". `check` on this source changes nothing
and does not move the floor (a unit test and the push scenario).

## How to change it safely

1. Change the tasks, the defaults and `meta/argument_specs.yml` together: the spec
   and the defaults must agree. A new step id is two edits, `STEP_IDS` in the program
   and the `choices` of the step `id` in the spec; a unit test fails when they differ.
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
