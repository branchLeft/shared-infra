# secrets_and_no_log

This role is a pattern. It is the recipe a maintainer follows when a shell script
writes a secret to a file on a host: a password in a file the service reads, a
token in an environment file, or a copy of a root-only file into the directory
the service reads. It delivers placeholder secrets named `EXAMPLE_…` to one
placeholder account. Copy the shape, not the names.

The role does not decide where a secret comes from. That is the owner's decision
(see "What the role decides, and what it does not"), and the recipe works with
either of the two ways a secret can arrive.

## What it does, and what it does not

It creates one directory that only its owner can enter, and puts in it one file
per secret, each file mode `0600`, owned by a named account and group, written in
one step so a reader sees the old content or the new content and never half of
either. A secret arrives as a value given at run time, or as the path of a
root-only file already on the host. It can also write one environment file, with
a `NAME=value` line for each secret that was given as a value.

It does not decide where a secret is kept, fetch one, generate one, create the
account, restart or reload the service that reads the files, remove a file whose
secret was retired, or apply itself to a host. An empty list of secrets changes
only the directory.

## What the role decides, and what it does not

The role takes the secret in one of two forms and accepts both:

- `value`: the text, supplied at run time by the play that includes the role
  (an extra variable, a vault-encrypted variable, a lookup in the play). The
  role never reads it from anywhere itself.
- `source_file`: the absolute path of a file that is already on the host, owned
  by root, with no group or other permission. The role copies it on the host, so
  the text never passes through a variable at all.

Which store the value comes from, and how it reaches a host that pulls its
commit from `main`, is not the role's decision and not this pattern's. It is the
owner's (PRIN-6: a sensitive-data boundary is the owner's to cross). Until the
owner has chosen, a service role built from this pattern has no source for its
secrets and must not invent one. No variable in this role has a default that
carries a secret, and no file in this directory holds one.

## What an agent may and may not do with a secret

Under this pattern an agent:

- may write and run the role and its test with the throwaway sentinels the test
  makes for itself, and may read the sentinels' files in the test's scratch
  directory;
- may declare a secret by name in a service role's variables, with no value, and
  document the name in the list below;
- may check that a delivered file has the owner, group, mode and checksum
  declared, because the test compares checksums and prints no value;
- never reads, prints, logs, pastes, commits or summarises the value of a real
  secret, in a command, a file, a pull request, an issue, a log or a reply, and
  never puts one in a command line, where it is visible to every account that can
  list processes;
- never creates, rotates or reads a store entry: the owner creates the entries
  (the list below says which), and the owner puts the value where the host can
  read it;
- never uses a real value in a test. A test uses a sentinel made for that run;
- never turns `no_log` off to see why a task failed on a real host. Reproduce on
  a lab host with a throwaway value, as the README of `sudoers_and_keys` does for
  its fragment.

An agent that finds it needs a real value stops and asks the owner.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables, and
[`defaults/main.yml`](defaults/main.yml) holds the same defaults, none of which is
a secret. The fixed values (the modes `0700` and `0600`, and the patterns that a
name, a path and an environment line must match) are in `vars/main.yml`, not in
the interface, so an inventory cannot loosen them.

| Variable                       | Default                        | Meaning                                                                   |
| ------------------------------ | ------------------------------ | ------------------------------------------------------------------------- |
| `secrets_and_no_log_directory` | `/etc/example-service/secrets` | The directory the files go in, an absolute path of plain characters       |
| `secrets_and_no_log_owner`     | `root`                         | The account that owns the directory and the files                         |
| `secrets_and_no_log_group`     | `root`                         | The group of the directory and the files                                  |
| `secrets_and_no_log_env_name`  | empty                          | The name of one environment file inside the directory; empty writes none  |
| `secrets_and_no_log_secrets`   | `[]`                           | The list of secrets: `name`, and exactly one of `value` and `source_file` |

`secrets_and_no_log_secrets` is the secret variable (ANS-14): each entry's `value`
is a secret and must never be written in a file, a default or a log. Its
`source_file` is a path, not a secret, but the file it names holds one. A secret
is given as a `source_file` (a root-only file on the host) where the source can
be one, and as a `value` only where a consumer needs it in the play. The
environment file (`secrets_and_no_log_env_name`) is the second choice (CRED-10):
use it only for a program that can read its secrets from the environment and not
from a file. One file per secret is the first choice.

The role leaves two facts for the play after it: `secrets_and_no_log_changed`,
the paths of the files it replaced, and `secrets_and_no_log_notified`, true when
any file was replaced. Neither holds a value.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, and `min_ansible_version`
  in `meta/main.yml` equal to it.
- No collection beyond `ansible.builtin`.
- Target: a Debian-family host with Python 3 and the account and group named in
  `owner` and `group`. The test image is Debian 13, the release the production
  hosts run.

## What it changes on a host

- `<directory>` (mode `0700`, owner and group as given).
- `<directory>/<NAME>` for each declared secret (mode `0600`, owner and group as
  given), holding exactly the value, or exactly the contents of the source file.
- `<directory>/<env_name>`, when set (mode `0600`), holding one `NAME=value` line
  for each secret given as a value, in the order declared, and nothing else.
- No service, port, user or firewall rule. No file outside the directory, and no
  backup copy of a replaced file.

## The recipe

### (a) The bash shape it replaces

```bash
umask 077
printf 'EXAMPLE_NAME=%s\n' "$EXAMPLE_VALUE" > /etc/example-service/secrets.env
cp /root/EXAMPLE_SOURCE /etc/example-service/EXAMPLE_NAME
chown example_user:example_group /etc/example-service/EXAMPLE_NAME
chmod 600 /etc/example-service/EXAMPLE_NAME
```

The mode of the first file depends on the `umask` of the shell that happened to
run it. `cp` makes the new file with the mode of the shell's umask, so the second
file is readable by others until the `chmod` runs. The redirection truncates the
file in place, so a crash leaves it empty or half written. A `set -x` anywhere in
the script prints the value. The line reports nothing about what changed, so a
rotation cannot be told from a no-op, and `cp … .bak` is how an old value comes to
sit in a second file for good.

### (b) The Ansible shape

```yaml
- name: Create the secrets directory, closed to everyone but its owner
  ansible.builtin.file:
    path: '{{ secrets_and_no_log_directory }}'
    state: directory
    owner: '{{ secrets_and_no_log_owner }}'
    group: '{{ secrets_and_no_log_group }}'
    mode: '0700'

- name: Write the secrets given as values
  ansible.builtin.copy:
    content: '{{ item.value }}'
    dest: '{{ secrets_and_no_log_directory }}/{{ item.name }}'
    owner: '{{ secrets_and_no_log_owner }}'
    group: '{{ secrets_and_no_log_group }}'
    mode: '0600'
    backup: false
  loop: '{{ secrets_and_no_log_secrets | selectattr("value", "defined") | list }}'
  no_log: true
  diff: false
  register: secrets_and_no_log_written
```

[`tasks/main.yml`](tasks/main.yml) is this with the checks in front, the host-file
copy, the environment file and the clean-up after. The checks run before anything
changes. Every check that reads an entry does it in a task with `no_log: true`
that keeps only the number of each entry that breaks a rule, and the assertion
after it names that number and the rule, never a name, a path or a value.

### (c) Why each parameter is set

- `mode: '0600'`, `owner`, `group`. `copy` keeps the owner and mode of a file
  that already exists unless told otherwise, so without them a file left by an
  earlier release, world readable and owned by root, stays that way. The test
  starts from such a file, and runs with an owner and group that are not root, so
  the assertion on them fails when the parameters are missing.
- The directory is created, mode `0700`, before any file is written, and the
  check of the source files comes before that. This is the control for the one
  moment the file is wider than `0600`. Ansible writes a new file to a temporary
  name in the destination directory, moves it into place, and only then sets the
  owner and mode. For a file that is new, the move gives it the mode the umask
  allows (`0644` on Debian) until the next step. The test makes the second step
  fail (an owner that does not exist) and shows the file stays at `0644`, and that
  an account that is neither the owner nor root cannot read it, because the
  directory it is in is `0700`. So the secret is never exposed to another
  account, but it is not true that the file is `0600` at every instant: root and
  the owner can read it in that moment, and so could any process that held the
  directory open from before the role closed it. See the named limits.
- `backup: false`. `copy` can keep the replaced file next to the new one. That
  copy would hold the old value for good, and the rotation test requires that no
  file on the host holds it.
- `content` and `remote_src` are the two forms. `content` carries the text through
  a variable, so every task that handles it has `no_log`. `remote_src: true` with
  `src` copies on the host, so the loop items hold a path. The task keeps
  `no_log: true` anyway, so the rule has no exception to remember. The copy's
  result still holds the SHA-1 and MD5 of the delivered file, which is a digest of
  the secret; `no_log` is what keeps that result out of the log (see "What the test
  shows about logs").
- The source file is checked first, and must be a plain file (not a link), owned
  by root, with no group or other permission. Its `stat` asks for no digest
  (`get_checksum: false`): the default SHA-1 of a secret would be printed by the
  assertion that refuses a bad source, and the register is emptied in the always
  section like the write registers. A copy keeps the mode of its source
  until the role sets the final mode, so a source that others could read would
  make the delivered file readable for a moment, in the one case the directory
  does not cover.
- `no_log: true` on every task that reads, templates, passes, registers or loops
  over a secret: the two writes, the environment file, the task that records which
  files changed (it reads the registered results, and a registered loop result
  keeps its items, which hold the values), and the task that empties those
  registers. `no_log` hides a task's output from the screen and the log; it does
  not empty the registered variable. The always section sets the three registers
  to empty after the writes, also after a failure, so a later task that prints its
  variables prints no secret.
- `diff: false` on the same tasks (ANS-16). With `--diff` Ansible prints the
  difference between the old and the new content, and the plan job's diff is read
  by everyone who can see the run. See "What the test shows about logs" for what
  was measured about this keyword.
- The handler takes no value. `notify` on the three write tasks runs one handler,
  which sets `secrets_and_no_log_notified`. A service role replaces the handler
  with the reload of its service. A handler is a task, and any that handled a
  value would need `no_log` too; this one handles none.
- `meta: flush_handlers` at the end, so the play that includes the role can read
  the flag straight away, and a failure later in the play does not leave a
  reload pending.
- The environment file is written by `template`, not assembled by `lineinfile` or
  a shell loop. It lives inside the secrets directory, so its parent is always the
  `0700` directory. It holds exactly one line per secret given as a value.
- The name of a secret must match `^[A-Z][A-Z0-9_]*\Z`, the path of a source file
  `^/[A-Za-z0-9._/-]+\Z`, and the name of the environment file
  `^[A-Za-z0-9][A-Za-z0-9._-]*\Z`. The patterns end in `\Z`, not `$`, because `$`
  also matches before a trailing line break.
- A value that goes in the environment file must be printable ASCII
  (U+0020 to U+007E). A line break of any kind, a control character, or a
  character outside ASCII would start a second line, or be read differently by the
  program that parses the file, so the role refuses it and says to give the secret
  as a host file instead. The test builds each of thirteen code points.
- The assertions use no `loop` over the entries. A failed loop prints its item,
  which here would be a secret. The checks work on the whole list inside a
  template that returns numbers only.
- `FQCN` everywhere (ANS-8); `copy`, `file`, `template`, `stat` (ANS-9: no
  `lineinfile` on a secret, no `shell`).

## What the test shows about logs

Each scenario value is a sentinel: a 40-character string made for the run by the
seeded password lookup on the controller (`prepare.yml`), so the same label gives
the same text and the run's output can be searched for it afterwards. A sentinel is
not in `molecule.yml`, which names only the file it is read from. The scenario sets
`ANSIBLE_LOG_PATH` to a file on the controller and `ANSIBLE_VERBOSITY` to `3`, which
makes Ansible print each task's result together with the arguments it was given,
and the loop items. The verify play reads that log last, so it covers the check-mode
run against the fresh host (which runs with `--diff`), the converge, the second
converge, the plan with `--diff` for a rotation, every rotation, the refused inputs (each is
one include of `tasks/refused.yml` in `verify.yml`, so `grep -c 'tasks/refused.yml'
ansible/patterns/secrets_and_no_log/molecule/default/verify.yml` gives their number;
the code-point loop adds one case per code point), a write that fails (a directory
is in the way of one secret's file), and the argument checks. It fails if any sentinel except one is in the log. The exception
is the sentinel that Ansible's own argument validation printed (see "What a failed
argument check prints"), which the scan uses as a positive control.

A scan that finds nothing proves nothing unless it can find something. The scan's
controls, all required before it counts: the converge also runs a harmless command
with a known canary argument and no `no_log`, and the scan requires the canary, two
of the role's task names and the one sentinel Ansible printed to be in the log.

The scan also covers the other files the run leaves: the second play of
`verify.yml` searches the whole scenario directory on the controller (the
inventory Molecule built, its state, the log) for every sentinel but the one the
validation printed. Last, the harness output was captured to a file and searched by
a separate throwaway playbook that regenerates the sentinels from the same seeds
and counts them; the counts were zero for every sentinel but the validation's, and
nine for that one. That outside scan is a check made at this state, not a step of
the harness.

What was observed on ansible-core 2.21.5, by editing the role and running the
harness (the table at the end has every edit):

- With `no_log: true` removed from the copy that writes the values (a loop task),
  the values are in the log: the loop items and the module arguments print them.
  The verify play fails at "Assert no sentinel reached the log" and names the
  labels it found.
- With `no_log: true` removed from the task that reads the registered results
  (the one that records which files changed), the values are in the log: the loop
  over the registered results prints each item, and the items of a registered loop
  hold the values. The verify play fails at the same assertion.
- The `diff: false` keyword on the value copy and on the environment file's template
  is redundant with `no_log: true` on this version: removed alone, the harness is
  green, because `no_log` also censors the diff. Removed together with `no_log`,
  the verify play fails at "Assert no sentinel reached the log". The keyword stays
  because ANS-16 asks for it and a later version may differ.
- The `diff: false` keyword on the host-file copy is redundant the same way: removed
  alone the harness is green, and removed with `no_log` the verify play fails.
- `no_log: true` on the environment file's template, removed alone, is caught by the
  digest of the whole file: the template's result carries its SHA-1 and MD5. The
  verify play fails at "Assert no sentinel reached the log" and names the two
  environment file texts (before and after a rotation). Before the scan searched
  those digests, this edit was green.
- `no_log: true` on the host-file copy, removed alone, is caught by the digests of
  the delivered file (the copy's result carries them). The verify play fails and
  names the host secret and its rotated value.
- The stat that reads each source file takes no digest (`get_checksum: false`). With
  the default restored, the SHA-1 of the host-file secret reaches the log, and the
  same assertion fails.
- The scan's digest control: the scan's own control sentinel is printed only as its
  SHA-1, and "Assert the scan finds the digest control in the log" fails when the
  digest comparison is removed from the scan.
- The `no_log: true` on the task that works out which entries break a rule is
  **reviewed, not tested**: its result holds only numbers.

A consequence of `no_log: true` that a maintainer will meet: when one of these
tasks fails on a host, the output says only that it is hidden. The role's failure
modes that a maintainer can act on are checked before the tasks that hold a value
(source file, name, path, line), and they print the entry number and the rule. For
the rest, reproduce on a lab host with a throwaway value.

The failing write (a directory is in the way of one secret's file) is the case
that matters most: the module's own error would repeat its arguments. The task
prints that its output is hidden, the scenario asserts that the failure message
holds no sentinel, and that no registered result holds one afterwards, because the
always section emptied them.

## Rotation as a re-run

Rotation is the role run again with a new value. Nothing else is needed: the file
is replaced, the old value is gone, and a run with the same value changes nothing.
The scenario starts from a host where an earlier release left an old value in a
world-readable file at the place the role writes, then checks each step below by
the inode of the file as well as by its content.

- The same values again: `secrets_and_no_log_changed` is empty, the notified flag
  is false, and every inode is the one it was (nothing was rewritten).
- One value rotated: exactly its file and the environment file are replaced (new
  inodes, `changed` lists the two paths, the flag is true), the other two files keep
  their inodes, and the value it replaced is in no file under `/etc`, `/home`,
  `/opt`, `/root`, `/srv`, `/tmp`, `/usr/local` or `/var`: `grep` reads every file
  there, backups and temporary files included, and must find nothing. The same run
  proves the earlier release's value is gone.
- The rotated value again: nothing changes.
- A secret given as a host file is rotated at its source. The plan (check mode with
  `--diff`, as the approval gate shows it) reports that file as changed and does not
  rewrite the delivered file; the real run does, and the old value is gone.
- Both values are rotated back so that the host ends as the converge left it, and
  the rotated values are gone.

The scan of the host skips one directory, `.ansible` under the connection user's
home, because Ansible keeps the arguments of a running module there for the length
of the run and a search for the value finds that file (the copy is removed when the
module ends; the scan does not examine it).

A retired secret is a different case. A name that is no longer declared is not
removed: the role never deletes a file it was not asked to write. See the named
limits.

## What a failed argument check prints

Ansible checks a role's `meta/argument_specs.yml` before the role's first task,
in a task that no keyword reaches, so the role cannot put `no_log` on it. Whether
that check prints a value it rejects is not documented by Ansible, so the scenario
tests it, and these are facts about ansible-core 2.21.5 as the test saw them:

- Handing the role a string where it expects a list of mappings, or a string as a
  list item, fails with a message that names the option and the types
  (`is of type str and we were unable to convert to dict`) and not the value.
- A key the spec does not know (a misspelt `value`) and a mapping used as a list
  entry fail with a message that prints the key names (`secrets_and_no_log_secrets.valu`).
  It prints the keys, not their values. A mapping key is data, so a secret must
  never be a key.
- A value that fails `choices` is printed: `value of … must be one of: …, got: <value>`.
- A value that cannot be converted to an integer is printed, in quotes.
- A `no_log: true` key on the option in the spec does not stop either message. The
  scenario runs the same option with and without the key, and both print the value.
- The failure result also carries the whole spec, with its descriptions, as
  `argument_spec_data`. It carries no supplied value.

So the role has no secret-bearing option with `choices`, a number type or a pattern:
every option that can hold a secret is plain text, which the check accepts, and the
role's own checks (the name, the source, the path, the environment line) run in
tasks that print entry numbers only. The test supplies the sentinel in each of the
four shapes above and finds it nowhere in the log. A service role that adds an
option of a type that can fail next to a secret must keep the secret out of that
option, and the test of the three probes tells a maintainer when a newer
ansible-core changes any of this: they assert that the value is printed, so they
fail when it stops being printed and the README needs to change.

## The secret names the services will need

Names only, taken by reading the scripts, compose files and runbooks under
`hetzner/` and `mail/` for the variables that hold a credential. A name here means
a file under those directories reads a variable of that name; it is not a check
that the service needs it today. There are no values, no store entry names and no
account identifiers in this list.

| Name                                         | Read under                | How it is made today                                      |
| -------------------------------------------- | ------------------------- | --------------------------------------------------------- |
| `STALWART_PROMETHEUS_SECRET`                 | `mail/provision`          | Minted on the host by the deploy script                   |
| `SHIM_DRAIN_TOKEN`                           | `mail/provision`          | Minted on the host by the render script                   |
| `CROWDSEC_BOUNCER_KEY`                       | `hetzner/edge`            | Generated on the host by a runbook command                |
| `NEXTCLOUD_DB_PASSWORD`                      | `hetzner/nextcloud1`      | Generated on the host by a runbook command                |
| `NEXTCLOUD_REDIS_PASSWORD`                   | `hetzner/nextcloud1`      | Not read                                                  |
| `NEXTCLOUD_ADMIN_PASSWORD`                   | `hetzner/nextcloud1`      | Not read                                                  |
| `NTFY_PAGER_TOKEN`                           | `hetzner/monitoring`      | Not read                                                  |
| `NTFY_WATCHER_TOKEN`                         | `hetzner/monitoring`      | Not read                                                  |
| `GRAFANA_ADMIN_PASSWORD`                     | `hetzner/monitoring`      | Not read                                                  |
| `CONTROL_PLANE_DB_ADMIN_PASSWORD`            | `hetzner/control-plane`   | Not read                                                  |
| `CONTROL_PLANE_ZITADEL_DB_PASSWORD`          | `hetzner/control-plane`   | Not read                                                  |
| `CONTROL_PLANE_ZITADEL_FIRST_ADMIN_PASSWORD` | `hetzner/control-plane`   | Not read                                                  |
| `HCLOUD_TOKEN`                               | the provisioning runbooks | Issued in the provider's console, then typed by the owner |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | the provisioning runbooks | Issued in the provider's console, then typed by the owner |

"Not read" means the creation step was not examined for this list. Under this
pattern the owner creates the last two rows: a provider's console issues them, and
the runbooks read them into the shell with `read -rs`. Whether any other row stays
generated on the host or becomes an entry the owner creates is the source decision
this pattern leaves to the owner. The last two rows are credentials of the people
and pipelines that provision, not of a running service, and may not belong on a
host at all; that is the owner's call too.

## How to run its test

From the repository root, with Docker running locally and Python 3.12 or later.
`ansible/README.md` describes the harness and the tools in full. The controller
needs nothing else: the sentinels are made by Ansible's own password lookup.

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/secrets_and_no_log
```

Run it through the harness. A bare `molecule` run reuses its scratch directory, and
the log file there then holds the output of earlier runs, which can fail the log
scan for a reason the current role does not have.

What each part of the scenario does:

- `prepare.yml` makes the throwaway sentinels on the controller (one file per
  label, in a directory under Molecule's scratch directory, never in the
  repository), creates the placeholder account and group, puts a root-only source
  file on the host, three bad source files (open to others, owned by another
  account, a link), and an earlier release's state: the directory open to everyone
  and a world-readable file holding an old value at the place the role writes.
- `check-fresh`: the converge in check mode with `--diff` against that host.
- `converge`: applies the role with three secrets (two values, one host file) and
  an environment file, then runs the canary command.
- `idempotence`: a second converge reports no change (ANS-11).
- `verify`: the host is checked (`tasks/assert_state.yml`), the earlier value is
  gone, the defaults and the argument spec are checked for secrets, the refused
  inputs run, the rotations run, the failing write runs, the argument checks run,
  the host is checked again, and the log and the scenario directory are scanned.
- `check-configured` and `molecule-check`: the configured host shows no drift.

`tasks/assert_state.yml` checks: the directory's mode, owner and group; that the
directory holds the declared files and nothing else, hidden files and backups
included; each file's mode `0600`, owner, group, link count and checksum (no value
is printed, the checksums are compared); the source file untouched.

The refused cases build their awkward characters from code points (`'%c' | format(N)`),
because a character typed into the YAML file is folded or refused by the linter.
Each case runs the role inside a `block` and requires that the role stopped at the
named task, with the entry number in the message where the rule gives one, and that
the message holds no sentinel.

What breaks which step. Each row is an edit, one harness run, and a `git restore`;
the harness is green again after the restores, and a last full run and a run on an
unedited fresh role were green too.

| Edit                                                                                                  | Step that fails, and the assertion                                                                                                                                                                |
| ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `no_log: true` removed from the copy that writes the values (a loop task)                             | `verify`: "Assert no sentinel reached the log" (four sentinels found)                                                                                                                             |
| `no_log: true` removed from the task that records the changed paths (it reads the registered results) | `verify`: the same assertion (three sentinels found)                                                                                                                                              |
| `diff: false` removed from the value copy, `no_log` kept                                              | green: `no_log` hides the diff too; redundant, see the row below                                                                                                                                  |
| `diff: false` and `no_log: true` both removed from the value copy                                     | `verify`: "Assert no sentinel reached the log" (five sentinels found, the loop items)                                                                                                             |
| `no_log: true` removed from the environment file's template, `diff: false` kept                       | `verify`: "Assert no sentinel reached the log" (the two environment file digests found)                                                                                                           |
| `diff: false` removed from the environment file's template, `no_log` kept                             | green: `no_log` hides the diff too; redundant, see the row below                                                                                                                                  |
| `no_log: true` and `diff: false` both removed from the environment file's template                    | `verify`: "Assert no sentinel reached the log" (four labels found)                                                                                                                                |
| `no_log: true` removed from the host-file copy                                                        | `verify`: "Assert no sentinel reached the log" (the host secret and its rotation found by digest)                                                                                                 |
| `diff: false` removed from the host-file copy, `no_log` kept                                          | green: `no_log` hides the diff too; redundant, see the row below                                                                                                                                  |
| `no_log: true` and `diff: false` both removed from the host-file copy                                 | `verify`: "Assert no sentinel reached the log" (the host secret and its rotation found)                                                                                                           |
| The source file's stat with its default digest (`get_checksum` true)                                  | `verify`: "Assert no sentinel reached the log" (the host secret's SHA-1 found)                                                                                                                    |
| The scan's digest comparisons removed from its `when`                                                 | `verify`: "Assert the scan finds the digest control in the log"                                                                                                                                   |
| The source-file mode check `% 64` changed to `% 8`                                                    | `verify`: "Expected the role to stop at Refuse a source file that is missing, not a plain file, not owned by root or open to group or other" (a source file that the group can read was accepted) |
| The name pattern widened to allow `.` and `/`                                                         | `verify`: "Expected the role to stop at Refuse a secret name that is not an ALL_CAPS name" (the role went on to the write)                                                                        |
| A variable added to `defaults/main.yml`                                                               | `verify`: "Assert the defaults hold no secret and the list of secrets is empty"                                                                                                                   |
| File mode `0644`                                                                                      | `verify`: "Assert each file is private to its owner and holds exactly its value" (all four files)                                                                                                 |
| `owner: root` on the value copy                                                                       | `verify`: the same assertion, for the files the copy wrote                                                                                                                                        |
| `backup: true` on the value copy                                                                      | `verify`: "Assert the directory holds the declared files and nothing else" (a backup is listed)                                                                                                   |
| A task that keeps a copy of the old file outside the directory, made once                             | `verify`: "Assert no file on the host holds the value" (the earlier value is in the kept copy)                                                                                                    |
| The same task, copying again on every run                                                             | `idempotence`                                                                                                                                                                                     |
| A `command` task with `changed_when: true` added                                                      | `idempotence`: the task is named                                                                                                                                                                  |
| The directory task moved after the write tasks                                                        | `verify`: "Assert the directory task ran before the write tasks"                                                                                                                                  |
| The check that a source file has no group or other permission made always true                        | `verify`: "Expected the role to stop at Refuse a source file that is missing, not a plain file, not owned by root or open to group or other"                                                      |

### Named limits

- **The source of a secret is the owner's decision.** The role takes a value at run
  time or the path of a root-only file already on the host. It does not fetch, store
  or generate a secret, and it does not know where the value came from. How the
  value of an approved store entry reaches a host that pulls its commit from `main`
  is not decided here (PRIN-6); until it is, a service role built from this pattern
  has no source and must not invent one.
- **The file is not `0600` at every instant.** Ansible moves the new file into place
  and sets the owner and mode afterwards, so a new file has the mode the umask
  allows (`0644`) until the second step. The control is the directory, created
  `0700` before any write: another account cannot enter it. The scenario proves
  this by making the second step fail and showing the file stays `0644` and an
  unrelated account cannot read it. What it does not prove: that root and the owner
  cannot read the file in that moment (they can, and are not the threat), and that
  no process which already held the directory open from before the role closed it
  can read the file. The pattern is for a directory the role owns.
- **The value passes through temporary files.** For `content`, Ansible writes the
  value to a temporary file on the controller, sends it to the connection user's
  `.ansible/tmp` on the host, and writes the target from there; it removes both when
  the module ends. The scenario searches the host for the old value after each
  rotation, but skips the `.ansible` directory, and it searches the controller's
  scenario directory but not the controller's system temporary directory. A crash
  of the run can leave a temporary file; it is `0600` and owned by the connection
  user.
- **A failed argument check can print the value of an option that has a type or a
  choice.** See "What a failed argument check prints". The role has none, and the
  `no_log` key of an argument spec does not stop it.
- **`no_log` hides the reason for a failure on a real host.** A failing write on a
  host prints only that the output is hidden. The role's own checks come first and
  print the rule and the entry number; for the rest, reproduce on a lab host with a
  throwaway value. Do not turn `no_log` off on a real host.
- **A value given as plain text is read as a template when it holds a template
  marker.** Ansible evaluates `{{ ... }}` and `{# ... #}` in a play's own text, so a
  value of `a{{ 1 + 1 }}b` is delivered as `a2b`, and a value with a broken marker
  fails in the argument check, which prints the line of the file that holds it. A
  value from a `file` lookup, an encrypted vault variable or one marked `!unsafe`
  is delivered literally. The role does not refuse a marker in a value, so a secret
  that holds one must come as a `source_file` or from a lookup. Not tested for every
  shape.
- **An environment file named like a secret overwrites that secret's file, and
  is not idempotent.** `secrets_and_no_log_env_name` equal to a secret's name is not
  refused. The environment file replaces the secret's file, and the role reports a
  change on every run. Give the environment file a name no secret uses.
- **An empty source file is delivered as an empty secret.** A `value` of the empty
  string is refused, but a `source_file` that is empty is copied, and the consumer
  gets an empty secret with no error. The role does not check the content of a
  source file.
- **The parent directories of a source file are not checked.** Only the final
  component (a plain file, not a link, owned by root, mode with no group or other
  bit) is checked. A link in a parent directory that another account can write to
  could redirect the path to another root-only file, and the check and the copy are
  not atomic. The owner's source paths must sit in directories only root writes.
- **A retired secret is not removed.** The role writes the files it is given and
  removes none. A secret that is no longer declared stays on the host until a
  deliberate removal change.
- **Mode `0600` only.** A service that runs as another account than the owner of
  the file cannot read it. The owner is the account that reads (or root), and the
  role does not offer group read. A service role that needs `0640` changes
  `vars/main.yml` deliberately and re-proves the table below.
- **The environment file is written verbatim.** One `NAME=value` line for each
  secret given as a value, printable ASCII only. How a consumer parses it differs:
  a systemd `EnvironmentFile` reads quotes and a trailing backslash differently from
  a Docker `env_file`, which keeps quotes, and neither is the shell. A value with a
  quote, a `$`, a backslash or a leading or trailing space is accepted and written
  as it is; the service role decides whether its consumer reads it back. Not tested
  against any consumer.
- **Check mode on a fresh host shows less.** Check mode creates nothing, so on a host
  where the directory does not exist the plan lists the directory and skips the file
  writes. The plan job (`--check --diff`, ANS-17) cannot show the per-file changes
  of a first run. Once the directory exists, the plan lists each changed file.
- **The handler is a placeholder.** It sets a flag. A service role replaces it with
  the reload of its service, and the test of that reload belongs to the service role.
- **The scenario scans the log and the scenario directory, not the harness console.**
  The harness prints Ansible's console output (verbosity 3) to its own standard
  output. That output was captured and searched once, outside the harness, for each
  sentinel, and held none but the validation's. It is not a step of the harness, so
  a change that prints a value to the console but not to the log would not fail it.
- **Only the Debian 13 image on Docker Desktop (arm64) was run**; an amd64 runner was
  not.
- CI runs this scenario: the Ansible workflow on `main` installs the pinned
  collections and runs the harness over every role and every pattern under
  `ansible/patterns/`, so this pattern's lint, interface and container steps run on
  each change.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after the
approval of its protected environment. A plan job shows each host's diff in check
mode first; after the approval the host pulls that exact commit of `main` and applies
it, and a second run must report zero changes. Nothing is applied from a laptop. This
pattern is not applied to any host: it exists to be copied, and the trigger and the
reusable workflow are separate work.

The plan job's diff is the reason `diff: false` is in the recipe: a job summary is
read by everyone who can see the run. How the value reaches the play on a host that
pulls its commit is the source decision above.

## How a service role copies it

1. Make the new role from the skeleton, as `ansible/README.md` says, under
   `ansible/roles/`.
2. Copy `tasks/main.yml`, `handlers/main.yml`, `vars/main.yml`, the two templates
   and the whole of `molecule/default/` over the new role's files. Keep `namespace`
   in `meta/main.yml`: Molecule links the role under it.
3. Rename. The variable prefix `secrets_and_no_log_` becomes the new role's name in
   `defaults/main.yml`, `meta/argument_specs.yml`, `vars/main.yml`, the tasks, the
   templates and the `include_role` calls in `converge.yml`, `verify.yml` and
   `tasks/apply.yml` and `tasks/refused.yml` (`branchleft.secrets_and_no_log`). The
   task names appear in `verify.yml` as the `refused_task` values: change both
   together.
4. Replace the placeholders: the directory, the owner and group, the secret names
   (use the names in the list above) and the ALL_CAPS values in `meta/`.
5. Take the secrets from the service's own variables, supplied at run time. Do not
   put a value in `defaults/main.yml`, in `argument_specs.yml` or in a file in the
   repository; the test fails if you do.
6. Replace the handler with the service's reload.
7. Run the harness on the new role. Then break each control in the table above on the
   copy and see the same step fail: a control is yours only after you have broken it.
8. Keep the image pin and its reason below.

## The test base image (a third-party image, trusted by digest)

The scenario needs Python, `grep`, `runuser` and the account tools. It does not need
systemd, so it sets none of the settings that run systemd: no cgroup mount, no
cgroup namespace mode, no tmpfs. It sets `command: sleep infinity`, so systemd is
never the first process. The image's own command starts systemd, which needs those
settings; the container can exit at once on a host with cgroup v2 without them. No
`privileged`, no capabilities.

- Image: `geerlingguy/docker-debian13-ansible`, referenced in
  `molecule/default/molecule.yml` as `name:latest@sha256:<digest>` (CON-3). The
  production hosts run Debian 13. The digest is the pin and the tag beside it is
  informational.
- Source: the public repository `geerlingguy/docker-debian13-ansible` on GitHub (MIT
  licence), built `FROM debian:trixie` with `sudo`, `systemd`, `python3-pip`,
  `python3-apt` and a few network tools, then `ansible` and `cryptography` from PyPI
  without version pins. The image's own Ansible is not used: Molecule runs the
  controller's pinned Ansible against the container.
- The image declares `/sys/fs/cgroup` as a volume, so every container started from it
  gets an anonymous volume. Molecule's destroy keeps a container's volumes by
  default, so the platform sets `keep_volumes: false`. Without it each run leaves a
  volume that has no label to find it by. Any scenario on this image must set it.

Named limit: the image is trusted by its digest and by review. It is not built by
this repository, and its unpinned PyPI installs were resolved once, at its build and
are frozen by the digest.

## How to change it safely

Change the tasks, the templates, the argument spec, the defaults and the converge,
verify and refusal plays together, run the harness, and break the control you
touched (the table above) to see it fail. A change to the digest is its own change,
reviewed on its own. Removing a `no_log`, the `backup: false`, the closed directory,
the source file check or any assertion removes a control the table shows. Never
add a value to a file in this directory, and never run the role against a real
secret to test it.
