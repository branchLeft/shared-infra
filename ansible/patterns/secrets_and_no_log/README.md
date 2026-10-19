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
  `no_log: true` anyway, so the rule has no exception to remember.
- The source file is checked first, and must be a plain file (not a link), owned
  by root, with no group or other permission. A copy keeps the mode of its source
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

RESULTS_PENDING

## Rotation as a re-run

RESULTS_PENDING

## What a failed argument check prints

RESULTS_PENDING

## The secret names the services will need

RESULTS_PENDING
