# sudoers_and_keys

This role is a pattern. It is the recipe a maintainer follows when a shell script
installs a sudoers fragment, adds SSH keys to an account, or adds a key that may
run one forced command. It configures one placeholder account with placeholder
keys and commands, and no real access. Copy the shape, not the names.

## What it does, and what it does not

It installs one fragment under `/etc/sudoers.d`, checked by `visudo` before it
replaces anything, and it makes the authorised keys of one existing account
exactly the declared list, so a key that is no longer declared is removed. A key
can carry a forced command and a source restriction.

It does not install `sudo` or an SSH server, create the account, edit
`/etc/sudoers`, `sshd_config` or any file of another role, remove a fragment, or
apply itself to a host. An empty list for either half means "not declared": it
changes nothing and never removes everything.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables, and
[`defaults/main.yml`](defaults/main.yml) holds the same defaults. The restrictive
options, the key pattern and the other fixed values are in `vars/main.yml`, not
in the interface, so an inventory cannot change them.

No variable is a secret. The keys are public keys and the sudoers lines are
policy, but both are treated as sensitive: every task that handles them sets
`no_log: true` and `diff: false` (ANS-16), and the test proves it (below).

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, and `min_ansible_version`
  in `meta/main.yml` equal to it.
- `ansible.posix`, pinned in `ansible/requirements.yml`, for `authorized_key`.
- Target: a Debian-family host with `sudo` (the role calls `/usr/sbin/visudo`),
  Python 3, and an existing account. The test image is Debian 13, the release the
  production hosts run.

## What it changes on a host

- `/etc/sudoers.d/<sudoers_and_keys_sudoers_name>`: owner `root`, group `root`,
  mode `0440`, holding the declared lines and nothing else.
- `<home>/.ssh` (mode `0700`) and `<home>/.ssh/authorized_keys` (mode `0600`) of
  the account, owned by the account: exactly the declared keys.
- No service, port, user or firewall rule. `/etc/sudoers` is never opened.

## The recipe

### (a) The bash shape it replaces

```bash
cat > /etc/sudoers.d/EXAMPLE_FRAGMENT <<'EOF'
EXAMPLE_USER ALL=(root) NOPASSWD: /usr/local/bin/EXAMPLE_COMMAND
EOF
chmod 0440 /etc/sudoers.d/EXAMPLE_FRAGMENT
echo 'command="/usr/local/bin/EXAMPLE_COMMAND" ssh-ed25519 EXAMPLE_KEY_BODY' >> /home/EXAMPLE_USER/.ssh/authorized_keys
```

It writes the fragment before anything checks it, so a typo is live in the file
sudo reads (a file `sudo` cannot parse is a lock-out risk, which this test does
not exercise). It appends a key on every run and never removes one, so a key
that was retired stays valid. The forced command carries no restriction on port
forwarding, a terminal or the agent, and no source address. It reports nothing
about what changed, and a reader must simulate it to learn the end state.

### (b) The Ansible shape

```yaml
- name: Install the sudoers fragment
  ansible.builtin.copy:
    content: "{{ sudoers_and_keys_sudoers_lines | join('\n') }}\n"
    dest: '/etc/sudoers.d/{{ sudoers_and_keys_sudoers_name }}'
    owner: root
    group: root
    mode: '0440'
    validate: /usr/sbin/visudo -cf %s
  no_log: true
  diff: false
  when: sudoers_and_keys_sudoers_lines | length > 0

- name: Make the authorised keys of the account exactly the declared keys
  ansible.posix.authorized_key:
    user: '{{ sudoers_and_keys_user }}'
    key: "{{ lookup('ansible.builtin.template', 'authorized_keys.j2') }}"
    exclusive: true
    manage_dir: true
  no_log: true
  diff: false
  when: sudoers_and_keys_keys | length > 0
```

`templates/authorized_keys.j2` writes one line per declared key: the `from="…"`
option when addresses are given, then, when a command is given,
`command="…"` and the four options in `sudoers_and_keys_restrict_options`, then
the key. Five assertion tasks at the top of `tasks/main.yml` check the inputs
before anything changes.

### (c) Why each parameter is set

- `validate: /usr/sbin/visudo -cf %s`. Ansible writes the content to a temporary
  file, runs the command on it, and moves it over the old file only if the command
  succeeds. A fragment `visudo` refuses fails the task and the old fragment stays.
  `-f` makes `visudo` read `%s` and not `/etc/sudoers`; `-c` makes it check and
  exit. The test that a weak validator is caught is in the table below.
- `owner`, `group`, `mode: '0440'`. `copy` keeps the owner and mode of a file that
  already exists unless told otherwise, so without them an earlier file owned by
  someone else stays theirs. The test starts from such a file.
- `content` joined with `\n` and ending in a newline: the file is exactly the
  declared lines. There is no "managed by" header, because the test compares the
  file with the declared lines and a header is a line nobody declared. Put a
  comment in the declared lines when one is wanted.
- The file name is checked against `^[A-Za-z0-9_-]+\Z`. `sudo` skips a file name
  with a dot or ending in a tilde, so a fragment named `ops.conf` would be written,
  would look right in a listing, and would grant nothing.
- `exclusive: true`. The account's file becomes the declared list, so a key that is
  no longer declared is removed. The module's option is "not loop aware", so all
  keys go in one task as one newline-separated value (the template), never one task
  per key in a loop, which would remove each key's predecessors.
- Options are built from structured fields, not accepted in the `key` value. The
  key pattern allows a key type, a base64 body and a comment on one line and nothing
  in front, so a `key` value cannot bring its own options or hide a second key
  behind a line break.
- A forced command must come with `from_addresses`, and gets `no-port-forwarding`,
  `no-pty`, `no-agent-forwarding` and `no-X11-forwarding`. The command may not hold
  a double quote or a line break, which would end its option early.
- `when: … | length > 0` on both tasks. An empty list is "not declared". With
  `exclusive: true` an empty value would write an empty file and remove every key,
  and a variable that arrived empty by mistake is exactly how that happens.
- `no_log: true` and `diff: false` (ANS-16). See "What the test shows about logs".
- The assertions use no `loop`. A failed loop prints its item, which here would be
  a key. Each assertion has its own task name, and the test names the task it
  expects to refuse each bad input.
- `FQCN` everywhere (ANS-8); `ansible.posix.authorized_key` is the module the
  pinned collection provides (ANS-9: no `lineinfile`, no `shell`).

### What the lock-out checks are

A role that replaces the only working sudoers file or the only working key locks
the host out. The recipe does this:

- It never edits `/etc/sudoers`. The test keeps a copy of the main file from before
  the role and compares checksums afterwards.
- The fragment is validated before it replaces anything. The test applies a fragment
  `visudo` refuses and checks that the role stopped at the install task, and that
  the good fragment is afterwards still there with the same owner, group, mode and
  lines, and the directory holds no leftover file. After the refusals, `visudo -c`
  for the whole configuration still passes and lists the fragment.
- Keys are replaced as one file by the module, which writes a temporary file and
  moves it over the old one. An empty list never reaches the module.
- A role that manages the account Ansible logs in as lists that account's own key
  among the declared keys, and a role that removes access applies after the access
  that replaces it. This is review, not test.

## What the test shows about logs

The scenario sets `ANSIBLE_LOG_PATH` to a file on the controller and
`ANSIBLE_VERBOSITY` to `1`, which makes Ansible print each task's result together
with the arguments it was given. The verify play reads that log last, so it covers
the converge, the second converge, the check-mode run against the fresh host (which
runs with `--diff`), and the refused runs. It fails if any throwaway key body, the
word `NOPASSWD`, or the text of the invalid fragment is in it.

A scan that finds nothing proves nothing unless it can find something, so the
converge also runs a harmless command with a known canary argument and no `no_log`.
The verify play requires that the canary and the names of the two role tasks are in
the log.

What was observed on ansible-core 2.21.5, by editing the role and running the
harness:

- With `no_log: true` removed from the key task, the key bodies are in the log and
  the verify play fails.
- With `no_log: true` removed from the sudoers task, the successful result does not
  show the lines, but a refused
  fragment prints `visudo`'s message with the offending line, so the scan fails on
  the invalid fragment's text.
- With `diff: false` removed and `no_log: true` kept, nothing leaks: `no_log` also
  hides the diff. With both removed, the key bodies appear more often than with only
  `no_log` removed, which is the `--diff` output. So `diff: false` is not what stops
  the leak on this version, and no test fails if it is removed: it is **reviewed, not
  tested**. It stays because ANS-16 asks for it and a later version may behave
  differently.
- The argument validation task printed the spec name and the role path, not the
  values it checked. That is the success path at verbosity 1 only.

A consequence of `no_log: true` that a maintainer will meet: when `visudo` refuses
a fragment, the task output says only that the output is hidden. To see why, run
`visudo -cf` on the lines by hand on a lab host, or remove `no_log` on a copy of
the role in a lab with a throwaway fragment.

A trap the test found: a sudoers line such as `example_ops ALL=(root) NOPASSWD:
EXAMPLE_COMMAND` written without quotes in YAML is a mapping, because of the
colon and the space. The argument check turns the mapping into text without
complaint, and the role would hand `visudo` the text of a dictionary. The role
refuses a non-text line with a message that says to quote it.

## How to run its test

From the repository root, with Docker running locally and Python 3.12 or later.
`ansible/README.md` describes the harness and the tools in full. The controller
also needs `ssh-keygen`, which the test uses to make its throwaway keys.

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/sudoers_and_keys
```

Run it through the harness. A bare `molecule` run reuses its scratch directory, and
the log file there then holds the output of earlier runs, which can fail the log
scan for a reason the current role does not have.

What each part of the scenario does:

- `prepare.yml` makes three throwaway key pairs on the controller (`forced`,
  `interactive`, `stale`), creates the placeholder account, gives the account the
  stale key, leaves an earlier fragment owned by the account with other content, and
  keeps a copy of the main sudoers file. The image has no `ssh-keygen`, so the keys
  are made on the controller; they exist for this run only.
- `check-fresh`: the converge in check mode against that host. It completes.
- `converge`: applies the role with two keys, one with a forced command and two
  source ranges and one without, then runs the canary command.
- `idempotence`: a second converge reports no change (ANS-11).
- `verify`: `tasks/assert_state.yml` checks the host, then the refusals run, then the
  host is checked again, then the log is scanned.
- `check-configured` and `molecule-check`: the configured host shows no drift.

`tasks/assert_state.yml` checks: the fragment's owner, group and mode; its lines,
exactly; that the directory holds no other file besides the image's README; that the
main sudoers file is unchanged; that `visudo -c` passes and lists the fragment; the
owner and mode of the account's `.ssh` directory and key file; the key file's lines,
exactly, written out in `verify.yml` and not built by the role's template, so that a
dropped option fails; and that the stale key is gone.

What breaks which step. Each row was done by an edit, one harness run, and a
`git restore`, on 2026-10-17, and the harness was green again after the restores:

| Edit                                                                     | Step that fails and the assertion                                            |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `validate` removed                                                       | `verify`: "Expected the role to stop at Install the sudoers fragment"        |
| `validate` replaced by `/bin/true %s`                                    | `verify`: the same                                                           |
| An extra comment line written after the declared lines                   | `verify`: the fragment holds the declared lines and nothing else             |
| Mode `0644`                                                              | `verify`: the fragment mode assertion                                        |
| `owner` and `group` removed from the fragment task                       | `verify`: the owner assertion (passes if the earlier file is owned by root)  |
| A `lineinfile` task adding `#includedir` to `/etc/sudoers`               | `verify`: the main sudoers file is the file the image shipped                |
| `exclusive: true` removed                                                | `verify`: the keys are exactly the declared ones                             |
| `no-X11-forwarding` dropped from the restrictive options                 | `verify`: the same                                                           |
| The `from` option left out of the key line                               | `verify`: the same                                                           |
| `no_log: true` removed from the key task                                 | `verify`: no key body reached the log                                        |
| `no_log: true` removed from the sudoers task                             | `verify`: no sudoers line reached the log (the invalid fragment's text)      |
| The `when` that skips an empty key list removed                          | `verify`: the keys are exactly the declared ones, after the empty run        |
| The check for a forced command without `from_addresses` made always true | `verify`: "Expected the role to stop at Refuse a forced command with no ..." |
| The check for a double quote in a command made always true               | `verify`: the same form, naming that task                                    |
| The key-shape check made always true                                     | `verify`: the same form, naming that task                                    |
| The non-text-line check made always true                                 | `verify`: "stopped at Install the sudoers fragment" (`visudo` still refuses) |
| The fragment-name check made always true                                 | `verify`: the same form, naming that task                                    |
| The line-break check made always true                                    | `verify`: the same form, naming that task                                    |
| A `command` task with `changed_when: true` added                         | `idempotence`                                                                |

### Named limits

- **`visudo` checks syntax, not meaning.** A fragment that grants
  `ALL=(ALL) NOPASSWD: ALL` passes `visudo` and the whole harness, and is installed
  as declared (run on 2026-10-17: all steps passed). What a fragment grants is
  decided by the declared lines and caught by review. The role does not try to judge
  a sudoers line.
- **A key body is not validated.** The module accepts any base64 text after a key
  type. A typo in the body of the only declared key replaces a working key with a
  useless one and locks the account out. The test cannot log in, because the image
  has no SSH server. Keep a second way into the account, and read the declared keys
  as the review step.
- **`from=` restricts the source address, nothing else.** What a forced command can
  be talked into doing through `SSH_ORIGINAL_COMMAND` depends on the command, which
  is outside this role.
- **The SSH server's own settings are not read.** `AuthorizedKeysFile`,
  `AllowUsers`, `PubkeyAuthentication` and similar settings decide whether the file
  is used at all.
- **No removal.** A role that stops declaring the fragment leaves it on the host.
  An empty key list leaves the keys as they are. Removing access is a separate
  deliberate change.
- **The log scan covers the steps up to and including verify.** The
  `check-configured` and `molecule-check` steps run afterwards and are not scanned;
  they make no change, so the `--diff` they print has nothing to show.
- **Check mode and `validate`.** The check-mode runs complete. Whether a check-mode
  run applies `validate` was not tested here.
- **A broken fragment on a real `sudo` was not run.** The claim that `sudo` stops
  working with a file it cannot parse is sudo's documented behaviour and was not
  exercised.
- **Only the Debian 13 image on Docker Desktop (arm64) was run**; an amd64 runner was
  not.
- CI does not run this scenario today: the Ansible workflow runs the harness over
  `ansible/roles` only. Until it lists `ansible/patterns`, a change here is proven
  by the local run above.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after the
approval of its protected environment. A plan job shows each host's diff in check
mode first; after the approval the host pulls that exact commit of `main` and applies
it, and a second run must report zero changes. Nothing is applied from a laptop. This
pattern is not applied to any host: it exists to be copied, and the trigger and the
reusable workflow are separate work.

The plan job's diff is the reason `diff: false` is in the recipe: a job summary is
read by everyone who can see the run.

## How a service role copies it

1. Make the new role from the skeleton, as `ansible/README.md` says, under
   `ansible/roles/`.
2. Copy `tasks/main.yml`, `vars/main.yml`, `templates/authorized_keys.j2` and the
   whole of `molecule/default/` over the new role's files. Keep `namespace` in
   `meta/main.yml`: Molecule links the role under it. Copy only the half the service
   needs: a service that has no forced-command key drops the key half and its
   assertions, and its test cases.
3. Rename. The variable prefix `sudoers_and_keys_` becomes the new role's name in
   `defaults/main.yml`, `meta/argument_specs.yml`, `vars/main.yml`, the tasks, the
   template, and the `include_role` calls in `converge.yml`, `verify.yml` and
   `tasks/refused.yml` (`branchleft.sudoers_and_keys`). The task names are in
   `verify.yml` as the `refused_task` values: change both together.
4. Replace the placeholders: the fragment lines, the forced command, the addresses,
   the account name, and the ALL_CAPS values in `meta/`. Quote every sudoers line
   in YAML.
5. Take the declared lines and keys from the service's own variables, supplied at
   run time. Do not put a real key or a real address in `defaults/main.yml`.
6. Run the harness on the new role. Then break each control in the table above on
   the copy and see the same step fail: a control is yours only after you have
   broken it.
7. Keep the image pin and its reason below, and do not give the scenario more
   privilege than this one has.
8. Record, in the new role's README, what its fragment grants and why: the role
   cannot judge it (see the first named limit).

## The test base image (a third-party image, trusted by digest)

The scenario needs `sudo`, `visudo`, Python and a user database. It does not need
systemd, so it sets none of the settings that run systemd: no cgroup mount, no
tmpfs, and no `command`. With no `command` Molecule starts the container with a
sleep loop instead of the image's systemd. No `privileged`, no capabilities.

- Image: `geerlingguy/docker-debian13-ansible`, referenced in
  `molecule/default/molecule.yml` as `name:latest@sha256:<digest>` (CON-3). The
  production hosts run Debian 13, and a sudoers and SSH test should run the release
  it protects. The digest is the pin and the tag beside it is informational.
- Source: the public repository `geerlingguy/docker-debian13-ansible` on GitHub
  (MIT licence). Its Dockerfile, read on 2026-10-17, is `FROM debian:trixie` and
  installs `sudo`, `systemd`, `systemd-sysv`, build tools, `python3-pip`,
  `python3-apt` and a few network tools from Debian, then `ansible` and
  `cryptography` from PyPI without version pins. It does not install an SSH client
  or server. The image's own Ansible is not used: Molecule runs the controller's
  pinned Ansible against the container.
- The image was created on 2026-10-11 (read from the pulled image). The
  repository's last push was 2025-07-31, so the image is rebuilt from an unchanged
  Dockerfile. Whether the published image is built from the Dockerfile on `master`
  was not verified.
- The digest is read with `docker image inspect --format '{{index .RepoDigests 0}}'`
  after a pull.
- The image declares `/sys/fs/cgroup` as a volume, so every container started from it
  gets an anonymous volume. Molecule's destroy keeps a container's volumes by
  default, so the platform sets `keep_volumes: false`. Without it each run leaves a
  volume that has no label to find it by (a daemon that had run many of these
  scenarios held hundreds on 2026-10-17). Any scenario on this image must set it.
- Differences from Debian 12 that the test met: Python is 3.13 (Ansible found
  `/usr/bin/python3.13`); `/etc/sudoers` has `@includedir /etc/sudoers.d`; the sudo
  version is 1.9.16p2; `/etc/sudoers.d` already holds a `README` that is mode
  `0440`; there is no `openssh-client` in the image.

Named limit: the image is trusted by its digest and by review. It is not built by
this repository, and its unpinned PyPI installs were resolved once, at its build and
are frozen by the digest. Whether Docker Hub keeps an old digest pullable
indefinitely is not established.

## How to change it safely

Change the tasks, the template, the argument spec, the defaults and the converge,
verify and refusal plays together, run the harness, and break the control you
touched (the table above) to see it fail. A change to the digest is its own change,
reviewed on its own. Removing the `validate`, the `exclusive`, the `no_log`, the
guards on empty lists or any assertion removes a control the table shows. Do not add
a task that opens `/etc/sudoers`.
