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
    validate: /usr/sbin/visudo -csf %s
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
the key. The assertion tasks at the top of `tasks/main.yml` check every input
before anything changes: the fragment name, each sudoers line, each key, each
forced command and each source address.

### (c) Why each parameter is set

- `validate: /usr/sbin/visudo -csf %s`. Ansible writes the content to a temporary
  file, runs the command on it, and moves it over the old file only if the command
  succeeds. A fragment `visudo` refuses fails the task and the old fragment stays.
  The flags, from `visudo --help` on the pinned image: `-c, --check` is "check-only
  mode", `-f, --file=sudoers` is "specify sudoers file location" (so `visudo` reads
  `%s` and not `/etc/sudoers`), and `-s, --strict` is "strict syntax checking". The
  `-s` matters. On the pinned image, a line that names an alias nobody defined makes
  `-cf` print a warning (`... referenced but not defined`) and then `parsed OK` with
  exit status 0, so `validate` passes; `-csf` prints the same warning and exits with
  status 1, so `validate` fails. A misspelt alias would otherwise mean a grant that
  does nothing, or a deny in a deny list that does nothing. Ansible's own documentation of
  the `copy` module shows `-csf` for a sudoers file. The test that a weak validator
  is caught is in the table below, and an undefined alias is one of its cases.
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
  key pattern allows a key type from a fixed list, a base64 body of a length that
  type can have, and an optional comment, all on one line and nothing in front. A
  key value, a forced command, a source address and a sudoers line may hold printable
  ASCII only (U+0020 to U+007E): no control character of any kind and nothing outside
  ASCII. This is a list of what is allowed, not of what is refused, on purpose: the
  key module splits what it is given with Python's `str.splitlines`, which breaks on
  eight characters besides line feed and carriage return (U+000B, U+000C, U+001C to
  U+001E, U+0085, U+2028, U+2029), and each piece becomes a key line of its own with
  options the caller never wrote. A pattern that refuses the characters it knows
  leaves the ones it forgot. So a `key` value cannot bring its own options or hide a
  second key behind a line break of any of those kinds, and the test builds each one.
  The lengths are exact for `ssh-ed25519` and the three `ecdsa-sha2-nistp` curves
  (fixed-size keys, checked against keys made by `ssh-keygen`) and a floor for
  `ssh-rsa` and the two security-key types (the floors for the security-key types
  come from the wire format, not from a real key). So a key cut short by a paste,
  or with a typo in its type, is refused; a one-character typo inside a body of the
  right length is not (see the named limits).
- The key check never prints a key. A task with `no_log: true` works out which
  entries fail and keeps only their numbers; the assertion after it says "Key entry
  number N" and the rule, and nothing else. The check runs before the module that
  writes the keys, so the module's own failure for a line it cannot read (which
  repeats the whole line) is not reached by a key the check refuses.
- A forced command must come with `from_addresses`, and gets `no-port-forwarding`,
  `no-pty`, `no-agent-forwarding` and `no-X11-forwarding`. The command may hold
  printable ASCII only, and no double quote (it would end the option early) and no
  backslash (one at the end turns the closing quote into an escaped quote, so the
  rest of the line is swallowed and `ssh-keygen` does not read the line as a key;
  the key module also rewrites `\#` to `#` in what it is given). It may not hold a
  key type as a word of its own: the key module takes the first word of a line that
  is a key type as the key, so a command such as `/bin/x ssh-rsa y` moves the real
  key into the comment and the line is rewritten wrongly on every run. The words
  are the module's own list of types, in `vars/main.yml`. A word is a stretch not
  touching a letter, digit, `@`, `.`, `_` or `-`, so `/usr/bin/ssh-rsa` is refused
  and `/usr/bin/ssh-rsa-helper` is not.
- Each source address is one list item and is checked on its own: letters, digits and
  `. : / * ? ! _ -` only. A space, a double quote, a comma, a semicolon, a backslash,
  a control character, a line break or an empty item would give a line the SSH
  server will not accept (the key stops working, which locks out a slot key) or a
  second line the caller never declared, so the role refuses it before it writes
  anything. The patterns end in `\Z`, not `$`: `$` also matches before a trailing
  line break, so a name, an address or a key with a line break after it would pass.
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
  with a syntax error, and one that names an undefined alias, which `visudo` refuses
  in strict mode, and checks that the role stopped at the install task, and that
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

The key check is the one place the role refuses on key text, so it is kept out of
the log on purpose. The module that writes the keys fails on a line it cannot read
with `invalid key specified:` followed by the whole line, and on ansible-core 2.21.5
that text reached the console even though the task has `no_log: true`. The role does
not rely on `no_log` for that path: the key is checked first, and a key the check
refuses never reaches the module. The test supplies a key that is too short and a
key with a mistyped type, requires that the role stops at the check and that the
refusal names the entry by number, and then scans the log for the key bodies. With
the check made always true, the test fails at the first refused key case. With only
the key type left open, the mistyped type reaches the module, the role stops there
instead, and the module's `invalid key specified` line appears in the harness output
with the key in it: the leak this design prevents. That run fails at the refused
case, before the log scan is reached, so the log scan is shown to catch a key in the
refusal message (the table row for the key text added to that message) and not the
module's line.
The `no_log: true` on the task that works out the entry numbers is reviewed, not
tested: its result holds only numbers, so removing it leaks nothing and no test can
fail.

A consequence of `no_log: true` that a maintainer will meet: when `visudo` refuses
a fragment, the task output says only that the output is hidden. To see why, run
`visudo -csf` on the lines by hand on a lab host, or remove `no_log` on a copy of
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
# Install the lock with the one recipe: ansible/README.md, "Install, and install with no network".
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
dropped option fails; that the stale key is gone; and that `ssh-keygen -l -f`, run on
the controller on a copy of the key file, reads as many keys as the file has lines
(it skips a line it cannot read without failing, so the counts are compared).

The refused cases build their awkward characters from code points (`'%c' | format(N)`
in a loop over the code points), because a character typed into the YAML file is
folded to a space (U+2028) or refused by the linter (a tab). The loops cover tab,
line feed, vertical tab, form feed, carriage return, U+001C to U+001E, U+0085, U+2028
and U+2029 in a key, in a forced command, in a source address and in a sudoers line.
The cases that carry a second key (a key value, a forced command) also read the key
file back after the refusal and require that the key the host retired is not in it
and that the lines are those the converge left, before they check which task
refused. The check of the key file comes first so that a check that lets the input
through fails with the key file as the evidence.

What breaks which step. Each row is an edit, one harness run, and a `git restore`;
the harness is green again after the restores. The rows up to the `changed_when`
row were run at an earlier state of this role; the rows for the key check, the
command quote check, the address character class and the sudoers line check were
run again at this state, and the rows after the `changed_when` row were run at
this state only. Several of the later rows stand for a run for each character
named in them (one harness run each).

| Edit                                                                                                                                               | Step that fails and the assertion                                                                                                                                                         |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `validate` removed                                                                                                                                 | `verify`: "Expected the role to stop at Install the sudoers fragment"                                                                                                                     |
| `validate` replaced by `/bin/true %s`                                                                                                              | `verify`: the same                                                                                                                                                                        |
| `validate` weakened to `visudo -cf %s` (not strict)                                                                                                | `verify`: the same, at the undefined-alias case                                                                                                                                           |
| An extra comment line written after the declared lines                                                                                             | `verify`: the fragment holds the declared lines and nothing else                                                                                                                          |
| Mode `0644`                                                                                                                                        | `verify`: the fragment mode assertion                                                                                                                                                     |
| `owner` and `group` removed from the fragment task                                                                                                 | `verify`: the owner assertion (passes if the earlier file is owned by root)                                                                                                               |
| A `lineinfile` task adding `#includedir` to `/etc/sudoers`                                                                                         | `verify`: the main sudoers file is the file the image shipped                                                                                                                             |
| `exclusive: true` removed                                                                                                                          | `verify`: the keys are exactly the declared ones                                                                                                                                          |
| `no-X11-forwarding` dropped from the restrictive options                                                                                           | `verify`: the same                                                                                                                                                                        |
| The `from` option left out of the key line                                                                                                         | `verify`: the same                                                                                                                                                                        |
| `no_log: true` removed from the key task                                                                                                           | `verify`: no key body reached the log                                                                                                                                                     |
| `no_log: true` removed from the sudoers task                                                                                                       | `verify`: no sudoers line reached the log (the invalid fragment's text)                                                                                                                   |
| The `when` that skips an empty key list removed                                                                                                    | `verify`: the keys are exactly the declared ones, after the empty run                                                                                                                     |
| The check for a forced command without `from_addresses` made always true                                                                           | `verify`: "Expected the role to stop at Refuse a forced command with no ..."                                                                                                              |
| A double quote allowed in a forced command                                                                                                         | `verify`: the same form, naming the quoting task                                                                                                                                          |
| The key check made always true                                                                                                                     | `verify`: "the retired key did not come back", at the first key that carries a second key                                                                                                 |
| The ed25519 body length left open                                                                                                                  | `verify`: the same form, at the key whose body was cut short                                                                                                                              |
| The key type left open                                                                                                                             | `verify`: stopped at the key module, not at the key check; the module's `invalid key specified` line is then in the output                                                                |
| A space allowed in a source address                                                                                                                | `verify`: the same form, naming the address task                                                                                                                                          |
| A double quote allowed in a source address                                                                                                         | `verify`: the same                                                                                                                                                                        |
| A line break allowed in a source address                                                                                                           | `verify`: stopped at the key module, not at the address check                                                                                                                             |
| A control character allowed in a source address                                                                                                    | `verify`: the same form, naming the address task                                                                                                                                          |
| An empty source address allowed                                                                                                                    | `verify`: the same                                                                                                                                                                        |
| The key text added to the key refusal message                                                                                                      | `verify`: the log scan, "no key body reached the log"                                                                                                                                     |
| `no-pty` dropped from the restrictive options                                                                                                      | `verify`: the keys are exactly the declared ones                                                                                                                                          |
| The `from` option dropped from the key line                                                                                                        | `verify`: the same                                                                                                                                                                        |
| The non-text-line check made always true                                                                                                           | `verify`: "stopped at Install the sudoers fragment" (`visudo` still refuses)                                                                                                              |
| The fragment-name check made always true                                                                                                           | `verify`: the same form, naming that task                                                                                                                                                 |
| The sudoers line check weakened to refuse only line feed and carriage return                                                                       | `verify`: the same form, naming the printable-ASCII task (the role then stops at the install task)                                                                                        |
| A `command` task with `changed_when: true` added                                                                                                   | `idempotence`                                                                                                                                                                             |
| The key comment class widened by one of tab, line feed, carriage return, vertical tab, form feed, U+001C, U+001D, U+001E, U+0085, U+2028 or U+2029 | `verify`: "the retired key did not come back" (the key file holds the retired key, with the option the case gave it, or inside the comment for a tab)                                     |
| The key comment class set back to anything but line feed and carriage return                                                                       | `verify`: the same, at the first separator                                                                                                                                                |
| `\Z` replaced by `$` in the key pattern                                                                                                            | `verify`: the key file differs from the converged one, at the key that ends in a line break                                                                                               |
| `\Z` replaced by `$` in the address pattern                                                                                                        | `verify`: "Expected the role to stop at Refuse a source address ..."; the role stopped at the key module                                                                                  |
| `\Z` replaced by `$` in the fragment-name pattern                                                                                                  | `verify`: "Expected the role to stop at Refuse a sudoers fragment name ..."; the role accepted the input                                                                                  |
| The forced command class widened by one of the same eleven characters                                                                              | `verify`: "Expected the role to stop at Refuse a forced command that would break its own quoting"; the role stopped at the key type check, which refuses the key behind the separator too |
| A backslash allowed in a forced command (the case ends in one)                                                                                     | `verify`: the key file differs from the converged one                                                                                                                                     |
| A backslash refused only at the end of a forced command                                                                                            | `verify`: the key file differs from the converged one, at the case with a backslash inside                                                                                                |
| The key type check made always true                                                                                                                | `verify`: the key file differs from the converged one, at the first key type word                                                                                                         |
| The first, the last, or the `ssh-rsa` key type word dropped from the list                                                                          | `verify`: the key file differs from the converged one, at that word                                                                                                                       |
| The address class widened by a comma, a semicolon, a backslash, a space, a double quote, `\x01` or an empty item                                   | `verify`: "Expected the role to stop at Refuse a source address ..."; the role accepted the input (one run each)                                                                          |
| The address class widened by one of the eleven separators                                                                                          | `verify`: the same form; the role stopped at the key module for a line break, accepted the input for a tab (one run each)                                                                 |
| The check on a written key file: a forced command ending in a backslash allowed, as well as in the scenario's own command                          | `verify`: "ssh-keygen read every line of the key file as a public key"                                                                                                                    |

### Named limits

- **`visudo` checks syntax, not meaning.** A fragment that grants
  `ALL=(ALL) NOPASSWD: ALL` passes `visudo -csf` and the whole harness, and is
  installed as declared (the grant to `ALL` was run through the harness and every step
  passed). What a fragment grants is decided by the declared lines and caught by
  review. The role does not try to judge a sudoers line, and a tripwire for one
  spelling of an over-broad grant would read as a control it is not, because an alias
  or `(ALL) ALL` gets round it.
- **A key body is checked for shape, not for being the right key.** The role checks
  the type, the characters and the length. A one-character change inside a body of
  the right length is a different, valid key: it replaces a working key with a
  useless one, and if it is the only declared key the account is locked out. The test
  cannot log in, because the image has no SSH server. Keep a second way into the
  account, and read the declared keys as the review step.
- **A key whose label differs from its body is accepted.** The check reads the label
  (`ssh-rsa`) and the length and characters of the body, not the type the body
  encodes inside it: `ssh-rsa` in front of a P-521 body passes. Such a line is, as
  far as is known, unusable (not run), the same class as the one-character typo, so
  it is a useless key and not a wider one.
- **An alias defined in another file is refused.** `visudo -csf` checks the fragment
  on its own, so a fragment that uses an alias defined in `/etc/sudoers` or in
  another fragment is refused as undefined. That fails safe (nothing is installed);
  put the alias in the same fragment.
- **The length floors for RSA and the security-key types were not tested against
  real keys.** The RSA floor and the two security-key floors come from the wire
  format; only the ed25519 and NIST-curve lengths were checked against keys made by
  `ssh-keygen`. A legitimate unusual key (a very short RSA key, a certificate type)
  is refused, which fails safe.
- **`ssh-keygen` and `sshd` acceptance is checked only as far as one assertion
  says.** The test copies the written key file to the controller and requires that
  `ssh-keygen -l -f` reads as many keys as the file has lines. It does not run an
  SSH server, so it does not show that `sshd` accepts a line, and the version of
  `ssh-keygen` on the controller may differ from the one on a host.
- **The key type words are a copy.** The words a forced command may not hold are the
  module's own list in the collection pinned in `ansible/requirements.yml`; a newer
  collection that adds a key type adds a word the role does not know. Nothing in the
  test compares the two lists.
- **A forced command may hold no backslash** (a command that needs one must be put in
  a script on the host and run by its path), and a sudoers line may hold no tab.
- **A forced command keeps no run of two spaces.** The key module joins the words of
  the command with one space, so `command="/bin/x  two spaces"` is written back as
  `command="/bin/x two spaces"`, and a second run reports no change. A consumer must not
  rely on a double space in a forced command, including one inside a quoted argument.
- **`exclusive: true` removes every key the pattern did not write.** That includes
  the operator's own key on the account Ansible logs in as: a role that manages that
  account must list its key among the declared keys, or the next run locks the
  operator out. Two roles must not both manage one account's key file, because each
  would remove the other's keys.
- **The fragment directory must be included by the host's sudoers.** The role does not
  check that `/etc/sudoers` includes `/etc/sudoers.d`. The test image does, and the
  production hosts are assumed to run Debian 13 with the stock `sudo` package.
- **Where the failure text of the key module goes is not established.** The scenario
  scans `ANSIBLE_LOG_PATH`, which the harness sets. The role's own default log
  settings on a real controller (the log path, and whether the module's failure line
  reaches it) were not examined, so the key check, which stops a bad key before the
  module runs, is the control, and `no_log` is not relied on for that line.
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
- **Check mode does not run `validate`.** In the `copy` module of ansible-core 2.21.5
  (`ansible/modules/copy.py`), the `validate` command is run inside the branch
  `if not module.check_mode:`, so `--check` skips it. A run showed the same thing: a
  deliberately invalid fragment passed in check mode and failed in a real run. The
  plan job (`--check --diff`, ANS-17) therefore shows an invalid fragment as an
  ordinary change and cannot vouch for sudoers syntax. The syntax verdict comes from
  this scenario, which runs the same text through `visudo -csf` for real, and from
  the validate of the live apply, which happens after the approval. The input checks
  (names, quoting, keys, addresses) are assertions and do run in check mode. No
  check-mode-safe validation was added: one would have to write the text to a
  temporary file on the host in a mode that promises to change nothing.
- **A broken fragment on a real `sudo` was not run.** The claim that `sudo` stops
  working with a file it cannot parse is sudo's documented behaviour and was not
  exercised.
- **Only the Debian 13 image on Docker Desktop (arm64) was run**; an amd64 runner was
  not.
- CI runs this scenario: the Ansible workflow on `main` installs the pinned collections
  and runs the harness over every role and every pattern under `ansible/patterns/`, so
  this pattern's lint, interface and container steps run on each change. The workflow
  installs the collections before `ansible-lint`, which is what lets it resolve
  `ansible.posix.authorized_key`.

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
cgroup namespace mode, no tmpfs. It sets `command: sleep infinity`, so systemd is
never the first process. The image's own command starts systemd, which needs those
settings; the container can exit at once on a host with cgroup v2 without them (this
is the behaviour reported for a GitHub-hosted runner; on that runner CI runs this
scenario's 14 steps and they pass). Molecule already replaces the image command with a sleep loop
when none is set, so the key makes explicit what the default did and does not change
the run. No `privileged`, no capabilities.

- Image: `geerlingguy/docker-debian13-ansible`, referenced in
  `molecule/default/molecule.yml` as `name:latest@sha256:<digest>` (CON-3). The
  production hosts run Debian 13, and a sudoers and SSH test should run the release
  it protects. The digest is the pin and the tag beside it is informational.
- Source: the public repository `geerlingguy/docker-debian13-ansible` on GitHub
  (MIT licence). Its Dockerfile on the default branch is `FROM debian:trixie` and
  installs `sudo`, `systemd`, `systemd-sysv`, build tools, `python3-pip`,
  `python3-apt` and a few network tools from Debian, then `ansible` and
  `cryptography` from PyPI without version pins. It does not install an SSH client
  or server. The image's own Ansible is not used: Molecule runs the controller's
  pinned Ansible against the container.
- The image is rebuilt from an unchanged Dockerfile: the image's creation time
  (`docker image inspect --format '{{.Created}}'`) is later than the repository's
  last push (the `pushed_at` field of the repository on the GitHub API). Whether the
  published image is built from the Dockerfile on the default branch is not verified.
- The digest is read with `docker image inspect --format '{{index .RepoDigests 0}}'`
  after a pull.
- The image declares `/sys/fs/cgroup` as a volume, so every container started from it
  gets an anonymous volume. Molecule's destroy keeps a container's volumes by
  default, so the platform sets `keep_volumes: false`. Without it each run leaves a
  volume that has no label to find it by, and a daemon that has run many of these
  scenarios holds hundreds (`docker volume ls -q | wc -l` counts them). Any scenario
  on this image must set it.
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
