# ci_jump

Owns the `authorized_keys` options of the CI jump account on edge1: the account the gated Ansible
run connects through to reach the private hosts. Each key line the role writes allows port 22 of the
named hosts and nothing else, so adding a tenant host is one reviewed line in `owner_vars/edge1.yml`
and a gated run, not a hand edit on edge1.

## What the role does, and what it does not

- **Report, always, read only.** Every run prints which local accounts carry forwarding options
  (`permitopen`, `permitlisten` or `port-forwarding`) in the key files sshd reads, with, for each key
  line, the option names, the `permitopen` host and port, the key type and a 12-character
  fingerprint. It also says whether all of an account's lines carry the same `permitopen` set, whether
  the account is one another role owns (`ci_login`, `tunnel_account`), and what `sshd -T` reports for
  `AuthorizedKeysCommand`, `AuthorizedKeysFile` (`authorized_keys2` included), TCP forwarding and
  `PermitOpen`. It never prints a key body, a comment field or the value of any option other than
  `permitopen` and `permitlisten`. With `ci_jump_manage_keys` false this is all the role does: it
  writes nothing and always reports no change, so the gated plan for edge1 stays clean.
- **Write, only when `ci_jump_manage_keys` is true.** The jump account's `authorized_keys` becomes
  exactly one line per declared key: `restrict`, `port-forwarding`, one `permitopen="HOST:22"` per
  declared destination, then the key type and body, and nothing else (the key's comment is dropped).
  The file is written exclusively (`ansible.posix.authorized_key`, `exclusive: true`), and an empty
  list is refused, never read as remove-all or allow-all.
- **Guards, each with its own code, a unit test and a refusal case that must fail** (see
  `molecule/refusals`):
  - destinations: a wildcard (`E-DEST-WILDCARD`), a port (`E-DEST-PORT`), a quote
    (`E-DEST-QUOTE`), a comma (`E-DEST-COMMA`), a space or control character (`E-DEST-SPACE`), an
    IPv6 form (`E-DEST-IPV6`), any other malformed name (`E-DEST-SHAPE`), a repeat
    (`E-DEST-DUPLICATE`), an empty list (`E-DEST-EMPTY`), a non-text entry (`E-DEST-TYPE`);
  - keys: an empty list (`E-KEY-EMPTY`), an unknown shape, found by decoding the key blob and
    matching its embedded type, or options in front of the key (`E-KEY-SHAPE`), a repeat
    (`E-KEY-DUPLICATE`), a non-text entry (`E-KEY-TYPE`);
  - account: none named (`E-USER-EMPTY`), a malformed name (`E-USER-SHAPE`), root or an account
    another role owns (`E-USER-FORBIDDEN`), absent (`E-USER-ABSENT`), a shell that can run a command
    (`E-USER-SHELL`: only `nologin` and `false` pass, because `restrict` alone does not stop a
    remote command on a login shell);
  - sshd, read with `sshd -T -C user=...,host=...,addr=...` so `Match` blocks are evaluated:
    TCP forwarding off for the account (`E-SSHD-FORWARDING`), an effective `AuthorizedKeysCommand`
    (`E-SSHD-KEYSCOMMAND`), a `PermitOpen` of sshd's own (`E-SSHD-PERMITOPEN`), the managed file not
    among the files sshd reads (`E-SSHD-FILE`), a second key file sshd reads, such as
    `authorized_keys2`, that holds any key line (`E-SSHD-KEYS2`), sshd not answering
    (`E-SSHD-UNAVAILABLE`);
  - the read-back: after the write the file is compared with lines the module builds for itself,
    apart from the template that wrote them, and sshd is asked again (`E-READBACK-MISMATCH`).
    A refusal message is a code and an entry number, never a value.
- **One account has one owning role.** The jump account may not be root, the `ci_login` account or
  the `tunnel_account` account. Two roles writing one account's keys exclusively would remove each
  other's keys, so the role refuses rather than share.

It does not create, edit or lock an account, change `sshd_config`, reload sshd, install a package,
manage a key anywhere but the one file, or take a destination per key: every key line carries the
same destinations. If the report shows lines that differ in their `permitopen` sets, the role is not
enabled until the owner rules on it.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the four variables and
[`defaults/main.yml`](defaults/main.yml) holds the same defaults. All four are read from
`ansible/owner_vars/edge1.yml` on edge1; none comes from `host_inputs`.

| Variable               | Default | Meaning                                                                     |
| ---------------------- | ------- | --------------------------------------------------------------------------- |
| `ci_jump_manage_keys`  | `false` | `false`: report only. `true`: guards, write, read-back.                     |
| `ci_jump_user`         | `''`    | The jump account. Read only when the flag is true.                          |
| `ci_jump_destinations` | `[]`    | Host names or IPv4 addresses, no port. The role adds port 22.               |
| `ci_jump_keys`         | `[]`    | `{key}` entries: public keys, one per entry. Read only when the flag is on. |

The port (22), the fixed options (`restrict,port-forwarding`) and the accounts other roles own are
constants in [`vars/main.yml`](vars/main.yml), so an inventory cannot change them. The module
(`library/ci_jump_authorized_keys.py`) pins the port and the options for itself, as the oracle of its
read-back, and `ansible/checks/test_ci_jump_pins.py` holds the two copies equal, holds the account
names equal to `ci_login_user` and `tunnel_account_user` in their own roles, and holds the template to
the module's lines.

A destination must be the exact text the runner's `ssh` sends for the host: sshd matches `permitopen`
literally, so a name in the list and an address on the command line do not match each other.

Public keys are not secrets, but every task that handles them sets `no_log: true` and `diff: false`
(ANS-16), the module returns fingerprints only, and the plan shows no key. The text the role prints is
also kept out of the plan scan of the gated apply (below).

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `ansible.posix` from the pinned `ansible`
  package, for `authorized_key`.
- Target: a Debian-family host with OpenSSH (`/usr/sbin/sshd`, run as root for `sshd -T`) and
  Python 3. The test image is Debian 13, the release the production hosts run.
- The jump account already exists, with a shell of `nologin` or `false`.

## What it changes on a host

- With the flag false: nothing.
- With the flag true: `<home>/.ssh` (mode `0700`, owned by the account, only if absent) and
  `<home>/.ssh/authorized_keys` (mode `0600`). No service, port, firewall rule, account or sshd
  setting.

## How to test it

From the repository root, with Docker running and the tools installed as `ansible/README.md`
describes (the harness runs in CI, never against a host):

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ci_jump
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ci_jump --scenario refusals
cd ansible/roles/ci_jump && PYTHONPATH=library ../../../.venv/bin/python -m unittest discover -b -s tests/unit
```

- `default` starts from a container with a real sshd, a `nologin` jump account and a hand-made key
  file whose one line allows an address the new list will not. It proves the role replaces that file
  with exactly the declared lines, and then, over real SSH connections: the key reaches the listed
  address on port 22 (the target's banner comes back); a live listener that is not on the list is
  refused, with sshd logging that it denied the forward; the listed address on another port is
  refused; a key in no file and the replaced line's key are turned away; remote commands are not
  run. As a control, with the second address on the list the same connection goes through, and with
  the list put back it is refused again. It records what `sshd -T -C` evaluates for a user under a
  `Match` block, runs the report, and scans the run's log for any key body.
- `refusals` applies the role once and then runs each guard alone against the bad input or the bad
  state, expecting the guard's own code, with a control beside each group that must be accepted. The
  read-back cases change the file behind the role's back and run the read-back step alone.
- The unit tests run the module against a fake host: every code above, the parser, the report over
  hostile values, and the read-back.

## How it is delivered

Only through the gated workflow (ANS-17): the role is on edge1's list in `ansible/checks/host_roles.yml`
and applied by `ansible/playbooks/edge1.yml`, directly after `ci_login`. It is delivered in two
steps, and nothing about edge1 was read to write it.

1. **The role, inert.** Merged with the flag false. The first gated plan for edge1 then prints the
   report: which accounts carry forwarding options, their destinations and fingerprints, and whether
   a jump account is the `ci_login` account. The owner reads it and chooses the jump account.
2. **The data.** A change to `owner_vars/edge1.yml` alone: the account name, the destinations, the
   public keys and the flag true. The owner must read the plan's check-mode lines before approving
   the apply: for each destination whether it is live and wanted, and for each key whether it is live
   and wanted, with a destination or key that would be removed named as such. The role takes the
   current destinations from the report, never from a guess. If the report shows lines whose
   `permitopen` sets differ, the second step is not opened and the owner rules first.

A list that is missing a live destination is repaired by a corrective change to `owner_vars` and the
next gated pull. edge1 takes that pull through `ansible-ci`, not through the jump account, so a
wrong list cannot lock the pull out and there is no hand step.

## Named limits

- **The live state was not read.** The report is the first reading. The plan of the first run shows
  it, and the second step is built from it.
- **The `sshd -T -C` check uses a stand-in client address.** The jump key is used from runners that
  have no fixed address, so a `Match` block keyed on a real runner address is not seen. A `Match` on
  the user, the group or the host name is.
- **sshd is read, not changed.** If sshd switches forwarding off, runs a keys command or reads a second
  key file with keys in it for the jump account, the role refuses and stays refused until the owner
  clears it; it will not edit `sshd_config` or another key file.
- **A key body is checked for shape, not for being the right key.** A decoded blob of the right type
  is a valid key; a wrong one locks the pipeline out of the jump.
- **The report's code is a copy of the plan scan's pattern.** The module carries `SCAN_PATTERN`,
  copied from `branchLeft/github-workflows`, `.github/actions/ssh-check-hosts/action.yml` line 434 at
  tag v1.0.19, and withholds any line of its own that the pattern would match. A change of the
  original is not seen until branchLeft/shared-infra#574 lands a test that holds them equal.
- **Trailing blank.** The writer leaves one blank after the key where a comment would go; the
  read-back trims it.

## How to change it safely

Change the tasks, the module, the argument spec, the defaults, the owner's file and the molecule
plays together. Run the unit tests and both scenarios, and break the control you touched to see its
test fail: the destination refusal over real SSH (`molecule/default`), the guard cases
(`molecule/refusals`) and `ansible/checks/test_ci_jump_pins.py` each have a red state to see. Do not
let another role write this account's keys, and do not make the role take a destination per key
without an owner ruling.
