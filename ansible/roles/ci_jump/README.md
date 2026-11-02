# ci_jump

Owns the two things that decide which private hosts the gated Ansible run may reach through a jump
host: the jump account's root-owned `authorized_keys` file and the sshd drop-in whose `Match User`
block gives the account its settings. Each key line allows port 22 of the named hosts and nothing
else, and sshd's own `PermitOpen` for the account carries the same list, so adding a tenant host is
one reviewed line in the host's `owner_vars` file and a gated run, not a hand edit on the jump
host. The role works on any jump host: `edge1` now, `edge-t` later, each with its own
`owner_vars/HOST.yml`, its own jump account and its own address. Nothing in the role is specific to
one host.

## What the role does, and what it does not

- **Report, always, read only, naming no account.** Every run prints which local accounts carry
  forwarding options (`permitopen`, `permitlisten` or `port-forwarding`) in the key files sshd reads
  for them. The files are found per account with `sshd -T -C user=...`, so a `Match` block's
  `AuthorizedKeysFile` is followed. The report names an account by its index in the report and by
  the class of its shell (`nologin`, `false` or `login`), never by its name: the name of the jump
  account is held out of the public Actions log. For each account it prints, per key line, the
  option names, the `permitopen` host and port, the key type and a 12-character fingerprint; whether
  all lines carry the same `permitopen` set; whether the key file is the managed one and root-owned;
  what sshd reports for TCP forwarding, `AuthorizedKeysCommand` and `PermitOpen`; and, for each
  destination, whether it is in the key lines, in sshd's `PermitOpen`, and in the owner's list. It
  never prints a key body, a comment field or the value of any option other than `permitopen` and
  `permitlisten`. With `ci_jump_manage_keys` false this is all the role does: it writes nothing and
  always reports no change, so the gated plan stays clean. Host names and private addresses are
  printed as destinations; they are already public in this repository (`hetzner/tenants.ts` and
  `hetzner/egress.ts` hold the tenant host names and the private addresses), so the report crosses no
  new boundary.
- **Write, only when `ci_jump_manage_keys` is true.** Two files, both `root:root` at `0644`, written
  with `ansible.builtin.template` and never with `authorized_key` into a home (that would hand the
  account the ownership of its own keys):
  - `/etc/ssh/ci-jump/authorized_keys` becomes exactly one line per declared key: `restrict`,
    `port-forwarding`, one `permitopen="HOST:22"` per declared destination, `command="/usr/sbin/nologin"`,
    then the key type and body, and nothing else (the key's comment is dropped);
  - `/etc/ssh/sshd_config.d/50-branchleft-ci-jump.conf` holds the `Match User` block the runbook
    documents (the key file as `AuthorizedKeysFile`, `AuthenticationMethods publickey`,
    `AllowTcpForwarding local`, `PermitOpen` with the same destinations on port 22, and every
    other forwarding and tty setting off, `ForceCommand /usr/sbin/nologin`), closed by `Match all`.
    Both are made from the one list `ci_jump_destinations`, so the key lines' `permitopen` and the
    block's `PermitOpen` cannot differ; `test_ci_jump_pins.py` proves both templates read that one
    variable and render the same destinations.
- **Check, reload, read back.** After the write the whole sshd configuration is checked with
  `sshd -t`, sshd is reloaded when either file changed, and the module reads both files back and asks
  `sshd -T -C user=ACCOUNT,host=x,addr=OWN_ADDRESS` what sshd applies to the account. A failed check
  or read-back puts the previous files back, reloads sshd again and fails the run (the same shape as
  the `tunnel_account` replica half).
- **Remote forwarding is refused.** A key line with `port-forwarding` also lets its holder open a
  listening port on the jump host (`ssh -R`) unless sshd says `AllowTcpForwarding local` for the
  account. The read-back requires exactly that, and refuses any other value (`E-SSHD-FORWARDING`),
  including one set by a `Match` block that outranks the role's. `molecule/default` makes the
  attempt with the real key against the real sshd and requires it to be refused.
- **Guards, each with its own code, a unit test and a refusal case that must fail** (see
  `molecule/refusals`):
  - destinations: a wildcard (`E-DEST-WILDCARD`), a port (`E-DEST-PORT`), a quote
    (`E-DEST-QUOTE`), a comma (`E-DEST-COMMA`), a space or control character (`E-DEST-SPACE`), an
    IPv6 form (`E-DEST-IPV6`), any other malformed name (`E-DEST-SHAPE`), a repeat
    (`E-DEST-DUPLICATE`), an empty list (`E-DEST-EMPTY`), a non-text entry (`E-DEST-TYPE`);
  - the jump host's own address: unset (`E-OWN-EMPTY`), not an IPv4 address (`E-OWN-SHAPE`), or not
    among the destinations (`E-DEST-OWN`). The runner reaches every host through the jump once the
    jump pair is set, the jump host itself included, so a list without the jump host's own address
    on port 22 fails the plan of every host, and the pull that would correct it is one of those
    plans;
  - keys: an empty list (`E-KEY-EMPTY`), an unknown shape, found by decoding the key blob and
    matching its embedded type, or options in front of the key (`E-KEY-SHAPE`), a repeat
    (`E-KEY-DUPLICATE`), a non-text entry (`E-KEY-TYPE`);
  - account: none named (`E-USER-EMPTY`), a malformed name (`E-USER-SHAPE`), root or an account
    another role owns (`E-USER-FORBIDDEN`), absent (`E-USER-ABSENT`), a shell that can run a command
    (`E-USER-SHELL`: only `nologin` and `false` pass);
  - sshd, before the write: sshd not answering (`E-SSHD-UNAVAILABLE`), forwarding disabled outright
    (`DisableForwarding`, `E-SSHD-FORWARDING`) and an effective `AuthorizedKeysCommand`
    (`E-SSHD-KEYSCOMMAND`), the two things the drop-in cannot put right;
  - sshd and the files, after the write: forwarding other than `local` (`E-SSHD-FORWARDING`), a key
    command, a key file other than the managed one (`E-SSHD-FILE`), a `PermitOpen` that is not the
    owner's list (`E-SSHD-PERMITOPEN`), any other setting of the runbook changed
    (`E-SSHD-EFFECTIVE`), and a file that is not exactly the wanted text, not `root:root` at
    `0644`, or in a directory that is not `root:root` at `0755` (`E-READBACK-MISMATCH`).
    A refusal message is a code and an entry number, never a value.
- **One account has one owning role.** The jump account may not be root, the `ci_login` account or
  the `tunnel_account` account. Two roles writing one account's keys would remove each other's
  keys, so the role refuses rather than share.

It does not create, edit or lock an account, install a package, or manage a key anywhere but the one
file, and it takes no destination per key: every key line carries the same destinations. It writes
no file but the two above and the directory `/etc/ssh/ci-jump`.

The report reads other accounts' key files as root. It opens each with `O_NOFOLLOW` and `O_NONBLOCK`
and checks the opened descriptor with `fstat` for a regular file, so a link or a pipe put there by a
local account is skipped and cannot make the pull read another file or hang.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the five variables and
[`defaults/main.yml`](defaults/main.yml) holds the same defaults. All five are read from the host's
file under `ansible/owner_vars/` (`edge1.yml` today); none comes from `host_inputs`.

| Variable               | Default | Meaning                                                                     |
| ---------------------- | ------- | --------------------------------------------------------------------------- |
| `ci_jump_manage_keys`  | `false` | `false`: report only. `true`: guards, write, check, reload, read-back.      |
| `ci_jump_user`         | `''`    | The jump account. Read only when the flag is true; never printed.           |
| `ci_jump_own_address`  | `''`    | The jump host's own private IPv4 address; it must be a destination.         |
| `ci_jump_destinations` | `[]`    | Host names or IPv4 addresses, no port. The role adds port 22.               |
| `ci_jump_keys`         | `[]`    | `{key}` entries: public keys, one per entry. Read only when the flag is on. |

The port (22), the fixed options (`restrict,port-forwarding`), the forced command, the paths of the
key file and the drop-in, the name of the sshd service and the accounts other roles own are constants
in [`vars/main.yml`](vars/main.yml), so an inventory cannot change them. The module
(`library/ci_jump_authorized_keys.py`) pins the same values for itself, as the oracle of its
read-back, and `ansible/checks/test_ci_jump_pins.py` holds the two copies equal, holds the account
names equal to `ci_login_user` and `tunnel_account_user` in their own roles, and holds both templates
to the module's text. `ansible/checks/check_enrolment.py` (R10) allows the five variables in the
`owner_vars` file of every host in `JUMP_HOSTS`, which must be the hosts whose row in
`ansible/checks/host_roles.yml` lists the role.

A destination must be the exact text the runner's `ssh` sends for the host: sshd matches `permitopen`
and `PermitOpen` literally, so a name in the list and an address on the command line do not match each
other.

### How the account's name reaches the role

The name of the jump account is not committed. The gated workflow holds it only in the `user@host`
secret `SSH_JUMP_HOST`, splits it on the runner and uses it as the `User` of the jump hop; nothing
sends it to a host, and the host's pull has no `-e`. So there is no way to give the role the name
without either committing it to `owner_vars/HOST.yml` (the owner's ruling on publishing the name) or a
new channel (a `host_inputs` key the owner seeds by hand before the merge, or a change to the
workflow). Until the owner chooses, `ci_jump_user` stays empty and the flag false: the role is
inert, and a run with the flag true and no name stops at `E-USER-EMPTY` before any write. The role
reads one variable, `ci_jump_user`, whichever channel fills it. Everything the role prints or logs is
written so that the name is in none of it: the module takes it as a `no_log` parameter, every task
that handles it hides its result and its diff, and `molecule/default` requires the name to be absent
from the output of every task of the role.

Public keys are not secrets, but every task that handles them sets `no_log: true` and `diff: false`
(ANS-16), the module returns fingerprints only, and the plan shows no key. The text the role prints is
also kept out of the plan scan of the gated apply (below).

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`.
- Target: a Debian-family host with OpenSSH (`/usr/sbin/sshd`, run as root for `sshd -T`), the
  drop-in directory `/etc/ssh/sshd_config.d`, systemd with `ssh.service`, and Python 3. The test image
  is Debian 13, the release the production hosts run.
- The jump account already exists, with a shell of `nologin` or `false`. The role never makes it.

## What it changes on a host

- With the flag false: nothing.
- With the flag true: `/etc/ssh/ci-jump` (`root:root`, `0755`), `/etc/ssh/ci-jump/authorized_keys`
  and `/etc/ssh/sshd_config.d/50-branchleft-ci-jump.conf` (`root:root`, `0644`), and a reload of
  `ssh.service` when either file changed. No port, firewall rule, account or other sshd setting.
- Skipped in check mode, with the reason (ANS-10): the whole-configuration check, the reload and the
  read-back, because `sshd -t` and `sshd -T` read the files on disk, which a plan has not changed.
  The plan shows the live files against the wanted ones, destination by destination, in the key file
  and in sshd's `PermitOpen`, and each key. Whether sshd applies `AllowTcpForwarding local` is first
  proved at the apply.

## How to test it

From the repository root, with Docker running and the tools installed as `ansible/README.md`
describes (the harness runs in CI, never against a host):

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ci_jump
.venv/bin/python ansible/harness/run_harness.py ansible/roles/ci_jump --scenario refusals
cd ansible/roles/ci_jump && PYTHONPATH=library ../../../.venv/bin/python -m unittest discover -b -s tests/unit
```

- `default` starts from a container that runs systemd and the real OpenSSH server as `ssh.service`,
  laid out as the ci-jump runbook builds it by hand: a `nologin` account whose home is
  `/nonexistent`, a root-owned key file whose one line allows an address the new list will not, and
  a drop-in with a `Match` block carrying that old address. It proves the role replaces both with
  the declared text, reloads sshd, and then, over real SSH connections: the key reaches the listed
  address and the jump host's own address on port 22 (the target's banner comes back); a live
  listener that is not on the list is refused, with sshd logging that it denied the forward; the
  listed address on another port is refused; **`ssh -R` is refused, for each key**; a key in no file
  and the replaced line's key are turned away; remote commands are not run. As a control, with a
  second address on the list the same connection goes through, and with the list put back it is
  refused again. It records what `sshd -T -C` evaluates for a user under another `Match` block, runs
  the report, and scans the run's log for any key body and, in the output of the role's tasks, for
  the account's name.
- `refusals` applies the role once and then runs each guard alone against the bad input or the bad
  state, expecting the guard's own code, with a control beside each group that must be accepted. The
  read-back cases put a `Match` block ahead of the role's, which outranks it, or change a file or its
  owner, mode or directory behind the role's back, and run the read-back step alone. The last two
  cases run the write step with a configuration that fails the whole check, and with a read-back
  sshd refuses, and require the previous files to be back.
- The unit tests run the module against a fake host: every code above, the parser, the report over
  hostile values with no account name in it, the read-back, and the reader's refusal of a link and a
  pipe.

## How it is delivered

Only through the gated workflow (ANS-17): the role is on the host's list in
`ansible/checks/host_roles.yml` and applied by `ansible/playbooks/HOST.yml`, directly after
`ci_login` on `edge1`. It is delivered in steps, and nothing about a host is read by an agent to write
it.

1. **The role, inert.** Merged with the flag false. The first gated plan for the host then prints the
   report: which accounts carry forwarding options, their destinations, whether each is in the
   owner's list, and fingerprints. The owner reads it against the runbook's hand-made layout.
2. **The data.** A change to `owner_vars/HOST.yml` alone: the account's name (by whichever channel
   the owner chooses, above), the host's own address, the destinations, the public keys and the flag
   true. The owner must read the plan's check-mode lines before approving the apply: for each
   destination whether it is live and wanted, in the key file and in sshd, and for each key whether it
   is live and wanted, with a destination or key that would be removed named as such. The first apply
   reloads sshd and then proves, with sshd's own answer, that remote forwarding is off. If the report
   shows lines whose `permitopen` sets differ, the second step is not opened and the owner rules first.

**Recovery.** Once the jump pair is set, every host in `ANSIBLE_HOSTS` is reached through the jump,
`edge1` included. A destination list that drops or misspells a host fails the plan of every host
(one unreachable host fails them all), and the pull that would correct it is one of those plans, so
the correction cannot be delivered by the gated route. The role therefore refuses a list that lacks
the jump host's own address (`E-DEST-OWN`) before it writes, which is the one host the role can check
for itself; the other hosts are the owner's to keep equal to the host list, and the runbook's rule
("extend the set before the host joins the list") stands. If a wrong list does reach a host, the
way back is the runbook's hand edit of the two files, or the previous commit's files restored by the
owner. In the plan of the jump host itself the action relabels that host's address as `host N` or
`the jump host`, so the report cannot carry that one destination over to the owner's list character
for character: the owner supplies its exact spelling.

## Adding the next jump host

`edge-t` is enrolled by its own change. To give a host this role, list `ci_jump` in its row of
`ansible/checks/host_roles.yml`, apply the role in its playbook, add the host to `JUMP_HOSTS` in
`ansible/checks/check_enrolment.py` and give it an `owner_vars/HOST.yml` that ships the five
variables inert. The role itself changes nothing: the constants are the same on every jump host (the
paths are host-local), and the account, the address, the destinations and the keys are that host's own.

## Named limits

- **The live state was not read.** The report is the first reading. The plan of the first run shows
  it, and the second step is built from it.
- **The `sshd -T -C` check uses the jump host's own address as the client address.** The jump key is
  used from runners that have no fixed address, so a `Match` block keyed on a real runner address is
  not seen. A `Match` on the user, the group or the host name is.
- **sshd is read, not edited, beyond the one drop-in.** If another configuration disables
  forwarding, runs a keys command, or has a `Match` block ahead of the role's that changes a setting
  of the account, the role refuses and stays refused until the owner clears it; it will not edit
  `sshd_config` or another drop-in.
- **A key body is checked for shape, not for being the right key.** A decoded blob of the right type
  is a valid key; a wrong one locks the pipeline out of the jump.
- **The report's code is a copy of the plan scan's pattern.** The module carries `SCAN_PATTERN`,
  copied from `branchLeft/github-workflows`, `.github/actions/ssh-check-hosts/action.yml` line 434 at
  tag v1.0.19, and withholds any line of its own that the pattern would match. A change of the
  original is not seen until a test holds the two equal.
- **Only the last part of a path is opened without following a link.** A link in a directory above a
  key file is followed; the report prints through the closed vocabulary only, so what it could reach
  is never shown.

## How to change it safely

Change the tasks, the module, the argument spec, the defaults, the templates, the owner's files and
the molecule plays together. Run the unit tests and both scenarios, and break the control you touched
to see its test fail: the remote-forwarding refusal over real SSH (`molecule/default`), the guard
cases (`molecule/refusals`) and `ansible/checks/test_ci_jump_pins.py` each have a red state to see. Do
not let another role write this account's keys, do not make the role take a destination per key, and
do not print the account's name.
