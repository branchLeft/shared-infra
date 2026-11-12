# ci_jump

Owns the two things that decide which private hosts the gated Ansible run may reach through a jump
host: the jump account's root-owned `authorized_keys` file and the sshd drop-in whose `Match User`
block gives the account its settings. Each key line allows port 22 of the named hosts and nothing
else, and sshd's own `PermitOpen` for the account carries the same list, so adding a tenant host is
one reviewed line in the host's `owner_vars` file and a gated run, not a hand edit on the jump
host. The role works on any jump host: `edge1` and `edge-t`, each with its own
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
  - `/etc/ssh/authorized_keys.d/branchleft-jump` becomes exactly one line per declared key: `restrict`,
    `port-forwarding`, one `permitopen="HOST:22"` per declared destination, `command="/usr/sbin/nologin"`,
    then the key type and body, and nothing else (the key's comment is dropped);
  - `/etc/ssh/sshd_config.d/40-branchleft-jump.conf` holds the `Match User` block the private
    jump-host runbook documents (the key file as `AuthorizedKeysFile`, `AuthenticationMethods publickey`,
    `AllowTcpForwarding local`, `PermitOpen` with the same destinations on port 22, and every
    other forwarding and tty setting off, `ForceCommand /usr/sbin/nologin`), closed by `Match all`.
    Both are made from the one list `ci_jump_destinations`, so the key lines' `permitopen` and the
    block's `PermitOpen` cannot differ; `test_ci_jump_pins.py` proves both templates read that one
    variable and render the same destinations.
  - **No path is made from the account's name.** The owner ruled that the account's
    name is not published. A path
    is printed by a lot of tooling, so the two files and the directory are named for the role's
    purpose, and `test_ci_jump_pins.py` and both Molecule scenarios fail on a path that holds the
    name. The drop-in is `40-` so that it sorts ahead of the earlier hand-made `50-` file: while both
    are on the host sshd already applies the new one (the first value sshd obtains wins), and the
    read-back proves that before the old file is removed.
- **Migration from the hand-made layout.** The private runbook lays the files out by hand at
  `/etc/ssh/ACCOUNT/authorized_keys` and `/etc/ssh/sshd_config.d/50-branchleft-ACCOUNT.conf`. Those
  paths are made from the name, so the role builds them at run time from `ci_jump_user`
  (`ci_jump_legacy_*` in `vars/main.yml`), prints none of them (the module is given them and only
  counts them, and every task that handles one hides its result and its diff), and never ships
  them. The order, in `tasks/_write.yml`:
  1. Refuse, before anything is changed, an old path that is a link or the wrong kind of thing.
  2. Keep the old and new files in memory for a rollback, and make the marker (below) when the
     module's plan says a write is owed.
  3. Write the new key file and drop-in, `sshd -t`, reload sshd if either changed, and read back
     (the new files exact, and sshd's own answer for the account).
  4. Only then remove the old drop-in and key file, and the old directory when nothing else is in it.
     Nothing is removed recursively but that directory.
  5. `sshd -t` again, reload again, and read back again, now also requiring the old files gone
     (`E-LEGACY-PRESENT`).
  6. Take the marker away.
     A failure anywhere puts every file back as it was (the new files as they were, the old files and
     their directory byte for byte), reloads sshd and fails the run. A second run finds the host
     finished and changes nothing. A host that never had the hand-made layout skips steps 4 and 5.
- **A pull that dies after the write still reloads sshd.** Before the first write the role leaves
  `/run/branchleft-jump-reload-owed` whenever the module's plan says a write is owed (a managed file
  not exactly as wanted, or an old file still there). The next run reloads sshd if the marker is
  there, even though the files by then read as wanted, and takes it away after the last read-back.
  `/run` is cleared at boot and a boot starts sshd afresh. A finished host has no marker and is not
  reloaded. `sshd -T` cannot be used for this: it parses the files on disk, not the running daemon.
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
  - the jump host's own address: unset (`E-OWN-EMPTY`), not an IPv4 address (`E-OWN-SHAPE`), not a
    private one, that is outside 10/8, 172.16/12 and 192.168/16, loopback excepted for a test host
    (`E-OWN-PRIVATE`), or not among the destinations (`E-DEST-OWN`). The runner reaches every host through the jump once the
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
no file but the two above, the directory `/etc/ssh/authorized_keys.d` and the marker, and it
removes the old hand-made layout only as the migration above says.

The report reads other accounts' key files as root. It opens each with `O_NOFOLLOW` and `O_NONBLOCK`
and checks the opened descriptor with `fstat` for a regular file, so a link or a pipe put there by a
local account is skipped and cannot make the pull read another file or hang.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the five variables and
[`defaults/main.yml`](defaults/main.yml) holds the defaults of the four others (`ci_jump_user` has none and is optional: see below). Four are read from the host's
file under `ansible/owner_vars/` (`edge1.yml` today). The fifth, `ci_jump_user`, comes from the
host's private inputs file through `host_inputs` and is in no file of this repository.

| Variable               | Default | Meaning                                                                                                              |
| ---------------------- | ------- | -------------------------------------------------------------------------------------------------------------------- |
| `ci_jump_manage_keys`  | `false` | `false`: report only. `true`: guards, write, check, reload, read-back.                                               |
| `ci_jump_user`         | none    | Optional input. The jump account, from `host_inputs`; never committed or printed. Needed only when the flag is true. |
| `ci_jump_own_address`  | `''`    | The jump host's own private IPv4 address; it must be a destination.                                                  |
| `ci_jump_destinations` | `[]`    | Host names or IPv4 addresses, no port. The role adds port 22.                                                        |
| `ci_jump_keys`         | `[]`    | `{key}` entries: public keys, one per entry. Read only when the flag is on.                                          |

The port (22), the fixed options (`restrict,port-forwarding`), the forced command, the paths of the
key file and the drop-in, the name of the sshd service and the accounts other roles own are constants
in [`vars/main.yml`](vars/main.yml), so an inventory cannot change them. The module
(`library/ci_jump_authorized_keys.py`) pins the same values for itself, as the oracle of its
read-back, and `ansible/checks/test_ci_jump_pins.py` holds the two copies equal, holds the account
names equal to `ci_login_user` and `tunnel_account_user` in their own roles, and holds both templates
to the module's text. `ansible/checks/check_enrolment.py` (R10) allows the four variables other than `ci_jump_user` in
the `owner_vars` file of every host in `JUMP_HOSTS`, which must be the hosts whose row in
`ansible/checks/host_roles.yml` lists the role, and refuses an `owner_vars` file that holds
`ci_jump_user`.

A destination must be the exact text the runner's `ssh` sends for the host: sshd matches `permitopen`
and `PermitOpen` literally, so a name in the list and an address on the command line do not match each
other.

### How the account's name reaches the role

The name of the jump account is the owner's secret and is in no file of this repository, no
pull-request text and no log. It reaches the role as the host input `ci_jump_user`: the owner writes
it once into the host's root-only file `/etc/branchleft/host-inputs.json`, the `host_inputs` role
(the first role of the host's playbook) sets it as a fact before this role runs, and this role reads
the one variable `ci_jump_user` as it reads any other. For edge1 the row of
`host_inputs_required_by_host` holds it (a twelfth key) and `host_inputs_optional_by_host` lists
it, so the file may leave it out until the owner has seeded it. It was required in the first
version of this role, and edge1's gated plan then failed as exit 30 (`host_inputs[missing-key]`)
because the tool that seeds it comes only with the commit that adds the role and a failed plan
never reaches the apply that delivers a commit. Without it the role only
reports and prints a `WARNING ci_jump` line in the plan; with the flag true and no name it stops at
`ci_jump[user-missing]` before any task that handles a name. On edge1, once, as root, hidden
prompt, nothing echoed, after the apply that delivers the tool:

```text
python3 -I /var/lib/pull-trigger/current/ansible/tools/seed_host_inputs.py --host edge1 --set ci_jump_user
```

The tool asks for the name hidden and prints the key name and the byte length only. Everything the
role prints or logs is written so that the name is in none of it: the argument spec marks it
`no_log`, the module takes it as a `no_log` parameter, every task that handles it, or a path made
from it, hides its result and its diff, no managed path holds it, and `molecule/default` requires
the name to be absent from the log of every run of the role and from every path under `/etc/ssh`.
The role reads the name only when the flag is true; a run with the flag true and no name stops at
`E-USER-EMPTY` before any write.

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
- With the flag true: `/etc/ssh/authorized_keys.d` (`root:root`, `0755`),
  `/etc/ssh/authorized_keys.d/branchleft-jump` and `/etc/ssh/sshd_config.d/40-branchleft-jump.conf`
  (`root:root`, `0644`), the marker `/run/branchleft-jump-reload-owed` while a reload is owed, a
  reload of `ssh.service` when either file changed, a marker was left, or the old layout was
  removed, and the removal of the old hand-made files and their directory once the new ones have
  read back. No port, firewall rule, account or other sshd setting.
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
  laid out as the private runbook builds it by hand: a `nologin` account of a realistic name
  (lowercase words joined by a hyphen) whose home is `/nonexistent`, a root-owned key file in a
  directory named after it whose one line allows an address the new list will not, and a drop-in
  named after it with a `Match` block carrying that old address. It proves the role replaces both
  with the declared text at the new paths, removes the old ones, reloads sshd, and then, over real SSH connections: the key reaches the listed
  address and the jump host's own address on port 22 (the target's banner comes back); a live
  listener that is not on the list is refused, with sshd logging that it denied the forward; the
  listed address on another port is refused; **`ssh -R` is refused, for each key**; a key in no file
  and the replaced line's key are turned away; remote commands are not run. As a control, with a
  second address on the list the same connection goes through, and with the list put back it is
  refused again. It records what `sshd -T -C` evaluates for a user under another `Match` block, runs
  the report, and requires that no path under `/etc/ssh` holds the account's name; it applies the
  role once more in check mode and scans the log of every run (the check run over the host as the
  prepare left it, the converge, the idempotence run and that check run) for any key body and for the
  account's name, which must be in none of the output. Phase 1b makes the same forward cases through
  the pipeline's own client (`ssh -F` with a `jump_hop` stanza and `ProxyJump`) to a second account
  with its own key that runs `cat`: the listed target gives the standard input back, and the unlisted
  target, another port, the jump host's own loopback and a wrong or replaced key do not (see "Push
  hosts" below).
- `refusals` applies the role once and then runs each guard alone against the bad input or the bad
  state, expecting the guard's own code, with a control beside each group that must be accepted. The
  read-back cases put a `Match` block ahead of the role's, which outranks it, or change a file or its
  owner, mode or directory behind the role's back, and run the read-back step alone. Two cases run
  the write step with a configuration that fails the whole check, and with a read-back sshd refuses,
  and require the previous files to be back. A last play starts from the hand-made layout and runs:
  the first read-back failing (the old files are the very files that were there afterwards); the
  second read-back failing, made to happen by a test-only hook on `ssh.service` that puts the old
  drop-in back after the role removed it (the old files are back with the same checksum and the new
  files are gone); a success (the old layout and its directory gone, the new files in place, sshd
  reloaded exactly twice); and a marker left by a dead pull (the next run reloads sshd exactly once,
  the run after it not at all).
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
   The owner seeds `ci_jump_user` on the host after the apply that delivers the seeding tool (see
   "How the account's name reaches the role"), and before the flag is turned on. Until then the
   plan warns and the role stays inert; with the flag true it stops at `ci_jump[user-missing]`.
2. **The data.** A change to `owner_vars/HOST.yml` alone: the host's own address, the destinations,
   the public keys and the flag true. The account's name is already on the host. With the old
   hand-made layout still there, the first apply migrates it as the migration above says. The owner must read the plan's check-mode lines before approving the apply: for each
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

## The jump hosts: edge1 and edge-t

Two hosts apply this role, `edge1` and `edge-t` (the logical host `edget`), and the pipeline goes
through them in that order: the runner reaches edge1, then edge-t through edge1's jump account
(two hops, ws#2899). The role is the same on both. `ansible/checks/test_ci_jump_hosts.py` holds that:
every host in `JUMP_HOSTS` applies it as a plain role entry, and no part of the role names the host
or a group of hosts, so the real-sshd proof in `molecule/default` (a destination not on the list is
refused) is the proof for each. Only the data differs:

| List     | Holds                                                                                                  |
| -------- | ------------------------------------------------------------------------------------------------------ |
| edge1's  | the estate hosts, and edge-t's public address; never a tenants private address                         |
| edge-t's | edge-t's own private address (`TENANTS_HOST_IPS.edgeT`, which the role requires) and the tenants hosts |

The same test reads `TENANTS_HOST_IPS` from `hetzner-host/addressPlan.ts`, its one home, and
refuses a tenants private address in `owner_vars/edge1.yml` and an own address on edget that is not
edge-t's.

edge-t's owner values are in `owner_vars/edget.yml` (flag true, its own address, its
destinations and the second-hop key). The jump account on the host is never made by the role.
`ci_jump_user` is a key in the host's row of the `host_inputs` loader
(`ansible/roles/host_inputs/vars/main.yml`), set with `seed_host_inputs.py --host edget`; a
run stops at `host_inputs[file-missing]` while the host's inputs file is absent.

To give a further host this role, list `ci_jump` in its row of `ansible/checks/host_roles.yml`
(with `host_inputs` first), apply both roles in its playbook, add the host to `JUMP_HOSTS` in
`ansible/checks/check_enrolment.py`, give it an `owner_vars/HOST.yml` that ships the four variables
inert and a `ci_jump_user` key in its row of `host_inputs_required_by_host` and in
`ansible/tools/seed_host_inputs.py`. The role itself changes nothing: the constants are the same on
every jump host (the paths are host-local), and the account, the address, the destinations and the
keys are that host's own.

## Push hosts: demo1 and the tenant hosts behind a jump

A host in `pull_trigger_bundle_hosts` (`roles/pull_trigger/vars/main.yml`, `demo1` today) never opens
a connection. The gated run sends it the commit as a git bundle on standard input and asks it to
check or apply that, and the only way the runner reaches it is through a jump host. The route:

```text
runner  --ssh -F config -o ProxyJump=jump_hop-->  edge1 (the jump account's key line)  --port 22-->  demo1
```

- **The destination is demo1's public address.** demo1 sits in its own Hetzner project, shares no
  network with edge1, serves 80 and 443, and has SSH open to edge1's address alone. So edge1 reaches
  it on that public IPv4, and the owner's `ci_jump_destinations` in `owner_vars/edge1.yml` names it
  there, as it names edge-t's public address. This role takes the address as data and does not
  hold it; adding a further push host later is one more line of that list.
- **What the route guarantees.** The runner never connects to demo1 directly. demo1's SSH stays
  closed to everything but edge1. demo1 never initiates a connection: it receives the bundle on
  standard input and never fetches. The jump key can open a connection to port 22 of the listed
  addresses and nothing else, whichever client presents it.
- **A pushed host is a leaf, never a hop.** `ansible/checks/test_ci_jump_hosts.py` holds that no host
  in `pull_trigger_bundle_hosts` is in `JUMP_HOSTS` and that its playbook does not apply this role.
  The list is read from the pull_trigger role's vars, its one home.
- **Nothing in this role changes for it.** The destination list, the key lines and the sshd block
  are the same for every host behind the jump. The workflow side is shipped in github-workflows
  (the jump pair, the push list and the push playbook), and the receiver on the host is the
  pull_trigger role's bundle mode.

What is proven where:

| What                                                                                                                                                                                                                                                                                                                                      | Where                                            |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| The jump key reaches a listed address and a command runs there, with the standard input carried, through the pipeline's own client shape (`ssh -F`, a `jump_hop` stanza, `ProxyJump`); an unlisted address, the listed address on another port and the jump host's own loopback are refused; a wrong or replaced key is denied at the hop | `molecule/default`, phase 1b, over the real sshd |
| A pushed host is not a hop                                                                                                                                                                                                                                                                                                                | `test_ci_jump_hosts.py`                          |

Phase 1b's far end is a second account on the same test sshd, with its own key, as a pushed host's CI
account is; it reads the standard input into `cat`, so the bytes the client sent are the proof that
the forward reached the target and not an absent listener. The owner's steps for demo1 itself (the
CI account and its key on the host, the address and public key in `owner_vars/edge1.yml`, the
repository secrets, the host lists) are in the private runbooks, not here.

## Named limits

- **Phase 1b copies the client's options, it does not import them.** Its `jump_hop` stanza mirrors
  `.github/actions/ssh-check-hosts/action.yml` in `branchLeft/github-workflows` at `v1.0.21`
  (`IdentitiesOnly`, `BatchMode`, `ForwardAgent no`, `ClearAllForwardings yes`, reached with
  `-F` and `-o ProxyJump=jump_hop`). It cannot be imported across repositories, and
  `tools/ssh_jump_proof.py` in github-workflows is the authority for the client side. Here only this
  role's sshd side is proven against those options. The stanza does not check host keys, which the
  action pins in its own `known_hosts`.
- **The `sshd -T -C` check uses the jump host's own address as the client address.** The jump key is
  used from runners that have no fixed address, so a `Match` block keyed on a real runner address is
  not seen. A `Match` on the user, the group or the host name is.
- **The old layout is found by the runbook's naming.** The migration removes
  `/etc/ssh/ACCOUNT/authorized_keys`, that directory when it is then empty, and
  `/etc/ssh/sshd_config.d/50-branchleft-ACCOUNT.conf`, and nothing else. A host whose hand-made files
  are named otherwise keeps them: the new drop-in outranks the old one (`40-` before `50-`), but a
  file the role does not know stays on the host for the owner to remove.
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
