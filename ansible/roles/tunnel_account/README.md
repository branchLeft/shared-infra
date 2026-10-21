# tunnel_account

The reverse tunnel that publishes db1's MySQL on the replica host's loopback.
db1 dials out; the replica never dials in. One role, four entry points:

| Entry point | Host         | What it does                                                                                                                  |
| ----------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| `db1_key`   | db1          | Creates the tunnel account (no login shell) and db1's ed25519 key, once. Prints the public half. Reads no input.              |
| `db1`       | db1          | Runs `db1_key`, reads its three input files, pins the replica host key, writes the target file, installs the unit, starts it. |
| `replica`   | replica host | Reads its two input files, creates the account, writes the sshd drop-in and the authorized key, checks sshd, reads it back.   |
| `teardown`  | either       | Removes the tunnel from the host it runs on. Needs `tunnel_account_teardown_confirm: true`.                                   |

The ports (13306, 3306, 9105, 9104) and paths are constants in `vars/main.yml`,
not inputs. A caller cannot change them. The play that calls the role may run with
`gather_facts` off: `db1` gathers the network addresses itself and finds db1's
address on the private subnet from the `all_ipv4_addresses` fact. The role needs `ssh` and `ssh-keygen` or the Python
`cryptography` library on db1, and the OpenSSH server on the replica host (its
`sshd_config.d` directory; the role stops if it is missing).

## Run-time inputs (root-only files, placed once)

The run-time inputs are not role arguments. Each is one file in
`/etc/branchleft/db-tunnel/inputs/`, owned by root and group root, mode `0600`, a
regular file (not a link). The directory is owned by root, mode `0700`. The
operator places each file once. The role reads them, asserts their owner, group,
mode and type, and never writes them. A missing or unsafe file fails the run and
names its path. The same files serve a check run and the nightly run alike.

| File                | Read by   | What it is                                                                                                       |
| ------------------- | --------- | ---------------------------------------------------------------------------------------------------------------- |
| `replica_host`      | `db1`     | The replica host's public IPv4 address. Private.                                                                 |
| `replica_host_key`  | `db1`     | The replica host's one-line `ssh-ed25519` host key, with or without its comment. Public data, but not committed. |
| `db1_subnet_prefix` | `db1`     | The first three octets of db1's private bind address, with a trailing dot. Must be a private range. Private.     |
| `from_address`      | `replica` | db1's public NAT egress address, as the replica host sees it. The key is accepted only from it. Private.         |
| `db1_public_key`    | `replica` | db1's one-line `ssh-ed25519` public key, copied from the `db1_key` run output. Public data.                      |

Every value is refused before any file changes when its shape is wrong: an
address must be public and made of four octets from 0 to 255 with no leading
zero (`from_address`, `replica_host`), a subnet prefix private, a key one
`ssh-ed25519` line with at most a plain comment. Each pattern ends at the line
break (`\Z`), so a second line is refused, and a second line in `from_address`
or `db1_public_key` would otherwise be a second, unrestricted authorized key.

### What a run never shows (ANS-16)

No private input reaches a log. Every task that reads or renders an input has
`no_log: true`, and the tasks that render one into a file also have
`diff: false`, because a `--diff` run (the plan job, and the harness's check
runs) prints the file's content. The asserts name no value: a failure says which
input is wrong and not what it held. The Molecule scenario writes its whole log
at verbosity 3, and `verify` scans it for each input. See "Tests".

## Run order (the gated live run)

The live run is Rob's, through the gated apply. The agent does not apply.

1. db1: `tasks_from: db1_key`. Copy the printed public key.
2. Operator places the five input files (above) on db1 and on the replica host,
   each where its entry point reads it. `db1_public_key` and `from_address` go on
   the replica host; the other three go on db1.
3. Replica host: `tasks_from: replica`.
4. db1: `tasks_from: db1`.

`db1_key` reads no input, so step 1 needs nothing placed. Step 4 runs `db1_key`
first; `regenerate: never` keeps the existing key.

## The sshd change on the replica

The role writes `/etc/ssh/sshd_config.d/50-branchleft-db-tunnel.conf` and
`/etc/ssh/branchleft-db-tunnel/authorized_keys`. It checks the whole sshd
configuration with `sshd -t`, reloads sshd, then reads `sshd -T` back for the
tunnel account and compares each setting in `tunnel_account_expected_effective`
(`vars/main.yml`) with the one it wrote: one `permitlisten`, one `permitopen`, no
command, public key only, and the forwardings and tty it does not allow. The drop-in ends with `Match all`, so no
later line of the main configuration is read as part of the tunnel account's
block. If a check fails, the previous drop-in and authorized key are put back,
and the run fails naming the cause. Under `--check` the role changes nothing.
A check run on a host that has none of the role's directories yet completes (the
harness's `check-fresh` step runs it): the role's modules report what they would
do. The one read that cannot be reported is db1's public key file, which does not
exist until the run creates it, so that read is guarded by a `stat`.

### Golden files

The drop-in and the authorized key are what the ghost-platform program
(`db/tunnel/tunnel_account.py`, commit 5e52f78427cab104438057164e4baa16b329875c)
renders for the same inputs. That was checked once, by rendering both with the
program and diffing. The authorized key line is byte for byte the program's.
The drop-in differs in three recorded ways: a different header comment, the
`AuthorizedKeysFile` path (the role keeps the keys outside the key directory
that holds the inputs), and a closing `Match all`. The two golden files in
`molecule/default/files/golden/` hold those outputs, and `verify` compares what
the role wrote with them. Until the program's tunnel duties are removed (a
follow-up ticket), the drop-in and the authorized key have two live homes.

## Host key

The replica host key is pinned, not trusted on first use. The operator reads
`/etc/ssh/ssh_host_ed25519_key.pub` on the replica host over the operator's own
root session and places it as `replica_host_key`. `ssh-keyscan` is not used. The
unit's `StrictHostKeyChecking=yes` makes a key that does not match fail the
connection.

## Teardown

`tasks_from: teardown` runs only when `tunnel_account_teardown_confirm` is true
(default false, and no converge or drift run sets it). On db1 it stops and
removes the unit, db1's key files, the known hosts file, the target file, then
the account. On the replica host it removes the sshd drop-in, the authorized key
directory, then the account. One run serves both hosts: each path is removed if
it is there. It never removes the run-time inputs or the key directory that
holds them, which are the operator's.

## Tests

`molecule/default` runs the role in one container, which is the replica and db1
at once; the test inputs stand in for the two hosts. It runs in the order
converge, idempotence, verify. Verify does these things, in order:

- Reads the host back: the key's owner and mode, the account's shell, the
  unit's state in systemd, both rendered files against their golden files, the
  effective sshd settings, the pinned host key, the target file, the modes of the
  files, and the unit against both its pin and the hetzner copy.
- Checks the role's address, subnet and key patterns against tables of edge
  values (every private range, one either side of each edge, out-of-range octets,
  leading zeros, trailing and embedded line breaks, options before a key).
- Changes every public input to a second set and reads each file again, so no
  value is fixed in a template. The second set lies just outside two private
  ranges.
- Runs the control cases, each of which must be refused with its own message: a
  private address and a non-address for each address input, a second line, a bad
  key, a key with options, a public subnet prefix, a subnet with no address of the
  host, a missing file, a file that is not mode 0600, a symbolic link, an inputs
  directory that is not root-only, a sshd configuration that fails its check (the
  marked previous drop-in must be back, byte for byte), an unconfirmed teardown,
  and an existing account with a login shell.
- Runs teardown with confirmation, reads it back, and runs the three halves again
  so the configured check meets a configured host.
- Last, scans the log of every Ansible run of the scenario, check runs with
  `--diff` included, for each private input, as text and as the base64 that
  `slurp` returns. It first requires the log to hold
  the names of tasks that handle inputs, a diff header, a censored result and the
  public key the role prints on purpose, so an empty log cannot pass.

## Limits

- The sshd in the container is a stand-in (`molecule/default/files/sshd-stub.sh`):
  the pinned test image has no OpenSSH server. It answers `sshd -t` and `sshd -T`
  from the drop-ins on disk, refuses keywords it does not know and keywords
  outside a Match block, and ignores `-C` except for `user=`. It is not OpenSSH.
  Real sshd enforcement is unproven until the lab proof or the live run.
- The container has no `ssh` binary and is not privileged. The unit is installed,
  enabled and loaded by systemd, and systemd accepts its start. That the process
  runs, connects and holds the tunnel is not proven here.
- Molecule runs on arm64 Docker Desktop only. amd64 is not proven.
- The second run's zero-change result and the nightly drift check need the live hosts.
- Teardown leaves the key directory itself, because it holds the inputs.
- The unit file carries a header comment that names the legacy installer
  (`45-install-db-tunnel.sh`) until that installer is retired. The legacy copies
  stay live until the follow-up retirement ticket. That ticket also removes the
  byte comparison in `verify` against `hetzner/provision/branchleft-db-tunnel.service`.
- The pin on the unit file's sha256 catches an accidental edit when the role
  runs. A deliberate edit shows in review as a changed digest in the same diff.
