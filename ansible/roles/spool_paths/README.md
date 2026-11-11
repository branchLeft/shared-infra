# spool_paths

This role holds the path from `ops1` to each host's mail spool. For every host the collector is
told to drain, it runs one supervised `ssh -N -L` that `ops1` dials. The forward binds an alias
address on `ops1` and lands on the spool's drain port on the far host's loopback address. The
collector dials the alias as if it were a private address on a routed network, and never learns an
ssh detail, a public address or a host key.

The direction is the point. `ops1` initiates every connection and the spool never dials out, so the
valuable estate reaches into the cheap one and never the reverse. No port is opened on any host: the
path rides the far host's existing ssh.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role:

1. Checks that `/etc/branchleft` exists and is root's and that no one else can change it. It makes
   it never (`host_inputs` does).
2. Reads the collector's descriptor directory and the owner's table of far hosts, and works out
   which hosts get a path (The derived list). This step only reads, so a plan says what an apply
   will do.
3. Makes `/etc/branchleft/spool-paths` (root's, `0700`) and installs the template unit
   `branchleft-spool-path@.service`. Both are harmless with no path.
4. Takes down the path of every host no descriptor names any more: stops and disables its unit, then
   removes its configuration and pinned-key files. It never removes a key.
5. For each host that gets a path, writes `<slug>.conf` (the ssh client configuration) and
   `<slug>.known_hosts` (the pinned host keys), and for a path through a jump host a drop-in that
   adds the jump's start conditions to that one instance.
6. Writes the alias addresses: a dummy interface and one address for each path, as systemd-networkd
   files, only while at least one path exists.
7. Enables each path's unit. A unit is started only when the owner's files for it are in place.

What it does not do, each on purpose:

- It never creates, reads, hashes, writes or removes a private key, or the file that names a jump
  account. The owner places them (The owner's files).
- It does not open a port, add a firewall rule or change any other host. The far host's side is the
  `spool_path_account` role.
- It does not install `ssh` or change the network manager's own setup.
- It does not change the collector. The collector's code and role are untouched: a descriptor's
  `appHostIp` is the alias, which is a private address, so the collector's checks pass unchanged.

## The derived list

A path exists for a host only when both of these are true: a descriptor in the collector's descriptor
directory names it, and the owner's table `spool_paths_hosts` has a row with the same slug. The two
lists are one thing seen twice. A descriptor is how the collector learns a host is to be drained, and
this role reads the same directory, so a host the collector does not drain has no path.

| Descriptor | Table row | Result                                                                   |
| ---------- | --------- | ------------------------------------------------------------------------ |
| yes        | yes       | A path: files, an enabled unit, an alias address                         |
| yes        | no        | Nothing. The host is reached on its own address, and the plan says so    |
| no         | yes       | Nothing. No file, no unit, no alias and so no listener. The plan says so |
| no         | no        | Nothing                                                                  |

The alias is the descriptor's own `appHostIp`, so the collector and the path cannot disagree about
it. It must be a private IPv4 address inside `spool_paths_alias_block` and outside `10.20.0.0/16`,
which the estate network and the tenants network share; two descriptors may not name one address. A
descriptor that is a link, is not valid JSON, names another slug than its file's, or carries a public
address names no host.

`spool_paths_plan` (in `library/`) does all of this and writes nothing. It returns the paths, the
descriptors with no row, the rows with no descriptor, the unusable descriptor files, and the path
configuration files an earlier run wrote that no descriptor names now. It finds those by a first
line the role writes; a configuration file without the line is never taken down.

The collector role runs first in the host's play. A descriptor it removes is therefore already gone
when this role reads the directory, so a path is taken down after its descriptor and never before.
Taking one down first would turn an ordinary retirement into a failed cycle and a page.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the inputs and Ansible checks them when
the role starts. A malformed value stops the run before anything changes, and a message names a row
by its place in the list or a host by its slug, never a value (ANS-16). None is a secret.

| Variable                  | Default | Meaning                                                                      |
| ------------------------- | ------- | ---------------------------------------------------------------------------- |
| `spool_paths_hosts`       | `[]`    | The owner's table of far hosts (below)                                       |
| `spool_paths_alias_block` | empty   | The IPv4 block every alias must sit in; must be set before any path is built |
| `spool_paths_shim_port`   | `8080`  | The port the collector dials on every alias: the collector's own shim port   |

A row of `spool_paths_hosts` holds exactly these keys:

| Key          | Meaning                                                                                            |
| ------------ | -------------------------------------------------------------------------------------------------- |
| `slug`       | The host's name, equal to its descriptor's slug                                                    |
| `ssh_host`   | The address or name `ops1` dials: the far host's public address, or its private one through a jump |
| `ssh_port`   | Optional, 22 unless set                                                                            |
| `spool_port` | The far host's drain port, bound on its loopback                                                   |
| `host_key`   | The far host's public key, one key type and its base64 body, pinned for this path                  |
| `jump`       | Optional: `host`, `host_key` and `port` (22 unless set) of the jump host                           |

The paths, the account name, the unit name and the interface name are constants in `vars/main.yml`
and the unit file, not inputs: an inventory value cannot move them. With the defaults the role
changes nothing but the empty directory and the template unit.

## The owner's files

The role never handles these. They are in `/etc/branchleft/spool-paths`, root's, `0600`:

| File               | Meaning                                                                         |
| ------------------ | ------------------------------------------------------------------------------- |
| `<slug>.key`       | The private key for the far host. One for each host, used for nothing else      |
| `<slug>.jump.key`  | A path through a jump host only: the key for the jump host                      |
| `<slug>.jump.user` | A path through a jump host only: one line, `User NAME`, naming the jump account |

The jump account's name is held out of this repository, so it comes from the owner's file and the
configuration `Include`s it. The unit starts only when the files its path needs are present: a
missing file leaves the unit inactive and not failed, and the next gated apply starts it once the file
is there. Nothing on `ops1` is started, dialled or changed by landing the role.

## What the path is

For a host `<slug>` the unit runs `ssh -F /etc/branchleft/spool-paths/<slug>.conf -N <slug>`. The file
holds, for the far hop, a `LocalForward` from the alias and the shim port to the far loopback and the
spool port; `ProxyJump` to a second stanza when the path goes through a jump host; and for every hop
the options the design names:

- `IdentitiesOnly yes`, `IdentityAgent none` and `IdentityFile` of the host's own key: no agent and no
  default key is ever offered, and a hop offers only its own key;
- `StrictHostKeyChecking yes` against `<slug>.known_hosts`, which pins one key for each hop, with
  `GlobalKnownHostsFile /dev/null`: a changed key fails the unit instead of being trusted;
- `BatchMode yes`, `PreferredAuthentications publickey`, no password, no agent forwarding;
- `ExitOnForwardFailure yes`, `ServerAliveInterval 10`, `ServerAliveCountMax 3`: a link that goes
  silent is given up on in about thirty seconds, and a path that cannot bind its alias exits.

The jump hop carries the session end to end: the connection to the far host is checked against its
own pinned key, so a jump host can drop the drain but cannot read or change it.

The unit has `Restart=always`, no start limit and a growing delay (`RestartSec=5`, `RestartSteps=6`,
`RestartMaxDelaySec=120`), so a path that stays failed is never left that way. It owns no address and
depends on no device.

## Failure behaviour

The alias is held by systemd-networkd on a dummy interface, not by the unit, and that is what makes a
failure honest.

| Condition                                        | What the collector sees                                                                                |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| Path down (link lost, key refused, sshd gone)    | `ssh` exits. The alias stays and nothing listens, so the connection is refused at once: a failed cycle |
| A link that goes silent without closing          | The keepalive ends `ssh` in about thirty seconds, then as above                                        |
| A held thirty-second request when the path drops | The socket resets mid-request: a failed cycle, not a stall                                             |
| Path up, spool down                              | The far sshd cannot open the loopback port and closes the channel: a failed cycle                      |
| Path restored                                    | The unit restarts within its delay and the next cycle succeeds with no collector restart               |
| Host no longer in any descriptor                 | No unit, no alias, no listener. The collector never tries it                                           |

The collector reports a cycle with an error as not completed, and its heartbeat pings only when every
named host has completed one, so a downed path pages after the grace period. That is the intended
reading: silence and failure look the same.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`; `min_ansible_version` is that version.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 with systemd 254 or later (the unit uses `RestartSteps`), systemd-networkd running
  and managing interfaces, and `/usr/bin/ssh`. The role asserts `ssh` when a path is to be held, and
  never installs it.
- `/etc/branchleft` made by `host_inputs`, which goes first on `ops1`.
- The collector role before this one in the play (see The derived list).

## What it changes on a host

| Path                                                                   | Owner | Mode   | What                                                  |
| ---------------------------------------------------------------------- | ----- | ------ | ----------------------------------------------------- |
| `/etc/branchleft/spool-paths`                                          | root  | `0700` | The directory of the files below and the owner's keys |
| `/etc/branchleft/spool-paths/<slug>.conf`                              | root  | `0644` | A path's ssh client configuration                     |
| `/etc/branchleft/spool-paths/<slug>.known_hosts`                       | root  | `0644` | A path's pinned host keys                             |
| `/etc/systemd/system/branchleft-spool-path@.service`                   | root  | `0644` | The template unit                                     |
| `/etc/systemd/system/branchleft-spool-path@<slug>.service.d/jump.conf` | root  | `0644` | A jump path's two start conditions                    |
| `/etc/systemd/network/05-branchleft-spool-paths.netdev`                | root  | `0644` | The dummy interface, while any path exists            |
| `/etc/systemd/network/05-branchleft-spool-paths.network`               | root  | `0644` | One address for each path, while any path exists      |

It also enables one unit instance for each path. It names, and never writes, the owner's key files.

## How to test it

From the repository root, with the pinned tools installed as `ansible/README.md` describes:

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/spool_paths
```

The role has unit tests. From `ansible/roles/spool_paths`:

```text
PYTHONPATH=files:library python -m unittest discover -b -s tests/unit -p 'test_*.py'
```

- `test_spool_paths_plan.py` judges the derived list on scratch directories: a row no descriptor names
  gets no path, a descriptor no row names gets none, an alias outside the block or the same for two
  hosts is refused, and a file the role did not write is never taken down.
- `test_spool_paths_files.py` runs the role's own file tasks with Ansible against a scratch tree: the
  files exist for a host a descriptor names and for no other, a removed descriptor takes its files and
  its alias with it, a key and a foreign file are never removed, a second run changes nothing and a
  refusal writes nothing.
- `test_spool_paths_unit.py` holds the unit to its restart policy, its start conditions and its lack of
  any address, and asks ssh itself (`ssh -G`) what the written configuration does, for a direct path and
  a path through a jump host.
- `test_spool_paths_forward.py` runs the written configuration with a real ssh client against a real
  sshd on a loopback port, with a stand-in spool that holds a request. It proves a request held for the
  full thirty seconds is answered, that killing the path is refused at once and restoring it recovers
  with nothing else restarted, that a request in flight when the path drops fails and does not stall,
  and that a link that goes silent makes the client exit within the keepalive window. Two things are
  replaced: the alias is the loopback address, because a test machine cannot bind a private one, and the
  shim port is a free one. The test needs `ssh`, `ssh-keygen` and `sshd`, and fails, never skips, when
  one is missing.

The Molecule `default` scenario converges twice on a systemd container with stand-ins for `ssh` and
`networkctl`, with two listed hosts and one descriptor and no key placed. It checks the files, owners and
modes, that the listed host with no descriptor has nothing, that the named host's path is enabled and
left stopped because no key is there, that other roles' files are untouched, and that no private key text
is in the run's log. It needs Docker. The scenario passes under the harness; the unit tests above run the real `ssh` and `sshd`.## How it is delivered

Delivery is the gated workflow only (ANS-17): a plan in check mode, the `ansible-hosts` approval, a
pull of that exact commit on the host, and a second run that must report zero changes. Nothing here
applies the role by hand, and nobody reads or carries a key. Wiring the role to `ops1` is the owner's
merge, because the lists it edits are owner-merged paths (`ansible/checks/host_roles.yml`,
`.github/CODEOWNERS`). The first apply after that merge installs the template unit and the empty
directory and changes nothing else until the owner lists a host.

## How to change it safely

- A change to the unit, the configuration template or the key handling changes which key can open which
  port on which host, so it gets the deep review and the owner's merge.
- Never add an agent, a default identity, a password method, a `ControlMaster`, or a second forward to
  the configuration. The tests name each.
- Never make the unit own the alias or depend on a device. That would turn a downed path from a refusal
  into a hang.
- Keep `spool_paths_shim_port` equal to the collector's shim port, `spool_paths_far_user` equal to the far
  role's account and `spool_paths_descriptor_dir` equal to the collector's descriptor directory.
  `ansible/checks/test_spool_paths_agree.py` holds each pair.

## Named limits

- **Live reading owed.** Which block is free on `ops1` is read from its routing table and Docker bridges,
  and the owner sets `spool_paths_alias_block` from that reading. The role refuses any alias outside it.
- **Reaching the alias from the collector's container is unconfirmed.** The role puts the alias on the
  host. Whether a container on its bridge reaches an address bound on the host depends on the host's
  firewall input rules; the live proof must show it from inside the collector's container, and if it fails
  the collector runs on the host network instead of the block being widened.
- **systemd-networkd must be managing the host's links.** If it is not, the alias never exists, the
  forward cannot bind, the unit exits and the collector is refused: honest, but it needs the owner to
  read.
- **A plan on a fresh host shows less than an apply.** The descriptors the collector role writes in the
  same run are not on disk during a plan, so the first plan lists no path. The harness's fresh-host step
  runs this state.
- **An unstarted path is not an alarm by itself.** A unit whose key is missing stays inactive and does
  not fail, so nothing pages on it from here. The collector's silence does.
- **A retired path leaves its key behind.** The role never removes a key. Removing it is the owner's act.
- **The dummy interface outlives the last path.** The network manager does not delete an interface whose
  file is removed. Its addresses go; the empty interface goes at the next restart.
- **Drop-in directories stay.** A path that stops using a jump leaves an empty `.service.d` directory.
- **The test platform is a container with a stand-in `ssh`.** It proves files, modes, instances and
  enablement; it does not prove a connection. The unit tests do, against a real client and sshd.

## Clauses this role exercises

ANS-7 (defaults mirror the spec), ANS-9 (no shell), ANS-10 (check mode), ANS-11 (idempotence), ANS-12
(no role imports another), ANS-14 (this README), ANS-15 (a container test), ANS-16 (no value in a
message) and ANS-17 (the gated pull).
