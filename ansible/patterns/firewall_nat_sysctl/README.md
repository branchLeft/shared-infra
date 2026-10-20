# firewall_nat_sysctl

This role is a pattern. It is the recipe a maintainer follows when a shell script
persists IPv4 forwarding, loads a firewall and NAT ruleset, and must not lock the
host out when the new ruleset is wrong. It configures no real service and no real
network. Copy the shape, not the names.

## What it does, and what it does not

It persists `net.ipv4.ip_forward` in a sysctl drop-in file. It renders one nftables
ruleset, checks its syntax on the target, and compares it with the host: with the
active rules file, with the boot rules file, and with the tables the kernel holds.
When any of the three differs it loads the ruleset, then connects to a control port
on the host. If that connection fails, it restores the previous ruleset and fails. If
it succeeds, the ruleset becomes the active file and the boot rules file, and the
distribution's `nftables` unit, which loads the boot rules file when the host starts,
is enabled.

It does not:

- write `/proc/sys`: the running forwarding value is not set (see the limits);
- have a forward rule, or a rule in a chain that Docker owns. The bash scripts this
  replaces accept forwarded traffic in the Docker-owned chains; this pattern has no
  forward chain, so masquerade here comes with no forwarding permission. A host that
  runs Docker needs that rule added, in a way the consumer designs and tests;
- replace an iptables firewall. The tables it loads are nftables tables beside whatever
  iptables rules the host has. A packet must pass every hook, so an iptables drop still
  drops;
- accept loopback, ICMP, ICMPv6 neighbour discovery or DHCP traffic on input (see the
  lock-out hazards);
- choose the control port or the uplink for a service, or apply itself to a host.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables, and
[`defaults/main.yml`](defaults/main.yml) holds their defaults. None of them is a
secret. The control port and the allowed ports are the two values an operator must
get right: see the lock-out hazards below. The NAT source, the uplink name and the
table name are refused before anything is loaded unless they are plain values (a
newline, a space or any other character outside the documented set is refused).

The role leaves facts after it runs, which a caller or a test reads:

| Fact                                   | Meaning                                                                                |
| -------------------------------------- | -------------------------------------------------------------------------------------- |
| `firewall_nat_sysctl_drift`            | The ways the host differed from the desired rules; empty when there was nothing to do. |
| `firewall_nat_sysctl_reloaded`         | True when this run loaded the ruleset and the connection check passed.                 |
| `firewall_nat_sysctl_rolled_back`      | True only when the guard's rollback completed.                                         |
| `firewall_nat_sysctl_failed_task`      | The name of the task that failed inside the guard.                                     |
| `firewall_nat_sysctl_rejected_listing` | The tables the kernel held when that task failed.                                      |

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, and `min_ansible_version` in
  `meta/main.yml` equal to it.
- The collection `ansible.posix`, pinned in `ansible/requirements.yml`, for the sysctl
  module. No module in the pinned collections loads an nftables ruleset (the
  `firewalld` modules in `ansible.posix` manage a different firewall), so the loader
  is called with `ansible.builtin.command` as an argument list, with `changed_when`
  set (ANS-9).
- Target: Debian 13, with the `nftables` package installed. The package brings the
  `nft` loader and the `nftables` unit; the role does not install it. The process
  that loads the ruleset needs `CAP_NET_ADMIN`, since the loader talks to the kernel
  over netlink. The test installs the package in its prepare play.

## What it changes on a host

- The sysctl drop-in at `firewall_nat_sysctl_sysctl_file`, holding the line
  `net.ipv4.ip_forward=1`. The running kernel value is not written by this role.
- The directory `firewall_nat_sysctl_rules_dir`, `root:root`, mode `0700`.
- In that directory, three files, all `root:root` mode `0600`: `active.nft` (the rules
  last loaded and confirmed), `previous.nft` (the active file before the last load)
  and `active.list` (the listing the kernel gave when the active rules were confirmed).
- `/etc/nftables.conf`, `root:root` mode `0600`: the boot rules file. The role takes the
  whole file. Whatever else it held, including the distribution's sample, is replaced,
  and the role keeps no copy of it.
- The `nftables` unit, enabled. It is not started: starting it loads the file the guard
  has just confirmed, and stopping it flushes the whole kernel ruleset, which would
  remove tables that are not the role's.
- The kernel's nftables tables named by `firewall_nat_sysctl_table`: an `inet` filter
  table whose input chain drops by default and accepts established traffic and the
  allowed TCP ports, and an `ip` NAT table with a postrouting masquerade rule for
  `firewall_nat_sysctl_nat_source` out of `firewall_nat_sysctl_uplink_interface`.

## How to run its test

From the repository root, with Docker running locally and Python 3.12 or later.
`ansible/README.md` describes the harness and the tools in full.

```text
python3 -m venv .venv
.venv/bin/pip install -r ansible/requirements.txt
.venv/bin/python ansible/harness/run_harness.py ansible/patterns/firewall_nat_sysctl
```

The harness lints the role and runs the scenario in `molecule/default/` on one
container, and exits non-zero if any step fails. It removes its container when it
finishes. The scenario adds one capability to the container, `NET_ADMIN`; it does not
use `privileged`.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after the
approval of its protected environment. A plan job shows each host's diff in check mode
first; after the approval the host pulls that exact commit of `main` and applies it, and
a second run must report zero changes. Nothing is applied from a laptop. This pattern is
not applied to any host: it exists to be copied, and the trigger and the reusable
workflow are separate work.

The Ansible workflow on `main` (`.github/workflows/ansible.yml`) runs the harness over
every role and every pattern: `ansible/roles/*` and `ansible/patterns/*`, with no path
filter on the workflow. A change to this pattern is therefore tested in CI.

## How to change it safely

1. Edit the rules in `templates/rules.nft.j2`, or the tasks in `tasks/main.yml`. Change
   the template, the tasks and the plays in `molecule/default/` together.
2. Run the test (the commands above). Then break the control you touched, as section (d)
   lists, and see the step it names go red: a control is yours only after you have broken
   it.
3. To allow another inbound port, add it to `firewall_nat_sysctl_allowed_tcp_ports`. The
   control port must stay in that list. Every port a person or a monitor reaches the
   host on must be in it, because the guard checks one port only.
4. A failing guard means the set you wrote does not accept the control port once it is
   loaded. The role has already put the previous set back; read
   `firewall_nat_sysctl_rejected_listing`, which holds the tables the kernel had when the
   check failed. If the test's bad-set attempt stops being rolled back, the guard no
   longer runs: do not loosen the assertion, find which task stopped the run first.
5. The previous set is kept as `previous.nft`, copied from `active.nft` just before a
   load. Only one is kept. After a rollback `active.nft` and the boot rules file are
   unchanged.
6. A host that restarted into a bad persisted set: the boot rules file is written only
   after the connection check passed, so a set that closes the control port is never
   persisted. A set that passes the check but closes a port the check does not look at is
   persisted, and a restart loads it. Reach the host without the network the rules close
   (the provider's console), load `previous.nft` with `nft -f`, copy it over
   `/etc/nftables.conf`, correct the variable and let the gated workflow apply it.
   Operational detail for a real host belongs in the private operations documents, not
   here.

### Lock-out hazards

- The input chain drops every new connection except the TCP ports in
  `firewall_nat_sysctl_allowed_tcp_ports`. The guard checks that the control port answers
  on the host's loopback address after the load. It cannot see a remote session. A remote
  session on a port the allowed list does not carry is cut off when the set loads, and
  the guard does not roll it back.
- The input chain accepts nothing on loopback beyond the allowed ports, nothing for ICMP
  or ICMPv6 (including neighbour discovery, which IPv6 needs to keep its neighbour
  entries), and nothing for DHCP (a lease renewal can be dropped). A host that relies on
  any of these loses it after the load, and the guard cannot see it. Loopback is not
  accepted as a whole on purpose: the connection check is a loopback connection, and a
  blanket loopback accept would let every set pass it. A copier adds the rules the host
  needs, narrowly, and tests that the check still fails for a set that closes the
  control port. IPv6 and DHCP behaviour is reviewed, not tested.
- The rollback can itself fail. The restore loads `previous.nft`; if that file cannot be
  loaded, the role stops on the loader's error and the bad set stays loaded. The host then
  fails closed, not open, and neither the active file nor the boot rules file was changed.
- The first install has no previous set. The guard then removes the two tables it loaded,
  which leaves the host as it was.

## The recipe

### (a) The bash shape it replaces

The bash scripts this replaces use `iptables`, not `nft`, and are shaped like this
(placeholder names):

```bash
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-EXAMPLE.conf
sysctl -q -w net.ipv4.ip_forward=1
iptables -t nat -I POSTROUTING 1 -s EXAMPLE_SUBNET -o EXAMPLE_UPLINK -j MASQUERADE
iptables -t filter -I FORWARD 1 -s EXAMPLE_SUBNET -o EXAMPLE_UPLINK -j ACCEPT
```

A second run of that script inserts the rules again unless each insert is wrapped in a
check. Nothing checks the loaded rules after the insert, and nothing reverts them when
the change cuts the operator off. The reader must simulate the script to learn the end
state. Nothing loads the rules again after a restart of the host unless a unit does.

### (b) The Ansible shape

```yaml
- name: Persist IPv4 forwarding in the sysctl drop-in
  ansible.posix.sysctl:
    name: net.ipv4.ip_forward
    value: '1'
    state: present
    sysctl_set: false
    sysctl_file: '{{ firewall_nat_sysctl_sysctl_file }}'
    reload: false

- name: Render the desired rules
  ansible.builtin.set_fact:
    firewall_nat_sysctl_rules: "{{ lookup('ansible.builtin.template', 'rules.nft.j2') }}"

- name: Check the desired rules parse, loading nothing
  ansible.builtin.command:
    argv: [nft, -c, -f, '-']
    stdin: '{{ firewall_nat_sysctl_rules }}'
  changed_when: firewall_nat_sysctl_plan and (firewall_nat_sysctl_drift | length > 0)
  check_mode: false
```

The guard itself is a `block` with a `rescue`. Its tasks keep the active file as the
previous set, load the desired rules, read the tables the kernel holds, connect to the
control port, and then promote the rules to the active file, the recorded listing and the
boot rules file. The `rescue` records what failed, restores the previous file (or removes
the tables when there was no previous file), records that the rollback completed, and
fails. A last task enables the `nftables` unit. See `tasks/main.yml` for the full list.

### (c) Why each parameter is set

- `sysctl_set: false` and `reload: false` make the module write only the drop-in file.
  With `reload` left at its default, the module runs `sysctl -p`, which writes
  `/proc/sys`. The running value is then a separate step that belongs to the consumer.
- The desired rules are rendered in memory and fed to the loader on standard input. No
  staging file is written, so there is no candidate file that can be stale after a
  rollback, and check mode can compute the desired rules without writing anything.
- `nft -c -f -` is the loader's check-only mode. It loads nothing, so it runs in check
  mode too (`check_mode: false`, ANS-10), and an invalid file is never loaded.
- The decision to do nothing compares the desired rules with the host, not with a file
  alone. The active file and the boot rules file must equal the desired rules (by
  checksum), and the tables the kernel holds must equal the listing the kernel gave when
  the active rules were last confirmed. The role chose the table-scoped listing of the
  two tables it owns, not `nft list ruleset`: other tables, such as those a container
  runtime keeps, change on their own and would make every run look like drift. The role
  cannot turn the desired rules into the kernel's own text without loading them, which is
  why the comparison uses the recorded listing for the loaded side. A flush, a restart or
  a foreign reload changes the loaded tables and no file, and is found by this
  comparison.
- In check mode a difference is reported by the syntax-check task (it reports changed),
  and nothing is loaded or written.
- The table is written as `add`, `delete`, then the definition. Loading the file
  replaces the whole table, so a restored previous file leaves no rule of the failed set
  behind.
- `wait_for` on `127.0.0.1` runs after the load. A loopback connection enters the input
  chain, so a set that does not accept the control port refuses it. Listing the ruleset
  would prove the rules are present, not that the port still answers.
- The `rescue` restores the previous file rather than an empty set. A guard that
  restored an empty set would leave a host with no rules where it had working ones.
- The boot rules file is written only after the check passed, and the `nftables` unit is
  enabled, so a restart loads a set the guard has already confirmed. The role enables the
  unit and does not start it.
- The string inputs are matched with patterns that end in `\Z`, not `$`. `$` also matches
  just before a trailing newline; `\Z` matches only at the end of the string.

### (d) What the test proves and the named limits

The test is the scenario in `molecule/default/`, run by the harness. Its default
sequence proves:

- **The rules are checked by content, not by exit code.** `verify.yml` reads the loaded
  `inet` filter table and the `ip` NAT table with `nft list table` and asserts the
  control port rule, the established-traffic rule, the drop policy and a single
  masquerade line, with the scenario's non-default values, and that the loaded tables
  equal the recorded listing.
- **The guard, and not another task, rolls a bad set back.** On the first converge,
  `tasks/probe.yml` applies a set that every check before the load accepts (valid ports,
  a plain source, it parses with the check-only mode) but that does not accept the
  control port. It asserts four things together: the role accepted the set up to the
  load; the tables the kernel held when the check ran contain the bad set's rule; the
  task that failed is the connection check, by name; and the loaded ruleset afterwards
  equals the one before, byte for byte, with the active file and the boot rules file
  unchanged. A role with the check, the rescue and the restore removed, and an ordinary
  up-front refusal added, fails the assertions that the guard recorded its rollback and
  that the kernel held the bad set.
- **The first-install branch.** The same bad set is tried before any set is on the host;
  the tables must be gone afterwards.
- **The rollback itself failing.** The active file is made unloadable and the bad set is
  tried: the run must stop on the restore task and the bad set must still be loaded. The
  next good apply must recover.
- **Inputs that are not plain values are refused.** A NAT source with a newline in the
  middle, with a trailing newline and with a second token is refused by name before
  anything is loaded, and the loaded ruleset is unchanged.
- **The guard keeps a good set**, and verify connects to the control port.
- **The kernel's state, not only the files, decides.** `verify.yml` flushes the kernel
  ruleset and runs the role in check mode, which must report the difference and load
  nothing; it runs the role for real, which must load the recorded set again; and a third
  run must report nothing to do.
- **The set survives a restart.** The unit is asserted enabled and linked into the
  start-up target. The kernel ruleset is flushed, as a restart leaves it, the unit is
  started, and the loaded tables must equal the recorded listing.
- **The persisted sysctl drop-in is checked by content.** `verify.yml` asserts the
  drop-in holds `net.ipv4.ip_forward=1`, and that the file is `root:root` mode `0644`.
- **The second converge changes nothing**, and **check mode changes nothing**: the
  idempotence step and the check-fresh and check-configured steps, with the converge play
  asserting that a check-mode run on a fresh host wrote no rules file, no recorded
  listing, no drop-in, did not change the boot rules file and did not enable the unit.

The named limits follow. Each is stated so that a green run is not read as more.

- **Reviewed, not tested: the runtime sysctl write.** The role does not write
  `/proc/sys`. The test container mounts `/proc/sys` read-only, so a runtime write is
  denied even with `NET_ADMIN` added. The role persists the drop-in only, so the running
  value stays what it was until the host restarts or `sysctl --system` runs. A consumer
  that needs forwarding on before then adds its own task with `ansible.posix.sysctl` and
  `sysctl_set: true`, and on the first live apply reads `sysctl -n net.ipv4.ip_forward` on
  the host to confirm the value is `1`. That read is the consumer's to add.
- **Reviewed, not tested: a real restart of the host.** The test starts the enabled
  unit, which runs the same action the start-up runs, on a flushed kernel. It does not
  restart the container's init, so the order of the unit against the network at start-up
  is not exercised.
- **Reviewed, not tested: the root ownership of the drop-in and the rules files.** The
  test runs as root, so omitting `owner` and `group` gives the same result, and the
  assertion cannot tell the two apart. The scenario does not give these files a
  non-root owner.
- **Reviewed, not tested: the recorded listing across an nft upgrade.** The listing is
  the kernel tool's text. A new version that prints the tables differently makes one
  run look like drift; that run reloads the set and records the new text.
- **Reviewed, not tested: check mode skips the guard.** The `when` on the guard block
  reads `not firewall_nat_sysctl_plan`, because check mode loads nothing and promotes
  nothing. The role learns it is in check mode from a skipped command, not from
  `ansible_check_mode`, which is set only by `--check` on the command line and stays
  false for a play or task that sets `check_mode: true`.
  A check-mode run reports the plan through the syntax-check task and proves the rules
  parse; it does not exercise the connection check.
- **The nftables unit and the boot rules file are taken over.** The role writes the
  distribution's own boot file. A host that keeps other rules there loses them. Stopping
  the `nftables` unit flushes the whole ruleset, the role's tables and any others.
- **The connection check is one port, from the host itself.** It does not prove a remote
  client can reach the port, and it checks no other allowed port.
- **The rollback is only as good as the previous file.** If it cannot be loaded, the bad
  set stays loaded (tested, above), and the host fails closed.
- **The test runs on the Docker runtime's kernel.** The runtime's kernel decides whether
  nftables loads and whether masquerade works. CI runs the same scenario on a runner's
  kernel; neither is a production host's kernel.
- **The uplink is a placeholder.** The masquerade rule names `UPLINK_INTERFACE` by
  default. Nothing checks that a real host passes its own uplink name.
- **The timeout is short.** The connection check waits five seconds. A host whose control
  port takes longer to answer after a load is rolled back.
- **A failed table removal in the rescue is not reported.** The command that removes the
  tables when there was no previous file has `failed_when: false`. The first-install test
  proves the tables are gone in the case it runs; a removal that fails for another
  reason is not reported, and the role's failure message still says it removed them.

### (e) How a service role copies it

1. Make the new role from the skeleton, as `ansible/README.md` says, under
   `ansible/roles/`.
2. Copy `tasks/` (the main file and `_read_loaded.yml`), `vars/main.yml`,
   `templates/rules.nft.j2` and the whole of `molecule/default/` over the new role's
   files. Keep `namespace` in `meta/main.yml`.
3. Rename the variable prefix `firewall_nat_sysctl_` to the new role's name in
   `defaults/main.yml`, `vars/main.yml`, `meta/argument_specs.yml`, the tasks, the
   template, the scenario plays and the group variables in `molecule.yml`. The rules
   directory and sysctl file names become the service's.
4. Replace the placeholders: the allowed ports, the control port, the NAT source and the
   uplink interface. Add the rules the host needs that this template leaves out (forward,
   loopback, ICMP, DHCP), narrowly.
5. Keep the guard, the comparison with the loaded tables, the boot rules file and the
   unit. A role whose rules are a different set still needs a connection check, a
   `rescue` that restores what was there before, and a persisted copy that a restart
   loads.
6. Run the harness on the new role. Then break each control named in section (d) on the
   copy and see the same step fail.

## Platform and capability

The scenario uses a systemd test base, pinned by digest, on Debian 13 (trixie), the
release every production host runs. Systemd runs as the container's init because the
scenario needs two units: the placeholder listener that the connection check connects to,
and the distribution's `nftables` unit, whose load of the boot rules file is what the
restart test starts. Each platform key carries its reason in `molecule.yml` itself. The
scenario adds one capability, `NET_ADMIN`, the netlink right the nftables loader needs.
It does not add `privileged`.

## Proof record

The proof is recorded in the pull request's report, not in this file, so that no count
or result goes stale here.
