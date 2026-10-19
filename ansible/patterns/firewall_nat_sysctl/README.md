# firewall_nat_sysctl

This role is a pattern. It is the recipe a maintainer follows when a shell script
persists IPv4 forwarding, loads a firewall and NAT ruleset, and must not lock the
host out when the new ruleset is wrong. It configures no real service and no real
network. Copy the shape, not the names.

## What it does, and what it does not

It persists `net.ipv4.ip_forward` in a sysctl drop-in file. It renders one nftables
ruleset file, checks its syntax on the target, and loads it only when it differs from
the active file. After the load it connects to a control port on the host. If that
connection fails, it restores the previous ruleset and fails. If it succeeds, the new
ruleset becomes the active file.

It does not write `/proc/sys` (see the limits), does not make the ruleset load at boot
(see the limits), does not choose the control port or the uplink for a service, and
does not apply itself to a host.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables, and
[`defaults/main.yml`](defaults/main.yml) holds their defaults. None of them is a
secret. The control port and the allowed ports are the two values an operator must
get right: see the lock-out hazard below.

## Requirements

- ansible-core as pinned in `ansible/requirements.txt`, and `min_ansible_version` in
  `meta/main.yml` equal to it.
- The collection `ansible.posix`, pinned in `ansible/requirements.yml`, for the sysctl
  module.
- Target: a Linux host with `nft` on the path (the nftables package) and the
  `CAP_NET_ADMIN` capability for the process that loads the ruleset, since the loader
  talks to the kernel over netlink. The test installs `nftables` in its prepare play.

## What it changes on a host

- The sysctl drop-in at `firewall_nat_sysctl_sysctl_file`, holding
  `net.ipv4.ip_forward = 1`. The running kernel value is not written by this role.
- The directory `firewall_nat_sysctl_rules_dir`, `root:root`, mode `0700`.
- In that directory, three rules files, all `root:root` mode `0600`: `candidate.nft`
  (the file rendered this run), `active.nft` (the file last loaded and confirmed) and
  `previous.nft` (the active file before the last load).
- The kernel's nftables tables named by `firewall_nat_sysctl_table`: an `inet` filter
  table whose input chain drops by default and accepts the allowed TCP ports, and an
  `ip` NAT table with a postrouting masquerade rule for `firewall_nat_sysctl_nat_source`
  out of `firewall_nat_sysctl_uplink_interface`.

## Lock-out hazard

The input chain drops every new connection except the TCP ports in
`firewall_nat_sysctl_allowed_tcp_ports`. The guard checks one thing: that the control
port `firewall_nat_sysctl_control_port` still answers on the host's loopback address
after the load. The guard cannot see a remote session. A remote session on a port that
the allowed list does not carry is cut off when the set loads, and the guard does not
roll it back. Before a real host runs this role, the operator confirms that the allowed
list includes every port they reach the host on, and that the control port is one of
them.

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
state.

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

- name: Render the candidate rules file
  ansible.builtin.template:
    src: rules.nft.j2
    dest: '{{ firewall_nat_sysctl_rules_dir }}/candidate.nft'
    owner: root
    group: root
    mode: '0600'
    validate: nft -c -f %s
```

The guard itself is a `block` with a `rescue`. Its tasks load the candidate, connect to
the control port and promote the candidate. The `rescue` restores the previous file, or
removes the tables when there was no previous file, and then fails. See
`tasks/main.yml` for the full task list.

### (c) Why each parameter is set

- `sysctl_set: false` and `reload: false` make the module write only the drop-in file.
  With `reload` left at its default, the module runs `sysctl -p`, which writes
  `/proc/sys`. The running value is then a separate step that belongs to the consumer.
- `validate: nft -c -f %s` loads nothing. It is the check-only mode of the loader, so
  an invalid file never becomes the candidate that is loaded.
- The candidate is compared with the active file by checksum, not by the template's
  `changed` flag. The template's flag reports the candidate's own change, and a rollback
  leaves the candidate holding the rejected set. A checksum compares what the guard
  would load with what is active.
- The table is written as `add`, `delete`, then the definition. Loading the file
  replaces the whole table, so a restored previous file leaves no rule of the failed set
  behind.
- `wait_for` on `127.0.0.1` runs after the load. A loopback connection enters the input
  chain, so a set that does not accept the control port refuses it. Listing the ruleset
  would prove the rules are present, not that the port still answers.
- The `rescue` restores the previous file rather than an empty set. A guard that
  restored an empty set would leave a host with no rules where it had working ones.

### (d) What the test proves and the named limits

The test is the scenario in `molecule/default/`, run by the harness. Its default
sequence proves:

- **The rules are checked by content, not by exit code.** `verify.yml` reads the loaded
  `inet` filter table and the `ip` NAT table with `nft list table` and asserts the
  control port rule, the established-traffic rule, the drop policy and the masquerade
  line, with the scenario's non-default values.
- **The guard rolls back a bad set.** `converge.yml` first applies a good set, reads the
  loaded ruleset, then applies a set that drops the control port inside a `block` and
  expects the role to fail. It reads the loaded ruleset again and asserts the two
  readings are equal. This runs only on the first converge, so the second converge does
  not repeat it.
- **The guard keeps a good set.** The final converge applies the good set again, and
  verify connects to the control port.
- **The persisted sysctl drop-in is checked by content.** `verify.yml` asserts the
  drop-in holds `net.ipv4.ip_forward = 1`, and that the file is `root:root` mode `0644`.
- **The second converge changes nothing**, and **check mode changes nothing**: the
  idempotence step and the check-fresh and check-configured steps.

The named limits follow. Each is stated so that a green run is not read as more.

- **Reviewed, not tested: the runtime sysctl write.** The role does not write
  `/proc/sys`. The test container mounts `/proc/sys` read-only, so a runtime write is
  denied even with `NET_ADMIN` added (measured on 2026-10-19 with throwaway containers,
  with and without the namespaced `--sysctl` preset). A runtime write is therefore not
  proven here. The first live consumer's gated run is where the runtime effect is
  observed: it must read `sysctl -n net.ipv4.ip_forward` on the host after apply, and
  that check is the consumer's to add.
- **Reviewed, not tested: the root ownership of the drop-in and the rules files.** The
  test runs as root, so omitting `owner` and `group` gives the same result, and the
  assertion cannot tell the two apart. The scenario does not give these files a
  non-root owner.
- **Reviewed, not tested: check mode skips the guard.** The `when` on the guard block
  reads `not ansible_check_mode`, because check mode loads nothing and promotes nothing.
  A check-mode run therefore proves only that the candidate renders. Check mode also does
  not run `validate`, so the syntax check happens at apply, not in the plan. This is a
  silent skip under ANS-10, stated on the line that does it.
- **The ruleset is not reloaded at boot.** The guard runs when the role runs. A reboot of
  a real host loads whatever the kernel's boot-time configuration holds. A service role
  adds a unit that loads `active.nft`, as the bash shape's units do; that unit is not in
  this pattern.
- **The connection check is one port, from the host itself.** It does not prove a remote
  client can reach the port, and it checks no other allowed port.
- **The test runs on one container's kernel.** The Docker runtime's kernel decides
  whether nftables loads and whether masquerade works. The result is for the Docker
  Desktop runs recorded in the pull request, not for a host's kernel.
- **The uplink is a placeholder.** The masquerade rule names `UPLINK_INTERFACE` by
  default. Nothing checks that a real host passes its own uplink name.
- **The timeout is short.** The connection check waits five seconds. A host whose control
  port takes longer to answer after a load is rolled back.
- **A failed table removal in the rescue is not reported.** The command that removes the
  tables when there was no previous file has `failed_when: false`. The next run reloads
  the candidate in full, so a leftover table is replaced rather than merged, but the
  rescue does not report that a removal failed.

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

## How a service role copies it

1. Make the new role from the skeleton, as `ansible/README.md` says, under
   `ansible/roles/`.
2. Copy `tasks/main.yml`, `templates/rules.nft.j2` and the whole of `molecule/default/`
   over the new role's files. Keep `namespace` in `meta/main.yml`.
3. Rename the variable prefix `firewall_nat_sysctl_` to the new role's name in
   `defaults/main.yml`, `meta/argument_specs.yml`, the tasks, the template and the group
   variables in `molecule.yml`. The rules directory and sysctl file names become the
   service's.
4. Replace the placeholders: the allowed ports, the control port, the NAT source and the
   uplink interface.
5. Keep the guard. A role whose rules are a different set still needs a connection check
   and a `rescue` that restores what was there before.
6. Run the harness on the new role. Then break each control in the proof table on the
   copy and see the same step fail: a control is yours only after you have broken it.

## Platform and capability

The scenario uses the same systemd test base as `files_and_units`, pinned by digest, on
Debian 13 (trixie), the release every production host runs. The platform keys are the
same, each with its reason in `molecule.yml`. The scenario adds one capability,
`NET_ADMIN`, the netlink right the nftables loader needs; the reason is a comment above
the key. It does not add `privileged`.

## Proof record

The proof is recorded in the pull request's report, not in this file, so that no count
or result goes stale here.
