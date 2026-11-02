# edge_firewall

This role gives the estate's one gateway host an input firewall of its own and the
masquerade that lets the hosts behind it reach the internet. It does that with two
nftables tables that belong to the role alone, loaded by a boot unit that belongs to the
role alone, behind a guard that puts the previous rules back if the host stops answering
on its control port. It is the first consumer of the `firewall_nat_sysctl` pattern
(`ansible/patterns/firewall_nat_sysctl`), copied from it as that pattern's README tells a
consumer to, and changed where a host that runs Docker needs it to be.

This README is written for a maintainer who is new to the repository. It follows the
order the standard sets for a role README (ANS-14), with the design's reasons after the
interface, because a firewall role is only safe to change if its reasons are known.

## What the role does, and what it does not

It does these things, in this order:

1. Masks `nftables.service`, and has systemd read the mask, before anything installs the
   `nftables` package.
2. Installs the `nftables` package.
3. Persists `net.ipv4.ip_forward = 1` in a sysctl drop-in, sets it on the running kernel,
   and refuses to go on unless the kernel reads `1`.
4. Reads the uplink (the interface the default route leaves through) and the host's own
   address in the estate subnet, and refuses, before loading anything, a host whose
   uplink holds no public address or that holds no address in the subnet.
5. Renders one rules file with two tables: `inet branchleft_edge` (an input filter) and
   `ip branchleft_edge_nat` (the masquerade for the estate subnet out of the uplink),
   compares it with the host, and, when the host differs, loads it and then connects to
   the host's own private address on the control port. If that connection fails, the
   previous rules come back and the role fails. If it succeeds, the rules become the
   file the boot unit loads.
6. Removes the old `iptables` masquerade rule, once the role's own table is confirmed.
7. Enables `branchleft-firewall.service`, the boot unit that loads the confirmed file.

It does not:

- **flush the ruleset, or start, stop or restart `nftables.service`.** That unit's stop
  command is `nft flush ruleset`, which removes every table on the host, Docker's
  included, and a package upgrade restarts it on its own. See "Why `nftables.service`
  is masked".
- **have a forward chain or an output chain.** Docker's `FORWARD` policy and its
  `DOCKER-USER` chain stay in charge of forwarded traffic. A rule in an nftables forward
  chain cannot rescue a packet that Docker's `iptables` policy drops, and a rule that
  accepts would shadow Docker's. The forwarding accepts for the estate subnet are
  `DOCKER-USER` rules, installed by the `egress_nat` role's reconciler.
- **write `/etc/nftables.conf`.** The distribution's boot rules file is left as it is.
- **choose the gateway host, the estate subnet or the moment to enforce.** The play does,
  and the owner-only checks pin all three to edge1 (see "How it is delivered").
- **apply itself to a host.**

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables and
[`defaults/main.yml`](defaults/main.yml) holds the defaults. None of them is a secret and
the role handles no secret.

| Variable                   | Default | Meaning                                                                                                                                                    |
| -------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `edge_firewall_nat_source` | none    | The estate subnet whose traffic leaving through the uplink is masqueraded, as a dotted `/24`. Required, and refused unless it is a plain value.            |
| `edge_firewall_enforce`    | `false` | `false` is monitor mode: the input policy is `accept` and the rules that would refuse a packet log it. `true` is enforce mode: the input policy is `drop`. |

`vars/main.yml` holds the constants: the two table names, the rules directory, the
sysctl drop-in, the boot unit's name and path, the control port, the public ports, the
Docker-bridge ports, the log prefix and the patterns the string inputs must match. They
are not inputs; a caller cannot set them from a play. The Molecule scenario overrides one
of them, `edge_firewall_rules_template`, through an include parameter, to hand the guard
a bad rules file of its own. No play sets it.

The role leaves facts after a run, which a caller or a test reads:

| Fact                             | Meaning                                                                            |
| -------------------------------- | ---------------------------------------------------------------------------------- |
| `edge_firewall_drift`            | A list of the ways the host differed from the desired rules; empty when it did not |
| `edge_firewall_reloaded`         | True when this run loaded the ruleset and the guard confirmed it                   |
| `edge_firewall_rolled_back`      | True when the guard put the previous rules back (or removed the tables)            |
| `edge_firewall_failed_task`      | The name of the task that failed inside the guard                                  |
| `edge_firewall_rejected_listing` | The kernel's listing of the tables at the moment the connection check failed       |

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- The `ansible.posix` collection, for the `sysctl` module. The harness installs the
  pinned collections before it starts Molecule.
- Target: Debian 13 (the release every host runs and the test runs on) with systemd,
  `iproute2` and Python 3. The role runs as root.
- `iptables` and Docker on the host, for the removal of the old masquerade rule. A host
  with neither has no such rule, and the removal task reads that and does nothing.
- The host must hold a public address on the interface of its default route, and an
  address in the estate subnet. The role refuses before it loads anything when it does
  not.
- Network access to the distribution's package archive when `nftables` is not installed.

## What it changes on a host

Every file is `root:root`.

- A link at `/etc/systemd/system/nftables.service` to `/dev/null`: the mask.
- The `nftables` package.
- `/etc/sysctl.d/99-branchleft-nat.conf` with `net.ipv4.ip_forward = 1`, and the running
  value `1`. This file has one writer: this role.
- `/etc/branchleft-firewall/` (mode `0700`) with `active.nft` (the confirmed rules),
  `previous.nft` (the rules the guard restores) and `active.list` (the kernel's own
  listing of the confirmed tables, which the next run compares with the kernel to find
  drift). All three are mode `0600`.
- `/etc/systemd/system/branchleft-firewall.service`, enabled and not started by the
  role, and one `daemon-reload` when a unit or the mask changed.
- The two tables in the kernel: `inet branchleft_edge` and `ip branchleft_edge_nat`.
- The removal of the one `iptables` rule that masqueraded the estate subnet out of the
  uplink, if it is there.

Nothing else is read, changed or flushed. In particular the role reads no table it does
not own, and the tables of `iptables-nft` (Docker's, `fail2ban`'s if it uses `nftables`)
are untouched.

### The input chain, in order

The rules are in [`templates/rules.nft.j2`](templates/rules.nft.j2). In enforce mode the
chain is `policy drop` and starts with a drop of invalid conntrack states; in monitor
mode it is `policy accept` and the invalid states are counted and logged. After that,
in both modes:

1. `ct state established,related accept`.
2. Loopback by address: `iif "lo"` with `127.0.0.0/8` (and `::1`) as both source and
   destination. It is not a blanket accept of the interface, because the guard's
   connection arrives on `lo` too (see "The revert guard").
3. ICMP echo, destination-unreachable, time-exceeded and parameter-problem; ICMPv6 with
   neighbour discovery, packet-too-big and echo.
4. DHCP renewals (`udp sport 67 dport 68`, and the DHCPv6 pair).
5. `tcp dport 22 accept`, from any source, as the Hetzner firewall opens it: deploys run
   from GitHub-hosted runners.
6. `tcp dport { 80, 443 } accept`, the public ports.
7. The four ports Docker publishes on the host's private address, accepted from the
   Docker bridges (`br-*`, `docker0`) and from the host itself.
8. Rate-limited `log prefix "branchleft-fw would-drop: "` rules, the last of which every
   remaining packet reaches. In enforce mode the policy then drops it. In monitor mode
   the policy accepts it, and the log line is the record of what enforce mode would have
   dropped.

### Every flow, and where it is cited

The table is the enumeration the design rests on. Each row is a flow edge1 needs and the
rule that carries it. The port rows are held to the repository by
`ansible/checks/test_edge_firewall_flows_agree.py`.

| Flow                                                                                                                   | Hook                                                                         | Rule                                                         | Cited in                                                             |
| ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------- |
| SSH from CI (apply, check, drift, deploy, jump) and from the owner                                                     | input                                                                        | `tcp dport 22`, any source                                   | `hetzner-host/firewalls.ts`; `ansible-delivery.yml`                  |
| Everything the host opens itself: package archive, ACME, the pull from GitHub, registry pulls, scrapes, mail probes    | input (replies)                                                              | `established,related`                                        | `hetzner/monitoring/render.ts`; the Prometheus scrape configuration  |
| ICMP and path MTU discovery                                                                                            | input                                                                        | the ICMP rules                                               | `hetzner-host/firewalls.ts`                                          |
| DHCP renewals, IPv6 neighbour discovery                                                                                | input                                                                        | rules 3 and 4                                                | the pattern README's lock-out hazards                                |
| Loopback listeners: the edge probe, Prometheus, Alertmanager (the owner's tunnels and the runbooks' probes)            | input, `lo`                                                                  | the `127.0.0.0/8` rule                                       | the two Compose files                                                |
| The pager behind Caddy, Grafana, CrowdSec metrics, Caddy metrics, reached by Prometheus, Caddy and the owner's tunnels | forward via Docker DNAT; input from a bridge if a hairpin lands on the proxy | `iifname br-*` / `docker0` / `lo` to the four ports          | the two Compose files; the Caddyfile; `hetzner/monitoring/render.ts` |
| Public 80 and 443 (the ACME challenge and every site)                                                                  | forward via Docker DNAT                                                      | `tcp dport { 80, 443 }`, as well                             | `EDGE_RULES` in `hetzner-host/firewalls.ts`; the edge Compose file   |
| The private hosts' egress through this host                                                                            | forward and postrouting                                                      | the NAT table, and the `DOCKER-USER` accepts of `egress_nat` | `hetzner/network.ts`; `hetzner/provision/branchleft_nat.sh`          |
| Caddy's upstreams on the app hosts, the ops host                                                                       | output and forward                                                           | none                                                         | `hetzner/edge/render.ts`                                             |

The reading that Docker-published ports are forwarded and never reach the input chain is
a theory until a live host is observed. That is why enforce mode is not the first stage:
see "How it is delivered".

### Monitor mode and enforce mode

Monitor mode (`edge_firewall_enforce: false`, the default) loads exactly the same rules
with the input policy `accept`, so nothing is refused, and each rule that would refuse a
packet in enforce mode counts and logs it. The owner reads the kernel log for
`branchleft-fw would-drop:` after a soak. Enforce mode is one line changed in two files,
both owner-only, followed by its own gated run.

### Why `nftables.service` is masked

Starting the unit loads `/etc/nftables.conf` after `flush ruleset`, and stopping or
restarting it runs `flush ruleset`. On a host that runs Docker, Docker's tables are in the
same netfilter and a flush removes them: the published ports and the estate's forwarding
stop until Docker is restarted. A package upgrade restarts the unit on its own. So:

- The role masks it, by writing the link to `/dev/null` itself, which works before the
  package (and so the unit) exists, and has systemd read the mask **before** the package
  is installed, because the package's own scripts can start the unit.
- The role loads its tables with its own unit, `branchleft-firewall.service`, which has
  no stop command: stopping or restarting it flushes nothing. The file it loads adds,
  deletes and defines only the role's two tables, in one atomic transaction.
- The role refuses to go on unless the mask reads `masked`.

A person who unmasks the unit re-opens the hazard. That is a named limit below.

### The revert guard

Before the guard the role keeps the confirmed file as `previous.nft`. The guard then:

1. loads the new rules (one `nft -f` transaction);
2. connects to the host's **own private address** on the control port;
3. on success, writes the new rules as `active.nft`, records the kernel's listing of the
   tables, and carries on;
4. on failure, loads `previous.nft`, or, when there was no earlier set (a first install),
   deletes the role's two tables, and then fails the role with the name of the task that
   failed.

The connection is to the host's own private address and not to `127.0.0.1` on purpose.
A packet to the host's own address enters the input chain on the loopback interface with
a source and destination that are not in `127.0.0.0/8`, so it matches the real
`tcp dport 22` rule and not the loopback rule. A set that closes the control port but
keeps loopback open is caught by this check; one that connected over `127.0.0.1` would
pass it.

The old `iptables` masquerade rule is removed after the guard, never before, so the
estate has a masquerade at every moment: a failed load ends the role in the rescue and
never reaches the removal.

If the restore itself fails, the host is left with the new rules loaded and the role
failed at "Restore the previous ruleset". In enforce mode that is closed to everything
the new rules close; the Hetzner firewall still stands in front of the public interface.

## How to run its test

From the repository root, with the tools installed as `ansible/README.md` describes
(Docker running locally, Python 3.12 or later):

```text
python3 -m venv .venv
# Install the lock with the one recipe: ansible/README.md, "Install, and install with no network".
.venv/bin/python ansible/harness/run_harness.py ansible/roles/edge_firewall
```

The harness lints the role and runs the scenario in `molecule/default/` on one systemd
container (the reasons for each platform key are in `molecule.yml`). The scenario needs
the capability to load nftables rules and nothing more. It removes its container when it
finishes and never touches a host.

The unit tests need no container. They read the role's files, render the template and
check the contracts that must not change by accident:

```text
cd ansible
.venv/bin/python -m unittest discover -b -s roles/edge_firewall/tests/unit -p "test_*.py"
.venv/bin/python -m unittest discover -b -s checks -p "test_edge_firewall_*.py"
```

What each part of the scenario does:

- `prepare.yml` gives the container the addresses the role reads (a public documentation
  address on the uplink and an address in the estate subnet), a stateful stand-in for the
  `sysctl` command (a container's `/proc/sys` is read-only), placeholder listeners on
  every port the plan keeps open, and Docker stand-ins built with `iptables-nft`: a
  `DOCKER-USER` chain, a `DNAT` rule, the `FORWARD` policy `DROP`, an old masquerade rule
  and marker rules.
- `converge.yml`, on the first converge, tries what the role must refuse or roll back,
  then applies the good set. In order: NAT sources that are not plain subnets (a newline
  then a second rule, a trailing newline, a second token); a host whose uplink holds no
  public address; a host with no address in the subnet; a set that closes the control
  port but keeps loopback open, on a host with no previous set; monitor mode; the good
  set in enforce mode; the same bad set over a previous set; and the same bad set with an
  unloadable previous set (the restore fails). Each attempt is judged on facts the run
  leaves (the failing task, the tables before and after, whether Docker's stand-ins and
  the old masquerade rule are untouched), not on the bare fact that the role failed.
- `idempotence`: a second converge reports zero changed tasks.
- `verify.yml` checks, by content: the sysctl drop-in and the running value; the mask;
  that `/etc/nftables.conf` was left alone; the owner and mode of every file; that the
  boot unit is enabled and has no stop command; that the loaded tables are the recorded
  set; the input chain in order, with the control-port accept unrestricted and no drop
  before it but the allowed one; that neither table has a forward or output chain; one
  masquerade, scoped to the subnet and the real uplink; that Docker's stand-ins are
  intact and the old masquerade rule is gone; the runbook's gateway check, run as written
  against the kernel's own text; a connection to every port the plan keeps open, and the
  refusal of a closed one on the private address while the same port on loopback is open;
  that a restart of the boot unit, an attempted start and restart of `nftables.service`
  (refused: masked), and a reinstall of the package leave Docker's rules and the role's
  tables as they were; that the boot unit restores the tables after they are deleted; and
  that check mode reports a damaged kernel and loads nothing, a real run repairs it, and
  a repaired host reports nothing to do.
- `check-fresh`, `check-configured` and `molecule-check`: the role runs under
  `--check --diff` before the first apply and against the configured instance, and shows
  no drift on the latter.

### What breaks which step

Each row is an edit made with the editor, one run, and a restore. The run is the
retrieval: make the row's edit and run the command shown to see the message.

| Control                                                 | The edit                                                                          | The step that fails                                                                                                                                                                      |
| ------------------------------------------------------- | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The guard rolls back a set that closes the control port | in `tasks/main.yml`, delete the `rescue:` of the guard                            | harness `converge`: the "bad set" attempts; unit test `test_the_guard_has_a_rescue_that_restores_and_fails`                                                                              |
| The guard checks the path that matters                  | in the connection check, change `host:` to `127.0.0.1`                            | harness `converge`: the "bad set" attempts (the set keeps loopback open); unit test `test_the_connection_check_targets_the_hosts_own_private_address_not_loopback`                       |
| Never flush, never restart `nftables.service`           | add `flush ruleset` to the template, or a task that restarts `nftables.service`   | unit tests `test_no_shipped_file_contains_a_flush` and `test_no_task_starts_stops_restarts_or_reloads_nftables_service`                                                                  |
| Docker's chains survive                                 | delete the "Mask nftables.service" task                                           | harness `verify`: the assertion that `nftables.service` is masked, and the stand-in chains after the restart                                                                             |
| The mask comes before the install                       | move "Install the nftables package" above the mask                                | harness `converge` (Docker's stand-ins differ after the package install); unit test `test_the_mask_comes_before_the_install_with_a_reload_between`                                       |
| The legacy masquerade goes only after the guard         | move "Remove the legacy iptables masquerade rule" above the guard                 | unit test `test_the_removal_follows_the_guard`; harness `converge` (the legacy rule must still be there after every failed attempt)                                                      |
| One masquerade, scoped, on the derived uplink           | drop `ip saddr` from the NAT rule, or write a literal interface name              | harness `verify`: the masquerade assertion; unit tests `test_one_masquerade_scoped_to_the_estate_source_and_the_derived_uplink` and `test_the_uplink_is_never_a_literal_in_the_template` |
| Forwarding is on                                        | delete "Persist IPv4 forwarding"                                                  | harness `verify`: the running value reads `0`                                                                                                                                            |
| Monitor mode accepts, enforce mode drops                | invert the `if` on `edge_firewall_enforce` in the template                        | harness `converge` (monitor phase) and `verify` (policy); unit test `test_enforce_mode_drops_by_policy_and_monitor_mode_accepts`                                                         |
| Every published port has a rule                         | delete 2586 from `edge_firewall_bridge_tcp_ports`, or publish a port with no rule | `ansible/checks/test_edge_firewall_flows_agree.py`                                                                                                                                       |
| Inputs are plain values                                 | change `edge_firewall_source_pattern` to end in `$` instead of `\Z`               | harness `converge`: the "trailing newline" attempt; unit test `test_the_source_pattern_refuses_a_trailing_newline_and_a_second_token`                                                    |
| The role's variables are edge1's alone                  | remove a key from `HOST_PLAY_VARS["edge1"]`, or set one in another playbook       | `ansible/checks/test_edge_firewall_single_home.py`, `test_check_enrolment.py`                                                                                                            |

### Named limits

- **No traffic is shown crossing the gateway.** The scenario proves which rules are
  loaded and which ports answer, not that a packet from the private subnet reaches the
  internet through the masquerade. The first live apply and the estate's own egress
  check are that proof.
- **Docker's DNAT is stood in for, not run.** The scenario has no Docker; it has
  `iptables-nft` chains in the shape Docker makes. That Docker-published ports reach
  their containers by forwarding, and never by the input chain, is confirmed only by the
  owner's reads on the live host, and monitor mode exists so that a flow this reading
  missed shows as a log line and not as an outage.
- **A person can unmask `nftables.service`.** `verify` asserts the mask, and a second
  apply writes it again, but the role cannot stop a person running `systemctl unmask`
  and then a restart between two applies.
- **A boot-time load failure leaves the host unfiltered.** If the file the boot unit
  loads fails to load, the unit fails visibly and the host runs without the role's
  tables until it is fixed. The Hetzner firewall still stands in front of the public
  interface.
- **The restore can fail.** The scenario shows the host fails closed (the bad set stays
  loaded and the role fails at the restore); it cannot make a restore succeed from a
  corrupted file.
- **Drift is found at the next apply.** A table deleted while the host stays up is found
  by the next run's comparison of the kernel with the recorded listing, and repaired
  then; nothing watches between applies.
- **Counters and logs depend on the kernel.** The scenario asserts that monitor mode
  counts a packet to a closed port; it does not assert the text the kernel logs,
  because a container does not own the kernel log.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after the
approval of its protected environment. A plan job shows the host's diff in check mode
first; after the approval the host pulls that exact commit of `main` and applies it, and
a second run must report zero changes. Nothing is applied from a laptop. The role is
wired into `ansible/playbooks/edge1.yml`, after `host_baseline` (Docker and `iptables`
come from there) and before `egress_nat` (whose reconciler refuses to run unless this
role's table is loaded and forwarding is on), and nowhere else. The two variables are set
in the play vars, not in an inventory (the inventory trees load no group variables), and
the enrolment checker pins both to edge1 in `HOST_PLAY_VARS` (R2), so the role entry stays
bare and no other host can carry them. That file is an owner path, so the move from
monitor mode to enforce mode is a change the owner merges and a gated run the owner
approves.

The rollout is in two stages:

- **Stage A** applies everything with `edge_firewall_enforce: false`: the NAT move, the
  mask, the tables and the log lines. The owner reads the journal after a soak. Every
  source and port in it is a flow to open before the next stage.
- **Stage B** is the one-line flip to `true` in `ansible/playbooks/edge1.yml` and
  `ansible/checks/check_enrolment.py`, merged by the owner, with its own gated run and
  its own second run reporting zero changes.

The owner's reads on the host before stage A, and after it, are the runbook's and the
issue's, not this README's.

## How to change it safely

1. To open a port, add it to the right list in `vars/main.yml` and make the Compose file
   that publishes it say so; the flows test fails until both agree. To close one, take it
   out of both.
2. To change a rule, change `templates/rules.nft.j2` and keep its order: the control-port
   accept must stay before every log rule and every drop but the invalid-state drop, and
   loopback must stay an accept by address.
3. Never add a `flush`, a forward chain or an output chain, and never start, stop or
   restart `nftables.service`. The unit tests fail if you do.
4. Keep every task able to run under `--check --diff`, and keep the guard skipped in check
   mode (ANS-10).
5. Run the test commands above before opening a pull request, then break the control you
   touched (the table above) and see the same step fail: a control is yours only after
   you have broken it.
