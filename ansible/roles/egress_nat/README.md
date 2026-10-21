# egress_nat

This role installs the two programs that keep a host's route to the internet true:
the private-host egress reconciler, which gives a host with no public address a
default route and a resolver, and the NAT gateway reconciler, which lets the one
gateway host forward and source-NAT the estate's private subnet. It installs each
program to `/usr/local/sbin` with the systemd unit that runs it at every boot, runs
it, and puts the previous files back if the run fails.

This README is written for a maintainer who is new to the repository. It follows the
order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

It does what two shell scripts did, in the same order:

1. `hetzner/provision/05-configure-host-egress.sh`: installs
   `branchleft_host_egress.sh` as `/usr/local/sbin/branchleft-host-egress` and
   `branchleft-host-egress.service` as its unit, makes systemd read the unit, enables
   it and runs it. This is for every host.
2. `hetzner/provision/nat-gateway.sh`: the same for `branchleft_nat.sh` as
   `/usr/local/sbin/branchleft-nat` and `branchleft-nat.service`. This is for the one
   gateway host, and the role does it only when `egress_nat_gateway_enabled` is true.

The two reconcilers themselves (`branchleft_host_egress.sh` and `branchleft_nat.sh`)
are programs that stay as code. The role installs them and rewrites none: they are
the files in `hetzner/provision`, and the copy tasks read them from there in place (below).

It does not:

- install a package. The host egress reconciler needs `resolvconf` and the NAT
  reconciler needs `iptables`; each refuses to run, with a message naming the package,
  when it is missing. The packages come with the host baseline and with Docker.
- choose the gateway host. Setting `egress_nat_gateway_enabled` for the right host,
  and for that host only, is the caller's.
- write a firewall ruleset of its own. The NAT reconciler inserts its three
  `iptables` rules, each once, and the role neither adds nor removes any.
- remove anything. A role that stops being applied to a host leaves its files and
  units in place.
- apply itself to a host (see how it is delivered).

### How it differs from the shell scripts, and why

| Shell scripts                                          | This role                                                                  | Why                                                                                                                                         |
| ------------------------------------------------------ | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmp -s`, then `install -m 0755 -o root -g root`       | `copy` with owner, group, mode and `backup`                                | Same end state. The module reports a change only when content or metadata differs, and `backup` keeps the replaced file for the guard.      |
| `systemctl daemon-reload` when the unit was written    | a handler, flushed before the unit is enabled                              | Same: once, and only when a unit changed.                                                                                                   |
| `systemctl enable`, then `systemctl restart` every run | enable, then restart only when the reconciler or the unit changed          | A restart on every run reports a change on every run (ANS-11). A unit that is not active is still started, which runs the reconciler again. |
| `systemctl status` at the end                          | an assertion that the unit is `active` after the run                       | The same failure, in a message that names the unit.                                                                                         |
| nothing                                                | the revert guard                                                           | The ticket's control: see below. A restart that fails would otherwise leave the host with a reconciler that has just been shown to fail.    |
| two scripts, run by hand                               | one task file called twice, host egress first, the gateway only on request | The two scripts differ in their names. One recipe, written once.                                                                            |

The shell scripts run the reconciler on every run, so a route or a rule lost since
the last run was put back. This role runs it when a file changed and when the unit is
not active, and the unit runs it at every boot. A rule lost while the host stays up
and the unit stays active is not put back by a second apply: that is the drift the
named limits below describe.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares the variables and
[`defaults/main.yml`](defaults/main.yml) holds their defaults. There is one,
`egress_nat_gateway_enabled` (default false). None of the role's variables is a
secret and the role handles no secret.

`vars/main.yml` holds the constants of the two reconcilers (their source files, their
install paths and the unit names). They are not inputs; a caller cannot override them.

The role leaves facts after a failed guard, which a caller or a test reads:

| Fact                     | Meaning                                                              |
| ------------------------ | -------------------------------------------------------------------- |
| `egress_nat_failed_task` | The name of the task that failed inside the guard.                   |
| `egress_nat_failed_unit` | The unit the guard was installing.                                   |
| `egress_nat_reverted`    | True once the guard has put the previous state back (or removed it). |

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collection beyond `ansible.builtin`.
- Target: Debian 13 (the release every host runs and the test runs on) with systemd
  and Python 3. The role runs as root.
- The files come from this repository: the copy tasks read them from
  `hetzner/provision` through `role_path`, so the role must be run from a checkout of the
  whole repository, which is what the gated pull delivers (ANS-17).
- On the host, before the role runs: `resolvconf` (host egress) and `iptables` (NAT).
  On the gateway host, the reconciler also needs the host to hold a public address on
  the interface of its default route and an address in the estate's private subnet; it
  exits with a message when it does not.

## What it changes on a host

Every file is `root:root`. The reconcilers are mode `0755` and the units mode `0644`,
as `install -m 0755 -o root -g root` and `-m 0644` made them.

- `/usr/local/sbin/branchleft-host-egress` and
  `/etc/systemd/system/branchleft-host-egress.service`, enabled, and run at every boot.
- When `egress_nat_gateway_enabled` is true: `/usr/local/sbin/branchleft-nat` and
  `/etc/systemd/system/branchleft-nat.service`, enabled, and run at every boot.
- One `daemon-reload` of the systemd manager, only when a unit file changed.
- One restart of a unit, only when its reconciler or its unit file changed.
- While a replaced file is being swapped, a kept copy of it beside it, ending in `~`.
  It is removed when the run succeeds and after a revert. A run killed in the middle can
  leave one; it is inert and can be deleted.

What the two reconcilers then do to the host is their own work and is described in
their source: the host egress reconciler sets a default route and the resolver file on
a host with no public address and does nothing on any other; the NAT reconciler writes
`/etc/sysctl.d/99-branchleft-nat.conf`, turns forwarding on, and inserts one masquerade
rule and two forwarding rules. The role does not touch those.

### One home for every file

The role holds no copy of the files it delivers. Each copy task's `src` is the same-named
file in `hetzner/provision`, built from `role_path` (`{{ role_path }}/../../../hetzner/provision/`),
so a change to a reconciler or a unit in its own directory is what the next apply delivers,
and the role cannot drift from it. The unit tests fail if the role keeps a `files/` directory
or a copy task reads from anywhere else.

## The revert guard

Each reconciler is installed inside a block with a rescue. Before the block the role
records whether the reconciler and the unit were already on the host. The block installs
both files (keeping the one it replaces), reloads systemd, enables the unit, restarts it
when a file changed, starts it if it is not active, and asserts it is active. If any of
that fails:

- on an **update** the previous reconciler and unit are copied back from their kept
  copies, systemd reloads, and the unit is restarted so the previous reconciler runs
  again. That last step is the one that matters: it puts back the default route or the
  rules the failed version may have changed. The role then fails, naming the task;
- on a **first install** there is nothing to go back to, so the unit is stopped and
  disabled and both files are removed. A unit left enabled would fail again at every
  boot.

Nothing in the block can undo what a reconciler has already done to the kernel, other than
by running the previous reconciler. A rule the failed version inserted that the previous
version does not know stays until someone removes it.

## How to test it

From the repository root, with the tools installed as `ansible/README.md` describes
(Docker running locally, Python 3.12 or later):

```text
python3 -m venv .venv
# Install the lock with the one recipe: ansible/README.md, "Install, and install with no network".
.venv/bin/python ansible/harness/run_harness.py ansible/roles/egress_nat
```

The harness lints the role and runs the scenario in `molecule/default/` on one systemd
container (the same Debian 13 image as the `files_and_units` pattern; the reason for each
platform key is in `molecule.yml`). It adds one capability, `NET_ADMIN`, and not
`privileged`. It removes its container when it finishes and never touches a host.

The unit tests need no container. They read the role's files and check the contracts that
must not change by accident:

```text
cd ansible
.venv/bin/python -m unittest discover -b -s roles/egress_nat/tests/unit -p "test_*.py"
```

What each part of the scenario does:

- `prepare.yml` installs `iptables` and `iproute2`, a stand-in for the `sysctl` command
  (a container's `/proc/sys` is read-only, so the real one fails), and gives the container
  the addresses the two reconcilers look for: a public documentation address on the
  loopback interface (which makes the host egress reconciler take its no-op branch), and,
  on the interface of the default route, a public documentation address and an address in
  the estate's private subnet (which the NAT reconciler needs).
- `converge.yml`, on the first converge, applies the role four times before the real apply:
  with the gateway switch off (only the host half may be installed); with the uplink's
  public address taken off, on a host with no NAT reconciler (the restart must fail and the
  guard must remove what it installed); with the address back (a good install); and with
  an earlier release of the reconciler and unit in place and the address taken off again
  (the restart must fail and the guard must put the earlier release back, byte for byte,
  and run it again). It then applies the role for real. The attempts are skipped once the
  NAT reconciler is installed, so the second converge changes nothing.
- `idempotence`: a second converge reports zero changed tasks.
- `verify.yml`: each of the four files is on the host owned by root with its mode and is
  byte for byte its source in `hetzner/provision`, read directly and not through the role's
  links; no kept copy is left; both units are enabled and active with a successful last run;
  the host egress reconciler reported its no-op branch; and the NAT reconciler left exactly
  one masquerade rule and one rule of each forwarding direction, its sysctl drop-in, and a
  call to turn forwarding on.
- `check-fresh`, `check-configured` and `molecule-check`: the role runs under
  `--check --diff` before the first apply and against the configured instance and shows no
  drift.

### What breaks which step

Each row is an edit made with the editor, one run, and a restore. The run is the retrieval:
make the row's edit and run the command shown to see the message. The unit tests run in
seconds; the scenario run is the harness over the role.

| Control                                                   | The edit                                                                                   | The step that fails                                                        |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| Masquerade is limited to the estate's subnet as source    | in `hetzner/provision/branchleft_nat.sh`, drop `-s "$SUBNET"` from the `MASQUERADE` rule   | harness `verify`: `egress_nat_verify_masquerade \| length == 1`            |
| Forwarding stays one-way (return traffic only when known) | in the same file, drop `-m conntrack --ctstate ESTABLISHED,RELATED` from the return rule   | harness `verify`: `egress_nat_verify_forward_in \| length == 1`            |
| A failed update puts the previous reconciler back         | in `tasks/_reconciler.yml`, make the task "Put the previous reconciler back" `when: false` | harness `converge`: the reconciler's checksum equals the earlier release's |
| Only the gateway host gets the NAT half                   | in `tasks/main.yml`, replace the gateway task's `when` with `when: true`                   | unit test `test_nat_gateway_is_gated_on_the_switch`                        |

The first two edits are to the shell reconciler, not to the role, because the rule
shapes live there and the role delivers it unchanged; the scenario reads the rules the
installed reconciler left, so it fails when the reconciler stops inserting the right ones.

### Named limits

- **No traffic crosses the gateway.** The scenario proves which rules the reconciler
  inserted, not that a packet from the private subnet reaches the internet through them.
  The first live apply, and the estate's own egress check, are that proof.
- **There is no default-drop policy here to break.** Neither reconciler sets a drop
  policy: Docker sets the `FORWARD` policy on a real host, and the scenario container has
  no Docker, so the reconciler takes its `FORWARD` fallback and the `DOCKER-USER` branch is
  not run. The drop policy of `DOCKER-USER` belongs to its own reconciler, outside this role.
- **The private-only branch of the host egress reconciler is not run.** The scenario
  gives the container a public address, so that reconciler takes its no-op branch. The
  branch that sets a route and a resolver is covered by the reconciler's own tests in
  `hetzner/provision`.
- **Drift is not repaired by a second apply.** A rule removed while the host stays up and
  the unit stays active is not put back until a file changes or the host reboots.
- **Not shown to fail:** the `owner` and `group` of each file (the scenario runs as root, so
  omitting them gives the same result), and the sensitivity of the `--check --diff` steps to
  drift.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after the
approval of its protected environment. A plan job shows the host's diff in check mode
first; after the approval the host pulls that exact commit of `main` and applies it, and
a second run must report zero changes. Nothing is applied from a laptop. This role is not
applied to any host yet: the live run waits on the enrolment of the hosts and on the gate.
On the gateway host it is applied with `egress_nat_gateway_enabled` set in that host's
inventory; the inventory trees are still empty, so that variable is set when the host is
enrolled. Until then the manual steps in the provisioning runbook remain the way, and the
runbook section that names `05-configure-host-egress.sh` and `nat-gateway.sh` is pointed at
this role by the pull request that makes the first live apply.

## How to change it safely

1. To change what a reconciler does, change `hetzner/provision/branchleft_host_egress.sh`
   or `hetzner/provision/branchleft_nat.sh`, and its own tests there; the role delivers
   them as they are. To change a unit, change the `.service` file there. The role's unit
   test fails if a unit stops running the reconciler at the path the role installs it to.
2. To change a path or a unit name, change `vars/main.yml`, the unit's `ExecStart`, and the
   paths in `molecule/default/verify.yml` and `converge.yml` together.
3. Keep every task able to run under `--check --diff`, and keep the modes explicit.
4. Keep the restart conditional on a changed file. An unconditional restart reports a change
   on every run and fails the idempotence step. Never weaken that step.
5. Run the test commands above before opening a pull request, then break the control you
   touched (the table above) and see the same step fail: a control is yours only after you
   have broken it.
