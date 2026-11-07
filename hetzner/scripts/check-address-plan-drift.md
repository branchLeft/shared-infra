# check-address-plan-drift

Narrative for `check-address-plan-drift.py`; the script's docstring points here.

`hetzner-host/addressPlan.ts` is the one place `NETWORK_CIDR`, `SUBNET_CIDR`
and `HOST_IPS`/`APP_HOST_IPS` are decided. `hetzner/network.ts` and
`hetzner/egress.ts` import that module, so Pulumi always sees a plan change.
The NAT gateway script, the DOCKER-USER isolation-policy script, edge1's
playbook (where the edge_firewall role is given the subnet it masquerades) and
the provisioning runbook cannot: the scripts run on a host with no repository
checkout to import from, the playbook is YAML Ansible reads, and the runbook is
prose a human reads, not code anything executes. All of them therefore carry a
copy of the plan's subnet and/or a host address as a literal, and nothing stops
those literals drifting from the module that is supposed to be their source.

**A drifted literal presents as success.** The NAT script's own
`only a /24 subnet is understood` guard validates its own literal against
itself, so it stays green after the literal goes stale -- it was never
checking the literal against the plan. The runbook's verification block greps
for the masquerade rule it expects and finds it, correct for the subnet it
still names. The playbook's `edge_firewall_nat_source` is the worst of the
three: the role loads a masquerade for exactly that subnet, every check of the
role passes, and the private hosts of the plan's real subnet have no outbound
internet. Either way the host that is actually misconfigured is the one
outside the plan's current range, and every check available reports it
healthy.

This gate reads the plan's current values and asserts every subnet-shaped,
edge1-shaped and db1-shaped literal in the shell scripts and the runbook
still matches them -- every occurrence, not the first one found, because a
file edited in one place and left stale in another is the half-updated state
the gate exists to catch.

Two things a naive text match over these files would get wrong, both handled
below:

- **Not every address-shaped string in these files is a copy of the value
  being checked.** The runbook mentions the internet default route
  (`0.0.0.0/0`), and could reasonably mention Docker's own bridge default
  (`172.17.0.0/16`) or another host's address in prose without either being a
  stale copy of anything. A literal only counts as a disagreement if it falls
  inside the plan's `NETWORK_CIDR` _and_ matches none of the plan's current
  values -- outside the estate's own range it isn't an estate address at all,
  and inside it, it may simply be some other host's real, current address.
- **The runbook's nftables check writes the subnet with escaped dots**
  (`10\\.20\\.1\\.0/24`, a regular expression), which no address-shaped
  pattern matches. The subnet check unescapes them first, so a stale value in
  that one grep is read like any other.
- **A value that only appears in a comment is not the live export.** This
  module's house style narrates reasoning at length, including earlier
  decisions, so a stale value sitting in prose ahead of the real `export
const` is a realistic accident. Comments are stripped before any of the
  regexes below run.
