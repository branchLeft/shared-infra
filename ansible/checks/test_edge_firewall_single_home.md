# test_edge_firewall_single_home.py: one home per host for the masquerade and the sysctl

The estate has two NAT gateways, edge1 and edget. On edge1 the `edge_firewall` role loads the
masquerade in its own nftables table (`ip branchleft_edge_nat`) and owns the forwarding sysctl
drop-in. On edget, and on edge1 whenever that table is not loaded or cannot be read, the NAT
reconciler (`ansible/roles/egress_nat/files/branchleft_nat.py`) inserts the `iptables` masquerade and
writes the drop-in, as it always did. The reconciler decides at every run by reading the table. This
test holds that split:

- only the role's template adds an nftables masquerade, and only the two NAT reconcilers (the role's
  Python program, and the bash program the hand installer still installs) add an `iptables` one;
- in the Python reconciler the masquerade, the drop-in write and the sysctl write each sit in the
  `else` of `if role_owns_nat:`, so they cannot run beside the role's table (read from the syntax
  tree, with a sabotaged copy that shows the scan notices a call outside it);
- the forwarding drop-in is named only by the role and the two reconcilers;
- the role is on edge1's list and in edge1's playbook alone, after `host_baseline` and before
  `egress_nat`, and its two variables are pinned to edge1 by `HOST_PLAY_VARS`
  (`check_enrolment.py`), with enforce off until the owner merges the one-line flip.

`TheSourcePinIsThePlansSubnet` ties edge1's `edge_firewall_nat_source` pin, in `HOST_PLAY_VARS` and
in this file, to the one `SUBNET_CIDR` export in `hetzner-host/addressPlan.ts`, its one home. The
drift gate (`hetzner/scripts/check-address-plan-drift.py`) ties the playbook and the reconciler to
the same plan; this ties the owner-only pins, which the drift gate does not read. The plan must hold
exactly one `SUBNET_CIDR` export: zero or two is a finding, so an empty parse cannot pass.

Sabotage rows, each run on a copy of the tree, red then green on the copy left alone:

- (a) `ansible/playbooks/edge1.yml` with `edge_firewall_nat_source: 10.20.2.0/24`: the drift gate
  fails by name, and `test_edge1s_playbook_carries_exactly_the_pinned_values` fails.
- (b) a second host's playbook with `egress_nat_gateway_enabled: true`: `test_egress_nat_single_gateway.py`
  fails.
- (c) the reconciler's masquerade call moved out of the `else`: `test_the_reconciler_masquerades_only_where_the_roles_table_is_not_the_home` fails.
