# test_edge_firewall_flows_agree.py: the edge_firewall ports against the publications

The `edge_firewall` role accepts a short list of TCP ports on edge1. This test holds that list to
what the rest of the repository publishes and serves: the Compose files, the Hetzner firewall's
`EDGE_RULES`, the monitoring renderer, and the Caddyfile. A published port with no rule is a flow the
default-drop would shut; a rule with no publication is an opening for nothing. Both fail by name.

The Caddyfile is read from the caddy service's `/etc/caddy` bind mount in
`hetzner/edge/stack/compose.yml`, not from a fixed path. A move of the file therefore cannot leave
the test checking a stale copy: when the mount has no Caddyfile, the test fails by name.

A host listener that no Compose file publishes, such as node_exporter on `10.20.1.10:9100`, is
named by hand in `edge_firewall_native_dropped_tcp_ports` in the role's vars. The test holds that
port to `node_exporter`'s own vars, so the two cannot drift, but a new native listener on edge1 is
found by no machine check: it is a flow to decide by hand.

Sabotage: add 2586 to `edge_firewall_bridge_tcp_ports` with no publication, or publish a port in a
Compose file with no rule, and the named test fails. Restore it and the suite is green.
