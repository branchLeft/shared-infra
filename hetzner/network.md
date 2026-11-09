# network

The estate's default route, in `hetzner/network.ts`.

The estate's default route, and the whole reason a host with no public
interface can reach the internet at all.

A private-only host's only route off the subnet is the network's own
gateway, and Hetzner resolves that against this table. Without an entry
here such a host cannot run its own provisioning — `apt-get update`, the
Docker signing key — and, more durably, cannot receive the unattended
security upgrades `provision/10-harden-updates-fail2ban.sh` enables. The
gateway is the edge host because it is the only host this estate owns that
already terminates public traffic; `ansible/roles/egress_nat/files/branchleft_nat.py` is what
makes the address at the other end actually forward.

Additive: it neither reads nor writes a property of the network or the
subnet, so neither is replaced by its presence.

Deliberately not `protect: true`, unlike its two siblings above. Deleting
this route detaches nothing and loses no state — it costs the estate its
egress until it is reapplied, which is recoverable, and moving the gateway
to another host has to stay an ordinary apply.

`protect: false` has to be given explicitly, not left absent: a `parent`
option makes Pulumi inherit `protect` from the parent whenever a child
leaves its own unset, and `network` above carries `protect: true`. An
absent value here would silently pick that up instead of the `false` this
resource is meant to have.
