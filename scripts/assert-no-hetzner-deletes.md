# assert-no-hetzner-deletes.py

Fails if a `pulumi preview --json` plan would destroy a Hetzner resource.

It runs as a preflight inside a CI deploy job, against the same stack state
`pulumi up` is about to act on, seconds earlier and with the same credentials.
One script serves all four Hetzner stacks (`branchleft-mail`,
`branchleft-hetzner-network`, `branchleft-hetzner-estate`,
`branchleft-hetzner-dns`) because they share one provider and one failure
mode. The GCP edge stack had its own equivalent guard,
`assert-no-edge-deletes.py`, removed with that program in the GCP wind-down
(branchLeft/workspace#1000).

## Usage

    assert-no-hetzner-deletes.py <preview-json-file>
    assert-no-hetzner-deletes.py --self-test
    assert-no-hetzner-deletes.py --verify-coverage <program-dir>

Exit status 0 if clean, 1 if a protected resource would be destroyed (or if
any input could not be read or understood), 2 on usage error.

## What is protected

Protection is by resource type, not by logical id. Every stack this guard
fronts declares a handful of resources whose loss is an outage (mx1, its
firewall, the network, its subnet, edge1, the DNS zone), and hcloud resource
names carry no tenant identity that would force a name list. Every instance of
a protected type is covered, including the children a component like
`@branchleft/hetzner-host`'s `Host` creates under its own URN parent chain,
which a name list would miss, because the component derives its children's
names.

Two types are deliberately unprotected:

- `hcloud:index/networkRoute:NetworkRoute`. network.ts gives the egress route
  `protect: false` on purpose, because deleting it detaches nothing, loses no
  state, and moving the gateway to another host has to stay an ordinary apply.
- `hcloud:index/zoneRrset:ZoneRrset`, for the same reason: only the zone itself
  is protected. Deleting or replacing the zone takes the website, the edge and
  mail down together, but removing one record must stay an ordinary apply.

## What this cannot prove

Both limits are real.

1. `pulumi preview` compares the program to Pulumi _state_, never to live
   Hetzner. A resource already deleted out of band still reads as unchanged.
   This gate answers "will this apply destroy something", not "is the estate
   intact".

2. A resource that migrates out of a program dir (say mail's server moving
   behind the `Host` component) leaves the plan check intact but makes the
   coverage map here stale. `--verify-coverage` fails until the map is updated
   consciously, so the move is a reviewed edit rather than a silent erosion.
