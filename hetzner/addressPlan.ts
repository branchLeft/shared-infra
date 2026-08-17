/**
 * Static private addressing for the Hetzner estate.
 *
 * Hetzner's DHCP hands out addresses from the low end of the subnet in
 * allocation order, so an address assigned that way changes if a host is
 * ever rebuilt. Firewall rules, Caddy upstreams, MySQL grants and Prometheus
 * scrape targets all name peers by address, so every host declares its own
 * fixed IP here instead and nothing derives one at runtime.
 */

/** The whole network. Deliberately outside 10.0.0.0/24 and 172.17.0.0/16 —
 * the first is the default a hand-created Hetzner network gets, and the
 * second is Docker's default bridge, which would blackhole private-network
 * peers from inside a container. */
export const NETWORK_CIDR = '10.20.0.0/16';

/** One subnet for the whole estate. Hetzner subnets are per network zone,
 * not per location, so a second one buys nothing until the estate spans
 * zones — at which point private networking stops working between them
 * anyway and the split is a different design, not a bigger subnet. */
export const SUBNET_CIDR = '10.20.1.0/24';

// Hetzner assigns the subnet's gateway itself; it is read from
// `subnet.gateway` rather than restated here, and the ranges below start
// clear of the bottom of the range.
export const HOST_IPS = {
  edge1: '10.20.1.10',
  db1: '10.20.1.20',
  mon1: '10.20.1.30',
  mx1: '10.20.1.40',
} as const;

/**
 * App hosts occupy .100 upwards, listed rather than computed: an address that
 * a scale-out step derives is an address nobody can grep for when a firewall
 * rule or a scrape target stops matching. Adding a host to the estate is an
 * entry here first, then a stack that claims it.
 */
export const APP_HOST_IPS = {
  app1: '10.20.1.100',
  app2: '10.20.1.101',
  app3: '10.20.1.102',
} as const;

/**
 * The locations in Hetzner's `eu-central` network zone, which is the zone
 * `SUBNET_CIDR` is scoped to. A server outside the zone cannot attach to the
 * subnet, and the provider reports that at apply time rather than in the
 * preview. `HostArgs.location` is typed as this, so it is a compile error
 * instead — the narrowing only bites because nothing widens it back to
 * `string` on the way through.
 */
export type EuCentralLocation = 'fsn1' | 'nbg1' | 'hel1';

/**
 * Where the platform estate is placed, which is narrower than the zone.
 * `fsn1` is in `eu-central` and reaches the subnet, but no host in this estate
 * has been sanctioned there — the placement decision is `nbg1`, with `hel1`
 * named as the substitute. A lab host is free to use the wider type.
 */
export type EstateLocation = 'nbg1' | 'hel1';

/**
 * The one location every host in the estate is created in.
 *
 * Here rather than in any stack's configuration because the estate is built by
 * more than one stack, in more than one repository, and `location` is
 * create-time-only on `hcloud.Server`. A per-stack config value lets the second
 * apply land somewhere the first did not, permanently, with a clean preview —
 * and the app and database hosts are the latency-sensitive pairing, so a split
 * between them is the specific outcome that must not happen. A constant in the
 * module every host stack already imports is the only form of this decision
 * that reaches across a repository boundary.
 *
 * It is still only a shared constant, and it is weaker than one apply in two
 * distinct ways. Nothing prevents a stack passing something else to `Host`.
 * And a stack that has **already applied** does not follow a later edit to
 * this line — its hosts stay where they were created, so changing this value
 * after any host exists silently describes an estate that is already split.
 * Read `estateLocation` from the applied stack's outputs to learn where a host
 * actually is; this constant is the intention, not the fact.
 *
 * Nuremberg, with the mail host, so the bulk-mail hop stays inside the private
 * network. `hel1` is the substitute if `cx23` is out of stock at the moment of
 * an apply. Reach and cost are unaffected — a subnet spans the whole zone, so
 * the mail hop stays intra-network either way. What is given up is that the
 * hop's latency becomes unmeasured, which is the thing the placement rule
 * exists to avoid rather than a loss of the hop itself.
 */
export const ESTATE_LOCATION: EstateLocation = 'nbg1';
