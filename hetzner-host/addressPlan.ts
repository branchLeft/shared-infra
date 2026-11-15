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
  // .40 is deliberately skipped — see the note below. ops1 is a
  // shared-infra-owned host like the three above (role 'app', but created by
  // this repository's estate.ts, not by ghost-platform's own app-host stack),
  // so it belongs in this map rather than in APP_HOST_IPS.
  ops1: '10.20.1.50',
} as const;

/**
 * `10.20.1.40` is not listed above and is not free either.
 *
 * It was mx1's reservation, from when the estate and the mail host were
 * expected to share this network. They cannot: mx1 lives in its own hcloud
 * project, networks do not span projects, and the only cross-project path
 * Hetzner offers is a Robot vSwitch this programme has no dedicated-server
 * side for. So the Ghost→shim hop stays on the public internet permanently,
 * and an address here for mx1 would be a number that resolves to nothing
 * while looking exactly like one that resolves to a host.
 *
 * It is left unallocated rather than handed to the next host, so that a
 * firewall rule or scrape target still carrying the old value fails to match
 * anything instead of quietly reaching whatever took the address over.
 */

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
 * The tenants project's hosts. The tenants project has its own network, and a
 * network does not span projects, so it reuses the estate's range
 * (`NETWORK_CIDR`, the owner's ruling 5a of 2 Nov 2026). The two projects therefore
 * share one address space without sharing a network, and nothing but the
 * register below stops one address being given to a host in each. Both sit
 * clear of the estate's own hosts, and `edgeT` is the tenants network's one
 * NAT gateway and public host.
 */
export const TENANTS_HOST_IPS = {
  dbT1: '10.20.1.200',
  appT1: '10.20.1.201',
  edgeT: '10.20.1.210',
} as const;

export type AddressProject = 'org' | 'tenants';

export interface RegisteredAddress {
  project: AddressProject;
  name: string;
  ip: string;
}

const registered = (
  project: AddressProject,
  hosts: Readonly<Record<string, string>>
): RegisteredAddress[] => Object.entries(hosts).map(([name, ip]) => ({ project, name, ip }));

/**
 * Every private address the programme assigns, across both projects, built
 * from the constants above and never retyped. `addressRegister.test.ts`
 * refuses an address that appears twice anywhere in it, because two projects
 * on one range is exactly how two hosts end up claiming one address.
 */
export const ADDRESS_REGISTER: readonly RegisteredAddress[] = [
  ...registered('org', HOST_IPS),
  ...registered('org', APP_HOST_IPS),
  ...registered('tenants', TENANTS_HOST_IPS),
];

/** The addresses held by more than one entry of a register, each with its holders. */
export function duplicateAddresses(register: readonly RegisteredAddress[]): string[] {
  const holders = new Map<string, string[]>();
  for (const { project, name, ip } of register) {
    holders.set(ip, [...(holders.get(ip) ?? []), `${project}/${name}`]);
  }
  return [...holders.entries()]
    .filter(([, names]) => names.length > 1)
    .map(([ip, names]) => `${ip} is used by ${names.join(' and ')}`);
}

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
 * The one location every host in the estate is created in: Nuremberg, with the
 * mail host, so the bulk-mail hop stays inside the private network. `location`
 * is create-time-only, and a stack that has already applied keeps its hosts
 * where they were created, so `estateLocation` in the applied stack's outputs
 * is the fact and this constant is the intention. Why it is a constant, and
 * the substitute location, are in `hetzner-host/README.md`, "Where the estate
 * is placed".
 */
export const ESTATE_LOCATION: EstateLocation = 'nbg1';
