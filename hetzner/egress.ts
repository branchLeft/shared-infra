import { NETWORK_CIDR } from '@branchleft/hetzner-host';

/**
 * The network-side half of the estate's outbound internet path.
 *
 * A host created without public networking has no public interface at all, so
 * its default route can only be the private network's own gateway. Hetzner
 * resolves that route against the network's route table, which is empty until
 * something declares a default in it — until then a private-only host reaches
 * nothing beyond the subnet, and that includes the Debian and Docker apt
 * repositories its own provisioning needs and the security updates
 * `unattended-upgrades` fetches for the rest of its life.
 *
 * The route is only half the mechanism. It names a gateway address; the host
 * at that address has to forward and source-NAT the traffic, which is
 * `provision/branchleft_nat.sh`.
 *
 * IPv4 only. Hetzner networks carry no IPv6 range, so there is no v6 default
 * to declare here and a private-only host is v4-only end to end.
 */

/** The default route. Anything more specific is a peering decision, and this
 * estate has no peer. */
export const INTERNET_DESTINATION = '0.0.0.0/0';

/**
 * The gateway Hetzner puts on the *public* interface of every server. The
 * route API rejects it as a route gateway, and it is rejected here first so
 * the failure is a preview failure rather than an apply failure.
 */
const PUBLIC_INTERFACE_GATEWAY = '172.31.1.1';

export interface InternetEgressRoute {
  destination: string;
  gateway: string;
}

/**
 * Strict dotted-quad only. Leading zeros are refused rather than tolerated:
 * `010.20.1.10` is octal to some resolvers and decimal to others, so a value
 * that parses differently in the validator and at the provider is a gateway
 * pointing at a host nobody intended.
 */
function parseIpv4(address: string): number {
  const octets = address.split('.');
  if (octets.length !== 4) {
    throw new Error(`egress gateway "${address}" is not a dotted-quad IPv4 address`);
  }
  return octets.reduce((accumulator, octet) => {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(octet) || Number(octet) > 255) {
      throw new Error(`egress gateway "${address}" is not a dotted-quad IPv4 address`);
    }
    return accumulator * 256 + Number(octet);
  }, 0);
}

/**
 * The prefix is matched before it is converted, not after. `Number` accepts
 * an empty string as `0`, leading whitespace, exponents and hex — so
 * `10.20.0.0/` reads as `/0`, whose mask is zero and whose range check then
 * accepts every address on the internet. A digits-only match is what keeps
 * the strictness this module exists for from having a hole under it.
 */
function parseCidr(cidr: string): { base: number; mask: number } {
  const parts = cidr.split('/');
  if (parts.length !== 2) {
    throw new Error(`"${cidr}" is not an IPv4 CIDR`);
  }
  const [address, prefix] = parts as [string, string];
  const bits = Number(prefix);
  if (!/^(0|[1-9][0-9]?)$/.test(prefix) || bits > 32) {
    throw new Error(`"${cidr}" is not an IPv4 CIDR`);
  }
  // `<<` on 32 bits is signed in JavaScript, and `1 << 32` is `1` rather than
  // `0` — both are avoided by building the mask through division instead.
  const mask = bits === 0 ? 0 : (0xffffffff - (2 ** (32 - bits) - 1)) >>> 0;
  return { base: (parseIpv4(address) & mask) >>> 0, mask };
}

/**
 * Validates a gateway address against the constraints the route API enforces,
 * and returns the route arguments for it.
 *
 * Every rejection here is one the provider would otherwise raise mid-apply.
 * That matters more than usual for this resource: it is created against a
 * `protect: true` network whose other resources are applied approximately
 * never, so an apply that fails partway is an operator holding a wedged
 * update of the one stack nobody wants to be in.
 *
 * `networkCidr` is a parameter with the estate's own range as its default
 * because the whole judgement here is "is this address inside that range" —
 * a range baked into the body would leave the malformed-range case decidable
 * by nothing but an edit to the address plan.
 */
export function internetEgressRoute(
  gateway: string,
  networkCidr: string = NETWORK_CIDR
): InternetEgressRoute {
  const address = parseIpv4(gateway);
  const { base, mask } = parseCidr(networkCidr);

  // Ahead of the range check rather than after it. The estate's range does
  // not contain this address today, so ordering it second would make this
  // branch unreachable — and it exists precisely for a future range that
  // does contain it.
  if (gateway === PUBLIC_INTERFACE_GATEWAY) {
    throw new Error(
      `egress gateway ${gateway} is Hetzner's public-interface gateway and cannot route a network`
    );
  }

  if ((address & mask) >>> 0 !== base) {
    throw new Error(`egress gateway ${gateway} is outside the network range ${networkCidr}`);
  }

  // Hetzner's wording is "the first ip of the network's ip_range", which is
  // ambiguous between the range's own address and the address Hetzner then
  // uses as the network gateway. Both are refused, because no host is ever
  // placed at either and refusing a legal value costs nothing here.
  if (address === base || address === base + 1) {
    throw new Error(
      `egress gateway ${gateway} is reserved: it is the first address of ${networkCidr}`
    );
  }

  return { destination: INTERNET_DESTINATION, gateway };
}
