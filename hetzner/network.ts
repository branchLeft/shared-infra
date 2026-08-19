import { HOST_IPS, NETWORK_CIDR, SUBNET_CIDR } from '@branchleft/hetzner-host';
import * as hcloud from '@pulumi/hcloud';

import { internetEgressRoute } from './egress';

/**
 * The private network every platform host attaches to.
 *
 * Two properties of Hetzner networking make this resource unusually
 * load-bearing, and both are the reason for `protect: true`:
 *
 * - A network cannot be moved or resized in place, so a change to `ipRange`
 *   is a replacement, and replacing it detaches every attached server in one
 *   operation.
 * - Networks do not span hcloud projects. Anything that needs to reach a
 *   host over private addressing must live in the same project as this
 *   network, which makes the project boundary and the network boundary the
 *   same boundary.
 */
export const network = new hcloud.Network(
  'platform',
  {
    name: 'platform',
    ipRange: NETWORK_CIDR,
    // Route announcement to a Robot vSwitch. Off because this programme has
    // no dedicated-server side and therefore no vSwitch to announce to.
    exposeRoutesToVswitch: false,
    // API-level, independent of Pulumi's own `protect`. The two guard
    // different actors: `protect` stops this program, `deleteProtection`
    // stops a console click and any other token holder in the project.
    deleteProtection: true,
    labels: {
      env: 'production',
      'managed-by': 'pulumi',
    },
  },
  { protect: true }
);

/**
 * Subnets are scoped to a network zone, not a location, so every host in
 * `eu-central` can share this one regardless of which of the zone's
 * locations it ends up in. That is what makes the location choice a capacity
 * decision rather than a topology decision.
 */
export const subnet = new hcloud.NetworkSubnet(
  'platform-eu-central',
  {
    networkId: network.id.apply((id) => Number(id)),
    type: 'cloud',
    networkZone: 'eu-central',
    ipRange: SUBNET_CIDR,
  },
  { protect: true, parent: network }
);

/**
 * The estate's default route, and the whole reason a host with no public
 * interface can reach the internet at all.
 *
 * A private-only host's only route off the subnet is the network's own
 * gateway, and Hetzner resolves that against this table. Without an entry
 * here such a host cannot run its own provisioning — `apt-get update`, the
 * Docker signing key — and, more durably, cannot receive the unattended
 * security upgrades `provision/10-harden-updates-fail2ban.sh` enables. The
 * gateway is the edge host because it is the only host this estate owns that
 * already terminates public traffic; `provision/branchleft_nat.sh` is what
 * makes the address at the other end actually forward.
 *
 * Additive: it neither reads nor writes a property of the network or the
 * subnet, so neither is replaced by its presence.
 *
 * Deliberately not `protect: true`, unlike its two siblings above. Deleting
 * this route detaches nothing and loses no state — it costs the estate its
 * egress until it is reapplied, which is recoverable, and moving the gateway
 * to another host has to stay an ordinary apply.
 */
export const egressRoute = new hcloud.NetworkRoute(
  'platform-internet-egress',
  {
    networkId: network.id.apply((id) => Number(id)),
    ...internetEgressRoute(HOST_IPS.edge1),
  },
  {
    parent: network,
    // Hetzner serialises actions against a network and rejects a second one
    // while the first holds it. Pulumi sees the subnet and this route as
    // independent children of the network and would otherwise issue both at
    // once on a first apply.
    dependsOn: [subnet],
  }
);
