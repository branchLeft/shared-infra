import { NETWORK_CIDR, SUBNET_CIDR } from '@branchleft/hetzner-host';
import * as hcloud from '@pulumi/hcloud';

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
