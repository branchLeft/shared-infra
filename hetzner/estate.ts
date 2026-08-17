import * as pulumi from '@pulumi/pulumi';

import { ESTATE_LOCATION, HOST_IPS } from './addressPlan';
import { Host } from './host';

/**
 * The hosts this repository owns: the edge, and the monitoring host once it
 * splits off it. The application and database hosts are homed in the Ghost
 * platform repository and are created by a stack there, not by this one.
 *
 * Imports `./host` and `./addressPlan` directly and never `./index`, which
 * constructs the network at module scope — importing it here would put a
 * second network in this stack's state.
 *
 * The program file sits in the package root while its Pulumi project sits in
 * `estate/`, so that both projects share one `node_modules` and therefore one
 * `@pulumi/hcloud` version. A provider version is part of every resource's
 * URN, and these resources attach to a network another project owns.
 */

const config = new pulumi.Config();

/**
 * The network stack's outputs. A DIY (non-Pulumi-Cloud) backend fixes the
 * organisation segment to the literal `organization`.
 *
 * Read rather than configured: a hand-copied network id is a value that can be
 * stale, and `requireOutput` fails the preview if the network stack has not
 * been applied instead of planning an attachment to nothing.
 */
const networkStack = new pulumi.StackReference(
  'organization/branchleft-hetzner-network/production'
);
const networkId = networkStack.requireOutput('networkId').apply(String);

const image = config.require('image');

/** Names of keys already registered in the hcloud project, not key material.
 * `hcloud ssh-key list` is the only place the current names can be read. */
const ownerSshKeyNames = config.requireObject<string[]>('ownerSshKeyNames');

/**
 * The front door, and the only host in this estate that terminates public
 * traffic. Caddy, CrowdSec and the monitoring stack are delivered onto it
 * separately; nothing here installs them.
 */
export const edge1 = new Host({
  name: 'edge1',
  role: 'edge',
  location: ESTATE_LOCATION,
  image,
  ownerSshKeyNames,
  networkId,
  serverType: config.require('edge1ServerType'),
  privateIp: HOST_IPS.edge1,
  deployPublicKey: config.require('edge1DeployPublicKey'),
});

export const edge1PublicIpv4 = edge1.publicIpv4;

/** Restated from the address plan as a stack output so a later stack reads it
 * from state rather than importing this program. */
export const edge1PrivateIp = HOST_IPS.edge1;

/**
 * Read from the created server rather than re-exported from `ESTATE_LOCATION`.
 *
 * The constant is where the estate is *meant* to be; this is where `edge1`
 * actually is, and the two diverge the moment anyone edits the constant after
 * an apply — the host stays where it was created, because `location` is
 * create-time-only. A stack reference in another repository reading this gets
 * the applied fact, so a divergence is detectable there instead of being
 * papered over by both stacks quoting the same line of source.
 */
export const estateLocation = edge1.server.location;
