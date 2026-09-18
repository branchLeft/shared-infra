import { ESTATE_LOCATION, Host, HOST_IPS } from '@branchleft/hetzner-host';
import * as pulumi from '@pulumi/pulumi';

import { verifyEstateProject } from './projectGuard';

/**
 * The hosts this repository owns: the edge, the monitoring host once it
 * splits off it, and `nextcloud1` — a shared, product-agnostic collaboration
 * host (self-hosted Calendly-equivalent booking + video calling), which
 * belongs here rather than in `ghost-platform` precisely because it has
 * nothing to do with the Ghost platform. The Ghost application and database
 * hosts are still homed in the Ghost platform repository and created by a
 * stack there, not by this one — `nextcloud1` is not one of those; it is
 * shared estate infrastructure like `edge1`, just not edge-role.
 *
 * `Host` and the address plan come from `@branchleft/hetzner-host` — the same
 * package `ghost-platform` depends on for its own hosts — never from
 * `./index`, which constructs the network at module scope; importing it here
 * would put a second network in this stack's state.
 *
 * The program file sits in the package root while its Pulumi project sits in
 * `estate/`, so that both projects share one `node_modules`. That resolves
 * one `@pulumi/hcloud` version for `network.ts`'s own resources, and this
 * project's `@branchleft/hetzner-host` dependency exact-pins the same
 * version, so `Host`'s resources resolve it too. A provider version is part
 * of every resource's URN, and these resources attach to a network another
 * project owns.
 */

/**
 * Refuses the whole program if `hcloud:token` addresses the mail project.
 * See `projectGuard.ts` for why the check is one-directional.
 */
export const estateProjectVerified = verifyEstateProject();

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
 * Self-hosted Nextcloud (Calendar/Appointments booking + Talk video) —
 * shared collaboration infrastructure, not a Ghost tenant, so it is not
 * homed in `ghost-platform`. Private-only, like `db1`: reached through the
 * `edge1` jump host over the private network, per
 * `RUNBOOK-provision-host.md` §5, rather than carrying its own public IPs.
 * That keeps the estate's public attack surface unchanged by this host's
 * addition, which matters more than usual here because Nextcloud AIO's
 * master container needs the Docker socket to manage its own sibling
 * containers — root-equivalent access this estate's CI deploy identity is
 * deliberately never given (see `cloudInit.ts`). Confining that to one
 * private-only, `app-host-isolation.sh`-fenced host (no route to `db1` or
 * anywhere else in the estate) is the isolation trade this host exists to
 * make, not an oversight.
 */
export const nextcloud1 = new Host({
  name: 'nextcloud1',
  role: 'app',
  location: ESTATE_LOCATION,
  image,
  ownerSshKeyNames,
  networkId,
  serverType: config.require('nextcloud1ServerType'),
  privateIp: HOST_IPS.nextcloud1,
  deployPublicKey: config.require('nextcloud1DeployPublicKey'),
  publicNetworking: false,
});

/** Restated from the address plan as a stack output, matching `edge1PrivateIp`. */
export const nextcloud1PrivateIp = HOST_IPS.nextcloud1;

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
