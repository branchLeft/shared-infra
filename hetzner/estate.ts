import { ESTATE_LOCATION, Host, HOST_IPS } from '@branchleft/hetzner-host';
import * as pulumi from '@pulumi/pulumi';

import { verifyEstateProject } from './projectGuard';

// Narrative moved to hetzner/estate.md, "Header".

/**
 * Refuses the whole program if `hcloud:token` addresses the mail project.
 * See `projectGuard.ts` for why the check is one-directional.
 */
export const estateProjectVerified = verifyEstateProject();

/**
 * Resolves to `value` only once the project check has passed. An ungated
 * resource is registered even when the check refuses, so every input that
 * reaches a provider resource goes through this or through `gateRegistration`.
 */
const verified = <T>(value: pulumi.Input<T>): pulumi.Output<T> =>
  pulumi.all([estateProjectVerified, value]).apply(([, resolved]) => resolved as T);

/**
 * Makes the firewall's name, the server's type and the primary IPs' names wait
 * on the check, so a refused check registers none of them. Applied to each
 * Host below, whose children these are.
 */
export const GATED_PROPERTY: Record<string, string> = {
  'hcloud:index/firewall:Firewall': 'name',
  'hcloud:index/server:Server': 'serverType',
  'hcloud:index/primaryIp:PrimaryIp': 'name',
};

export const gateRegistration: pulumi.ResourceTransformation = (args) => {
  const property = GATED_PROPERTY[args.type];
  if (property === undefined) {
    return undefined;
  }
  return {
    props: { ...args.props, [property]: verified(args.props[property]) },
    opts: args.opts,
  };
};

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
// Gated directly: the server's network attachment is built from this value
// outside the transformation's reach.
const networkId = verified(networkStack.requireOutput('networkId').apply(String));

const image = config.require('image');

/** Names of keys already registered in the hcloud project, not key material.
 * `hcloud ssh-key list` is the only place the current names can be read. */
const ownerSshKeyNames = config.requireObject<string[]>('ownerSshKeyNames');

/**
 * The front door, and the only host in this estate that terminates public
 * traffic. Caddy, CrowdSec and the monitoring stack are delivered onto it
 * separately; nothing here installs them.
 */
export const edge1 = new Host(
  {
    name: 'edge1',
    role: 'edge',
    location: ESTATE_LOCATION,
    image,
    ownerSshKeyNames,
    networkId,
    serverType: config.require('edge1ServerType'),
    privateIp: HOST_IPS.edge1,
    deployPublicKey: config.require('edge1DeployPublicKey'),
  },
  { transformations: [gateRegistration] }
);

export const edge1PublicIpv4 = edge1.publicIpv4;

/** Restated from the address plan as a stack output so a later stack reads it
 * from state rather than importing this program. */
export const edge1PrivateIp = HOST_IPS.edge1;

// Narrative moved to hetzner/estate.md, "ops1".
export const ops1 = new Host(
  {
    name: 'ops1',
    role: 'app',
    location: ESTATE_LOCATION,
    image,
    ownerSshKeyNames,
    networkId,
    serverType: config.require('ops1ServerType'),
    privateIp: HOST_IPS.ops1,
    deployPublicKey: config.require('ops1DeployPublicKey'),
    publicNetworking: false,
  },
  {
    // The host was created as `nextcloud1`, and its resources' URNs in state
    // still carry that name. Without this alias a rename plans a new server
    // and the deletion of the live one; with it, the server and firewall are
    // updated in place. Their children inherit it because both names start
    // with the component's own (`ops1`, `ops1-firewall`). estate.test.ts pins
    // the exact URNs this must match. It can go only after the production
    // stack has applied the rename; before that, removing it is a replace.
    aliases: [{ name: 'nextcloud1' }],
    transformations: [gateRegistration],
  }
);

/** Restated from the address plan as a stack output, matching `edge1PrivateIp`. */
export const ops1PrivateIp = HOST_IPS.ops1;

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
