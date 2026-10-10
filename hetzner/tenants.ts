import { ESTATE_LOCATION, Host, NETWORK_CIDR, SUBNET_CIDR } from '@branchleft/hetzner-host';
import * as hcloud from '@pulumi/hcloud';
import * as pulumi from '@pulumi/pulumi';

import { checkProjectResults } from './projectGuard';

/**
 * The tenants project's own network and its one database host, db-t1.
 *
 * The tenants project is a separate Hetzner project from the estate project.
 * A Hetzner network does not span projects, so this program declares a network
 * of its own rather than attaching to the estate's `platform` network. Nothing
 * in the estate can reach db-t1 by private address: the only way in is through
 * the tenants project's own hosts, or through the tunnel, which is a separate
 * decision. That isolation is a property of the network boundary, not of a
 * firewall rule, and the network is created here so it cannot be shared by
 * accident.
 *
 * The estate's stack reads the platform network from another stack's outputs.
 * This stack does not: the tenants network is created here, and its only
 * consumer is the host below.
 *
 * The program file sits in the package root while its Pulumi project sits in
 * `tenants/`, matching `estate.ts`, so both projects share one `node_modules`.
 */

/**
 * Refuses the whole program unless `hcloud:token` addresses the tenants
 * project. The tenants project is new and empty, so the check also requires
 * its own marker firewall to be visible: an empty tenants project and an empty
 * demos project look identical without it. See `projectGuard.ts`.
 */
const TENANTS_PROJECT_FIX =
  'Point hcloud:token at the tenants project, and create the project-marker-tenants firewall there if it is missing';

export function checkTenantsProject(
  servers: { servers: { name: string }[] },
  firewalls: { firewalls: { name: string }[] }
): boolean {
  return checkProjectResults('tenants', servers, firewalls, TENANTS_PROJECT_FIX);
}

export const tenantsProjectVerified = pulumi
  .all([pulumi.output(hcloud.getServers()), pulumi.output(hcloud.getFirewalls())])
  .apply(([servers, firewalls]) => checkTenantsProject(servers, firewalls));

const config = new pulumi.Config();

const image = config.require('image');

/** Names of keys already registered in the tenants project, not key material.
 * A key registered only in the estate project fails the apply, because the
 * SSH key list is per project and create-time-only on the server. */
const ownerSshKeyNames = config.requireObject<string[]>('ownerSshKeyNames');

/**
 * The tenants network. Its address range is the same as the estate's, which is
 * deliberate and harmless: the two networks are in different projects and are
 * never joined, so no route can carry an address from one into the other.
 */
export const tenantsNetwork = new hcloud.Network(
  'tenants',
  {
    name: 'tenants',
    ipRange: NETWORK_CIDR,
    exposeRoutesToVswitch: false,
    deleteProtection: true,
    labels: {
      env: 'production',
      'managed-by': 'pulumi',
    },
  },
  { protect: true }
);

export const tenantsSubnet = new hcloud.NetworkSubnet(
  'tenants-eu-central',
  {
    networkId: tenantsNetwork.id.apply((id) => Number(id)),
    type: 'cloud',
    networkZone: 'eu-central',
    ipRange: SUBNET_CIDR,
  },
  { protect: true, parent: tenantsNetwork }
);

/**
 * db-t1's fixed private address on the tenants network. Listed here rather
 * than derived, for the same reason every host's address is listed in the
 * address plan: a rule or a client config that names it must match on grep.
 */
export const TENANTS_DB_PRIVATE_IP = '10.20.1.20';

/**
 * The shared MySQL host for every paid tenant instance. Private only: it has no
 * public address of its own, and `publicNetworking` is fixed at creation, so
 * the shape cannot be changed later without a two-step apply.
 *
 * The network id is routed through the subnet so the server cannot be created
 * before the subnet it attaches to. A component's `dependsOn` does not reach
 * its children, so the dependency is carried by the value itself.
 */
export const dbT1 = new Host({
  name: 'db-t1',
  role: 'db',
  location: ESTATE_LOCATION,
  image,
  ownerSshKeyNames,
  networkId: pulumi.all([tenantsNetwork.id, tenantsSubnet.id]).apply(([networkId]) => networkId),
  serverType: config.require('dbt1ServerType'),
  privateIp: TENANTS_DB_PRIVATE_IP,
  deployPublicKey: config.require('dbt1DeployPublicKey'),
  publicNetworking: false,
  environment: 'production',
  protection: true,
  backups: false,
});

/** Read from the applied server, so a later stack reads where db-t1 actually is. */
export const dbT1Location = dbT1.server.location;
export const dbT1PrivateIp = TENANTS_DB_PRIVATE_IP;
