import { ESTATE_LOCATION, Host, NETWORK_CIDR, SUBNET_CIDR } from '@branchleft/hetzner-host';
import * as hcloud from '@pulumi/hcloud';
import * as pulumi from '@pulumi/pulumi';

import { checkProjectResults } from './projectGuard';

/**
 * The tenants project's network and its one database host, db-t1.
 * Gated on the project check: the network and subnet, the Host's network
 * wiring, and the Host's firewall, server and PrimaryIp (the transformation
 * below). A resource declared outside the Host must depend on the verified
 * value itself, because an ungated resource is created even when the check
 * refuses.
 */

const TENANTS_PROJECT_FIX =
  'Point hcloud:token at the tenants project, and create project-marker-tenants there if missing';

export function checkTenantsProject(
  servers: { servers: { name: string }[] },
  firewalls: { firewalls: { name: string }[] }
): boolean {
  return checkProjectResults('tenants', servers, firewalls, TENANTS_PROJECT_FIX);
}

export const tenantsProjectVerified = pulumi
  .all([pulumi.output(hcloud.getServers()), pulumi.output(hcloud.getFirewalls())])
  .apply(([servers, firewalls]) => checkTenantsProject(servers, firewalls));

/** Resolves to `value` only once the project check has passed. */
const verified = <T>(value: pulumi.Input<T>): pulumi.Output<T> =>
  pulumi.all([tenantsProjectVerified, value]).apply(([, resolved]) => resolved as T);

/**
 * Makes the firewall's name and the server's type wait on the check, so a
 * refused check registers neither. Applied to the Host's children below.
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

const image = config.require('image');

/** Names of keys registered in the tenants project, not key material. */
const ownerSshKeyNames = config.requireObject<string[]>('ownerSshKeyNames');

/** The tenants network. A network does not span projects, so this is its own. */
export const tenantsNetwork = new hcloud.Network(
  'tenants',
  {
    name: verified('tenants'),
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
    networkId: verified(tenantsNetwork.id).apply((id) => Number(id)),
    type: 'cloud',
    networkZone: 'eu-central',
    ipRange: SUBNET_CIDR,
  },
  { protect: true, parent: tenantsNetwork }
);

/** db-t1's fixed private address on the tenants network. */
export const TENANTS_DB_PRIVATE_IP = '10.20.1.20';

/**
 * The shared MySQL host. Private only; `publicNetworking` is fixed at creation.
 * The network id waits on the subnet so the server cannot be created first.
 */
export const dbT1 = new Host(
  {
    name: 'db-t1',
    role: 'db',
    location: ESTATE_LOCATION,
    image,
    ownerSshKeyNames,
    networkId: pulumi
      .all([tenantsProjectVerified, tenantsNetwork.id, tenantsSubnet.id])
      .apply(([, networkId]) => networkId),
    serverType: config.require('dbt1ServerType'),
    privateIp: TENANTS_DB_PRIVATE_IP,
    deployPublicKey: config.require('dbt1DeployPublicKey'),
    publicNetworking: false,
    environment: 'production',
    protection: true,
    backups: false,
  },
  { transformations: [gateRegistration] }
);

export const dbT1Location = dbT1.server.location;
export const dbT1PrivateIp = TENANTS_DB_PRIVATE_IP;
