import {
  type AdoptArgs,
  ESTATE_LOCATION,
  Host,
  NETWORK_CIDR,
  SUBNET_CIDR,
  TENANTS_HOST_IPS,
} from '@branchleft/hetzner-host';
import * as hcloud from '@pulumi/hcloud';
import * as pulumi from '@pulumi/pulumi';

import { internetEgressRoute } from './egress';
import { checkProjectResults } from './projectGuard';

/**
 * The tenants project's network, its base host edge-t (web edge, SSH entry and
 * NAT gateway), the network's default route via edge-t, its one database
 * host, db-t1, which is declared only once `dbt1Enabled` is true, and its app
 * host, app-t1, which is declared only once `appt1Enabled` is true.
 * Gated on the project check: the network, subnet and route, the Hosts'
 * network wiring, and each Host's firewall, server and PrimaryIp (the
 * transformation below). A resource declared outside a Host must depend on the
 * verified value itself, because an ungated resource is created even when the
 * check refuses.
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

/**
 * Set for a host the owner made by hand in the console, to adopt it instead of
 * creating it: the live ids and the stage. Absent, the host is created. Read from
 * stack config, never defaulted here: `RUNBOOK-adopt-console-servers.md` says when
 * each key is set and what the preview must show before it is applied.
 */
const adoptionOf = (key: string): AdoptArgs | undefined => config.getObject<AdoptArgs>(key);

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

/**
 * The estate stack's outputs. A DIY (non-Pulumi-Cloud) backend fixes the
 * organisation segment to the literal `organization`, as `estate.ts` does for
 * the network stack. edge1's public address is read here, from state, and
 * never written into this repository: it is the one address edge-t accepts SSH
 * from. A project that has not applied the estate stack, or an output that is
 * not a public IPv4 address, fails the preview instead of planning a firewall.
 */
const estateStack = new pulumi.StackReference('organization/branchleft-hetzner-estate/production');
const edge1PublicIpv4 = verified(estateStack.requireOutput('edge1PublicIpv4').apply(String));

/**
 * The network id the hosts attach to. It waits on the subnet so no server can
 * be created before the subnet that holds its address exists.
 */
const hostNetworkId = pulumi
  .all([tenantsProjectVerified, tenantsNetwork.id, tenantsSubnet.id])
  .apply(([, networkId]) => networkId);

/**
 * The tenants project's one public host, doing for this project what edge1
 * does for the estate: the web edge (its Caddy configuration is not declared
 * here), the SSH entry (port 22 only from edge1's public address), and the
 * NAT gateway the private-only hosts reach the internet through. It is enrolled
 * in the gated Ansible delivery as `edget` (the logical name only: the server
 * and its hostname are `edge-t`). It is created with a deploy key and enrolled
 * by the owner's hand bootstrap, as db1, app1 and ops1 were: the component's
 * `enrolment` document is edge1's playbook and would start it here.
 *
 * With `edgetAdopt` set it is adopted, not created: the owner made the server in
 * the console, with a firewall that drops all inbound traffic, and the component
 * imports it and its two addresses and attaches this firewall beside that one. The
 * owner detaches theirs after this one is attached, so the host is never unfiltered.
 */
export const edgeT = new Host(
  {
    name: 'edge-t',
    role: 'edge',
    location: ESTATE_LOCATION,
    image,
    ownerSshKeyNames,
    networkId: hostNetworkId,
    serverType: config.require('edgetServerType'),
    privateIp: TENANTS_HOST_IPS.edgeT,
    deployPublicKey: config.require('edgetDeployPublicKey'),
    sshSourceIp: edge1PublicIpv4,
    publicNetworking: true,
    environment: 'production',
    protection: true,
    backups: false,
    adopt: adoptionOf('edgetAdopt'),
  },
  { transformations: [gateRegistration] }
);

/**
 * The tenants network's default route, via edge-t. The same construction as
 * the estate's (`network.ts`): `internetEgressRoute` validates the gateway,
 * and `ansible/roles/egress_nat/files/branchleft_nat.py`, run on edge-t by the `egress_nat` role,
 * is what makes the address at the other end forward.
 *
 * The network id goes through `verified`, because a resource declared outside
 * a Host is created even when the project check refuses. `protect: false` is
 * explicit, not absent: a child inherits `protect` from its parent, and the
 * network carries `protect: true`. Hetzner serialises actions per network, so
 * the route waits on the subnet and on edge-t (a component's dependency covers
 * its network attachment), the two actions it would otherwise race.
 */
export const tenantsEgressRoute = new hcloud.NetworkRoute(
  'tenants-internet-egress',
  {
    // The spread comes first so it cannot replace the gated network id, which
    // tenants.structure.scan.ts requires.
    ...internetEgressRoute(TENANTS_HOST_IPS.edgeT),
    networkId: verified(tenantsNetwork.id).apply((id) => Number(id)),
  },
  {
    parent: tenantsNetwork,
    protect: false,
    dependsOn: [tenantsSubnet, edgeT],
  }
);

/**
 * db-t1 is declared only when `dbt1Enabled` is true, and it defaults to false.
 * It is private-only and needs edge-t's route and NAT live before its first
 * boot (cloud-init fetches packages), so it is switched on in a later reviewed
 * change, after the NAT path is proven with Docker running on edge-t. A host
 * adopted from the console (`dbt1Adopt`) has already booted, so the route does not
 * decide its first boot; the order stays because the hand bootstrap fetches packages
 * through the same NAT path.
 */
const dbt1Enabled = config.getBoolean('dbt1Enabled') ?? false;

/**
 * The shared MySQL host. Private only; `publicNetworking` is fixed at creation.
 * The network id waits on the subnet so the server cannot be created first, and
 * the host waits on the egress route so it cannot boot before it has a path out.
 */
export const dbT1 = dbt1Enabled
  ? new Host(
      {
        name: 'db-t1',
        role: 'db',
        location: ESTATE_LOCATION,
        image,
        ownerSshKeyNames,
        networkId: hostNetworkId,
        serverType: config.require('dbt1ServerType'),
        privateIp: TENANTS_HOST_IPS.dbT1,
        deployPublicKey: config.require('dbt1DeployPublicKey'),
        publicNetworking: false,
        environment: 'production',
        protection: true,
        backups: false,
        adopt: adoptionOf('dbt1Adopt'),
      },
      { transformations: [gateRegistration], dependsOn: [tenantsEgressRoute] }
    )
  : undefined;

export const dbT1Location = dbT1?.server.location;
export const dbT1PrivateIp = TENANTS_HOST_IPS.dbT1;

/**
 * app-t1 is declared only when `appt1Enabled` is true, and it defaults to false:
 * the stack file carries no key until the owner has made the server and chosen to
 * bring it under the stack, so a merge changes no server. A server costs money, so
 * switching it on is the owner's change, reviewed on its own, and the apply stays
 * the owner's hand apply (`RUNBOOK-adopt-console-servers.md`, "app-t1"). With
 * `appt1Adopt` set the stack imports the hand-made server; with it absent the
 * preview shows a create, which the owner does not apply for a host that exists.
 */
const appt1Enabled = config.getBoolean('appt1Enabled') ?? false;

/**
 * The tenant app host. Private only, like db-t1: `publicNetworking` is fixed at
 * creation. It waits on the egress route for the same reason db-t1 does.
 */
export const appT1 = appt1Enabled
  ? new Host(
      {
        name: 'app-t1',
        role: 'app',
        location: ESTATE_LOCATION,
        image,
        ownerSshKeyNames,
        networkId: hostNetworkId,
        serverType: config.require('appt1ServerType'),
        privateIp: TENANTS_HOST_IPS.appT1,
        deployPublicKey: config.require('appt1DeployPublicKey'),
        publicNetworking: false,
        environment: 'production',
        protection: true,
        backups: false,
        adopt: adoptionOf('appt1Adopt'),
      },
      { transformations: [gateRegistration], dependsOn: [tenantsEgressRoute] }
    )
  : undefined;

export const appT1Location = appT1?.server.location;
export const appT1PrivateIp = TENANTS_HOST_IPS.appT1;

export const edgeTPublicIpv4 = edgeT.publicIpv4;
export const edgeTPrivateIp = TENANTS_HOST_IPS.edgeT;
