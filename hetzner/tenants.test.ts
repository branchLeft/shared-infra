import * as pulumi from '@pulumi/pulumi';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  type Created,
  EDGE1_PUBLIC_IPV4,
  installTenantsMocks,
  ofType,
  settle,
  TYPES,
} from './tenants.fixtures';

/**
 * The tenants program's resource graph with the default config: edge-t, the
 * network, the subnet and the route, and no db-t1 (`dbt1Enabled` is absent).
 * `tenants.dbt1.test.ts` covers db-t1 with the switch on.
 *
 * `@branchleft/hetzner-host` carries its own copy of the Pulumi SDK, so it is
 * imported after the mocks are installed, as the program itself imports it.
 * Imported first, it would be loaded before the config exists.
 *
 * `protect` is a plain boolean the SDK resolves at construction and stores as
 * a private field; a cast through `unknown` reads the value Pulumi resolved,
 * which is the only way to catch an edit that drops the explicit override.
 */

let created: Created[] = [];
let program: typeof import('./tenants.js');
let plan: typeof import('@branchleft/hetzner-host');

beforeAll(async () => {
  created = installTenantsMocks();
  program = await import('./tenants.js');
  plan = await import('@branchleft/hetzner-host');
  await settle();
});

const named = (type: string, name: string) =>
  ofType(created, type).find((resource) => resource.inputs.name === name);

const resolvedProtect = (resource: pulumi.Resource): boolean | undefined =>
  (resource as unknown as { readonly __protect?: boolean }).__protect;

type FirewallRule = { direction: string; protocol: string; port?: string; sourceIps: string[] };

const edgeTRules = (): FirewallRule[] =>
  (named(TYPES.firewall, 'edge-t')?.inputs.rules ?? []) as FirewallRule[];

describe('edge-t', () => {
  it('is a public server of the ruled type, in the estate location', () => {
    const server = named(TYPES.server, 'edge-t');
    expect(server, 'a server named edge-t').toBeDefined();
    expect(server?.inputs.serverType).toBe('cx23');
    expect(server?.inputs.location).toBe('nbg1');
    expect(server?.inputs.image).toBe('debian-13');
    const publicNets = server?.inputs.publicNets as { ipv4Enabled: boolean }[] | undefined;
    expect(publicNets?.[0]?.ipv4Enabled).toBe(true);
  });

  it('holds two primary IPs, and the only ones in the project', () => {
    const ips = ofType(created, TYPES.primaryIp);
    expect(ips.map((ip) => ip.inputs.name).sort()).toEqual(['edge-t-ipv4', 'edge-t-ipv6']);
  });

  it('is attached to the tenants network at its register address', () => {
    const attachment = ofType(created, TYPES.serverNetwork).find(
      (n) => n.name === 'edge-t-network'
    );
    expect(attachment?.inputs.ip).toBe(plan.TENANTS_HOST_IPS.edgeT);
    const network = ofType(created, TYPES.network)[0];
    expect(attachment?.inputs.networkId).toBe(Number(network?.id));
  });

  it('is protected against deletion and rebuild, with no backups', () => {
    const server = named(TYPES.server, 'edge-t');
    expect(server?.inputs.deleteProtection).toBe(true);
    expect(server?.inputs.rebuildProtection).toBe(true);
    expect(server?.inputs.backups).toBe(false);
  });

  // The firewall control. Red when the SSH source is widened in
  // hetzner-host/firewalls.ts (sshRestrictedRules) or when a rule is added;
  // the checking function's own teeth are in hetzner-host/firewalls.test.ts.
  it("accepts SSH only from edge1's /32", () => {
    const rules = edgeTRules();
    expect(rules.length).toBeGreaterThan(0);

    const ssh = rules.filter((rule) => rule.protocol === 'tcp' && rule.port === '22');
    expect(ssh).toHaveLength(1);
    expect(ssh[0]?.sourceIps).toEqual([`${EDGE1_PUBLIC_IPV4}/32`]);

    const publicPorts = rules.map((rule) => (rule.protocol === 'icmp' ? 'icmp' : rule.port));
    expect(publicPorts.sort()).toEqual(['22', '443', '80', 'icmp']);

    const anySource = rules
      .filter((rule) => rule.sourceIps.includes('0.0.0.0/0') || rule.sourceIps.includes('::/0'))
      .map((rule) => (rule.protocol === 'icmp' ? 'icmp' : rule.port))
      .sort();
    expect(anySource).toEqual(['443', '80', 'icmp']);

    expect(plan.sshFromOneAddressViolations(rules as never, EDGE1_PUBLIC_IPV4)).toEqual([]);
  });

  it('declares only inbound rules, so egress stays default-allow', () => {
    expect(edgeTRules().every((rule) => rule.direction === 'in')).toBe(true);
  });
});

describe('the tenants default route', () => {
  const route = () => ofType(created, TYPES.route);

  // The NAT control, declaration half. Red when the route is deleted, or
  // points at db-t1's address, or at the wrong network.
  it('is one default route via edge-t, on the tenants network', () => {
    expect(route()).toHaveLength(1);
    const [only] = route();
    expect(only?.inputs.destination).toBe('0.0.0.0/0');
    expect(only?.inputs.gateway).toBe(plan.TENANTS_HOST_IPS.edgeT);
    expect(only?.inputs.gateway).not.toBe(plan.TENANTS_HOST_IPS.dbT1);
    const network = ofType(created, TYPES.network)[0];
    expect(only?.inputs.networkId).toBe(Number(network?.id));
  });

  it("names the address edge-t holds on the network, not another host's", () => {
    const attachment = ofType(created, TYPES.serverNetwork).find(
      (n) => n.name === 'edge-t-network'
    );
    expect(route()[0]?.inputs.gateway).toBe(attachment?.inputs.ip);
  });

  it('is created after the subnet and after edge-t is attached, which Hetzner serialises per network', () => {
    const position = (type: string, name?: string) =>
      created.findIndex((r) => r.type === type && (name === undefined || r.name === name));
    expect(position(TYPES.route)).toBeGreaterThan(position(TYPES.subnet));
    expect(position(TYPES.route)).toBeGreaterThan(position(TYPES.serverNetwork, 'edge-t-network'));
  });

  it('does not inherit protect:true from the network it is parented to', () => {
    expect(resolvedProtect(program.tenantsNetwork)).toBe(true);
    expect(resolvedProtect(program.tenantsEgressRoute)).toBe(false);
  });
});

describe('the tenants network', () => {
  it('declares its own tenants network and never the estate platform network', () => {
    const networks = ofType(created, TYPES.network);
    expect(networks.map((network) => network.inputs.name)).toEqual(['tenants']);
    expect(networks[0]?.inputs.ipRange).toBe(plan.NETWORK_CIDR);
  });

  it('holds both tenants hosts inside the one subnet, clear of every org host', () => {
    const prefix = plan.SUBNET_CIDR.replace(/\.0\/24$/, '.');
    for (const ip of Object.values(plan.TENANTS_HOST_IPS)) {
      expect(ip.startsWith(prefix)).toBe(true);
      expect(Object.values(plan.HOST_IPS)).not.toContain(ip);
    }
    expect(plan.duplicateAddresses(plan.ADDRESS_REGISTER)).toEqual([]);
  });
});

describe('db-t1 behind its switch', () => {
  // Red when `dbt1Enabled` defaults to true: db-t1 would be planned before
  // edge-t's route and NAT are live and proven.
  it('declares no db-t1 server, firewall or address while dbt1Enabled is absent', () => {
    expect(named(TYPES.server, 'db-t1')).toBeUndefined();
    expect(named(TYPES.firewall, 'db-t1')).toBeUndefined();
    expect(program.dbT1).toBeUndefined();
    expect(ofType(created, TYPES.server).map((server) => server.inputs.name)).toEqual(['edge-t']);
  });
});
