import { beforeAll, describe, expect, it } from 'vitest';

import { type Created, installTenantsMocks, ofType, settle, TYPES } from './tenants.fixtures';

/**
 * The tenants program with `appt1Enabled` on and no adopt config: what a preview
 * shows for a server the stack would create. A separate file from
 * `tenants.test.ts` because the program reads its config once, at import.
 * `tenants.adopt.test.ts` covers the adopted case, which is the one the owner applies.
 */

let created: Created[] = [];
let plan: typeof import('@branchleft/hetzner-host');

beforeAll(async () => {
  created = installTenantsMocks({
    config: { 'branchleft-hetzner-tenants:appt1Enabled': 'true' },
  });
  await import('./tenants.js');
  plan = await import('@branchleft/hetzner-host');
  await settle();
});

const app = () => ofType(created, TYPES.server).find((server) => server.inputs.name === 'app-t1');

describe('tenants program with app-t1 enabled', () => {
  it('creates app-t1 as the ruled type, in the estate location, on the estate image', () => {
    expect(app(), 'a server named app-t1').toBeDefined();
    expect(app()?.inputs.serverType).toBe('cx23');
    expect(app()?.inputs.location).toBe(plan.ESTATE_LOCATION);
    expect(app()?.inputs.image).toBe('debian-13');
  });

  it('gives app-t1 no public address of its own', () => {
    expect(ofType(created, TYPES.primaryIp).map((ip) => ip.inputs.name)).not.toContain(
      'app-t1-ipv4'
    );
    const publicNets = app()?.inputs.publicNets as
      { ipv4Enabled: boolean; ipv6Enabled: boolean }[] | undefined;
    expect(publicNets?.[0]?.ipv4Enabled).toBe(false);
    expect(publicNets?.[0]?.ipv6Enabled).toBe(false);
  });

  it('gives app-t1 a firewall with only the SSH and ICMP inbound rules', () => {
    const firewall = ofType(created, TYPES.firewall).find(
      (resource) => resource.inputs.name === 'app-t1'
    );
    const rules = firewall?.inputs.rules as { port?: string; protocol: string }[] | undefined;
    expect(rules?.map((rule) => rule.protocol)).toEqual(['tcp', 'icmp']);
    expect(rules?.[0]?.port).toBe('22');
  });

  it('attaches app-t1 inline to the tenants network at its register address', () => {
    const networks = app()?.inputs.networks as { ip: string; aliasIps: unknown[] }[] | undefined;
    expect(networks).toHaveLength(1);
    expect(networks?.[0]?.ip).toBe(plan.TENANTS_HOST_IPS.appT1);
    expect(plan.TENANTS_HOST_IPS.appT1).not.toBe(plan.TENANTS_HOST_IPS.dbT1);
  });

  it('protects app-t1 against deletion and rebuild, with no backups switched on', () => {
    expect(app()?.inputs.deleteProtection).toBe(true);
    expect(app()?.inputs.rebuildProtection).toBe(true);
    expect(app()?.inputs.backups).toBe(false);
  });

  it('creates app-t1 only after the default route exists, so its first boot has a path out', () => {
    const route = created.findIndex((resource) => resource.type === TYPES.route);
    const server = created.findIndex((resource) => resource === app());
    expect(route).toBeGreaterThanOrEqual(0);
    expect(server).toBeGreaterThan(route);
  });

  it('declares exactly one server for the switch, and none for db-t1 while it is off', () => {
    const names = ofType(created, TYPES.server).map((server) => server.inputs.name);
    expect(names.sort()).toEqual(['app-t1', 'edge-t']);
  });
});
