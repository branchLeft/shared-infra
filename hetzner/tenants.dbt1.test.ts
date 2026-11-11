import { beforeAll, describe, expect, it } from 'vitest';

import { type Created, installTenantsMocks, ofType, settle, TYPES } from './tenants.fixtures';

/**
 * The tenants program with `dbt1Enabled` on: db-t1, the shared MySQL host, as
 * a private-only server on the tenants network. A separate file from
 * `tenants.test.ts` because the program reads its config once, at import.
 */

let created: Created[] = [];
let plan: typeof import('@branchleft/hetzner-host');

beforeAll(async () => {
  created = installTenantsMocks({
    config: { 'branchleft-hetzner-tenants:dbt1Enabled': 'true' },
  });
  await import('./tenants.js');
  plan = await import('@branchleft/hetzner-host');
  await settle();
});

const db = () => ofType(created, TYPES.server).find((server) => server.inputs.name === 'db-t1');

describe('tenants program with db-t1 enabled', () => {
  it('creates db-t1 as a private-only server on the tenants network', () => {
    expect(db(), 'a server named db-t1').toBeDefined();
    expect(db()?.inputs.serverType).toBe('cx23');
    expect(db()?.inputs.location).toBe('nbg1');
    expect(db()?.inputs.image).toBe('debian-13');
  });

  it('gives db-t1 no public address of its own', () => {
    expect(ofType(created, TYPES.primaryIp).map((ip) => ip.inputs.name)).not.toContain(
      'db-t1-ipv4'
    );
    const publicNets = db()?.inputs.publicNets as
      { ipv4Enabled: boolean; ipv6Enabled: boolean }[] | undefined;
    expect(publicNets?.[0]?.ipv4Enabled).toBe(false);
    expect(publicNets?.[0]?.ipv6Enabled).toBe(false);
  });

  it('gives db-t1 a firewall with only the SSH and ICMP inbound rules', () => {
    const firewall = ofType(created, TYPES.firewall).find(
      (resource) => resource.inputs.name === 'db-t1'
    );
    const rules = firewall?.inputs.rules as { port?: string; protocol: string }[] | undefined;
    expect(rules?.map((rule) => rule.protocol)).toEqual(['tcp', 'icmp']);
    expect(rules?.[0]?.port).toBe('22');
  });

  it('attaches db-t1 inline to the tenants network at its register address', () => {
    const networks = db()?.inputs.networks as { ip: string; aliasIps: unknown[] }[] | undefined;
    expect(networks).toHaveLength(1);
    expect(networks?.[0]?.ip).toBe(plan.TENANTS_HOST_IPS.dbT1);
    expect(networks?.[0]?.aliasIps).toEqual([]);
  });

  it('protects db-t1 against deletion and rebuild, with no backups switched on', () => {
    expect(db()?.inputs.deleteProtection).toBe(true);
    expect(db()?.inputs.rebuildProtection).toBe(true);
    expect(db()?.inputs.backups).toBe(false);
  });

  it('creates db-t1 only after the default route exists, so its first boot has a path out', () => {
    const route = created.findIndex((resource) => resource.type === TYPES.route);
    const server = created.findIndex((resource) => resource === db());
    expect(route).toBeGreaterThanOrEqual(0);
    expect(server).toBeGreaterThan(route);
  });
});
