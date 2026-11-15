import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { type Created, installTenantsMocks, TYPES } from './tenants.fixtures';

/**
 * A token that addresses the demos project must register no provider resource.
 * The mocks answer the guard's reads with demos sentinels, so the guard refuses.
 * That covers the network, the subnet, the default route, both Hosts and
 * everything in them: the route and edge-t are declared outside any other gate
 * than the verified value, so this is their control.
 */

let created: Created[] = [];

/** Rejections the refused guard causes in resources that wait on it. */
const refusals: unknown[] = [];
const onRejection = (reason: unknown) => {
  refusals.push(reason);
};

const settle = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const providerCreates = () => created.filter((resource) => resource.type.startsWith('hcloud:'));

beforeAll(() => {
  process.on('unhandledRejection', onRejection);
  created = installTenantsMocks({
    config: {
      'branchleft-hetzner-tenants:dbt1Enabled': 'true',
      'branchleft-hetzner-tenants:appt1Enabled': 'true',
    },
    servers: [{ name: 'demo1' }],
    firewalls: [{ name: 'project-marker-demos' }],
  });
});

afterAll(() => {
  process.off('unhandledRejection', onRejection);
});

describe('tenants program under a token for another project', () => {
  it('refuses, and registers no provider resource', async () => {
    const program = await import('./tenants.js');
    const outcome = await new Promise<string>((resolve) => {
      program.tenantsProjectVerified.apply(() => resolve('resolved'));
      setTimeout(() => resolve('refused'), 500);
    });
    await settle(100);

    expect(outcome).toBe('refused');
    expect(refusals.length).toBeGreaterThan(0);
    expect(refusals.every((reason) => String(reason).includes('addresses the demos project'))).toBe(
      true
    );
    expect(providerCreates()).toEqual([]);
    // The first import of the program transforms it and its imports; under a
    // loaded full suite that has outlasted the 5s default.
  }, 30_000);

  it('registers no default route, no edge-t, no db-t1 and no app-t1 while the check refuses', () => {
    // db-t1 and app-t1 are switched on in this file's config so its absence is the gate's work.
    const types = created.map((resource) => resource.type);
    expect(types).not.toContain(TYPES.route);
    expect(types).not.toContain(TYPES.server);
    expect(types).not.toContain(TYPES.firewall);
    expect(types).not.toContain(TYPES.primaryIp);
    expect(types).not.toContain(TYPES.serverNetwork);
  });

  it('registers no PrimaryIp for a public-networked Host under the same gate', async () => {
    const { gateRegistration } = await import('./tenants.js');
    const { Host } = await import('@branchleft/hetzner-host');
    const before = created.length;

    new Host(
      {
        name: 'probe-public',
        role: 'db',
        serverType: 'cx23',
        location: 'nbg1',
        image: 'debian-13',
        ownerSshKeyNames: ['rob@branchleft.co.uk'],
        networkId: '1',
        privateIp: '10.20.1.21',
        deployPublicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE deploy@test',
        publicNetworking: true,
      },
      { transformations: [gateRegistration] }
    );
    await settle(200);

    const newCreates = created.slice(before);
    expect(newCreates.filter((resource) => resource.type.startsWith('hcloud:'))).toEqual([]);
    expect(newCreates.some((resource) => resource.type.includes('primaryIp'))).toBe(false);
  });
});
