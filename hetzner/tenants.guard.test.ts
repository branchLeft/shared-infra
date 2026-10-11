import * as pulumi from '@pulumi/pulumi';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * A token that addresses the demos project must register no provider resource.
 * The mocks answer the guard's reads with demos sentinels, so the guard refuses.
 */

interface Created {
  type: string;
  name: string;
}

const created: Created[] = [];

/** Rejections the refused guard causes in resources that wait on it. */
const refusals: unknown[] = [];
const onRejection = (reason: unknown) => {
  refusals.push(reason);
};

const settle = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const providerCreates = () => created.filter((resource) => resource.type.startsWith('hcloud:'));

beforeAll(() => {
  process.on('unhandledRejection', onRejection);
  process.env.PULUMI_CONFIG = JSON.stringify({
    'branchleft-hetzner-tenants:image': 'debian-13',
    'branchleft-hetzner-tenants:dbt1ServerType': 'cx23',
    'branchleft-hetzner-tenants:ownerSshKeyNames': '["rob@branchleft.co.uk"]',
    'branchleft-hetzner-tenants:dbt1DeployPublicKey':
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE deploy@test',
  });
  pulumi.runtime.setMocks(
    {
      newResource(args: pulumi.runtime.MockResourceArgs) {
        created.push({ type: args.type, name: args.name });
        return { id: `${args.name}-id`, state: { ...args.inputs } };
      },
      call(args: pulumi.runtime.MockCallArgs) {
        if (args.token === 'hcloud:index/getServers:getServers') {
          return { servers: [{ name: 'demo1' }] };
        }
        if (args.token === 'hcloud:index/getFirewalls:getFirewalls') {
          return { firewalls: [{ name: 'project-marker-demos' }] };
        }
        return {};
      },
    },
    'branchleft-hetzner-tenants',
    'production',
    false
  );
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
