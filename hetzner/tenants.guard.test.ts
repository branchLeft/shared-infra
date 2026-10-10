import * as pulumi from '@pulumi/pulumi';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * A token that addresses the demos project must register no tenants resource
 * of the cloud provider's types. The mocks answer the guard's reads with demos
 * sentinels, so the guard refuses.
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

describe('tenants program under a token for another project', () => {
  it('refuses, and registers no provider resource', async () => {
    const program = await import('./tenants.js');
    const outcome = await new Promise<string>((resolve) => {
      program.tenantsProjectVerified.apply(() => resolve('resolved'));
      setTimeout(() => resolve('refused'), 500);
    });
    await new Promise((resolve) => setTimeout(resolve, 100));

    process.off('unhandledRejection', onRejection);
    expect(outcome).toBe('refused');
    expect(refusals.length).toBeGreaterThan(0);
    expect(refusals.every((reason) => String(reason).includes('addresses the demos project'))).toBe(
      true
    );
    expect(created.filter((resource) => resource.type.startsWith('hcloud:'))).toEqual([]);
  });
});
