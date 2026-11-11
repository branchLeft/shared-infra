import { Host } from '@branchleft/hetzner-host';
import * as pulumi from '@pulumi/pulumi';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * `@branchleft/hetzner-host` is a `link:` dependency with its own copy of
 * `@pulumi/pulumi`, so this test is the one place that checks `Output` interop
 * across the two copies. The reasoning is in hetznerHost.test.md beside it.
 */

type Created = { type: string; name: string };

const created: Created[] = [];

beforeAll(() => {
  pulumi.runtime.setMocks(
    {
      newResource(args: pulumi.runtime.MockResourceArgs) {
        created.push({ type: args.type, name: args.name });
        return { id: `${args.name}-id`, state: { ...args.inputs, ipAddress: '203.0.113.10' } };
      },
      call() {
        return {};
      },
    },
    'estate-test',
    'test',
    false
  );
});

describe('Host, constructed from @branchleft/hetzner-host', () => {
  it('registers the resources this project depends on for edge1, across the package boundary', async () => {
    const host = new Host({
      name: 'boundarycheck1',
      role: 'edge',
      serverType: 'cx23',
      location: 'nbg1',
      image: 'debian-13',
      ownerSshKeyNames: ['owner'],
      networkId: '4242',
      privateIp: '10.20.1.10',
      deployPublicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE deploy@test',
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(created.some((r) => r.type === 'hcloud:index/server:Server')).toBe(true);
    expect(created.some((r) => r.type === 'hcloud:index/firewall:Firewall')).toBe(true);
    expect(created.some((r) => r.type === 'hcloud:index/serverNetwork:ServerNetwork')).toBe(true);

    // Output resolution across the boundary: `publicIpv4` is a
    // `pulumi.Output` constructed inside `hetzner-host`'s copy of
    // `@pulumi/pulumi`, read here through this project's own copy.
    const ip = await new Promise((resolve) => host.publicIpv4?.apply(resolve));
    expect(ip).toBe('203.0.113.10');

    // The cross-copy-safe check the SDK ships for exactly this situation: a
    // marker property, not `instanceof`. If the two `@pulumi/pulumi` copies
    // could not recognise each other's `Output` objects, this would be false
    // even though the value above resolved.
    expect(pulumi.Output.isInstance(host.publicIpv4)).toBe(true);
  });
});
