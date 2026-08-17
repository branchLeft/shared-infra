import * as pulumi from '@pulumi/pulumi';
import { beforeAll, describe, expect, it } from 'vitest';

import { Host } from './host';

/**
 * `Host` has three branches whose failure modes are all silent at apply time:
 * the role picks the firewall rule set, `publicNetworking` decides whether two
 * primary IPs exist, and the firewall is declared *on the server* rather than
 * attached afterwards. A wrong branch produces a host that boots, answers SSH,
 * and is exposed — nothing errors.
 *
 * `setMocks` runs in `beforeAll`, which is early enough: `host.ts` constructs
 * nothing at module scope, so the mocks only have to be in place before the
 * first `new Host(...)`. `estate.ts` and `network.ts` are the modules that do
 * build resources on import, and neither is imported here.
 */

type Created = { type: string; name: string; inputs: Record<string, unknown> };

const created: Created[] = [];

beforeAll(() => {
  pulumi.runtime.setMocks(
    {
      newResource(args: pulumi.runtime.MockResourceArgs) {
        created.push({ type: args.type, name: args.name, inputs: args.inputs });
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

const BASE = {
  serverType: 'cx23',
  location: 'nbg1' as const,
  image: 'debian-13',
  ownerSshKeyNames: ['owner'],
  deployPublicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE deploy@test',
  networkId: '4242',
};

async function build(args: Record<string, unknown>) {
  const before = created.length;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const host = new Host({ ...BASE, ...args } as any);
  await new Promise((resolve) => setTimeout(resolve, 0));
  return { host, resources: created.slice(before) };
}

const resolve = <T>(output: pulumi.Output<T> | undefined): Promise<T | undefined> =>
  output === undefined ? Promise.resolve(undefined) : new Promise((r) => output.apply(r as never));

describe('Host', () => {
  it('declares the firewall on the server rather than attaching it afterwards', async () => {
    // An attachment applied as a following step leaves a window in which a
    // freshly created host is on the public internet with no filter. There is
    // no ServerNetwork-style attachment resource for firewalls here by design.
    const { resources } = await build({ name: 'fw1', role: 'edge' });
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server).toBeDefined();
    expect(server?.inputs.firewallIds).toBeDefined();
    expect((server?.inputs.firewallIds as unknown[]).length).toBe(1);
  });

  it('gives an edge host the public rule set', async () => {
    const { resources } = await build({ name: 'edgeX', role: 'edge' });
    const firewall = resources.find((r) => r.type === 'hcloud:index/firewall:Firewall');
    const ports = (firewall?.inputs.rules as { port?: string; protocol: string }[]).map(
      (r) => r.port ?? r.protocol
    );
    expect(ports.sort()).toEqual(['22', '443', '80', 'icmp']);
  });

  it.each(['app', 'db', 'mon'] as const)('gives a %s host the internal rule set', async (role) => {
    const { resources } = await build({ name: `int-${role}`, role });
    const firewall = resources.find((r) => r.type === 'hcloud:index/firewall:Firewall');
    const ports = (firewall?.inputs.rules as { port?: string; protocol: string }[]).map(
      (r) => r.port ?? r.protocol
    );
    expect(ports.sort()).toEqual(['22', 'icmp']);
    expect(ports).not.toContain('80');
    expect(ports).not.toContain('443');
  });

  it('creates two non-auto-delete primary IPs when public networking is on', async () => {
    // auto_delete would release the address on a rebuild, and with a manual
    // DNS zone and HTTP-01 issuance a changed address cannot be repaired by
    // any program.
    const { host, resources } = await build({ name: 'pub1', role: 'edge' });
    const ips = resources.filter((r) => r.type === 'hcloud:index/primaryIp:PrimaryIp');
    expect(ips.map((i) => i.inputs.type).sort()).toEqual(['ipv4', 'ipv6']);
    expect(ips.every((i) => i.inputs.autoDelete === false)).toBe(true);
    expect(ips.every((i) => i.inputs.deleteProtection === true)).toBe(true);
    expect(await resolve(host.publicIpv4)).toBe('203.0.113.10');
  });

  it('creates no primary IPs at all when public networking is off', async () => {
    // Not "a filtered public address" — none. This is the control that keeps a
    // database host off the public internet.
    const { host, resources } = await build({
      name: 'priv1',
      role: 'db',
      publicNetworking: false,
    });
    expect(resources.filter((r) => r.type === 'hcloud:index/primaryIp:PrimaryIp')).toHaveLength(0);
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server?.inputs.publicNets).toEqual([{ ipv4Enabled: false, ipv6Enabled: false }]);
    expect(host.publicIpv4).toBeUndefined();
  });

  it('attaches to the private network at the address it was given', async () => {
    const { resources } = await build({ name: 'net1', role: 'app', privateIp: '10.20.1.100' });
    const attachment = resources.find((r) => r.type === 'hcloud:index/serverNetwork:ServerNetwork');
    expect(attachment?.inputs.ip).toBe('10.20.1.100');
  });

  it('protects a production host from delete and rebuild by default', async () => {
    const { resources } = await build({ name: 'prot1', role: 'edge' });
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server?.inputs.deleteProtection).toBe(true);
    expect(server?.inputs.rebuildProtection).toBe(true);
    expect(server?.inputs.backups).toBe(false);
    expect(server?.inputs.labels).toMatchObject({ env: 'production', 'managed-by': 'pulumi' });
  });

  it('drops protection and labels a lab host as lab', async () => {
    // With protection on, `pulumi destroy` cannot tear a spike down without
    // editing the component; and a lab host labelled production corrupts cost
    // attribution and any label-selector rule that reads it.
    const { resources } = await build({
      name: 'lab1',
      role: 'app',
      environment: 'lab',
      protection: false,
    });
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server?.inputs.deleteProtection).toBe(false);
    expect(server?.inputs.rebuildProtection).toBe(false);
    expect(server?.inputs.labels).toMatchObject({ env: 'lab', role: 'app' });
  });

  it('refuses a deploy key that could inject cloud-config, before creating anything', async () => {
    // The validation lives in cloudInit.ts and is unit-tested there. This
    // asserts the component routes through it rather than interpolating the
    // raw value, and that it does so synchronously — a throw from inside an
    // `apply` would surface as an unhandled rejection during serialization,
    // after the firewall and the primary IPs had already been registered.
    const before = created.length;
    expect(
      () =>
        new Host({
          ...BASE,
          name: 'bad1',
          role: 'app',
          privateIp: '10.20.1.199',
          deployPublicKey: 'ssh-ed25519 AAAA\nruncmd:\n  - [ sh, -c, "id" ]',
        })
    ).toThrow(/single-line OpenSSH public key/);
    expect(created.slice(before).some((r) => r.type === 'hcloud:index/server:Server')).toBe(false);
  });
});
