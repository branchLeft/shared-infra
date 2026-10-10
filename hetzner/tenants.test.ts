import * as pulumi from '@pulumi/pulumi';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * The tenants program's resource graph, read from the requests the SDK sends
 * the engine through mocks. Nothing is previewed or applied: no provider call
 * leaves the process, and the read calls the guard makes are answered here.
 *
 * The config is supplied in the shape the stack file carries, so a key the
 * program requires and the stack file lacks fails here.
 */

interface Created {
  type: string;
  name: string;
  inputs: Record<string, unknown>;
}

const created: Created[] = [];

const TENANTS_MARKER = 'project-marker-tenants';

beforeAll(() => {
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
        created.push({ type: args.type, name: args.name, inputs: args.inputs });
        return { id: `${args.name}-id`, state: { ...args.inputs } };
      },
      call(args: pulumi.runtime.MockCallArgs) {
        if (args.token === 'hcloud:index/getServers:getServers') {
          return { servers: [] };
        }
        if (args.token === 'hcloud:index/getFirewalls:getFirewalls') {
          return { firewalls: [{ name: TENANTS_MARKER }] };
        }
        return {};
      },
    },
    'branchleft-hetzner-tenants',
    'production',
    false
  );
});

async function load(): Promise<void> {
  await import('./tenants.js');
  await new Promise((resolve) => setTimeout(resolve, 0));
}

const ofType = (type: string) => created.filter((resource) => resource.type === type);

describe('tenants program', () => {
  it('creates db-t1 as a private-only server on the tenants network', async () => {
    await load();

    const servers = ofType('hcloud:index/server:Server');
    const db = servers.find((server) => server.inputs.name === 'db-t1');
    expect(db, 'a server named db-t1').toBeDefined();
    expect(db?.inputs.serverType).toBe('cx23');
    expect(db?.inputs.location).toBe('nbg1');
    expect(db?.inputs.image).toBe('debian-13');
  });

  it('gives db-t1 no public address of its own', async () => {
    await load();

    expect(ofType('hcloud:index/primaryIp:PrimaryIp')).toEqual([]);
    const db = ofType('hcloud:index/server:Server').find(
      (server) => server.inputs.name === 'db-t1'
    );
    const publicNets = db?.inputs.publicNets as { ipv4Enabled: boolean }[] | undefined;
    expect(publicNets?.[0]?.ipv4Enabled).toBe(false);
  });

  it('attaches db-t1 inline to the tenants network at its fixed address', async () => {
    await load();

    const db = ofType('hcloud:index/server:Server').find(
      (server) => server.inputs.name === 'db-t1'
    );
    const networks = db?.inputs.networks as { ip: string; aliasIps: unknown[] }[] | undefined;
    expect(networks).toHaveLength(1);
    expect(networks?.[0]?.ip).toBe('10.20.1.20');
    expect(networks?.[0]?.aliasIps).toEqual([]);
  });

  it('declares its own tenants network and never the estate platform network', async () => {
    await load();

    const networks = ofType('hcloud:index/network:Network');
    expect(networks.map((network) => network.inputs.name)).toEqual(['tenants']);
    expect(networks[0]?.inputs.ipRange).toBe('10.20.0.0/16');
  });

  it('protects db-t1 against deletion and rebuild, with no backups switched on', async () => {
    await load();

    const db = ofType('hcloud:index/server:Server').find(
      (server) => server.inputs.name === 'db-t1'
    );
    expect(db?.inputs.deleteProtection).toBe(true);
    expect(db?.inputs.rebuildProtection).toBe(true);
    expect(db?.inputs.backups).toBe(false);
  });
});
