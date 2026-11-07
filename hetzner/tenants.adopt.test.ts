import * as pulumi from '@pulumi/pulumi';
import { beforeAll, describe, expect, it } from 'vitest';

import { type Created, installTenantsMocks, ofType, settle, TYPES } from './tenants.fixtures';

/**
 * The tenants program with edge-t and db-t1 adopted from servers the owner made by
 * hand. A separate file, because the program reads its config once, at import.
 *
 * `ignoreChanges` and the import id are fields of the request the SDK sends the
 * engine, which the mocks do not hand to `newResource`, so they are read where the
 * request passes the monitor. A Pulumi preview against the real project is the
 * owner's; this is the offline half of it, and it is what goes red if adoption
 * could plan to replace a live server.
 */

const FIREWALL_ATTACHMENT = 'hcloud:index/firewallAttachment:FirewallAttachment';

interface Registration {
  type: string;
  name: string;
  importId: string;
  ignoreChanges: string[];
  inputs: Record<string, unknown>;
}

interface RegisterRequest {
  getType(): string;
  getName(): string;
  getImportid(): string;
  getIgnorechangesList(): string[];
  getObject(): { toJavaScript(): unknown };
}

const registrations: Registration[] = [];
let created: Created[] = [];

beforeAll(async () => {
  created = installTenantsMocks({
    config: {
      'branchleft-hetzner-tenants:dbt1Enabled': 'true',
      'branchleft-hetzner-tenants:edgetAdopt': JSON.stringify({
        serverId: '1001',
        ipv4Id: '2001',
        ipv6Id: '2002',
      }),
      'branchleft-hetzner-tenants:dbt1Adopt': JSON.stringify({ serverId: '1002' }),
    },
  });
  const monitor = pulumi.runtime.getMonitor() as unknown as {
    registerResource(req: RegisterRequest, callback: (err: unknown, resp: unknown) => void): void;
  };
  const register = monitor.registerResource.bind(monitor);
  monitor.registerResource = (req, callback) => {
    registrations.push({
      type: req.getType(),
      name: req.getName(),
      importId: req.getImportid(),
      ignoreChanges: req.getIgnorechangesList(),
      inputs: req.getObject().toJavaScript() as Record<string, unknown>,
    });
    register(req, callback);
  };
  await import('./tenants.js');
  await settle();
});

const server = (name: string) =>
  registrations.find((r) => r.type === TYPES.server && r.name === name);

describe('the tenants program with edge-t and db-t1 adopted', () => {
  it('imports each server by the id in its stack config', () => {
    expect(server('edge-t')?.importId).toBe('1001');
    expect(server('db-t1')?.importId).toBe('1002');
  });

  it('imports the two addresses of edge-t and creates no others', () => {
    const ips = registrations.filter((r) => r.type === TYPES.primaryIp);
    expect(ips.map((r) => [r.name, r.importId]).sort()).toEqual([
      ['edge-t-ipv4', '2001'],
      ['edge-t-ipv6', '2002'],
    ]);
  });

  // Red when a create-time-only field is dropped from the component's list: a
  // console-made server differs from the program on all of them, and a diff on
  // one plans to destroy a live host.
  it.each(['edge-t', 'db-t1'])(
    'never plans to replace %s over a create-time-only field',
    (name) => {
      for (const field of ['userData', 'sshKeys', 'image', 'firewallIds']) {
        expect(server(name)?.ignoreChanges, `${name} ${field}`).toContain(field);
      }
    }
  );

  it('gives each server its own firewall by attachment, never on the server', () => {
    expect(server('edge-t')?.inputs.firewallIds).toBeUndefined();
    const attached = registrations.filter((r) => r.type === FIREWALL_ATTACHMENT).map((r) => r.name);
    // db-t1 is at the import stage, with a possible leftover public address: its
    // firewall waits for the converge stage.
    expect(attached).toEqual(['edge-t-firewall-attachment']);
  });

  it('keeps db-t1 private-only, with no address of its own', () => {
    expect(ofType(created, TYPES.primaryIp).map((ip) => ip.inputs.name)).not.toContain(
      'db-t1-ipv4'
    );
    expect(server('db-t1')?.ignoreChanges).toEqual(
      expect.arrayContaining(['networks', 'publicNets'])
    );
  });

  it('is the ruled server type', () => {
    expect(server('edge-t')?.inputs.serverType).toBe('cx23');
    expect(server('db-t1')?.inputs.serverType).toBe('cx23');
  });
});
