import * as fs from 'node:fs';
import * as path from 'node:path';

import * as pulumi from '@pulumi/pulumi';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * `dns.ts` under Pulumi's mock runtime: the program as it resolves, which a
 * test of `dnsZone.ts` alone cannot see -- the resource options, and that
 * every rrset in the zone file becomes exactly one resource with its values
 * intact. The mock answers `hcloud:index/getServers:getServers` with an empty
 * project and `hcloud:index/getFirewalls:getFirewalls` with the dns
 * project's own marker, which is the only project the program accepts --
 * see `dnsZone.ts`'s `assertDnsOnlyProject`.
 */

const zoneFile = JSON.parse(fs.readFileSync(path.join(__dirname, 'dns', 'zone.json'), 'utf8'));

interface Registered {
  type: string;
  name: string;
  inputs: Record<string, unknown>;
}

function resolvedProtect(resource: pulumi.Resource): boolean | undefined {
  return (resource as unknown as { readonly __protect?: boolean }).__protect;
}

function output<T>(value: pulumi.Output<T>): Promise<T> {
  return new Promise((resolve) => value.apply(resolve));
}

describe('dns.ts, as Pulumi resolves it', () => {
  const registered: Registered[] = [];
  let program: typeof import('./dns.js');

  beforeAll(async () => {
    pulumi.runtime.setMocks(
      {
        newResource(args: pulumi.runtime.MockResourceArgs) {
          registered.push({ type: args.type, name: args.name, inputs: args.inputs });
          return { id: `${args.name}-id`, state: args.inputs };
        },
        call(args: pulumi.runtime.MockCallArgs) {
          if (args.token === 'hcloud:index/getServers:getServers') return { servers: [] };
          if (args.token === 'hcloud:index/getFirewalls:getFirewalls') {
            return { firewalls: [{ name: 'project-marker-dns' }] };
          }
          return {};
        },
      },
      'branchleft-hetzner-dns',
      'test',
      false
    );
    program = await import('./dns.js');
    await output(program.dnsOnlyProjectVerified);
    await Promise.all(program.rrsets.map((r) => output(r.urn)));
  });

  it('creates the zone as a primary zone, protected in both places', () => {
    const zone = registered.filter((r) => r.type === 'hcloud:index/zone:Zone');
    expect(zone).toHaveLength(1);
    expect(zone[0].inputs).toMatchObject({
      name: 'branchleft.co.uk',
      mode: 'primary',
      deleteProtection: true,
    });
    expect(resolvedProtect(program.zone)).toBe(true);
  });

  it('creates exactly one rrset per zone-file entry, values intact', () => {
    const rrsets = registered
      .filter((r) => r.type === 'hcloud:index/zoneRrset:ZoneRrset')
      .map((r) => ({
        name: r.inputs.name,
        type: r.inputs.type,
        ttl: r.inputs.ttl,
        values: (r.inputs.records as { value: string }[]).map((record) => record.value),
      }));
    const expected = zoneFile.rrsets.map((r: Record<string, unknown>) => ({
      name: r.name,
      type: r.type,
      ttl: r.ttl,
      values: r.values,
    }));
    const byKey = (a: { name: unknown; type: unknown }, b: { name: unknown; type: unknown }) =>
      `${a.name}/${a.type}`.localeCompare(`${b.name}/${b.type}`);
    expect(rrsets.sort(byKey)).toEqual(expected.sort(byKey));
  });

  it('points every rrset at the zone', () => {
    const zoneInputs = registered
      .filter((r) => r.type === 'hcloud:index/zoneRrset:ZoneRrset')
      .map((r) => r.inputs.zone);
    expect(new Set(zoneInputs)).toEqual(new Set(['branchleft.co.uk']));
  });

  it('leaves rrsets unprotected, so removing one from the zone file can delete it', () => {
    expect(program.rrsets.length).toBeGreaterThan(0);
    for (const rrset of program.rrsets) expect(resolvedProtect(rrset)).not.toBe(true);
  });
});
