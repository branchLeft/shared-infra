import * as fs from 'node:fs';
import * as path from 'node:path';

import * as pulumi from '@pulumi/pulumi';
import { beforeAll, describe, expect, it } from 'vitest';

import { rrsetResourceName, ZONE_FILES } from './dnsZone';

/**
 * `dns.ts` under Pulumi's mock runtime: the program as it resolves, which a
 * test of `dnsZone.ts` alone cannot see -- the resource options, and that
 * every rrset in each zone file becomes exactly one resource with its values
 * intact. The mock answers `hcloud:index/getServers:getServers` with an empty
 * project and `hcloud:index/getFirewalls:getFirewalls` with the dns
 * project's own marker, which is the only project the program accepts --
 * see `dnsZone.ts`'s `assertDnsOnlyProject`.
 */

const zoneFiles = ZONE_FILES.map((zoneFile) => ({
  ...zoneFile,
  data: JSON.parse(fs.readFileSync(path.join(__dirname, 'dns', zoneFile.file), 'utf8')) as {
    zone: string;
    rrsets: { name: string; type: string; ttl: number; values: string[] }[];
  },
}));

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

const byKey = (a: { name: unknown; type: unknown }, b: { name: unknown; type: unknown }) =>
  `${a.name}/${a.type}`.localeCompare(`${b.name}/${b.type}`);

describe('dns.ts, as Pulumi resolves it', () => {
  const registered: Registered[] = [];
  let program: typeof import('./dns.js');

  const rrsetsOf = (zone: string) =>
    registered
      .filter((r) => r.type === 'hcloud:index/zoneRrset:ZoneRrset' && r.inputs.zone === zone)
      .map((r) => ({
        name: r.inputs.name,
        type: r.inputs.type,
        ttl: r.inputs.ttl,
        values: (r.inputs.records as { value: string }[]).map((record) => record.value),
      }));

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
    await Promise.all(
      program.zones.flatMap((z) => [z.zone, ...z.rrsets].map((r) => output(r.urn)))
    );
  });

  it('builds one zone per zone file, in order', () => {
    expect(program.zones.map((z) => z.name)).toEqual(['branchleft.co.uk', 'publicpress.co.uk']);
  });

  it('creates each zone as a primary zone, protected in both places', () => {
    const zones = registered.filter((r) => r.type === 'hcloud:index/zone:Zone');
    expect(zones.map((z) => z.name)).toEqual(['branchleft-co-uk', 'publicpress-co-uk']);
    for (const zone of zones) {
      expect(zone.inputs).toMatchObject({ mode: 'primary', deleteProtection: true });
    }
    expect(zones.map((z) => z.inputs.name)).toEqual(['branchleft.co.uk', 'publicpress.co.uk']);
    for (const built of program.zones) expect(resolvedProtect(built.zone)).toBe(true);
  });

  it('creates exactly one rrset per zone-file entry, values intact, in each zone', () => {
    for (const { data } of zoneFiles) {
      const expected = data.rrsets.map((r) => ({
        name: r.name,
        type: r.type,
        ttl: r.ttl,
        values: r.values,
      }));
      expect(rrsetsOf(data.zone).sort(byKey)).toEqual(expected.sort(byKey));
    }
  });

  it('points every rrset at its own zone and at no other', () => {
    const rrsets = registered.filter((r) => r.type === 'hcloud:index/zoneRrset:ZoneRrset');
    const total = zoneFiles.reduce((sum, { data }) => sum + data.rrsets.length, 0);
    expect(rrsets).toHaveLength(total);
    expect(new Set(rrsets.map((r) => r.inputs.zone))).toEqual(
      new Set(['branchleft.co.uk', 'publicpress.co.uk'])
    );
  });

  it("keeps branchleft.co.uk's resource names byte for byte, and prefixes publicpress.co.uk's", () => {
    // Registration order is not file order (the mock resolves asynchronously).
    const names = (zone: string) =>
      registered
        .filter((r) => r.type === 'hcloud:index/zoneRrset:ZoneRrset' && r.inputs.zone === zone)
        .map((r) => r.name)
        .sort();
    const [first, second] = zoneFiles;
    expect(names('branchleft.co.uk')).toEqual(
      first.data.rrsets.map((r) => rrsetResourceName(r, undefined)).sort()
    );
    expect(names('branchleft.co.uk')).toContain('apex-mx');
    expect(names('publicpress.co.uk')).toEqual(
      second.data.rrsets.map((r) => rrsetResourceName(r, 'publicpress-co-uk')).sort()
    );
    for (const name of names('publicpress.co.uk')) expect(name).toMatch(/^publicpress-co-uk-/);
  });

  it('leaves rrsets unprotected, so removing one from a zone file can delete it', () => {
    expect(program.zones.length).toBeGreaterThan(0);
    for (const built of program.zones) {
      expect(built.rrsets.length).toBeGreaterThan(0);
      for (const rrset of built.rrsets) expect(resolvedProtect(rrset)).not.toBe(true);
    }
  });
});
