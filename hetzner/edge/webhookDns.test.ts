import * as fs from 'node:fs';
import * as path from 'node:path';

import { describe, expect, it } from 'vitest';

import { hostRedirects, sites, staticSites } from '../../sites';
import type { EdgeSite } from '../../siteTypes';
import { ZONE_FILES } from '../dnsZone';
import { POSTURE } from './posture';
import { renderCaddyfile } from './render';

// Why: see render.md section "siteBlock: inbound webhook", "Naming the hostname".

interface ZoneData {
  zone: string;
  rrsets: { name: string; type: string; values: string[] }[];
  probe_names: string[];
}

const zones: ZoneData[] = ZONE_FILES.map((entry) =>
  JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'dns', entry.file), 'utf8'))
);

/** A real, lowercase DNS name: never an ALL_CAPS placeholder or a stand-in. */
const REAL_HOSTNAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/** The zone that owns `hostname`, and the owner name inside it. */
function locate(hostname: string, all: ZoneData[]): { zone: ZoneData; owner: string } | undefined {
  for (const zone of all) {
    if (hostname === zone.zone) return { zone, owner: '@' };
    if (hostname.endsWith(`.${zone.zone}`)) {
      return { zone, owner: hostname.slice(0, -(zone.zone.length + 1)) };
    }
  }
  return undefined;
}

const addressesOf = (zone: ZoneData, owner: string): string[] =>
  zone.rrsets.filter((r) => r.name === owner && r.type === 'A').flatMap((r) => r.values);

/** What the edge's own hostnames resolve to today: the only address a site here may point at. */
function edgeAddresses(registry: EdgeSite[], all: ZoneData[]): Set<string> {
  const found = new Set<string>();
  for (const site of registry) {
    if (site.inboundWebhookPath !== undefined) continue;
    for (const hostname of site.hostnames) {
      const at = locate(hostname, all);
      if (at !== undefined) addressesOf(at.zone, at.owner).forEach((a) => found.add(a));
    }
  }
  return found;
}

/**
 * Everything wrong with the hostnames of every inbound-webhook site: a name
 * that is not a real hostname, one outside the managed zones, no address
 * record for it, one that points anywhere but the edge, or one the zone
 * comparison would never probe. An unnamed entry has none and so has no
 * problem: it serves nothing.
 */
function webhookDnsProblems(registry: EdgeSite[], all: ZoneData[]): string[] {
  const edge = edgeAddresses(registry, all);
  const problems: string[] = [];
  for (const site of registry.filter((s) => s.inboundWebhookPath !== undefined)) {
    for (const hostname of site.hostnames) {
      if (!REAL_HOSTNAME.test(hostname)) {
        problems.push(`${site.name}: ${hostname} is not a real hostname (a placeholder?)`);
        continue;
      }
      const at = locate(hostname, all);
      if (at === undefined) {
        problems.push(`${site.name}: ${hostname} is in no zone this repo manages`);
        continue;
      }
      const addresses = addressesOf(at.zone, at.owner);
      if (addresses.length === 0) problems.push(`${site.name}: no A record for ${hostname}`);
      for (const address of addresses) {
        if (!edge.has(address)) problems.push(`${site.name}: ${hostname} points at ${address}`);
      }
      if (!at.zone.probe_names.includes(at.owner)) {
        problems.push(`${site.name}: ${at.owner} is not in the zone's probe_names`);
      }
    }
  }
  return problems;
}

const registryEntry = sites.find((entry) => entry.name === 'sweego-webhook') as EdgeSite;

describe('the webhook hostname and the Hetzner zone', () => {
  it('the real registry has no placeholder hostname and, once named, a matching edge record', () => {
    expect(webhookDnsProblems(sites, zones)).toEqual([]);
  });

  it('no placeholder constant name reaches a zone file or the rendered edge configuration', () => {
    const rendered = renderCaddyfile(sites, hostRedirects, POSTURE, staticSites);
    const everything = [rendered, JSON.stringify(zones)].join('\n');
    expect(everything).not.toMatch(/WEBHOOK_HOSTNAME|WEBHOOK_PORT|undefined/);
  });

  it('is not vacuous: a placeholder hostname is refused', () => {
    const entry = { ...registryEntry, hostnames: ['WEBHOOK_HOSTNAME'] };
    expect(webhookDnsProblems([...sites, entry], zones).join('\n')).toMatch(/not a real hostname/);
  });

  it('is not vacuous: a named hostname with no record in the zone is refused', () => {
    const entry = { ...registryEntry, hostnames: ['hooks.branchleft.co.uk'] };
    expect(webhookDnsProblems([...sites, entry], zones).join('\n')).toMatch(/no A record/);
  });

  it('is not vacuous: a record pointing anywhere but the edge is refused', () => {
    const entry = { ...registryEntry, hostnames: ['hooks.branchleft.co.uk'] };
    const stray: ZoneData[] = zones.map((z) =>
      z.zone === 'branchleft.co.uk'
        ? {
            ...z,
            probe_names: [...z.probe_names, 'hooks'],
            rrsets: [...z.rrsets, { name: 'hooks', type: 'A', values: ['192.0.2.1'] }],
          }
        : z
    );
    expect(webhookDnsProblems([...sites, entry], stray).join('\n')).toMatch(/points at 192.0.2.1/);
  });

  it('is not vacuous: one record at the edge address, in the probe list, is accepted', () => {
    const entry = { ...registryEntry, hostnames: ['hooks.branchleft.co.uk'] };
    const edge = [...edgeAddresses(sites, zones)][0];
    const good: ZoneData[] = zones.map((z) =>
      z.zone === 'branchleft.co.uk'
        ? {
            ...z,
            probe_names: [...z.probe_names, 'hooks'],
            rrsets: [...z.rrsets, { name: 'hooks', type: 'A', values: [edge] }],
          }
        : z
    );
    expect(webhookDnsProblems([...sites, entry], good)).toEqual([]);
  });
});
