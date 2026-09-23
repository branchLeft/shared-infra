import { describe, expect, it } from 'vitest';

import { MARKER_PREFIX, PROJECT_NAMES, PROJECTS, tokenConfigKey } from './projects';

describe('the project table', () => {
  it('names five projects, the four of the design plus the DNS-only one', () => {
    expect(PROJECT_NAMES).toEqual(['mail', 'org', 'tenants', 'demos', 'dns']);
  });

  it('gives every project a distinct marker derived from its name', () => {
    const markers = PROJECT_NAMES.map((name) => PROJECTS[name].marker);
    expect(new Set(markers).size).toBe(markers.length);
    for (const name of PROJECT_NAMES) {
      expect(PROJECTS[name].marker).toBe(`${MARKER_PREFIX}${name}`);
    }
  });

  it('places no server in two projects, which would make it a sentinel for both', () => {
    const all = PROJECT_NAMES.flatMap((name) => PROJECTS[name].servers);
    expect(new Set(all).size).toBe(all.length);
  });

  it('never lets a server name collide with a marker', () => {
    const servers = PROJECT_NAMES.flatMap((name) => PROJECTS[name].servers);
    expect(servers.some((server) => server.startsWith(MARKER_PREFIX))).toBe(false);
  });

  it('keeps the existing mail and org stacks on the default provider', () => {
    expect(PROJECTS.mail.explicitProvider).toBe(false);
    expect(PROJECTS.org.explicitProvider).toBe(false);
    expect(PROJECTS.tenants.explicitProvider).toBe(true);
    expect(PROJECTS.demos.explicitProvider).toBe(true);
    expect(PROJECTS.dns.explicitProvider).toBe(true);
  });

  it('keeps the DNS project free of hosts', () => {
    expect(PROJECTS.dns.servers).toEqual([]);
  });

  it('derives one token key per project', () => {
    expect(tokenConfigKey('tenants')).toBe('tenantsToken');
  });
});
