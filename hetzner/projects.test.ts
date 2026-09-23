import { describe, expect, it } from 'vitest';

import { MARKER_PREFIX, PROJECT_NAMES, PROJECTS } from './projects';

describe('the project table', () => {
  it('names seven projects, the four of the design plus dns, backup and demo-dns', () => {
    expect(PROJECT_NAMES).toEqual(['mail', 'org', 'tenants', 'demos', 'dns', 'backup', 'demo-dns']);
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

  it('keeps the DNS project free of hosts', () => {
    expect(PROJECTS.dns.servers).toEqual([]);
  });

  it('keeps the backup and demo-dns projects free of hosts, permanently', () => {
    expect(PROJECTS.backup.servers).toEqual([]);
    expect(PROJECTS['demo-dns'].servers).toEqual([]);
  });
});
