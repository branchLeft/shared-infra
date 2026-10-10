import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

/**
 * The gate covers the resources the program declares. A provider resource
 * added outside the Host, and not wired to the verified value, would register
 * under a wrong-project token. This test reads the source and fails on any
 * provider resource declared directly, so the gap is a red test, not a review
 * finding. The two declared directly are gated in their own inputs.
 */

const source = readFileSync(join(__dirname, 'tenants.ts'), 'utf8');

describe('tenants program declarations', () => {
  it('declares directly only the network and subnet, both gated', () => {
    const direct = [...source.matchAll(/new hcloud\.(\w+)\(/g)].map((match) => match[1]);
    expect(direct).toEqual(['Network', 'NetworkSubnet']);
    expect(source).toMatch(/name: verified\('tenants'\)/);
    expect(source).toMatch(/networkId: verified\(tenantsNetwork\.id\)/);
  });

  it('declares the Host once, with the gate transformation', () => {
    expect([...source.matchAll(/new Host\(/g)].length).toBe(1);
    expect([...source.matchAll(/transformations: \[gateRegistration\]/g)]).toHaveLength(1);
  });

  it('gates the firewall, server and PrimaryIp through the transformation', () => {
    expect(source).toMatch(/'hcloud:index\/firewall:Firewall': 'name'/);
    expect(source).toMatch(/'hcloud:index\/server:Server': 'serverType'/);
    expect(source).toMatch(/'hcloud:index\/primaryIp:PrimaryIp': 'name'/);
  });
});
