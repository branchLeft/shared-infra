import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { SUBNET_CIDR, TENANTS_HOST_IPS } from '@branchleft/hetzner-host';
import { describe, expect, it } from 'vitest';

import { internetEgressRoute } from './egress';

/**
 * The NAT reconciler takes no subnet parameter from the `egress_nat` role: it
 * forwards and masquerades the subnet written in its own default, and the
 * tenants network's subnet is the same `SUBNET_CIDR` (the owner, 2 Nov 2026, ruling
 * 5a keeps the range). The script runs on a host with no checkout to import
 * the plan from, so the equality is pinned here. If the two drift, the gateway
 * masquerades a subnet nothing is in and every private host loses its path out
 * while every check of the script itself stays green.
 */

const script = readFileSync(
  join(__dirname, '..', 'ansible', 'roles', 'egress_nat', 'files', 'branchleft_nat.py'),
  'utf8'
);

describe("edge-t's NAT subnet", () => {
  it("is the script's default subnet, which is the plan's SUBNET_CIDR", () => {
    const match = /^DEFAULT_SUBNET = "([^"]+)"$/m.exec(script);
    expect(match, 'the default subnet line of branchleft_nat.py').not.toBeNull();
    expect(match?.[1]).toBe(SUBNET_CIDR);
  });

  it('holds edge-t, at an address the route accepts and that is not reserved', () => {
    const prefix = SUBNET_CIDR.replace(/\.0\/24$/, '.');
    expect(TENANTS_HOST_IPS.edgeT.startsWith(prefix)).toBe(true);
    expect(() => internetEgressRoute(TENANTS_HOST_IPS.edgeT)).not.toThrow();
    const last = Number(TENANTS_HOST_IPS.edgeT.split('.')[3]);
    expect(last).toBeGreaterThan(1);
    expect(last).toBeLessThan(255);
  });
});
