import { describe, expect, it } from 'vitest';

import {
  ADDRESS_REGISTER,
  APP_HOST_IPS,
  duplicateAddresses,
  HOST_IPS,
  SUBNET_CIDR,
  TENANTS_HOST_IPS,
} from './addressPlan';

/**
 * The tenants project reuses the estate's address range (the owner, 2 Nov 2026,
 * ruling 5a), so a register that every private address passes through is the
 * only thing that stops two hosts in two projects claiming one address.
 */

const subnetPrefix = SUBNET_CIDR.replace(/\.0\/24$/, '.');

describe('the address register', () => {
  it('holds no address twice, across both projects', () => {
    expect(duplicateAddresses(ADDRESS_REGISTER)).toEqual([]);
  });

  it('is built from the constants and covers org and tenants hosts', () => {
    const ips = ADDRESS_REGISTER.map((entry) => entry.ip).sort();
    const expected = [
      ...Object.values(HOST_IPS),
      ...Object.values(APP_HOST_IPS),
      ...Object.values(TENANTS_HOST_IPS),
    ].sort();
    expect(ips).toEqual(expected);
    expect(ADDRESS_REGISTER.filter((entry) => entry.project === 'tenants')).toEqual([
      { project: 'tenants', name: 'dbT1', ip: TENANTS_HOST_IPS.dbT1 },
      { project: 'tenants', name: 'edgeT', ip: TENANTS_HOST_IPS.edgeT },
    ]);
  });

  it('places every tenants host inside the subnet', () => {
    for (const ip of Object.values(TENANTS_HOST_IPS)) {
      expect(ip.startsWith(subnetPrefix)).toBe(true);
    }
  });

  it('keeps db-t1 and edge-t off every org address', () => {
    const org = new Set<string>([...Object.values(HOST_IPS), ...Object.values(APP_HOST_IPS)]);
    for (const ip of Object.values(TENANTS_HOST_IPS)) {
      expect(org.has(ip)).toBe(false);
    }
  });
});

describe('duplicateAddresses (teeth)', () => {
  it('refuses an address used in two projects', () => {
    const clash = [
      ...ADDRESS_REGISTER,
      { project: 'tenants' as const, name: 'dbT1', ip: HOST_IPS.db1 },
    ];
    const found = duplicateAddresses(clash);
    expect(found).toHaveLength(1);
    expect(found[0]).toContain(HOST_IPS.db1);
    expect(found[0]).toContain('org/db1');
    expect(found[0]).toContain('tenants/dbT1');
  });

  it('refuses an address used twice inside one project', () => {
    const clash = [
      ...ADDRESS_REGISTER,
      { project: 'tenants' as const, name: 'dbT2', ip: TENANTS_HOST_IPS.edgeT },
    ];
    expect(duplicateAddresses(clash)).toHaveLength(1);
  });

  it('is empty for an empty register', () => {
    expect(duplicateAddresses([])).toEqual([]);
  });
});
