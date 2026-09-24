import * as fs from 'node:fs';
import * as path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  assertDnsOnlyProject,
  checkDnsOnlyProject,
  rrsetResourceName,
  type RrsetSpec,
  validateZone,
} from './dnsZone';

const zoneFile = JSON.parse(fs.readFileSync(path.join(__dirname, 'dns', 'zone.json'), 'utf8'));

function zoneWith(...rrsets: RrsetSpec[]) {
  return { zone: 'example.test', rrsets };
}

const rr = (name: string, type: string, values: string[], ttl = 3600): RrsetSpec => ({
  name,
  type,
  ttl,
  values,
});

describe('the checked-in zone', () => {
  const spec = validateZone(zoneFile);
  const find = (name: string, type: string) =>
    spec.rrsets.find((r) => r.name === name && r.type === type)?.values ?? [];

  it('validates', () => {
    expect(spec.zone).toBe('branchleft.co.uk');
    expect(spec.rrsets.length).toBeGreaterThan(0);
  });

  it('carries the mail records, so the move cannot silently drop mail', () => {
    expect(find('@', 'MX')).toEqual(['10 mx1.branchleft.co.uk.']);
    expect(find('@', 'TXT').some((v) => v.startsWith('"v=spf1 '))).toBe(true);
    expect(find('_dmarc', 'TXT').some((v) => v.startsWith('"v=DMARC1;'))).toBe(true);
    expect(find('mx1', 'A')).toEqual(['167.233.252.240']);
    expect(find('mx1', 'AAAA')).toEqual(['2a01:4f8:1c18:866::1']);
    for (const selector of ['v1-ed25519-20260811._domainkey', 'v1-rsa-20260811._domainkey']) {
      expect(find(selector, 'TXT')[0]).toMatch(/^"v=DKIM1; /);
    }
  });

  it('gives every rrset a distinct resource name', () => {
    const names = spec.rrsets.map(rrsetResourceName);
    expect(new Set(names).size).toBe(names.length);
  });
});

describe('validateZone', () => {
  it('accepts a well-formed zone and returns its rrsets', () => {
    const spec = validateZone(
      zoneWith(
        rr('@', 'A', ['192.0.2.1']),
        rr('@', 'MX', ['10 mx1.example.test.']),
        rr('@', 'TXT', ['"v=spf1 -all"', '"a" "b"']),
        rr('_sip._tcp', 'SRV', ['0 5 5060 sip.example.test.']),
        rr('*.sites', 'A', ['192.0.2.2']),
        rr('www', 'CNAME', ['example.test.'])
      )
    );
    expect(spec.rrsets).toHaveLength(6);
  });

  it('rejects a file with no zone or no rrsets', () => {
    expect(() => validateZone({ rrsets: [] })).toThrow('needs a `zone`');
    expect(() => validateZone({ zone: 'x' })).toThrow('needs a `zone`');
    expect(() => validateZone(null)).toThrow('needs a `zone`');
  });

  it.each([
    [
      'a duplicate rrset',
      [rr('@', 'A', ['192.0.2.1']), rr('@', 'A', ['192.0.2.2'])],
      'appears twice',
    ],
    ['the apex NS', [rr('@', 'NS', ['ns1.example.'])], 'owns the apex NS'],
    ['the apex SOA', [rr('@', 'SOA', ['x'])], 'type not supported'],
    ['an unsupported type', [rr('@', 'SPF', ['"v=spf1"'])], 'type not supported'],
    ['a short ttl', [rr('@', 'A', ['192.0.2.1'], 30)], 'ttl must be'],
    ['a fractional ttl', [rr('@', 'A', ['192.0.2.1'], 60.5)], 'ttl must be'],
    ['no values', [rr('@', 'A', [])], 'no values'],
    ['a repeated value', [rr('@', 'A', ['192.0.2.1', '192.0.2.1'])], 'a value appears twice'],
    ['an absolute owner', [rr('www.example.test.', 'A', ['192.0.2.1'])], 'not a relative owner'],
    ['an upper-case owner', [rr('WWW', 'A', ['192.0.2.1'])], 'not a relative owner'],
    ['unquoted TXT', [rr('@', 'TXT', ['v=spf1 -all'])], 'quoted strings'],
    ['an over-long TXT string', [rr('@', 'TXT', [`"${'x'.repeat(256)}"`])], 'longer than 255'],
    ['a relative MX target', [rr('@', 'MX', ['10 mx1'])], 'must be absolute'],
    ['an MX with no target', [rr('@', 'MX', ['10'])], '(missing) must be absolute'],
    ['a relative CNAME target', [rr('www', 'CNAME', ['example.test'])], 'must be absolute'],
    ['a relative SRV target', [rr('_x._tcp', 'SRV', ['0 5 1 host'])], 'must be absolute'],
    [
      'a CNAME beside other data',
      [rr('www', 'CNAME', ['a.test.']), rr('www', 'TXT', ['"x"'])],
      'cannot share its name with TXT',
    ],
    ['a CNAME at the apex', [rr('@', 'CNAME', ['a.test.'])], 'cannot sit at the zone apex'],
  ])('rejects %s', (_label, rrsets, message) => {
    expect(() => validateZone(zoneWith(...rrsets))).toThrow(message);
  });

  it('counts an escaped TXT character once', () => {
    const value = `"${'x'.repeat(250)}\\"\\"\\"\\"\\""`;
    expect(() => validateZone(zoneWith(rr('@', 'TXT', [value])))).not.toThrow();
    const decimal = `"${'x'.repeat(254)}\\059"`;
    expect(() => validateZone(zoneWith(rr('@', 'TXT', [decimal])))).not.toThrow();
  });

  it('reports every problem at once, naming the zone', () => {
    expect(() => validateZone(zoneWith(rr('@', 'A', [], 1), rr('@', 'MX', ['10 x'])))).toThrow(
      /invalid zone example\.test:\n {2}@ A: ttl.*\n {2}@ A: no values\n {2}@ MX: target x must be absolute/
    );
  });
});

describe('rrsetResourceName', () => {
  it('is stable in owner and type and independent of values', () => {
    expect(rrsetResourceName({ name: '@', type: 'MX' })).toBe('apex-mx');
    expect(rrsetResourceName({ name: 'google._domainkey', type: 'TXT' })).toBe(
      'google._domainkey-txt'
    );
  });
});

describe('assertDnsOnlyProject', () => {
  it('passes the dns project on its own marker', () => {
    expect(() => assertDnsOnlyProject([], ['project-marker-dns'])).not.toThrow();
    expect(
      checkDnsOnlyProject({ servers: [] }, { firewalls: [{ name: 'project-marker-dns' }] })
    ).toBe(true);
  });

  it('refuses an empty project with no marker -- a servers-only check would have passed this', () => {
    expect(() => assertDnsOnlyProject([], [])).toThrow(
      /cannot see the firewall project-marker-dns/
    );
  });

  it('refuses another empty project on its own marker, not only a server -- this is the sabotage this guard exists to catch', () => {
    expect(() => assertDnsOnlyProject([], ['project-marker-demos'])).toThrow(
      /addresses the demos project, not the dns project/
    );
    expect(() => assertDnsOnlyProject([], ['project-marker-tenants'])).toThrow(
      /addresses the tenants project, not the dns project/
    );
  });

  it('still refuses a project holding a server', () => {
    expect(() => assertDnsOnlyProject(['edge1'], ['project-marker-dns'])).toThrow(
      /addresses the org project, not the dns project/
    );
    let message = '';
    try {
      assertDnsOnlyProject(['mx1', 'some-unrelated-host'], []);
    } catch (error) {
      message = String(error);
    }
    expect(message).toContain('mx1');
    expect(message).not.toContain('some-unrelated-host');
  });

  it('points at the runbook', () => {
    expect(() => assertDnsOnlyProject([], [])).toThrow(/RUNBOOK-dns-cutover\.md/);
  });
});

describe('checkDnsOnlyProject', () => {
  it('reads names out of both results the provider returns', () => {
    expect(
      checkDnsOnlyProject({ servers: [] }, { firewalls: [{ name: 'project-marker-dns' }] })
    ).toBe(true);
  });

  it('refuses when the marker is missing from the firewall result', () => {
    expect(() => checkDnsOnlyProject({ servers: [] }, { firewalls: [] })).toThrow(
      /project-marker-dns/
    );
  });
});
