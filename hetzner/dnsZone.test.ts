import * as fs from 'node:fs';
import * as path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  assertDnsOnlyProject,
  checkDnsOnlyProject,
  rrsetResourceName,
  type RrsetSpec,
  validateZone,
  ZONE_FILES,
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
    const names = spec.rrsets.map((r) => rrsetResourceName(r));
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

  it('prefixes only when asked, so the first zone keeps the names already applied', () => {
    expect(rrsetResourceName({ name: '@', type: 'A' }, 'publicpress-co-uk')).toBe(
      'publicpress-co-uk-apex-a'
    );
    expect(rrsetResourceName({ name: '@', type: 'A' }, undefined)).toBe('apex-a');
    expect(rrsetResourceName({ name: '@', type: 'A' }, '')).toBe('apex-a');
  });
});

/**
 * The resource name is part of each rrset's URN. These are the names already
 * applied for branchleft.co.uk: a change to any one is a delete-and-create of
 * a live record, mail included, so the list is literal and any drift fails.
 */
const BRANCHLEFT_RESOURCE_NAMES = [
  'apex-a',
  'apex-mx',
  'apex-txt',
  '_acme-challenge-cname',
  '_acme-challenge.blog-cname',
  '_acme-challenge.www-cname',
  '_dmarc-txt',
  '_domainconnect-cname',
  'blog-a',
  'book-a',
  'cloud-a',
  'console-a',
  'google._domainkey-txt',
  'mx1-a',
  'mx1-aaaa',
  'ntfy-a',
  'v1-ed25519-20260811._domainkey-txt',
  'v1-rsa-20260811._domainkey-txt',
  'www-a',
];

describe('ZONE_FILES', () => {
  const read = (file: string) =>
    validateZone(JSON.parse(fs.readFileSync(path.join(__dirname, 'dns', file), 'utf8')));

  it('lists branchleft.co.uk first, with the URN parts already applied', () => {
    expect(ZONE_FILES[0]).toEqual({ file: 'zone.json', zoneResource: 'branchleft-co-uk' });
    const spec = read(ZONE_FILES[0].file);
    expect(spec.zone).toBe('branchleft.co.uk');
    expect(spec.rrsets.map((r) => rrsetResourceName(r, ZONE_FILES[0].rrsetPrefix))).toEqual(
      BRANCHLEFT_RESOURCE_NAMES
    );
  });

  it('adds publicpress.co.uk second, every resource name prefixed', () => {
    expect(ZONE_FILES).toHaveLength(2);
    const [, second] = ZONE_FILES;
    expect(second.zoneResource).toBe('publicpress-co-uk');
    const spec = read(second.file);
    expect(spec.zone).toBe('publicpress.co.uk');
    expect(spec.rrsets.length).toBeGreaterThan(0);
    for (const rrset of spec.rrsets) {
      expect(rrsetResourceName(rrset, second.rrsetPrefix)).toMatch(/^publicpress-co-uk-/);
    }
  });

  it('gives every zone and every rrset, across both zones, a distinct resource name', () => {
    const names = ZONE_FILES.flatMap((zoneFile) => [
      zoneFile.zoneResource,
      ...read(zoneFile.file).rrsets.map((r) => rrsetResourceName(r, zoneFile.rrsetPrefix)),
    ]);
    expect(new Set(names).size).toBe(names.length);
  });

  it('names each zone resource after its zone', () => {
    for (const zoneFile of ZONE_FILES) {
      expect(zoneFile.zoneResource).toBe(read(zoneFile.file).zone.replaceAll('.', '-'));
    }
  });
});

describe('the checked-in publicpress.co.uk zone', () => {
  const spec = validateZone(
    JSON.parse(fs.readFileSync(path.join(__dirname, 'dns', 'publicpress.co.uk.json'), 'utf8'))
  );
  const find = (name: string, type: string) =>
    spec.rrsets.find((r) => r.name === name && r.type === type)?.values ?? [];

  it('carries the mail-authentication records, so the move cannot silently drop them', () => {
    expect(find('@', 'MX').length).toBeGreaterThan(0);
    expect(find('@', 'TXT').some((v) => v.startsWith('"v=spf1 '))).toBe(true);
    expect(find('_dmarc', 'TXT').some((v) => v.startsWith('"v=DMARC1;'))).toBe(true);
    expect(find('s1-ionos._domainkey', 'CNAME')).toEqual(['s1.dkim.ionos.com.']);
    expect(find('s2-ionos._domainkey', 'CNAME')).toEqual(['s2.dkim.ionos.com.']);
  });
});

/**
 * Every record the IONOS zone holds, as the cutover must carry it: written out
 * here from the IONOS dig transcript (`captures/publicpress.co.uk.ionos-dig.txt`),
 * not read back from the zone file, so a record dropped from the file fails
 * here. The zone must hold these and nothing else.
 */
const PUBLICPRESS_CARRIED: RrsetSpec[] = [
  { name: '@', type: 'A', ttl: 3600, values: ['46.225.95.167'] },
  { name: '@', type: 'MX', ttl: 3600, values: ['10 mx00.ionos.co.uk.', '10 mx01.ionos.co.uk.'] },
  {
    name: '@',
    type: 'TXT',
    ttl: 3600,
    values: ['"v=spf1 ip4:167.233.252.240 ip6:2a01:4f8:1c18:866::1 -all"'],
  },
  { name: '_dmarc', type: 'TXT', ttl: 3600, values: ['"v=DMARC1; p=none; adkim=s; aspf=s"'] },
  {
    name: '_domainconnect',
    type: 'CNAME',
    ttl: 3600,
    values: ['_domainconnect.ionos.com.'],
  },
  { name: 'autodiscover', type: 'CNAME', ttl: 3600, values: ['adsredir.ionos.info.'] },
  {
    name: 'bl._domainkey',
    type: 'TXT',
    ttl: 3600,
    values: [
      '"v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxhILakyM7YDapZ0m2C/X8rwQzyXiZqAK2P7wAecrq3DIb018rk4Ts6RlFrMh5NHgGGAY6nKC+H7uRidtzU7Q3Qso1FnfdQWoV0SWPw8TbKh0OsdzsS67Qa9uzGFzWH9qzr7FvuPzfykWZR062/CAWDGcsrzQ0LbgVp5hNnymlSp3hsJjAdo6lSg" "KKOwaDw7Zl76C9POHlJjyabVcdOVAJF6uSaDwxiJ/6GX/pGPBRUErkWKnI35lNk3k2BpfraI88WeP3wPphdxUqqmUPoidKNk5Kc1++f4EtKpWmWcAgmLhXvlJIKx7vCiKOH15+th0K5O4/QnNz/Qk64mU17OksQIDAQAB"',
    ],
  },
  { name: 'id', type: 'A', ttl: 3600, values: ['46.225.95.167'] },
  { name: 'portal', type: 'A', ttl: 3600, values: ['46.225.95.167'] },
  { name: 's1-ionos._domainkey', type: 'CNAME', ttl: 3600, values: ['s1.dkim.ionos.com.'] },
  { name: 's2-ionos._domainkey', type: 'CNAME', ttl: 3600, values: ['s2.dkim.ionos.com.'] },
];

describe('the publicpress.co.uk zone holds exactly the records IONOS holds', () => {
  const spec = validateZone(
    JSON.parse(fs.readFileSync(path.join(__dirname, 'dns', 'publicpress.co.uk.json'), 'utf8'))
  );
  const key = (r: Pick<RrsetSpec, 'name' | 'type'>) => `${r.name} ${r.type}`;

  it('carries every IONOS record with the same name, type, TTL and values', () => {
    for (const expected of PUBLICPRESS_CARRIED) {
      expect(spec.rrsets, key(expected)).toContainEqual(expected);
    }
  });

  it('holds no record the IONOS list lacks', () => {
    expect(spec.rrsets.map(key).sort()).toEqual(PUBLICPRESS_CARRIED.map(key).sort());
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
