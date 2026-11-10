import { describe, expect, it } from 'vitest';

import {
  assertSshSourceAddress,
  EDGE_RULES,
  edgeRulesSshFrom,
  INTERNAL_RULES,
  sshFromOneAddressViolations,
  sshRestrictedRules,
} from './firewalls';

/**
 * The control: SSH to a host that serves the web is accepted from one address
 * only. `sshFromOneAddressViolations` is the checking function, and the
 * "teeth" cases feed it a widened rule set and require a violation, so the red
 * is visible in CI without anyone editing the mechanism by hand.
 */

const EDGE1_PUBLIC = '203.0.113.10';

type Rule = (typeof EDGE_RULES)[number];

const ANY = ['0.0.0.0/0', '::/0'];

describe('edgeRulesSshFrom', () => {
  it('narrows SSH to the one address and leaves ICMP, 80 and 443 open to all', () => {
    const rules = edgeRulesSshFrom(EDGE1_PUBLIC);
    expect(rules).toEqual([
      { direction: 'in', protocol: 'tcp', port: '22', sourceIps: [`${EDGE1_PUBLIC}/32`] },
      { direction: 'in', protocol: 'icmp', sourceIps: ANY },
      { direction: 'in', protocol: 'tcp', port: '80', sourceIps: ANY },
      { direction: 'in', protocol: 'tcp', port: '443', sourceIps: ANY },
    ]);
    expect(sshFromOneAddressViolations(rules, EDGE1_PUBLIC)).toEqual([]);
  });

  it('does not change EDGE_RULES, which stay open for edge1', () => {
    edgeRulesSshFrom(EDGE1_PUBLIC);
    const ssh = EDGE_RULES.find((rule) => rule.port === '22');
    expect(ssh?.sourceIps).toEqual(ANY);
  });
});

describe('sshRestrictedRules', () => {
  it('narrows only the SSH rule of the internal set and keeps ICMP', () => {
    const rules = sshRestrictedRules(INTERNAL_RULES, EDGE1_PUBLIC);
    expect(rules.map((rule) => rule.port ?? rule.protocol)).toEqual(['22', 'icmp']);
    expect(rules[0]?.sourceIps).toEqual([`${EDGE1_PUBLIC}/32`]);
    expect(rules[1]?.sourceIps).toEqual(ANY);
  });

  it('refuses a rule set with no SSH rule or with two', () => {
    const icmp = EDGE_RULES.filter((rule) => rule.protocol === 'icmp');
    const ssh = EDGE_RULES.filter((rule) => rule.port === '22');
    expect(() => sshRestrictedRules(icmp, EDGE1_PUBLIC)).toThrow(/exactly one inbound tcp\/22/);
    expect(() => sshRestrictedRules([...ssh, ...ssh], EDGE1_PUBLIC)).toThrow(
      /exactly one inbound tcp\/22/
    );
  });
});

describe('assertSshSourceAddress', () => {
  it('accepts a public dotted quad and returns it', () => {
    expect(assertSshSourceAddress('95.216.10.20')).toBe('95.216.10.20');
    expect(assertSshSourceAddress(EDGE1_PUBLIC)).toBe(EDGE1_PUBLIC);
  });

  it.each([
    ['the unspecified address', '0.0.0.0'],
    ['the IPv6 unspecified address', '::'],
    ['an IPv6 loopback', '::1'],
    ['an IPv6 documentation address', '2001:db8::1'],
    ['a CIDR', '203.0.113.10/32'],
    ['a wide CIDR', '0.0.0.0/0'],
    ['a hostname', 'edge1.example.com'],
    ['the empty string', ''],
    ['a short dotted quad', '1.2.3'],
    ['a leading-zero octet', '01.2.3.4'],
    ['surrounding whitespace', ' 95.216.10.20'],
    ['a 10/8 address', '10.20.1.10'],
    ['a 172.16/12 address', '172.16.0.1'],
    ['a 192.168/16 address', '192.168.1.1'],
    ['a loopback address', '127.0.0.1'],
    ['a link-local address', '169.254.169.254'],
    ['a shared (CGNAT) address', '100.64.0.1'],
    ['a multicast address', '224.0.0.1'],
    ['the broadcast address', '255.255.255.255'],
    ['a reserved address', '240.0.0.1'],
  ])('refuses %s', (_label, value) => {
    expect(() => assertSshSourceAddress(value)).toThrow();
    expect(() => edgeRulesSshFrom(value)).toThrow();
  });
});

describe('sshFromOneAddressViolations (teeth)', () => {
  const good = (): Rule[] => edgeRulesSshFrom(EDGE1_PUBLIC);

  it('reports SSH widened to any source', () => {
    const widened = good().map((rule) => (rule.port === '22' ? { ...rule, sourceIps: ANY } : rule));
    const violations = sshFromOneAddressViolations(widened, EDGE1_PUBLIC);
    expect(violations.some((message) => message.includes('tcp/22 sources'))).toBe(true);
    expect(violations.some((message) => message.includes('open to any source'))).toBe(true);
  });

  it('reports SSH from a different address', () => {
    const wrong = good().map((rule) =>
      rule.port === '22' ? { ...rule, sourceIps: ['198.51.100.9/32'] } : rule
    );
    expect(sshFromOneAddressViolations(wrong, EDGE1_PUBLIC)).not.toEqual([]);
  });

  it('reports SSH from two addresses', () => {
    const two = good().map((rule) =>
      rule.port === '22' ? { ...rule, sourceIps: [`${EDGE1_PUBLIC}/32`, '198.51.100.9/32'] } : rule
    );
    expect(sshFromOneAddressViolations(two, EDGE1_PUBLIC)).not.toEqual([]);
  });

  it('reports an extra port even when it is narrow', () => {
    const extra = [
      ...good(),
      { direction: 'in', protocol: 'tcp', port: '3306', sourceIps: ['198.51.100.9/32'] } as Rule,
    ];
    expect(sshFromOneAddressViolations(extra, EDGE1_PUBLIC)).not.toEqual([]);
  });

  it('reports an extra port open to all', () => {
    const extra = [
      ...good(),
      { direction: 'in', protocol: 'tcp', port: '3306', sourceIps: ANY } as Rule,
    ];
    const violations = sshFromOneAddressViolations(extra, EDGE1_PUBLIC);
    expect(violations.some((message) => message.includes('tcp/3306 is open to any source'))).toBe(
      true
    );
  });

  it('reports a missing 443 and a missing SSH rule', () => {
    const noWeb = good().filter((rule) => rule.port !== '443');
    expect(sshFromOneAddressViolations(noWeb, EDGE1_PUBLIC)).not.toEqual([]);
    const noSsh = good().filter((rule) => rule.port !== '22');
    expect(sshFromOneAddressViolations(noSsh, EDGE1_PUBLIC)).not.toEqual([]);
  });

  it('reports the unmodified edge set, whose SSH is open to all', () => {
    expect(sshFromOneAddressViolations(EDGE_RULES, EDGE1_PUBLIC)).not.toEqual([]);
  });
});
