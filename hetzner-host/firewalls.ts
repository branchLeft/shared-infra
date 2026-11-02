import { isIPv4 } from 'node:net';

import type * as hcloud from '@pulumi/hcloud';

/**
 * Per-role inbound rule sets for Hetzner Cloud firewalls.
 *
 * The constraint that shapes all of them: **a Hetzner Cloud firewall filters
 * the public interface only.** Traffic arriving over the private network is
 * never evaluated against these rules, so nothing here isolates one host from
 * another. Private-side exposure is controlled by what a service binds to —
 * a database or an exporter binds its private address, never `0.0.0.0` — and
 * that is a property of the host's Compose file, not of this file.
 *
 * Egress is left unrestricted deliberately. Hetzner's default with only
 * inbound rules present is to allow all outbound; adding any outbound rule
 * switches the host to default-deny, which silently breaks package updates,
 * ACME, registry pulls and outbound mail at the moment it is applied. That is
 * a change worth making with a specific allow-list per role, not as a
 * side effect of adding an inbound rule.
 */

type Rule = hcloud.types.input.FirewallRule;

const ANY_SOURCE = ['0.0.0.0/0', '::/0'];

/**
 * Management access is open to the internet on every role because deploys run
 * from GitHub-hosted runners, whose egress addresses are a large published
 * range that changes without notice — pinning it would turn a routine runner
 * pool change into an outage of the deploy path. Key-only auth, no root
 * login and fail2ban are what actually carry this exposure; see
 * provision/00-harden-ssh.sh.
 */
const SSH: Rule = {
  direction: 'in',
  protocol: 'tcp',
  port: '22',
  sourceIps: ANY_SOURCE,
};

/** Kept open on every role: without it path-MTU discovery blackholes, which
 * presents as large responses hanging rather than as a firewall problem. */
const ICMP: Rule = {
  direction: 'in',
  protocol: 'icmp',
  sourceIps: ANY_SOURCE,
};

/** The only role that terminates public traffic. Port 80 is not redundant
 * with 443: HTTP-01 challenge validation arrives there, and every certificate
 * the edge holds renews over HTTP-01. DNS-01 needs the zone served by an
 * API-driven provider (`hetzner/dns/`); closing 80 is only safe once every
 * hostname has moved to it. */
export const EDGE_RULES: Rule[] = [
  SSH,
  ICMP,
  { direction: 'in', protocol: 'tcp', port: '80', sourceIps: ANY_SOURCE },
  { direction: 'in', protocol: 'tcp', port: '443', sourceIps: ANY_SOURCE },
];

/**
 * App, database and monitoring hosts publish nothing publicly. Their service
 * ports are reachable from the edge and from each other over the private
 * network, which these rules neither permit nor deny — see the note above.
 */
export const INTERNAL_RULES: Rule[] = [SSH, ICMP];

/**
 * Address ranges that are never a sensible single SSH source: this-network,
 * private, shared (CGNAT), loopback, link-local, IETF protocol, benchmarking,
 * multicast and reserved space. A host that wants SSH from "the other host"
 * names that host's public address; an address from one of these ranges is a
 * mistake that would either match nothing or, worse, match something local.
 * Documentation ranges (TEST-NET) are allowed: they match nothing on the
 * internet, so they cannot widen access.
 */
const NEVER_A_SSH_SOURCE: readonly (readonly [string, number])[] = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

function ipv4ToNumber(address: string): number {
  return address.split('.').reduce((accumulator, octet) => accumulator * 256 + Number(octet), 0);
}

function inRange(address: number, [base, bits]: readonly [string, number]): boolean {
  const size = 2 ** (32 - bits);
  const start = ipv4ToNumber(base);
  return address >= start && address < start + size;
}

/**
 * Validates the one address a host may be reached by SSH from, and returns it
 * unchanged. Strict on purpose: a dotted-quad IPv4 address only (`isIPv4` from
 * `node:net` refuses leading zeros, which different parsers read as octal or
 * decimal), then not private, loopback, link-local, shared, multicast,
 * reserved or unspecified. A CIDR, an IPv6 address, a hostname and the empty
 * string are not dotted quads, so they are refused by the first test.
 */
export function assertSshSourceAddress(address: string): string {
  if (!isIPv4(address)) {
    throw new Error(
      `ssh source "${address}" is not a dotted-quad IPv4 address; give one public address, not a CIDR, an IPv6 address or a hostname`
    );
  }
  const numeric = ipv4ToNumber(address);
  const refused = NEVER_A_SSH_SOURCE.find((range) => inRange(numeric, range));
  if (refused !== undefined) {
    throw new Error(
      `ssh source ${address} is inside ${refused[0]}/${refused[1]}, which is not a public address`
    );
  }
  return address;
}

const isSshRule = (rule: Rule): boolean =>
  rule.direction === 'in' && rule.protocol === 'tcp' && rule.port === '22';

/**
 * The rule set with its one SSH rule narrowed to a single address. Nothing
 * else changes: this can narrow SSH and cannot add a port, widen a source or
 * drop another rule. A rule set that does not hold exactly one SSH rule is
 * refused rather than guessed at.
 */
export function sshRestrictedRules(rules: readonly Rule[], address: string): Rule[] {
  const source = `${assertSshSourceAddress(address)}/32`;
  if (rules.filter(isSshRule).length !== 1) {
    throw new Error('expected exactly one inbound tcp/22 rule to narrow');
  }
  return rules.map((rule) => (isSshRule(rule) ? { ...rule, sourceIps: [source] } : rule));
}

/** `EDGE_RULES` with SSH from one address only: 80, 443 and ICMP stay open to all. */
export function edgeRulesSshFrom(address: string): Rule[] {
  return sshRestrictedRules(EDGE_RULES, address);
}

const PUBLIC_WEB_PORTS = new Set(['80', '443']);

interface PlainRule {
  direction: string;
  protocol: string;
  port?: string;
  sourceIps: string[];
}

/** The rules as plain values: the checking function reads resolved rules only. */
const plain = (rules: readonly Rule[]): PlainRule[] => rules as unknown as PlainRule[];

/**
 * What a rule set must look like for a host reached by SSH from one address
 * and serving the web: returns one message per departure, so an empty list is
 * a pass. The inbound ports are exactly 22, 80, 443 and ICMP; the port-22 rule
 * has exactly the one /32 as its source; and no rule other than 80, 443 and
 * ICMP has an any-source. It reads plain rule values, so a caller resolves
 * outputs first.
 */
export function sshFromOneAddressViolations(rules: readonly Rule[], address: string): string[] {
  const violations: string[] = [];
  const view = plain(rules);
  const ssh = view.filter(
    (rule) => rule.direction === 'in' && rule.protocol === 'tcp' && rule.port === '22'
  );
  if (ssh.length !== 1) {
    violations.push(`expected exactly one tcp/22 rule, found ${ssh.length}`);
  }
  for (const rule of ssh) {
    const sources = JSON.stringify(rule.sourceIps);
    if (sources !== JSON.stringify([`${address}/32`])) {
      violations.push(`tcp/22 sources are ${sources}, want exactly ["${address}/32"]`);
    }
  }
  for (const rule of view.filter((candidate) => candidate.direction !== 'in')) {
    violations.push(
      `${rule.direction} rule ${rule.protocol}/${rule.port ?? ''}: only inbound rules are declared`
    );
  }
  const labels = view.map((rule) =>
    rule.protocol === 'icmp' ? 'icmp' : `${rule.protocol}/${rule.port ?? ''}`
  );
  const wanted = ['icmp', 'tcp/22', 'tcp/443', 'tcp/80'];
  if (JSON.stringify([...labels].sort()) !== JSON.stringify(wanted)) {
    violations.push(`rules are ${JSON.stringify(labels)}, want exactly ${JSON.stringify(wanted)}`);
  }
  for (const rule of view) {
    const open = rule.protocol === 'icmp' || PUBLIC_WEB_PORTS.has(rule.port ?? '');
    if (!open && rule.sourceIps.some((source) => source === '0.0.0.0/0' || source === '::/0')) {
      violations.push(`${rule.protocol}/${rule.port ?? ''} is open to any source`);
    }
  }
  return violations;
}
