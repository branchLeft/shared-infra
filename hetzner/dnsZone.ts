import * as hcloud from '@pulumi/hcloud';
import * as pulumi from '@pulumi/pulumi';

import { checkProjectResults } from './projectGuard';

/**
 * The checked-in zone file, validated into the rrsets the Hetzner zone is
 * built from. Everything here is pure so that it is covered by Vitest; the
 * program in `dns.ts` only constructs resources from what this returns.
 */

export interface RrsetSpec {
  name: string;
  type: string;
  ttl: number;
  values: string[];
}

export interface ZoneSpec {
  zone: string;
  rrsets: RrsetSpec[];
}

/** The types the Hetzner Cloud DNS API accepts in a primary zone. */
const SUPPORTED_TYPES = new Set([
  'A',
  'AAAA',
  'CAA',
  'CNAME',
  'DS',
  'HINFO',
  'HTTPS',
  'MX',
  'NS',
  'PTR',
  'RP',
  'SRV',
  'SVCB',
  'TLSA',
  'TXT',
]);

/** A zone-file TXT value: one or more double-quoted strings, space separated. */
const TXT_VALUE = /^"(?:[^"\\]|\\.)*"(?: "(?:[^"\\]|\\.)*")*$/;
const TXT_STRING = /"((?:[^"\\]|\\.)*)"/g;

/** Rdata fields holding a target name, which must be absolute. */
const TARGET_FIELD: Record<string, number> = { CNAME: 0, NS: 0, PTR: 0, MX: 1, SRV: 3 };

const NAME =
  /^(@|\*|(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*)$/;

/**
 * Every rule here refuses a zone that would apply cleanly and serve something
 * other than what the registrar serves today, which is the one outcome the
 * cutover cannot survive: the API accepts all of these.
 */
export function validateZone(input: unknown): ZoneSpec {
  const data = input as { zone?: unknown; rrsets?: unknown };
  if (typeof data?.zone !== 'string' || !Array.isArray(data.rrsets)) {
    throw new Error('zone file needs a `zone` name and an `rrsets` list');
  }
  const errors: string[] = [];
  const seen = new Set<string>();
  const typesByName = new Map<string, Set<string>>();
  const rrsets: RrsetSpec[] = [];

  for (const raw of data.rrsets as RrsetSpec[]) {
    const where = `${raw.name} ${raw.type}`;
    const key = `${raw.name}/${raw.type}`;
    if (seen.has(key)) errors.push(`${where}: appears twice`);
    seen.add(key);
    if (!NAME.test(raw.name)) errors.push(`${where}: not a relative owner name`);
    if (!SUPPORTED_TYPES.has(raw.type)) errors.push(`${where}: type not supported by the provider`);
    if (raw.name === '@' && (raw.type === 'NS' || raw.type === 'SOA')) {
      errors.push(`${where}: the serving provider owns the apex ${raw.type}`);
    }
    if (!Number.isInteger(raw.ttl) || raw.ttl < 60)
      errors.push(`${where}: ttl must be an integer >= 60`);
    if (!Array.isArray(raw.values) || raw.values.length === 0) {
      errors.push(`${where}: no values`);
      continue;
    }
    if (new Set(raw.values).size !== raw.values.length)
      errors.push(`${where}: a value appears twice`);
    for (const value of raw.values) errors.push(...valueProblems(where, raw.type, value));
    const types = typesByName.get(raw.name) ?? new Set<string>();
    types.add(raw.type);
    typesByName.set(raw.name, types);
    rrsets.push({ name: raw.name, type: raw.type, ttl: raw.ttl, values: [...raw.values] });
  }

  for (const [name, types] of typesByName) {
    if (types.has('CNAME') && types.size > 1) {
      errors.push(
        `${name}: a CNAME cannot share its name with ${[...types].filter((t) => t !== 'CNAME').join(', ')}`
      );
    }
    if (types.has('CNAME') && name === '@') errors.push('@: a CNAME cannot sit at the zone apex');
  }

  if (errors.length > 0) throw new Error(`invalid zone ${data.zone}:\n  ${errors.join('\n  ')}`);
  return { zone: data.zone, rrsets };
}

function valueProblems(where: string, type: string, value: string): string[] {
  if (type === 'TXT') {
    if (!TXT_VALUE.test(value)) return [`${where}: TXT value must be one or more quoted strings`];
    const tooLong = [...value.matchAll(TXT_STRING)].filter((m) => unescapedLength(m[1]) > 255);
    return tooLong.length > 0 ? [`${where}: a TXT string is longer than 255 characters`] : [];
  }
  const field = TARGET_FIELD[type];
  if (field !== undefined) {
    const target = value.split(/\s+/)[field];
    if (!target?.endsWith('.'))
      return [`${where}: target ${target ?? '(missing)'} must be absolute`];
  }
  return [];
}

function unescapedLength(text: string): number {
  return text.replace(/\\(\d{3}|.)/g, 'x').length;
}

/**
 * One stable resource name per rrset. It is part of the URN, so it must not
 * change when anything but the owner and type does -- a value edit is then an
 * update in place, never a delete-and-create that briefly serves nothing.
 */
export function rrsetResourceName(rrset: Pick<RrsetSpec, 'name' | 'type'>): string {
  const owner = rrset.name === '@' ? 'apex' : rrset.name;
  return `${owner}-${rrset.type.toLowerCase()}`;
}

/**
 * Fixed instructions for the `dns` project's own-marker check, below.
 * `projectGuard.ts` prints this after its own message rather than deriving a
 * per-project command, since only the caller knows the runbook to point at.
 */
const DNS_PROJECT_FIX =
  "Export the dns project's token as HCLOUD_TOKEN; see hetzner/dns/RUNBOOK-dns-cutover.md";

/**
 * Throws unless the token addresses the `dns` project, proven by its own
 * marker firewall (`project-marker-dns`) rather than only the absence of
 * servers.
 *
 * The zone lives in a project of its own because a Hetzner token has full
 * power over its project: a DNS-only project bounds a leaked token to DNS.
 * A servers-only check rules in the *shape* dns is meant to have, but every
 * other zero-server project (tenants and demos before their first apply,
 * backup, demo-dns) has that same shape — a token minted for any of them
 * would pass a servers-only check identically to the dns project's own
 * token, and a preview run against the wrong empty project plans a clean
 * create of the whole zone *there*, every record succeeding. Requiring the
 * project's own marker (`projectGuard.ts`'s `assertProject` with
 * `requireOwnMarker: true`) is what tells two empty projects apart. The
 * message names no server: a preview's output gets pasted into issues, and
 * a project's inventory does not belong there.
 */
export function assertDnsOnlyProject(
  serverNames: readonly string[],
  firewallNames: readonly string[]
): void {
  checkProjectResults(
    'dns',
    { servers: serverNames.map((name) => ({ name })) },
    { firewalls: firewallNames.map((name) => ({ name })) },
    DNS_PROJECT_FIX
  );
}

export function checkDnsOnlyProject(
  servers: { servers: { name: string }[] },
  firewalls: { firewalls: { name: string }[] }
): boolean {
  return checkProjectResults('dns', servers, firewalls, DNS_PROJECT_FIX);
}

/** Awaited by construction as a stack output, like `verifyEstateProject`. */
export function verifyDnsOnlyProject(): pulumi.Output<boolean> {
  return pulumi
    .all([pulumi.output(hcloud.getServers()), pulumi.output(hcloud.getFirewalls())])
    .apply(([servers, firewalls]) => checkDnsOnlyProject(servers, firewalls));
}
