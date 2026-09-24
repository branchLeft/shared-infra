import * as fs from 'node:fs';
import * as path from 'node:path';

import * as hcloud from '@pulumi/hcloud';

import { rrsetResourceName, validateZone, verifyDnsOnlyProject } from './dnsZone';

/**
 * The branchleft.co.uk zone at Hetzner DNS, built record for record from
 * `dns/zone.json`. The registrar stays the registrar; which provider actually
 * answers is decided by the NS records there, which this program never
 * touches. Until they are switched, applying this changes what nothing asks.
 */

export const dnsOnlyProjectVerified = verifyDnsOnlyProject();

const spec = validateZone(
  JSON.parse(fs.readFileSync(path.join(__dirname, 'dns', 'zone.json'), 'utf8'))
);

/**
 * The zone's own name, threaded through the guard rather than passed as a
 * literal. A sibling output the program never reads is not a gate: nothing
 * stops the engine registering the zone while the guard's invokes are still
 * in flight, or after they have failed. Deriving an actual create-time input
 * from `dnsOnlyProjectVerified` means the SDK's own input serialisation --
 * which every resource registration waits on before it calls the engine --
 * is what refuses to register the zone at all once the guard rejects. Every
 * `ZoneRrset` below takes `zone: zone.name` as input, so the same rejection
 * reaches them without repeating it.
 */
const verifiedZoneName = dnsOnlyProjectVerified.apply(() => spec.zone);

/**
 * `protect` and the provider's own delete protection both, because they
 * guard different hands: Pulumi's stops this program, Hetzner's stops the
 * console and every other token-holder. Deleting the zone deletes every
 * record in it at once. The rrsets are deliberately not children of it:
 * `protect` is inherited from a parent, and a protected rrset could never be
 * corrected by removing it from the zone file.
 */
export const zone = new hcloud.Zone(
  'branchleft-co-uk',
  {
    name: verifiedZoneName,
    mode: 'primary',
    ttl: 3600,
    deleteProtection: true,
    labels: { managedBy: 'pulumi', repo: 'shared-infra' },
  },
  { protect: true }
);

export const rrsets = spec.rrsets.map(
  (rrset) =>
    new hcloud.ZoneRrset(rrsetResourceName(rrset), {
      zone: zone.name,
      name: rrset.name,
      type: rrset.type,
      ttl: rrset.ttl,
      records: rrset.values.map((value) => ({ value })),
    })
);

/** What the registrar's NS records must name at the cutover, read from the API rather than copied. */
export const authoritativeNameservers = zone.authoritativeNameservers;
