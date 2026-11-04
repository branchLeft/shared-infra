import * as fs from 'node:fs';
import * as path from 'node:path';

import * as hcloud from '@pulumi/hcloud';

import { rrsetResourceName, validateZone, verifyDnsOnlyProject, ZONE_FILES } from './dnsZone';

/**
 * The zones at Hetzner DNS -- branchleft.co.uk and publicpress.co.uk -- each
 * built record for record from its file in `dns/` (`ZONE_FILES`). The
 * registrar stays the registrar; which provider actually answers is decided
 * by the NS records there, which this program never touches. Until they are
 * switched, applying this changes what nothing asks.
 */

export const dnsOnlyProjectVerified = verifyDnsOnlyProject();

/**
 * One zone and its rrsets from one zone file. Every zone goes through this
 * one function, with the one guard, so a second zone cannot be built any
 * differently from the first.
 */
function buildZone(zoneFile: (typeof ZONE_FILES)[number]) {
  const spec = validateZone(
    JSON.parse(fs.readFileSync(path.join(__dirname, 'dns', zoneFile.file), 'utf8'))
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
  const zone = new hcloud.Zone(
    zoneFile.zoneResource,
    {
      name: verifiedZoneName,
      mode: 'primary',
      ttl: 3600,
      deleteProtection: true,
      labels: { managedBy: 'pulumi', repo: 'shared-infra' },
    },
    { protect: true }
  );

  const rrsets = spec.rrsets.map(
    (rrset) =>
      new hcloud.ZoneRrset(rrsetResourceName(rrset, zoneFile.rrsetPrefix), {
        zone: zone.name,
        name: rrset.name,
        type: rrset.type,
        ttl: rrset.ttl,
        records: rrset.values.map((value) => ({ value })),
      })
  );

  return { name: spec.zone, zone, rrsets };
}

export const zones = ZONE_FILES.map(buildZone);

/**
 * What the registrar's NS records must name at each cutover, read from the
 * API rather than copied. `authoritativeNameservers` stays the first zone's,
 * as before; the map names every zone.
 */
export const authoritativeNameservers = zones[0].zone.authoritativeNameservers;
export const authoritativeNameserversByZone = Object.fromEntries(
  zones.map((built) => [built.name, built.zone.authoritativeNameservers])
);
