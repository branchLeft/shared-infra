import { HOST_IPS, TENANTS_HOST_IPS } from '@branchleft/hetzner-host';

import type { MonitoredHost } from './render';

/**
 * The tenant hosts whose node_exporter is read through an SSH tunnel that
 * edge1 opens to edge-t, rather than directly on the tenants network. Each
 * tunnel lands on edge1's private address at its local port, and the
 * `node` job rewrites that address to the tenant's own `address:9100` in
 * `instance`, so alerts see the same series as a direct scrape would.
 * See render.md#tunnelled-tenant-node-targets.
 */
export interface TunnelledHost extends MonitoredHost {
  localPort: number;
}

export const TENANT_TUNNEL_BIND_ADDRESS = HOST_IPS.edge1;

export const TENANT_TUNNEL_TARGETS: readonly TunnelledHost[] = [
  { name: 'db-t1', address: TENANTS_HOST_IPS.dbT1, expectedUp: false, localPort: 19100 },
  { name: 'app-t1', address: TENANTS_HOST_IPS.appT1, expectedUp: false, localPort: 19101 },
  { name: 'edge-t', address: TENANTS_HOST_IPS.edgeT, expectedUp: false, localPort: 19102 },
];

export class TunnelRowMismatchError extends Error {}

/**
 * The direct node targets that still need a scrape of their own: every row
 * except the ones a tunnel stands in for. A direct row for a tunnelled host
 * must agree with its tunnel row on address and expectedUp, or the render
 * stops, so a host flipped in one place cannot quietly diverge from the other.
 */
export function hostsScrapedDirectly(
  hosts: readonly MonitoredHost[],
  tunnels: readonly TunnelledHost[]
): MonitoredHost[] {
  return hosts.filter((host) => {
    const tunnel = tunnels.find((candidate) => candidate.name === host.name);
    if (tunnel === undefined) {
      return true;
    }
    if (host.address !== tunnel.address || host.expectedUp !== tunnel.expectedUp) {
      throw new TunnelRowMismatchError(
        `direct node row for ${host.name} (${host.address}, expectedUp ${String(host.expectedUp)}) does not match its tunnel row (${tunnel.address}, expectedUp ${String(tunnel.expectedUp)})`
      );
    }
    return false;
  });
}
