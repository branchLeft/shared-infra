import { beforeAll, describe, expect, it } from 'vitest';

import { type Created, installTenantsMocks, ofType, settle, TYPES } from './tenants.fixtures';

/**
 * No metrics port is reachable from the public internet on any tenant host.
 * A Hetzner Cloud firewall filters the public
 * interface only, so the control that matters here is that no firewall the
 * tenants program declares has a rule for an exporter's port, from any source.
 * The exporters' own binds (the node exporter on the private address, the MySQL
 * exporter on loopback) are held in the roles' tests; the outside check on a
 * live host is the owner's step in `RUNBOOK-monitoring.md`.
 *
 * The program is run with both switches on, so db-t1 and app-t1 are declared
 * beside edge-t and every firewall of the project is read.
 */

let created: Created[] = [];
let metricsPorts: number[] = [];

beforeAll(async () => {
  created = installTenantsMocks({
    config: {
      'branchleft-hetzner-tenants:dbt1Enabled': 'true',
      'branchleft-hetzner-tenants:appt1Enabled': 'true',
    },
  });
  await import('./tenants.js');
  // The monitoring renderer imports the host package, which has its own Pulumi
  // SDK, so it is loaded after the mocks and the config, as the program is.
  const render = await import('./monitoring/render.js');
  metricsPorts = [
    render.NODE_EXPORTER_PORT,
    render.MYSQLD_EXPORTER_PORT,
    render.REPLICA_TUNNEL_METRICS_PORT,
    render.CADVISOR_PORT,
    render.BLACKBOX_EXPORTER_PORT,
    render.ALERTMANAGER_PORT,
    render.PROMETHEUS_PORT,
    render.CADDY_METRICS_PORT,
    render.CROWDSEC_METRICS_PORT,
    render.WEBSITE_METRICS_PORT,
  ];
  await settle();
}, 30_000);

type FirewallRule = { direction: string; protocol: string; port?: string; sourceIps: string[] };

/** A rule's port is one number or a range such as `9100-9200`. */
const covers = (rulePort: string, port: number): boolean => {
  const [low, high = low] = rulePort.split('-').map(Number);
  return port >= (low as number) && port <= (high as number);
};

describe('the tenant hosts expose no metrics port', () => {
  const firewalls = () => ofType(created, TYPES.firewall);

  it('declares a firewall for each of the three hosts', () => {
    expect(firewalls().map((firewall) => firewall.inputs.name)).toEqual(
      expect.arrayContaining(['edge-t', 'db-t1', 'app-t1'])
    );
  });

  it('has no inbound rule, from any source, covering an exporter port', () => {
    const opened = firewalls().flatMap((firewall) =>
      ((firewall.inputs.rules ?? []) as FirewallRule[])
        .filter((rule) => rule.port !== undefined)
        .flatMap((rule) =>
          metricsPorts
            .filter((port) => covers(String(rule.port), port))
            .map((port) => `${String(firewall.inputs.name)} opens ${port}`)
        )
    );
    expect(opened).toEqual([]);
  });

  it('opens nothing but SSH, HTTP, HTTPS and ICMP to the internet', () => {
    const anySource = firewalls().flatMap((firewall) =>
      ((firewall.inputs.rules ?? []) as FirewallRule[])
        .filter((rule) => rule.sourceIps.includes('0.0.0.0/0') || rule.sourceIps.includes('::/0'))
        .map((rule) => (rule.protocol === 'icmp' ? 'icmp' : String(rule.port)))
    );
    expect(anySource.filter((port) => !['443', '80', 'icmp', '22'].includes(port))).toEqual([]);
  });
});
