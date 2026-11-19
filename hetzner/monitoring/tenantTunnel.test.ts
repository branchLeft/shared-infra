import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { TENANTS_HOST_IPS } from '@branchleft/hetzner-host';
import { describe, expect, it } from 'vitest';

import { sites } from '../../sites';
import * as renderModule from './render';
import { MONITORED_NODE_HOSTS, NODE_EXPORTER_PORT, renderPrometheusConfig } from './render';
import {
  hostsScrapedDirectly,
  TENANT_TUNNEL_BIND_ADDRESS,
  TENANT_TUNNEL_TARGETS,
  TunnelRowMismatchError,
} from './tenantTunnel';

/** The node job's section of the rendered config, from its job_name to the next job. */
function nodeJobSection(rendered: string): string {
  const start = rendered.indexOf('  - job_name: node\n');
  const end = rendered.indexOf('  - job_name: mysqld\n');
  return rendered.slice(start, end);
}

describe('the tunnelled node targets in the rendered config', () => {
  const rendered = renderPrometheusConfig(sites);
  const node = nodeJobSection(rendered);

  it('scrapes each tunnel on edge1 private address at its local port, labelled as a direct row', () => {
    expect(node).toContain(
      `targets: ['${TENANT_TUNNEL_BIND_ADDRESS}:19100']\n        labels: {host: db-t1, expected_up: 'false'}`
    );
    expect(node).toContain(
      `targets: ['${TENANT_TUNNEL_BIND_ADDRESS}:19101']\n        labels: {host: app-t1, expected_up: 'false'}`
    );
    expect(node).toContain(
      `targets: ['${TENANT_TUNNEL_BIND_ADDRESS}:19102']\n        labels: {host: edge-t, expected_up: 'false'}`
    );
  });

  it('adds one relabel rule per tunnel to the node job and no other job', () => {
    expect(node.match(/target_label: instance/g)).toHaveLength(3);
    expect(node).toContain("regex: '10\\.20\\.1\\.10:19100'");
    expect(node).toContain("regex: '10\\.20\\.1\\.10:19101'");
    expect(node).toContain("regex: '10\\.20\\.1\\.10:19102'");
  });

  it('rewrites each tunnel instance to the tenant address on the node exporter port', () => {
    const cases: readonly [string, string][] = [
      ['10.20.1.10:19100', `${TENANTS_HOST_IPS.dbT1}:${NODE_EXPORTER_PORT}`],
      ['10.20.1.10:19101', `${TENANTS_HOST_IPS.appT1}:${NODE_EXPORTER_PORT}`],
      ['10.20.1.10:19102', `${TENANTS_HOST_IPS.edgeT}:${NODE_EXPORTER_PORT}`],
    ];
    for (const [localAddress, instance] of cases) {
      const pattern = localAddress.replace(/\./g, '\\.');
      expect(node).toContain(
        `      - source_labels: [__address__]\n        regex: '${pattern}'\n        target_label: instance\n        replacement: '${instance}'`
      );
    }
  });

  it('keeps the direct rows for hosts that are not tunnelled', () => {
    expect(node).toContain(
      "targets: ['10.20.1.20:9100']\n        labels: {host: db1, expected_up: 'true'}"
    );
    expect(node).not.toContain(`${TENANTS_HOST_IPS.dbT1}:9100']`);
  });
});

describe('hostsScrapedDirectly', () => {
  const [dbT1Row, appT1Row, edgeTRow] = TENANT_TUNNEL_TARGETS.map((tunnel) => ({
    name: tunnel.name,
    address: tunnel.address,
    expectedUp: tunnel.expectedUp,
  }));
  const tenantRows = [dbT1Row, appT1Row, edgeTRow];

  it('renders each tenant host exactly once, as the tunnel, when the direct rows are present', () => {
    const hosts = [...MONITORED_NODE_HOSTS, ...tenantRows];
    const direct = hostsScrapedDirectly(hosts, TENANT_TUNNEL_TARGETS).map((host) => host.name);
    expect(direct).toEqual(MONITORED_NODE_HOSTS.map((host) => host.name));
    for (const tunnel of TENANT_TUNNEL_TARGETS) {
      expect(direct).not.toContain(tunnel.name);
    }
  });

  it('keeps every host when no tunnel stands in for it', () => {
    expect(hostsScrapedDirectly(MONITORED_NODE_HOSTS, [])).toEqual(MONITORED_NODE_HOSTS);
  });

  it('throws a named error when a direct row address differs from its tunnel', () => {
    const hosts = [...MONITORED_NODE_HOSTS, { ...dbT1Row, address: '192.0.2.1' }];
    expect(() => hostsScrapedDirectly(hosts, TENANT_TUNNEL_TARGETS)).toThrow(
      TunnelRowMismatchError
    );
  });

  it('throws a named error when a direct row expectedUp differs from its tunnel', () => {
    const hosts = [...MONITORED_NODE_HOSTS, { ...edgeTRow, expectedUp: true }];
    expect(() => hostsScrapedDirectly(hosts, TENANT_TUNNEL_TARGETS)).toThrow(
      TunnelRowMismatchError
    );
  });

  it('names the host in the mismatch message', () => {
    const hosts = [...MONITORED_NODE_HOSTS, { ...appT1Row, expectedUp: true }];
    expect(() => hostsScrapedDirectly(hosts, TENANT_TUNNEL_TARGETS)).toThrow(/app-t1/);
  });
});

describe('tunnel local ports', () => {
  const localPorts = TENANT_TUNNEL_TARGETS.map((tunnel) => tunnel.localPort);

  it('are three distinct ports', () => {
    expect(new Set(localPorts).size).toBe(3);
    expect(localPorts).toEqual([19100, 19101, 19102]);
  });

  it('collide with no *_PORT constant exported by render.ts', () => {
    const exportedPorts = Object.entries(renderModule)
      .filter(([name]) => name.endsWith('_PORT'))
      .map(([, value]) => value);
    expect(exportedPorts.length).toBeGreaterThan(0);
    for (const port of localPorts) {
      expect(exportedPorts).not.toContain(port);
    }
  });

  it('collide with no port published by the monitoring compose file', () => {
    const compose = readFileSync(join(__dirname, 'stack', 'compose.yml'), 'utf8');
    const published = [...compose.matchAll(/^\s*-\s*'([^']+)'\s*$/gm)]
      .map((match) => match[1] ?? '')
      .filter((mapping) => mapping.split(':').length === 3)
      .map((mapping) => Number(mapping.split(':')[1]));
    expect(published.length).toBeGreaterThan(0);
    for (const port of localPorts) {
      expect(published).not.toContain(port);
    }
  });

  it('collide with no sweego receiver port in the edge1 owner vars', () => {
    const ownerVars = readFileSync(
      join(__dirname, '..', '..', 'ansible', 'owner_vars', 'edge1.yml'),
      'utf8'
    );
    const sweegoPorts = [...ownerVars.matchAll(/^sweego_receiver\w*_port: (\d+)$/gm)].map((match) =>
      Number(match[1])
    );
    expect(sweegoPorts).toHaveLength(2);
    expect(sweegoPorts).toEqual(expect.arrayContaining([18080, 18081]));
    for (const port of localPorts) {
      expect(sweegoPorts).not.toContain(port);
    }
  });
});
