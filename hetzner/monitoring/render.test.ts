import { describe, expect, it } from 'vitest';

import { sites } from '../../sites';
import type { EdgeSite } from '../../siteTypes';
import {
  blackboxTargets,
  MONITORED_MYSQLD_HOST,
  MONITORED_NODE_HOSTS,
  renderAlertmanagerTemplate,
  renderAlertRules,
  renderPrometheusConfig,
} from './render';

/**
 * The file-snapshot assertions at the bottom are not snapshots in the usual
 * sense: `stack/` is what gets copied onto `edge1`, so those files *are* the
 * deployment, same discipline as `../edge/render.test.ts`. `npm run render`
 * updates them; `npm test` fails if they drift.
 */

const site = (overrides: Partial<EdgeSite> = {}): EdgeSite => ({
  name: 'example',
  hostnames: ['example.test'],
  cloudRunService: 'example-service',
  ...overrides,
});

describe('blackboxTargets', () => {
  it('derives one https:// target per hostname in the registry, in order', () => {
    const entries = [
      site({ hostnames: ['a.test', 'b.test'] }),
      site({ name: 'other', hostnames: ['c.test'] }),
    ];
    expect(blackboxTargets(entries)).toEqual([
      'https://a.test',
      'https://b.test',
      'https://c.test',
    ]);
  });

  it('includes a redirect source, not only a servable site', () => {
    // Unlike the edge renderer, a probe target has nothing to do with which
    // backend currently serves a hostname -- www.example.test redirecting to
    // example.test is still a live public endpoint someone can hit, and the
    // GCP uptime check this replaces watched it too.
    const pending = site({ hostnames: ['pending.test'] });
    expect(blackboxTargets([pending])).toEqual(['https://pending.test']);
  });

  it('leaves the real registry renderable whatever it currently declares', () => {
    expect(() => renderPrometheusConfig(sites)).not.toThrow();
    const targets = blackboxTargets(sites);
    for (const hostname of sites.flatMap((entry) => entry.hostnames)) {
      expect(targets).toContain(`https://${hostname}`);
    }
  });
});

describe('the rendered Prometheus config', () => {
  it('names every estate host membership, address-plan-derived rather than typed twice', () => {
    expect(MONITORED_NODE_HOSTS.map((host) => host.name)).toEqual(['edge1', 'app1', 'db1']);
    expect(MONITORED_NODE_HOSTS.find((host) => host.name === 'edge1')?.address).toBe('10.20.1.10');
    expect(MONITORED_NODE_HOSTS.find((host) => host.name === 'app1')?.address).toBe('10.20.1.100');
    expect(MONITORED_NODE_HOSTS.find((host) => host.name === 'db1')?.address).toBe('10.20.1.20');
  });

  it('marks only edge1 expected up -- app1 and db1 have no exporter yet', () => {
    expect(MONITORED_NODE_HOSTS.find((host) => host.name === 'edge1')?.expectedUp).toBe(true);
    expect(MONITORED_NODE_HOSTS.find((host) => host.name === 'app1')?.expectedUp).toBe(false);
    expect(MONITORED_NODE_HOSTS.find((host) => host.name === 'db1')?.expectedUp).toBe(false);
    expect(MONITORED_MYSQLD_HOST.expectedUp).toBe(false);
  });

  it('excludes reserved-but-unallocated estate members', () => {
    // mon1's address is reserved for the eventual split (doc 14 §3.1) and
    // app2/app3 are scale-out rungs -- none of the three has a host behind
    // it, so none is a scrape target.
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).not.toContain('10.20.1.30');
    expect(rendered).not.toContain('10.20.1.101');
    expect(rendered).not.toContain('10.20.1.102');
  });

  it("reaches edge1's own node_exporter by Compose service name, not by address", () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain("targets: ['node-exporter:9100']");
    expect(rendered).not.toContain('10.20.1.10:9100');
  });

  it('reaches app1 and db1 node_exporter by their fixed private address', () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain("targets: ['10.20.1.100:9100']");
    expect(rendered).toContain("targets: ['10.20.1.20:9100']");
  });

  it('lists the db1 mysqld_exporter target even though nothing answers it yet', () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain("targets: ['10.20.1.20:9104']");
    expect(rendered).toContain("labels: {host: db1, expected_up: 'false'}");
  });

  it("scrapes Caddy's and CrowdSec's metrics on edge1's private address, not a public one", () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain("targets: ['10.20.1.10:9091']");
    expect(rendered).toContain("targets: ['10.20.1.10:6060']");
  });

  it("scrapes the website's contact-form metric on app1's private address, not through Caddy", () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain('job_name: website');
    expect(rendered).toContain("targets: ['10.20.1.100:9092']");
  });

  it('scrapes itself and Alertmanager', () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain("targets: ['localhost:9090']");
    expect(rendered).toContain("targets: ['alertmanager:9093']");
    expect(rendered).toContain("- targets: ['alertmanager:9093']\n");
  });

  it('probes over HTTP via the blackbox multi-target pattern, one static target list from the registry', () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain('job_name: blackbox_http');
    expect(rendered).toContain('metrics_path: /probe');
    expect(rendered).toContain("module: ['http_2xx']");
    expect(rendered).toContain('target_label: __param_target');
    expect(rendered).toContain("replacement: 'blackbox-exporter:9115'");
    for (const hostname of sites.flatMap((entry) => entry.hostnames)) {
      expect(rendered).toContain(`- https://${hostname}`);
    }
  });

  it('names the Alertmanager rule file it loads', () => {
    expect(renderPrometheusConfig(sites)).toContain('/etc/prometheus/alerts.yml');
  });
});

describe('the rendered alert rules', () => {
  const rendered = renderAlertRules();

  it('always fires the Watchdog, so silence itself is the signal', () => {
    expect(rendered).toContain('alert: Watchdog');
    expect(rendered).toContain('expr: vector(1)');
  });

  it('scopes the host/service-down alert to expected targets only', () => {
    expect(rendered).toContain('alert: HostOrServiceDown');
    expect(rendered).toContain('expr: up{expected_up="true"} == 0');
  });

  it('carries doc 14 §4’s named scale-out thresholds exactly', () => {
    expect(rendered).toContain('> 0.75');
    expect(rendered).toContain('for: 24h');
    expect(rendered).toContain('> 0.70');
    expect(rendered).toContain('threads_connected');
  });

  it('alerts on a failed public probe', () => {
    expect(rendered).toContain('alert: BlackboxProbeFailed');
    expect(rendered).toContain('expr: probe_success == 0');
  });
});

describe('the Alertmanager template', () => {
  const rendered = renderAlertmanagerTemplate();

  it('routes through mx1 over STARTTLS, matching the pattern the rest of the platform uses', () => {
    expect(rendered).toContain("smtp_smarthost: 'mx1.branchleft.co.uk:587'");
    expect(rendered).toContain('smtp_require_tls: true');
  });

  it('carries placeholder tokens rather than a literal credential', () => {
    expect(rendered).toContain('__SMTP_USERNAME__');
    expect(rendered).toContain('__SMTP_PASSWORD__');
    expect(rendered).toContain('__HEALTHCHECKS_PING_URL__');
    expect(rendered).toContain('__ALERT_RECIPIENT_EMAIL__');
  });

  it('routes the Watchdog alert to the heartbeat receiver and nothing else there', () => {
    const routeSection = rendered.split('receivers:')[0];
    expect(routeSection).toContain('alertname = "Watchdog"');
    expect(routeSection).toContain('receiver: heartbeat');
  });

  it('pings a receiver that is not mx1 -- the whole point of the switch (doc 14 §9.2)', () => {
    expect(rendered).toContain('name: heartbeat');
    expect(rendered).toContain('webhook_configs');
  });
});

describe('the committed stack directory', () => {
  it('is what this renderer produces from the registry', async () => {
    await expect(renderPrometheusConfig(sites)).toMatchFileSnapshot(
      './stack/prometheus/prometheus.yml'
    );
    await expect(renderAlertRules()).toMatchFileSnapshot('./stack/prometheus/alerts.yml');
    await expect(renderAlertmanagerTemplate()).toMatchFileSnapshot(
      './stack/alertmanager/alertmanager.yml.tmpl'
    );
  });
});
