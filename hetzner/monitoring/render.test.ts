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

  /**
   * Extracted so the exemption mechanism is testable on its own -- proving a
   * job missing the label gets caught is not the same as proving a named
   * exemption actually suppresses that catch for the job it names, and only
   * that job. See the test below.
   */
  function jobsMissingExpectedUp(rendered: string, exempt: readonly string[]): string[] {
    const jobSections = rendered
      .split(/\n(?=  - job_name: )/)
      .filter((section) => /job_name: /.test(section));
    return jobSections.flatMap((section) => {
      const jobName = section.match(/job_name: (\S+)/)?.[1];
      if (!jobName || exempt.includes(jobName)) return [];
      return /expected_up: '(true|false)'/.test(section) ? [] : [jobName];
    });
  }

  // Jobs deliberately rendered without an expected_up label, named here
  // rather than skipped inline inside the assertion loop below. An inline
  // skip reads as "this job doesn't need checking" and survives unnoticed
  // when a new job is added; a named list is something a reviewer has to
  // look at and defend. Empty today -- every scrape job this estate runs,
  // blackbox_http included, carries the label, so a job missing it is
  // exactly the defect this test exists to catch.
  const JOBS_WITHOUT_EXPECTED_UP: readonly string[] = [];

  it('gives every scrape job an expected_up label, so HostOrServiceDown can see it, unless the job is named in the exemption list above', () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain('job_name: blackbox_http'); // guards against the regex above silently matching nothing
    expect(jobsMissingExpectedUp(rendered, JOBS_WITHOUT_EXPECTED_UP)).toEqual([]);
  });

  it('an exemption suppresses the check only for the job it names, not for every job', () => {
    const twoUnlabelledJobs = [
      '  - job_name: unlabelled_example',
      '    static_configs:',
      "      - targets: ['example:1234']",
      '',
      '  - job_name: also_unlabelled',
      '    static_configs:',
      "      - targets: ['example:5678']",
    ].join('\n');
    expect(jobsMissingExpectedUp(twoUnlabelledJobs, [])).toEqual([
      'unlabelled_example',
      'also_unlabelled',
    ]);
    expect(jobsMissingExpectedUp(twoUnlabelledJobs, ['unlabelled_example'])).toEqual([
      'also_unlabelled',
    ]);
  });

  it('marks crowdsec and caddy expected up on edge1 -- a down WAF or reverse proxy is the outage this fix exists for', () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain(
      "targets: ['10.20.1.10:9091']\n        labels: {host: edge1, expected_up: 'true'}"
    );
    expect(rendered).toContain(
      "targets: ['10.20.1.10:6060']\n        labels: {host: edge1, expected_up: 'true'}"
    );
  });

  it('marks the website contact-form metrics target expected up -- it is live on app1', () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain(
      "targets: ['10.20.1.100:9092']\n        labels: {host: app1, expected_up: 'true'}"
    );
  });

  it('marks cadvisor, prometheus and alertmanager expected up -- all three already run on edge1', () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain(
      "targets: ['cadvisor:8080']\n        labels: {host: edge1, expected_up: 'true'}"
    );
    expect(rendered).toContain(
      "targets: ['localhost:9090']\n        labels: {host: edge1, expected_up: 'true'}"
    );
    expect(rendered).toContain(
      "targets: ['alertmanager:9093']\n        labels: {host: edge1, expected_up: 'true'}"
    );
  });

  it('marks blackbox_http expected up -- BlackboxProbeFailed fires on probe_success == 0, which never exists if the exporter itself is down and no probe ever ran', () => {
    const rendered = renderPrometheusConfig(sites);
    const blackboxSection = rendered.slice(rendered.indexOf('  - job_name: blackbox_http'));
    expect(blackboxSection).toContain("labels: {host: edge1, expected_up: 'true'}");
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

  it('adds a flap detector alongside HostOrServiceDown, scoped the same way -- see alert_rules_test.yml for the promtool proof that it catches a flap HostOrServiceDown misses and ignores a single clean restart', () => {
    expect(rendered).toContain('alert: ServiceFlapping');
    expect(rendered).toContain('expr: changes(up{expected_up="true"}[15m]) > 4');
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
