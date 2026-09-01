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

  it('marks only edge1 node_exporter expected up -- app1 and db1 still have none', () => {
    // Verified against edge1's own target list on 2026-08-28: `node` on app1
    // and db1 both report `down`, so `false` is a current fact here rather
    // than an assumption inherited from when the constant was written.
    expect(MONITORED_NODE_HOSTS.find((host) => host.name === 'edge1')?.expectedUp).toBe(true);
    expect(MONITORED_NODE_HOSTS.find((host) => host.name === 'app1')?.expectedUp).toBe(false);
    expect(MONITORED_NODE_HOSTS.find((host) => host.name === 'db1')?.expectedUp).toBe(false);
  });

  it('marks the db1 mysqld_exporter expected up, because it is live', () => {
    expect(MONITORED_MYSQLD_HOST.expectedUp).toBe(true);
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

  it('scrapes the db1 mysqld_exporter and expects it to answer', () => {
    const rendered = renderPrometheusConfig(sites);
    expect(rendered).toContain("targets: ['10.20.1.20:9104']");
    expect(rendered).toContain("labels: {host: db1, expected_up: 'true'}");
    // That the label puts this target inside the set the two scoped rules
    // actually select over is proved in alert_rules_test.yml, against the
    // rendered rules themselves -- a string assertion here would pass just as
    // well with the rules scoped somewhere else entirely.
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

  describe('the mx1 Stalwart exporter, which is what the liveness probe cannot see', () => {
    const stalwartSection = (rendered: string) =>
      rendered.slice(rendered.indexOf('  - job_name: stalwart'));

    it('scrapes it over HTTPS on the existing public listener, needing no new firewall rule', () => {
      const section = stalwartSection(renderPrometheusConfig(sites));
      expect(section).toContain('scheme: https');
      expect(section).toContain('metrics_path: /metrics/prometheus');
    });

    it('targets the IPv4 address rather than the hostname, because the AAAA record is refused', () => {
      // Not a preference for addresses over names -- blackbox_mail right
      // above deliberately goes by name. Stalwart's access-control rule
      // admits edge1's public IPv4 only, so a scrape that resolves
      // mx1.branchleft.co.uk and reaches for its AAAA record first gets a
      // 421 from a server that is otherwise answering correctly. That is not
      // hypothetical: it is what happened to curl during the live
      // verification that built this endpoint.
      const section = stalwartSection(renderPrometheusConfig(sites));
      expect(section).toContain("targets: ['167.233.252.240:443']");
      expect(section).not.toContain("targets: ['mx1.branchleft.co.uk:443']");
    });

    it('still verifies the certificate against the hostname, and labels the target by it', () => {
      // Without server_name the scrape would check the certificate against an
      // IP literal that is not in it and fail closed on a healthy server --
      // trading one failure mode for another rather than fixing anything.
      const section = stalwartSection(renderPrometheusConfig(sites));
      expect(section).toContain('server_name: mx1.branchleft.co.uk');
      expect(section).toContain("replacement: 'mx1.branchleft.co.uk:443'");
    });

    it('reads the credential from a file, never from this config', () => {
      // stack/prometheus/prometheus.yml is committed to a public repository.
      const rendered = renderPrometheusConfig(sites);
      expect(stalwartSection(rendered)).toContain(
        'password_file: /etc/prometheus/mx1-metrics-password'
      );
      expect(rendered).not.toContain('password:');
    });

    it('marks mx1 expected up, so a missing credential file pages rather than going quiet', () => {
      // The whole failure mode of a password_file that was never written:
      // Prometheus starts fine, this one scrape fails, and without this label
      // nothing would ever say so.
      const section = stalwartSection(renderPrometheusConfig(sites));
      expect(section).toContain("labels: {host: mx1, expected_up: 'true'}");
    });
  });

  describe('the mx1 mail liveness probe', () => {
    it('probes mx1 by hostname, on the four ports the mail firewall opens', () => {
      const rendered = renderPrometheusConfig(sites);
      expect(rendered).toContain('job_name: blackbox_mail');
      expect(rendered).toContain('- mx1.branchleft.co.uk:25');
      expect(rendered).toContain('- mx1.branchleft.co.uk:587');
      expect(rendered).toContain('- mx1.branchleft.co.uk:465');
      expect(rendered).toContain('- mx1.branchleft.co.uk:993');
      // No IP literal for mx1 anywhere in this repo -- it is outside the
      // estate address plan projectGuard.ts polices.
      expect(rendered).not.toMatch(/\d+\.\d+\.\d+\.\d+.*mx1/);
    });

    it('reads the SMTP banner on 25 and 587, and only completes a TLS handshake on 465 and 993', () => {
      const rendered = renderPrometheusConfig(sites);
      const mailSection = rendered.slice(rendered.indexOf('  - job_name: blackbox_mail'));
      expect(mailSection).toContain(
        "targets:\n          - mx1.branchleft.co.uk:25\n          - mx1.branchleft.co.uk:587\n        labels: {host: mx1, expected_up: 'true', __param_module: smtp_banner}"
      );
      expect(mailSection).toContain(
        "targets:\n          - mx1.branchleft.co.uk:465\n          - mx1.branchleft.co.uk:993\n        labels: {host: mx1, expected_up: 'true', __param_module: tls_connect}"
      );
    });

    it('scrapes gently -- probing mail ports on a schedule is exactly what scan-ban watches for', () => {
      const rendered = renderPrometheusConfig(sites);
      const mailSection = rendered.slice(rendered.indexOf('  - job_name: blackbox_mail'));
      expect(mailSection).toContain('scrape_interval: 60s');
    });

    it('reuses the blackbox relabel pattern -- __param_target then instance, address rewritten to the exporter', () => {
      const rendered = renderPrometheusConfig(sites);
      const mailSection = rendered.slice(rendered.indexOf('  - job_name: blackbox_mail'));
      expect(mailSection).toContain('target_label: __param_target');
      expect(mailSection).toContain('target_label: instance');
      expect(mailSection).toContain("replacement: 'blackbox-exporter:9115'");
    });

    it('marks mx1 expected up, so a dead blackbox_mail target pages', () => {
      const rendered = renderPrometheusConfig(sites);
      const mailSection = rendered.slice(rendered.indexOf('  - job_name: blackbox_mail'));
      expect(mailSection).toContain("host: mx1, expected_up: 'true'");
    });
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

  it('alerts on MySQL being unreadable, which no up-based rule can see -- see alert_rules_test.yml for the promtool proof that it fires while up stays 1', () => {
    expect(rendered).toContain('alert: MySQLUnreachable');
    expect(rendered).toContain('expr: mysql_up == 0');
    // Deliberately not scoped by expected_up: the metric only exists at all
    // when the exporter is answering, so the target is up by construction.
    expect(rendered).not.toContain('mysql_up{expected_up="true"} == 0');
  });

  it('carries doc 14 §4’s named scale-out thresholds exactly', () => {
    expect(rendered).toContain('> 0.75');
    expect(rendered).toContain('for: 24h');
    expect(rendered).toContain('> 0.70');
    expect(rendered).toContain('threads_connected');
  });

  it('alerts on a failed public probe, excluding the mail job so it is not double-alerted with MailHostDown', () => {
    expect(rendered).toContain('alert: BlackboxProbeFailed');
    expect(rendered).toContain('expr: probe_success{job!="blackbox_mail"} == 0');
  });

  it('alerts on a failed mail liveness probe, scoped to the mail job so the alertname names the path', () => {
    expect(rendered).toContain('alert: MailHostDown');
    expect(rendered).toContain('expr: probe_success{job="blackbox_mail"} == 0');
  });

  it('alerts on Caddy declining a non-bridge, non-aggregate rate-limited request -- see alert_rules_test.yml for the promtool proof of both exclusions and of the general zone working once it is scoped in', () => {
    expect(rendered).toContain('alert: RateLimitDecliningRealClients');
    expect(rendered).toContain(
      'expr: increase(caddy_rate_limit_declined_requests_total{key!~"172\\\\.(1[6-9]|2\\\\d|3[01])\\\\..*", key!=""}[15m]) > 0'
    );
    // Not scoped to zone -- posture.ts's rateLimit is 'off' today, but the
    // expression must still cover the general zone the moment it flips.
    expect(rendered).not.toContain('members_magic_link_per_ip');
  });

  it('alerts on Alertmanager failing to deliver an email notification -- see alert_rules_test.yml for the promtool proof it is scoped to the email integration', () => {
    expect(rendered).toContain('alert: AlertEmailDeliveryFailing');
    expect(rendered).toContain(
      'expr: increase(alertmanager_notifications_failed_total{integration="email"}[30m]) > 0'
    );
  });
});

describe('the mail-delivery alert rules', () => {
  const rendered = renderAlertRules();

  it('measures failures as a ratio, never as a raw count', () => {
    // A raw-count threshold fires on volume: it pages on a busy healthy day
    // and stays silent through a quiet poisoned one, which is the opposite of
    // what a reputation signal has to do.
    expect(rendered).toContain('alert: MailDeliveryFailureRatioHigh');
    expect(rendered).toContain('/ sum(increase(delivery_completed[6h])) > 0.10');
  });

  it('defaults both failure counters to zero, because an unfired counter is absent rather than zero -- see alert_rules_test.yml for the promtool proof that it fires with only one of the two present', () => {
    expect(rendered).toContain('(sum(increase(delivery_dsn_perm_fail[6h])) or vector(0))');
    expect(rendered).toContain('(sum(increase(delivery_rcpt_to_rejected[6h])) or vector(0))');
  });

  it('watches for its own denominator disappearing, since a rule with no input reads exactly like a healthy mail host', () => {
    expect(rendered).toContain('alert: MailDeliveryMetricsMissing');
    expect(rendered).toContain(
      'expr: absent(delivery_completed) and on() (up{job="stalwart"} == 1)'
    );
  });

  it('carries a volume ceiling alongside the ratio, which is the only one of the two that moves inside the hour', () => {
    expect(rendered).toContain('alert: MailDeliveryVolumeSpike');
    expect(rendered).toContain('expr: sum(increase(delivery_completed[1h])) > 200');
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
    expect(rendered).toContain('__MAILHOST_PING_URL__');
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

  it('routes MailHostDown and AlertEmailDeliveryFailing to the mx1-independent receiver in addition to email, not instead of it', () => {
    // Alertmanager's route tree falls back to the root's own receiver only
    // when no child route matches at all -- a single matching child with
    // continue: true does not also reach it. Proving that requires two
    // sibling routes on the same matcher, not just the matcher's presence,
    // which is why this checks for both rather than one string.
    const routeSection = rendered.split('receivers:')[0];
    const matcherLine = 'alertname =~ "^(MailHostDown|AlertEmailDeliveryFailing)$"';
    const matches = routeSection.split(matcherLine).length - 1;
    expect(matches).toBe(2);
    expect(routeSection).toContain('receiver: mailhost-deadman');
    expect(routeSection).toContain('continue: true');
    // The mailhost-deadman sibling comes first: continue: true has to sit
    // on it for the second (email) sibling to ever be reached.
    expect(routeSection.indexOf('receiver: mailhost-deadman')).toBeLessThan(
      routeSection.lastIndexOf('receiver: email')
    );
  });

  it('does not send a resolved notification to the mailhost-deadman receiver', () => {
    // The URL is the Healthchecks.io check's /fail endpoint -- there is no
    // "/fail but resolved" semantic on the receiving end, so a resolved
    // notification here would just hit /fail again.
    const receiverSection = rendered.slice(rendered.indexOf('name: mailhost-deadman'));
    expect(receiverSection).toContain("url: '__MAILHOST_PING_URL__'");
    expect(receiverSection).toContain('send_resolved: false');
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
