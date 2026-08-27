import { APP_HOST_IPS, HOST_IPS } from '@branchleft/hetzner-host';

import type { EdgeSite } from '../../siteTypes';

/**
 * Renders the monitoring stack's Prometheus scrape configuration and alert
 * rules from the estate address plan and the hostname registry in `sites.ts`.
 *
 * Pure string building, deliberately -- the same discipline `../edge/render.ts`
 * uses and for the same reason: the output is committed under `stack/` and
 * copied onto the host by hand, so the only thing that can differ between what
 * a reviewer reads and what the host runs is the copy step. `render.test.ts` is
 * what keeps the committed files and this file from drifting apart.
 *
 * Alertmanager's own configuration is *not* rendered here in final form: it has
 * no way to read an environment variable from inside its config file, unlike
 * Caddy's `{env.X}`, so the committed file is a template carrying placeholder
 * tokens and `stack/render_alertmanager_config.py` substitutes them from
 * `/etc/branchleft/monitoring.env` on the host, once, before each start.
 *
 * ## The registry is the only hostname list
 *
 * A blackbox probe target written here rather than derived from `sites.ts`
 * is exactly the class of stray record a cutover has to hunt for. Every
 * hostname below is derived.
 */

const GENERATED_BANNER = [
  '# Generated from sites.ts and hetzner/monitoring/render.ts.',
  '# Regenerate with `npm run render` in hetzner/. Hand edits are overwritten.',
];

/**
 * The estate hosts this stack watches, and whether each node_exporter target
 * is expected to answer today. `app1` and `db1` are base-provisioned but
 * carry no node_exporter yet -- provisioning their exporters is a separate
 * story -- so `up{job="node", expected_up="true"} == 0` and only edge1's
 * node target contributes to the `HostOrServiceDown` alert `renderAlertRules`
 * emits below. A target that has never been available must not page anyone;
 * a target that stops answering after being available must.
 *
 * Deliberately not every entry in `HOST_IPS`/`APP_HOST_IPS`: `mon1`'s address
 * is reserved for the eventual split (doc 14 §3.1) and nothing listens there
 * yet, and `app2`/`app3` are scale-out rungs with no host behind them either.
 * Listing a reserved address as a scrape target is not a mistake this file
 * can catch on its own -- it would just be a target nobody set up, scraped
 * forever. The membership below is reviewed, not derived, for that reason.
 */
export interface MonitoredHost {
  name: string;
  address: string;
  expectedUp: boolean;
}

export const MONITORED_NODE_HOSTS: readonly MonitoredHost[] = [
  { name: 'edge1', address: HOST_IPS.edge1, expectedUp: true },
  { name: 'app1', address: APP_HOST_IPS.app1, expectedUp: false },
  { name: 'db1', address: HOST_IPS.db1, expectedUp: false },
];

/**
 * `mx1` is not, and cannot yet be, a target here -- unlike `app1`/`db1`
 * above, this is not "the exporter isn't provisioned yet" (a `db1`-style
 * `expectedUp: false` entry would still be a real, if currently-failing,
 * scrape). `mx1` lives in its own hcloud project (`edge/render.ts`'s
 * `NOT_AN_UPSTREAM` carries the same fact for the edge), so it shares no
 * private network with this host, and its firewall
 * (`mail/firewall.ts`) opens only mail protocol ports and the bulk-mail
 * shim's API -- nothing a Prometheus scrape could reach. Stalwart's own
 * metrics are not configured anywhere in this repo either, since `mail/`
 * carries no config-as-code for it. A rule against a metric with no
 * network path and no confirmed source would never evaluate, which is
 * worse than not having it -- it would read as covered. Filed instead of
 * built: the gap needs a network-path decision (a firewalled, authenticated
 * public endpoint on `mx1`, since no private path can exist across the
 * project boundary) and confirmation of what Stalwart can actually export,
 * neither of which is a rendering change.
 */

/** `db1`'s MySQL exporter lands in a parallel story; the target is listed now
 * so the scrape config and the alert rule are already correct when it does. */
export const MONITORED_MYSQLD_HOST: MonitoredHost = {
  name: 'db1',
  address: HOST_IPS.db1,
  expectedUp: false,
};

export const NODE_EXPORTER_PORT = 9100;
export const MYSQLD_EXPORTER_PORT = 9104;
export const CADVISOR_PORT = 8080;
export const BLACKBOX_EXPORTER_PORT = 9115;
export const ALERTMANAGER_PORT = 9093;
export const PROMETHEUS_PORT = 9090;

/**
 * Caddy's and CrowdSec's own metrics listeners, enabled by a scoped edit in
 * `../edge/render.ts` and `../edge/stack/compose.yml` respectively (see those
 * files). Both bind to `edge1`'s private address, published there by Compose
 * rather than to `0.0.0.0`, so nothing off the private network can reach
 * them -- this Prometheus container reaches them the same way any other
 * process on this host reaches a service bound to the host's own private
 * interface.
 */
export const CADDY_METRICS_PORT = 9091;
export const CROWDSEC_METRICS_PORT = 6060;

/**
 * The website's contact-form send-failure counter (doc 14 §9.2), served by
 * its own Compose service in `branchLeft/website`'s `deploy/compose.yml`,
 * bound to `app1`'s private address the same way Caddy's and CrowdSec's
 * metrics ports above are bound to `edge1`'s -- never through Caddy, never on
 * the public interface.
 */
export const WEBSITE_METRICS_PORT = 9092;

export const BLACKBOX_MODULE = 'http_2xx';

function targetLabels(host: Pick<MonitoredHost, 'name' | 'expectedUp'>): string {
  return `{host: ${host.name}, expected_up: '${String(host.expectedUp)}'}`;
}

/**
 * Labels for services running on edge1 that are expected to be up and
 * answerable at all times. Applied to all scrape targets for edge1 services
 * in the config above. `HostOrServiceDown`'s `expr` picks up every
 * `up{expected_up="true"}` series without any change to the alert rule itself.
 *
 * `alertmanager` is included for the same reason as the rest: Prometheus
 * keeps running and evaluating while only Alertmanager is down, so a
 * crash-and-restart still produces a real, if delayed, alert once
 * Alertmanager is back to receive it. `prometheus`'s own self-scrape cannot
 * behave the same way -- while the Prometheus process itself is down nothing
 * evaluates or records a sample at all, and the instant it restarts its
 * self-scrape immediately succeeds, so `up{job="prometheus"}==0` can never
 * be observed true for a sustained window. It is labelled `true` anyway for
 * consistency with `RUNBOOK-monitoring.md` §8's verification list, not
 * because this rule can ever catch a Prometheus outage: a sustained loss of
 * the whole monitoring stack is caught by the `Watchdog` heartbeat's
 * external dead-man's switch (`RUNBOOK-monitoring.md` §11) instead, which
 * observes from outside this process entirely.
 *
 * `blackbox_http` carries this label across multiple targets: one per
 * hostname in `sites.ts`. If the blackbox_exporter dies, `HostOrServiceDown`
 * fires once per probed hostname rather than once total. That is correct
 * behaviour — `up{job="blackbox_http"}` measures whether Prometheus can reach
 * the exporter, not whether a probe succeeded.
 */
const EDGE1_SERVICE_LABELS = targetLabels({ name: 'edge1', expectedUp: true });
const APP1_SERVICE_LABELS = targetLabels({ name: 'app1', expectedUp: true });

/**
 * The scrape config for one estate host's node_exporter. `edge1`'s own
 * exporter is a service in this same Compose project, reached by name;
 * `app1` and `db1` have no compose service here -- they are other hosts on
 * the private network, reached by the address plan's fixed address.
 */
function nodeTarget(host: MonitoredHost): string {
  const address =
    host.name === 'edge1'
      ? `node-exporter:${NODE_EXPORTER_PORT}`
      : `${host.address}:${NODE_EXPORTER_PORT}`;
  return `      - targets: ['${address}']\n        labels: ${targetLabels(host)}`;
}

/** Every hostname in the registry, in registry order -- both a site's serving
 * hostnames and its redirect sources, since a redirect is still a public
 * endpoint someone can hit and expect a 2xx-after-redirect chain from. */
export function blackboxTargets(sites: readonly EdgeSite[]): string[] {
  return sites.flatMap((site) => site.hostnames).map((hostname) => `https://${hostname}`);
}

export function renderPrometheusConfig(sites: readonly EdgeSite[]): string {
  const targets = blackboxTargets(sites);
  const nodeTargets = MONITORED_NODE_HOSTS.map(nodeTarget).join('\n');

  return `${[
    ...GENERATED_BANNER,
    'global:',
    '  scrape_interval: 30s',
    '  evaluation_interval: 30s',
    '',
    'alerting:',
    '  alertmanagers:',
    `    - static_configs:`,
    `        - targets: ['alertmanager:${ALERTMANAGER_PORT}']`,
    '',
    'rule_files:',
    '  - /etc/prometheus/alerts.yml',
    '',
    'scrape_configs:',
    '  - job_name: prometheus',
    '    static_configs:',
    `      - targets: ['localhost:${PROMETHEUS_PORT}']`,
    `        labels: ${EDGE1_SERVICE_LABELS}`,
    '',
    '  - job_name: alertmanager',
    '    static_configs:',
    `      - targets: ['alertmanager:${ALERTMANAGER_PORT}']`,
    `        labels: ${EDGE1_SERVICE_LABELS}`,
    '',
    '  - job_name: caddy',
    '    static_configs:',
    `      - targets: ['${HOST_IPS.edge1}:${CADDY_METRICS_PORT}']`,
    `        labels: ${EDGE1_SERVICE_LABELS}`,
    '',
    '  - job_name: crowdsec',
    '    static_configs:',
    `      - targets: ['${HOST_IPS.edge1}:${CROWDSEC_METRICS_PORT}']`,
    `        labels: ${EDGE1_SERVICE_LABELS}`,
    '',
    '  - job_name: website',
    '    static_configs:',
    `      - targets: ['${APP_HOST_IPS.app1}:${WEBSITE_METRICS_PORT}']`,
    `        labels: ${APP1_SERVICE_LABELS}`,
    '',
    '  - job_name: node',
    '    static_configs:',
    nodeTargets,
    '',
    '  - job_name: mysqld',
    '    static_configs:',
    `      - targets: ['${MONITORED_MYSQLD_HOST.address}:${MYSQLD_EXPORTER_PORT}']`,
    `        labels: ${targetLabels(MONITORED_MYSQLD_HOST)}`,
    '',
    '  - job_name: cadvisor',
    '    static_configs:',
    `      - targets: ['cadvisor:${CADVISOR_PORT}']`,
    `        labels: ${EDGE1_SERVICE_LABELS}`,
    '',
    '  - job_name: blackbox_http',
    '    metrics_path: /probe',
    '    params:',
    `      module: ['${BLACKBOX_MODULE}']`,
    '    static_configs:',
    '      - targets:',
    ...targets.map((target) => `          - ${target}`),
    `        labels: ${EDGE1_SERVICE_LABELS}`,
    '    relabel_configs:',
    '      - source_labels: [__address__]',
    '        target_label: __param_target',
    '      - source_labels: [__param_target]',
    '        target_label: instance',
    '      - target_label: __address__',
    `        replacement: 'blackbox-exporter:${BLACKBOX_EXPORTER_PORT}'`,
  ].join('\n')}\n`;
}

export function renderAlertRules(): string {
  return `${[
    ...GENERATED_BANNER,
    'groups:',
    '  - name: watchdog',
    '    rules:',
    '      - alert: Watchdog',
    '        expr: vector(1)',
    '        labels:',
    '          severity: none',
    '        annotations:',
    '          summary: "Heartbeat: the evaluate-and-dispatch path is alive."',
    '          description: >-',
    '            Always firing. Alertmanager routes it to the heartbeat receiver,',
    '            which pings Healthchecks.io on every notification cycle. Silence',
    '            here means Prometheus stopped evaluating rules or Alertmanager',
    '            stopped dispatching -- not that a real incident occurred.',
    '',
    '  - name: estate',
    '    rules:',
    '      - alert: HostOrServiceDown',
    '        expr: up{expected_up="true"} == 0',
    '        for: 5m',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "{{ $labels.job }} on {{ $labels.host }} has been unreachable for 5 minutes."',
    '          description: >-',
    '            Scoped to expected_up="true" targets only -- app1 and db1 carry',
    '            expected_up="false" until their node exporters are provisioned,',
    '            so targets without exporters do not page anyone.',
    '',
    '      - alert: ServiceFlapping',
    '        expr: changes(up{expected_up="true"}[15m]) > 4',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "{{ $labels.job }} on {{ $labels.host }} has restarted repeatedly in the last 15 minutes."',
    '          description: >-',
    '            Catches what HostOrServiceDown cannot: for: requires up == 0 to',
    '            hold continuously, so a container that restarts on a backoff loop',
    '            -- coming up just long enough to answer one scrape before dying',
    '            again -- never accumulates an unbroken outage window and resets',
    '            that timer every cycle. Counting transitions over a trailing',
    '            window instead of requiring continuous downtime is why this rule',
    '            carries no for: of its own -- adding one would reintroduce the',
    '            same blind spot one level up. Threshold assumes routine deploys',
    '            restart a service at most once or twice in any 15-minute span (at',
    '            most 4 transitions); a scrape interval of 30s gives a genuine',
    '            crash loop many more transitions than that inside the same',
    '            window. Scoped to expected_up="true" for the same reason as',
    '            HostOrServiceDown above.',
    '',
    '      - alert: HostMemoryPressure',
    '        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) > 0.75',
    '        for: 24h',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.instance }} has used over 75% of memory for 24 hours."',
    '          description: "doc 14 §4 scale-out trigger: app-host memory >75% sustained 24h -> provision the next host."',
    '',
    '      - alert: HostDiskSpaceLow',
    '        expr: >-',
    '          (1 - (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} /',
    '          node_filesystem_size_bytes{fstype!~"tmpfs|overlay"})) > 0.70',
    '        for: 15m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.instance }} filesystem {{ $labels.mountpoint }} is over 70% full."',
    '          description: "doc 14 §4 scale-out trigger: disk >70% anywhere -> grow the volume."',
    '',
    '      - alert: MySQLConnectionsHigh',
    '        expr: mysql_global_status_threads_connected / mysql_global_variables_max_connections > 0.70',
    '        for: 10m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "db1 is using over 70% of its MySQL connection budget."',
    '          description: >-',
    '            doc 14 §4 scale-out trigger: threads_connected >70% of',
    '            max_connections -> escalate the DB rung. No data until the db1',
    '            mysqld_exporter lands -- expected_up="false" on that target',
    '            means this simply has nothing to evaluate until then.',
    '',
    '  - name: probes',
    '    rules:',
    '      - alert: BlackboxProbeFailed',
    '        expr: probe_success == 0',
    '        for: 5m',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "{{ $labels.instance }} failed its external probe for 5 minutes."',
    '          description: "The blackbox_exporter replacement for the GCP uptime check (doc 14 §9.1), probing every hostname in sites.ts over HTTPS."',
  ].join('\n')}\n`;
}

/**
 * Alertmanager's config template. `__SMTP_USERNAME__`, `__SMTP_PASSWORD__`,
 * `__HEALTHCHECKS_PING_URL__` and `__ALERT_RECIPIENT_EMAIL__` are substituted
 * by `stack/render_alertmanager_config.py` from `/etc/branchleft/monitoring.env`
 * before every start -- see that script's docstring for why this file cannot
 * just read the environment itself.
 */
export function renderAlertmanagerTemplate(): string {
  return `${[
    ...GENERATED_BANNER,
    '# Rendered into alertmanager.yml at container start by',
    '# render_alertmanager_config.py. This file is never read directly.',
    'global:',
    "  smtp_smarthost: 'mx1.branchleft.co.uk:587'",
    "  smtp_from: 'alerts@branchleft.co.uk'",
    "  smtp_auth_username: '__SMTP_USERNAME__'",
    "  smtp_auth_password: '__SMTP_PASSWORD__'",
    '  smtp_require_tls: true',
    '',
    'route:',
    '  receiver: email',
    "  group_by: ['alertname']",
    '  group_wait: 30s',
    '  group_interval: 5m',
    '  repeat_interval: 3h',
    '  routes:',
    '    - matchers:',
    '        - alertname = "Watchdog"',
    '      receiver: heartbeat',
    '      group_wait: 0s',
    '      group_interval: 1m',
    '      repeat_interval: 1m',
    '',
    'receivers:',
    '  - name: email',
    '    email_configs:',
    "      - to: '__ALERT_RECIPIENT_EMAIL__'",
    '        send_resolved: true',
    '',
    '  - name: heartbeat',
    '    webhook_configs:',
    "      - url: '__HEALTHCHECKS_PING_URL__'",
    '        send_resolved: false',
  ].join('\n')}\n`;
}
