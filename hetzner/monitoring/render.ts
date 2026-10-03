import { APP_HOST_IPS, HOST_IPS } from '@branchleft/hetzner-host';

import type { EdgeSite } from '../../siteTypes';
import {
  PAGE_REGISTER,
  renderPageReceiverBlock,
  renderPageRoute,
  type PageRegisterEntry,
} from './pageRegister';

/**
 * Renders the monitoring stack's Prometheus scrape configuration and alert
 * rules from the estate address plan and the hostname registry in `sites.ts`.
 * Pure string building, kept in step with the committed output by
 * `render.test.ts`. See render.md#module-overview for the rest.
 */

const GENERATED_BANNER = [
  '# Generated from sites.ts and hetzner/monitoring/render.ts.',
  '# Regenerate with `npm run render` in hetzner/. Hand edits are overwritten.',
];

/**
 * The estate hosts this stack watches, and whether each node_exporter target
 * is expected to answer today -- `app1`/`db1` have none yet, so only edge1's
 * node target contributes to `HostOrServiceDown` below. `ops1`'s own
 * membership and `expectedUp` flip are reviewed, never hand-edited; see
 * render.md#monitoredhost--monitored_node_hosts for why, and why the
 * membership below is reviewed rather than derived from `HOST_IPS` whole.
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
  { name: 'ops1', address: HOST_IPS.ops1, expectedUp: true },
];

/**
 * `mx1` is watched two ways, deliberately: liveness from outside (a
 * protocol-aware blackbox probe, never a bare TCP connect) and delivery
 * outcomes from inside (Stalwart's own exporter). See render.md#mx1s-two-watch-paths.
 */

/**
 * `db1`'s MySQL exporter is live, so unlike the `node` targets above this
 * one is expected to answer and pages when it does not -- the flip from
 * `false` is a hand edit satisfied by a deploy in another repo, which once
 * hid a four-day crash loop; see render.md#monitored_mysqld_host.
 */
export const MONITORED_MYSQLD_HOST: MonitoredHost = {
  name: 'db1',
  address: HOST_IPS.db1,
  expectedUp: true,
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
export const BLACKBOX_MODULE_SMTP_BANNER = 'smtp_banner';
export const BLACKBOX_MODULE_TLS_CONNECT = 'tls_connect';

/**
 * mx1 has no entry in the estate address plan -- it is not on this host's
 * private network, so there is no fixed private address to look one up by
 * -- so its DNS name is the address a probe uses, the same way blackbox_http
 * below reaches every sites.ts hostname by name rather than by IP.
 */
const MX1_HOSTNAME = 'mx1.branchleft.co.uk';

/**
 * The Stalwart exporter is reached by **address, not by name**: mx1's IPv6
 * (AAAA) half is not admitted by Stalwart's access-control rule, and naming
 * the address removes a Go dialer's own family choice rather than relying
 * on resolver preference. See render.md#mx1_public_ipv4.
 */
const MX1_PUBLIC_IPV4 = '167.233.252.240';

/**
 * Basic auth over TLS, password read from a file never committed --
 * `stack/render_alertmanager_config.py` writes it on the host before every
 * start, same as `alertmanager.yml`. A missing file just means
 * `up{job="stalwart"} == 0`, never a Prometheus start failure. See
 * render.md#stalwart_metrics_port.
 */
export const STALWART_METRICS_PORT = 443;
export const STALWART_METRICS_PATH = '/metrics/prometheus';
export const STALWART_METRICS_USERNAME = 'prometheus';
export const STALWART_METRICS_PASSWORD_FILE = '/etc/prometheus/mx1-metrics-password';

/**
 * One static_configs group per probe module: a job's `params:` block can
 * only carry one module for every target underneath it, so two modules in
 * one job need `__param_module` set as a target label instead -- a label
 * named `__param_<x>` becomes that query parameter at scrape time, which is
 * how blackbox_exporter's own multi-module examples do it.
 */
function mailProbeStaticConfig(ports: readonly number[], module: string): string {
  const targetLines = ports.map((port) => `          - ${MX1_HOSTNAME}:${port}`).join('\n');
  return [
    '      - targets:',
    targetLines,
    `        labels: {host: mx1, expected_up: 'true', __param_module: ${module}}`,
  ].join('\n');
}

function targetLabels(host: Pick<MonitoredHost, 'name' | 'expectedUp'>): string {
  return `{host: ${host.name}, expected_up: '${String(host.expectedUp)}'}`;
}

/**
 * Labels for services set up as inline scrape configs, expected to answer.
 * Each constant names a specific host and sets expected_up=true directly,
 * rather than deriving from MonitoredHost. See
 * render.md#edge1_service_labels--app1_service_labels for why
 * `alertmanager` and `prometheus` are both labelled `true` even though
 * a Prometheus outage can never actually be observed this way.
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
    '',
    '  - job_name: blackbox_mail',
    // Gentle by design: probing mail ports on a schedule is exactly the
    // traffic scan-ban watches for, so this runs a quarter as often as the
    // default scrape_interval rather than at it.
    '    scrape_interval: 60s',
    '    metrics_path: /probe',
    '    static_configs:',
    mailProbeStaticConfig([25, 587], BLACKBOX_MODULE_SMTP_BANNER),
    mailProbeStaticConfig([465, 993], BLACKBOX_MODULE_TLS_CONNECT),
    '    relabel_configs:',
    '      - source_labels: [__address__]',
    '        target_label: __param_target',
    '      - source_labels: [__param_target]',
    '        target_label: instance',
    '      - target_label: __address__',
    `        replacement: 'blackbox-exporter:${BLACKBOX_EXPORTER_PORT}'`,
    '',
    '  - job_name: stalwart',
    '    scheme: https',
    `    metrics_path: ${STALWART_METRICS_PATH}`,
    '    basic_auth:',
    `      username: ${STALWART_METRICS_USERNAME}`,
    `      password_file: ${STALWART_METRICS_PASSWORD_FILE}`,
    // Verification follows the hostname even though the target is an
    // address: without this the scrape would be checking the certificate
    // against an IP literal that is not in it, and TLS would fail closed on
    // a server that is answering correctly.
    '    tls_config:',
    `      server_name: ${MX1_HOSTNAME}`,
    '    static_configs:',
    `      - targets: ['${MX1_PUBLIC_IPV4}:${STALWART_METRICS_PORT}']`,
    `        labels: {host: mx1, expected_up: 'true'}`,
    '    relabel_configs:',
    '      - target_label: instance',
    `        replacement: '${MX1_HOSTNAME}:${STALWART_METRICS_PORT}'`,
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
    // The mirror of the two rules above: they are both scoped to
    // expected_up="true" by design, so neither one re-evaluates whether that
    // scoping is still correct. A target shipped and left at "false" is
    // invisible to both, indefinitely.
    '      - alert: ExpectedDownTargetAnswering',
    '        expr: max_over_time(up{expected_up="false"}[15m]) == 1',
    '        for: 5m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.job }} on {{ $labels.host }} is answering while labeled not expected to."',
    '          description: >-',
    '            HostOrServiceDown and ServiceFlapping both read',
    '            up{expected_up="true"}, so a target still carrying "false" gets',
    '            no coverage from either -- correct while the target genuinely',
    '            does not exist yet, silently wrong from the moment it ships.',
    '            max_over_time over a 15m window catches a target that answers',
    '            even once, crash-looping or clean, so this rule sees the same',
    '            shape a forgotten label hides from the other two. Warning, not',
    '            critical: the label itself says nobody depends on this target',
    '            today. Flip expected_up to true once the target is confirmed',
    '            live.',
    '',
    // In `estate` rather than a probes-style group: this reads a
    // Caddy-emitted counter local to edge1, the same class of signal as
    // ServiceFlapping above, not an external blackbox_exporter result.
    // Not scoped to members_magic_link_per_ip -- posture.ts's `rateLimit`
    // is 'off' today, but the expression has no zone label at all, so the
    // general zone is covered automatically the day that flips.
    '      - alert: RateLimitDecliningRealClients',
    '        expr: increase(caddy_rate_limit_declined_requests_total{key!~"172\\\\.(1[6-9]|2\\\\d|3[01])\\\\..*", key!=""}[15m]) > 0',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "Caddy declined at least one non-bridge rate-limited request in the last 15 minutes."',
    '          description: >-',
    '            key!="" excludes the keyless zone-aggregate series -- an absent',
    '            label reads as "" in PromQL, and without this exclusion the',
    '            alert double-counts every decline once under the aggregate and',
    '            once under its own key. key!~"172\\.(1[6-9]|2\\d|3[01])\\..*"',
    '            excludes the Docker bridge range: every decline on record today',
    '            is the loopback smoke test tripping the magic-link limiter at',
    '            172.18.0.1, and RUNBOOK-edge.md notes the bridge subnet itself',
    '            varies between 172.17 and 172.18, hence the whole /12 rather',
    '            than the literal address.',
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
    '            max_connections -> escalate the DB rung. Both inputs come from',
    '            the db1 mysqld_exporter, so this evaluates only while',
    '            MySQLUnreachable below is silent -- an exporter that cannot',
    '            read MySQL stops publishing these series rather than',
    '            publishing a safe-looking value, which is why the absence',
    '            needs its own rule.',
    '',
    '      - alert: MySQLUnreachable',
    '        expr: mysql_up == 0',
    '        for: 10m',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "db1 MySQL is not readable by its exporter."',
    '          description: >-',
    '            mysqld_exporter answers with a full 200 and mysql_up 0 when it',
    '            cannot reach or authenticate to MySQL, so up stays 1 and every',
    '            other MySQL rule quietly loses its inputs. HostOrServiceDown and',
    '            ServiceFlapping watch the exporter process; this watches whether',
    '            it can read the database.',
    '            Check MySQL itself first (db1: docker ps, then the mysql',
    '            container logs). If MySQL is healthy, this is the exporter',
    '            credential: mysqld_exporter v0.20.0 expands $ in a config value',
    '            as a shell variable, so a password containing one authenticates',
    '            as a truncated string while still serving 200. db/RUNBOOK-db.md',
    '            in branchLeft/ghost-platform carries the rotation.',
    '            for: 10m rather than 5m because a MySQL restart during a db',
    '            stack deploy produces mysql_up 0 legitimately for a minute or two.',
    '',
    '  - name: backup',
    // One group, not two -- both alerts watch the same producer.
    // TenantBackupAgeHigh is the producer-side signal, not a liveness
    // check; the or absent(...) branch covers the metric family vanishing
    // entirely. Warning, never page, off-host receiver. See
    // render.md#the-backup-rule-group.
    '    rules:',
    '      - alert: TenantBackupAgeHigh',
    '        expr: >-',
    '          (time() - backup_worker_last_success_timestamp_seconds > 129600)',
    '          or absent(backup_worker_last_success_timestamp_seconds)',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.tenant }}\'s last successful backup is over 36 hours old."',
    '          description: >-',
    '            backup_worker_last_success_timestamp_seconds only advances on',
    '            a floor-verified successful dump, so a stopped or',
    '            consistently-refused worker for one tenant leaves that',
    "            tenant's gauge frozen while every other tenant's keeps",
    '            advancing -- each tenant is its own series, so this fires for',
    '            the stale one alone. The `or absent(...)` half catches the',
    '            whole metric family vanishing -- the exporter down, or the',
    '            textfile deleted -- which the time() subtraction alone cannot',
    '            see, since subtracting from an absent series yields no series',
    '            at all, not a large number; that branch carries no tenant',
    '            label, unlike a single stale tenant firing on its own. 129600s',
    "            (36h) is 1.5x the nightly (24h) cadence, following this file's",
    '            own SNDSCollectorStale threshold convention -- LLD-9 names the',
    '            cadence, not a number of missed runs. Warning, never page: a',
    '            stale backup is not an outage on its own timescale. The scrape',
    "            wiring for the worker's own host -- the node_exporter",
    '            textfile-collector mount -- is a separate, host-specific',
    '            change; see RUNBOOK-monitoring.md for the bring-up shape once',
    '            that host is chosen. Per-tenant coverage is proved in',
    '            alert_rules_test.yml.',
    '',
    // Not `notify: on-host`: unlike an SNDS or mail-deferral alert, nothing
    // about this signal depends on a route that avoids mx1.
    //
    // No `for:` -- unlike every other alert in this group. The gauge is
    // written once per tenant per night and otherwise flat, so there is no
    // scrape-to-scrape flapping to debounce, and paging on the very next
    // scrape after a bad wait is the intended behaviour, not a shortcut.
    '      - alert: BackupLockWaitHigh',
    '        expr: backup_worker_lock_wait_seconds > 5',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.tenant }}\'s dump took over 5s from dial-in to its first byte."',
    '          description: >-',
    '            mysqldump --source-data=2 takes a brief, server-wide FLUSH TABLES',
    '            WITH READ LOCK to record the binlog position point-in-time recovery',
    '            depends on. This gauge is a PROXY for that wait, not a direct MySQL',
    '            read: it times from starting mysqldump to its first byte, which',
    "            also includes mysqldump's own TCP+TLS+auth connection to db1 --",
    '            a known, bounded overhead now that the real transport is wired',
    '            (RemoteMysqldumpTransport, a local subprocess with no separate',
    '            dial-in layer), but still not measured directly, so still a',
    '            proxy, not a settled lock-wait read (see',
    '            branchLeft/ghost-platform infra/provisioning/scripts/backup_worker.md#_lockwaittimer).',
    "            Dumping tenants strictly one at a time means two tenants' own",
    '            locks never queue against each OTHER, but a lock can still queue',
    '            behind ordinary write traffic on ANY tenant while it waits to be',
    '            granted -- this alert is that wait, per tenant, written whether or',
    '            not the dump that eventually ran past it also went on to pass its',
    '            own floor check. 5s is well past the sub-second wait',
    '            09-backup-and-recovery.html measured at toy scale; re-tune once',
    "            real-estate figures exist, the same as this group's own SNDS",
    '            thresholds.',
    '',
    '  - name: probes',
    '    rules:',
    '      - alert: BlackboxProbeFailed',
    // Excludes blackbox_mail rather than naming blackbox_http: every
    // blackbox job is covered by exactly one alert, and a job with no
    // dedicated alert of its own should still fall through to this one.
    '        expr: probe_success{job!="blackbox_mail"} == 0',
    '        for: 5m',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "{{ $labels.instance }} failed its external probe for 5 minutes."',
    '          description: "The blackbox_exporter replacement for the GCP uptime check (doc 14 §9.1), probing every hostname in sites.ts over HTTPS. Excludes blackbox_mail, which has its own MailHostDown alert below."',
    '',
    '      - alert: MailHostDown',
    '        expr: probe_success{job="blackbox_mail"} == 0',
    '        for: 5m',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "{{ $labels.instance }} failed its mail liveness probe for 5 minutes."',
    '          description: "smtp_banner and tls_connect validate the service, not just the socket -- a scan-banned or dead-backend connection completes the TCP handshake and then EOFs, so a plain connect check would stay green through this failure. A dedicated alertname rather than leaving this to BlackboxProbeFailed above: it is what the mailhost-deadman route in the Alertmanager template matches on, so this alert reaches a receiver that does not transit mx1 in addition to the mx1-routed email receiver. BlackboxProbeFailed excludes blackbox_mail, so exactly one of the two rules fires for a given probe."',
    '',
    // Stalwart's own counters, not a blackbox result: `probes` above watches
    // whether mx1 answers, this group watches what it does with the mail it
    // accepts. A host that is up and bouncing everything is indistinguishable
    // from a healthy one at the socket, and the difference is the whole of
    // the sender-reputation question.
    '  - name: mail-delivery',
    '    rules:',
    '      - alert: MailDeliveryFailureRatioHigh',
    '        expr: >-',
    '          (',
    '          (sum(increase(delivery_dsn_perm_fail[6h])) or vector(0))',
    '          +',
    '          (sum(increase(delivery_rcpt_to_rejected[6h])) or vector(0))',
    '          ) / sum(increase(delivery_completed[6h])) > 0.10',
    '          and sum(increase(delivery_completed[6h])) > 20',
    '        for: 30m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "Over 10% of mx1 delivery attempts in the last 6 hours failed permanently."',
    '          description: >-',
    '            A ratio rather than a threshold on a raw counter: a raw count',
    '            fires on volume, so it would page on a busy healthy day and',
    '            stay silent through a quiet poisoned one. Both numerator terms',
    '            carry `or vector(0)` because a counter Stalwart has never had',
    '            occasion to increment is absent from the exposition rather than',
    '            exported as zero -- and plain vector arithmetic drops the whole',
    '            expression when one side is missing, so without this the alert',
    '            would evaluate to nothing in exactly the state mx1 is in today.',
    '            The sum() around each term strips the instance labels so the',
    '            two terms and the denominator match on an empty label set. The',
    '            `> 20` floor keeps a two-message morning from paging on a',
    '            single bounce, where one failure is half the traffic.',
    '            This is the closest available proxy for sender reputation, not',
    '            a measure of it: complaint rate is reported by receiving',
    '            providers out of band and no self-hosted MTA can observe it.',
    '            See RUNBOOK-monitoring.md for what to do when this fires.',
    '',
    '      - alert: MailDeliveryVolumeSpike',
    '        expr: sum(increase(delivery_completed[1h])) > 200',
    '        for: 15m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "mx1 completed over 200 delivery attempts in the last hour."',
    '          description: >-',
    '            A ceiling, not a baseline-derived anomaly detector: this estate',
    '            has no legitimate reason to send at this rate today, and if it',
    '            ever does that is itself worth knowing. It is the leading',
    '            indicator the ratio alert above cannot be -- an abusive signup',
    '            flood inflates volume within the hour, while a bounce ratio',
    '            only moves once the far side starts rejecting, hours later. The',
    '            edge rate limiter is the control; this is the detection that',
    '            says the control was not enough. Re-tune the threshold from',
    '            observed volume once a fortnight of data exists.',
    '',
    '      - alert: MailDeliveryMetricsMissing',
    '        expr: absent(delivery_completed) and on() (up{job="stalwart"} == 1)',
    '        for: 30m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "mx1 is answering its metrics scrape but publishing no delivery counters."',
    '          description: >-',
    '            Both rules above divide by or threshold on delivery_completed.',
    '            If Stalwart renames it, drops it, or is reconfigured to a',
    '            metrics level that no longer includes delivery, those rules stop',
    '            evaluating and a broken rule reads exactly like a healthy mail',
    '            host -- which is the failure this whole target exists to avoid.',
    '            Gated on up == 1 so a scrape outage pages once, as',
    '            HostOrServiceDown, rather than twice here as well.',
    '',
    // Both deferral rules carry `notify: on-host`. The provider deferring mx1
    // is most often the one hosting ALERT_RECIPIENT_EMAIL, so an alert routed
    // there would queue behind the mail it reports on, and every retry would
    // add to the rate the provider is already refusing.
    '      - alert: MailDeliveryDeferred',
    '        expr: sum(increase(queue_rescheduled[6h])) > 5',
    '        labels:',
    '          severity: warning',
    '          notify: on-host',
    '        annotations:',
    '          summary: "A remote mail server deferred mx1 deliveries more than 5 times in 6 hours."',
    '          description: >-',
    '            queue_rescheduled counts retries mx1 schedules after a remote',
    "            4xx or a failed connection. Stalwart's counters carry no",
    '            recipient-domain label, so this cannot name the provider; the',
    '            likeliest is Gmail, whose 421 4.7.28 throttles a cold IP. The',
    '            baseline is 0-2 a day, so 5 in 6h is a provider refusing mx1',
    '            rather than one greylist. Never resend into a deferral -- the',
    "            queue's backoff is the right pacing. See RUNBOOK-monitoring.md.",
    '',
    '      - alert: MailDelayNotified',
    '        expr: >-',
    '          sum(increase(delivery_dsn_temp_fail[1h])) > 0',
    '          or',
    '          sum(delivery_dsn_temp_fail unless delivery_dsn_temp_fail offset 1h) > 0',
    '        labels:',
    '          severity: warning',
    '          notify: on-host',
    '        annotations:',
    '          summary: "mx1 told a sender their message is delayed."',
    '          description: >-',
    '            A delay DSN goes out only once a message has been stuck long',
    '            enough to warn its sender, so this is the point at which a',
    '            deferral became visible to someone -- a reader waiting on a',
    '            sign-in link, or an alert that has not arrived. Fires on the',
    '            first one. The unless-offset half catches the series being',
    '            born: Stalwart publishes a counter only once it has counted',
    '            something, and increase() cannot see a first sample.',
    '            See RUNBOOK-monitoring.md.',
    '  - name: alerting-pipeline',
    // Not folded into `probes` above: those alerts watch probe_success, an
    // external vantage point on the estate's own services. This one watches
    // whether Alertmanager's own delivery mechanism is working -- a property
    // of the pipeline that carries every other alert here, not of anything
    // it probes -- so it gets a group of its own rather than borrowing one
    // that means something else.
    '    rules:',
    '      - alert: AlertEmailDeliveryFailing',
    '        expr: increase(alertmanager_notifications_failed_total{integration="email"}[30m]) > 0',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "Alertmanager failed to deliver at least one email notification in the last 30 minutes."',
    '          description: >-',
    '            The alertmanager scrape job above only proves the process',
    '            answered a scrape, not that mx1 accepted a message it tried to',
    '            send -- this is the metric that would have caught the six-day',
    '            outage this repo failed to catch once already, because alert',
    '            email transits mx1 and "mail is down" is an alert delivered by',
    '            the thing that is down. Matched by the mailhost-deadman route',
    '            in the Alertmanager template, so this alert reaches a receiver',
    '            that does not depend on the path it is reporting as broken.',
    '',
    // Microsoft's own feedback-loop data, not a proxy -- see
    // render.md#the-snds-reputation-rule-group for why, and why every rule
    // here carries notify: on-host.
    '  - name: snds-reputation',
    '    rules:',
    '      - alert: SNDSComplaintRateHigh',
    '        expr: >-',
    '          (snds_complaint_rate > 0.001 and snds_message_volume > 50)',
    '          or',
    '          (snds_complaint_rate > 0.001 unless on(ip) snds_message_volume)',
    '        labels:',
    '          severity: warning',
    '          notify: on-host',
    '        annotations:',
    '          summary: "Microsoft SNDS reported a complaint rate over 0.1% for {{ $labels.ip }}."',
    '          description: >-',
    "            SNDS refreshes at most once a day, so this reports yesterday's",
    '            reputation snapshot, not a live rate -- treat "when did this fire"',
    '            as "as of Microsoft\'s last publish", not as the moment of the',
    '            complaints themselves. The volume floor keeps a handful of',
    '            complaints against a trickle of mail from paging, the same shape',
    "            as MailDeliveryFailureRatioHigh's `> 20`, but the second branch",
    '            bypasses it, per IP, for an IP that has no snds_message_volume',
    '            series of its own (`unless on(ip)` -- matched by ip, not blanket',
    "            `on()`: a global match would let one IP's real, present volume",
    '            satisfy the floor for a *different* IP that has none, which is',
    '            wrong regardless of which way it errs). A floor that silently',
    '            disabled the alert it was meant to only quiet would be worse',
    '            than no floor. Re-tune both numbers from observed volume once',
    '            real data exists. See RUNBOOK-monitoring.md for what to do when',
    '            this fires.',
    '',
    '      - alert: SNDSReputationRed',
    '        expr: snds_reputation_status{status="red"} == 1',
    '        labels:',
    '          severity: warning',
    '          notify: on-host',
    '        annotations:',
    '          summary: "Microsoft SNDS filter-result status for {{ $labels.ip }} is red."',
    '          description: >-',
    "            Microsoft's own red/yellow/green classification: red means most",
    '            or all mail from this IP is being routed to Junk, independent of',
    '            the complaint-rate figure above. Same daily-snapshot caveat as',
    "            SNDSComplaintRateHigh -- this is yesterday's status, not a live",
    '            reading.',
    '',
    '      - alert: SNDSCollectorStale',
    '        expr: >-',
    '          (time() - snds_collector_last_success_timestamp_seconds > 129600)',
    '          or absent(snds_collector_last_success_timestamp_seconds)',
    '        labels:',
    '          severity: warning',
    '          notify: on-host',
    '        annotations:',
    '          summary: "The SNDS collector has not published a successful snapshot in over 36 hours."',
    '          description: >-',
    '            Both rules above go silent, not critical, if this collector stops',
    '            running -- an absent-or-stale gauge reads exactly like a clean',
    "            reputation otherwise. 129600s (36h) is half again the collector's",
    '            own ~24h cadence, wide enough that one missed run does not page.',
    '            The `or absent(...)` half catches a collector that has never once',
    '            succeeded, which the time() subtraction alone cannot see --',
    '            subtracting from an absent series yields no series at all, not a',
    '            large number. This is the BACKSTOP, not the first signal:',
    '            SNDSCollectorFailing below fires within the hour on the same',
    '            underlying break, and SNDSAccessLinkExpiringSoon fires days before',
    '            the most likely cause of one. Reaching this alert without either of',
    '            those having fired first means the collector is not running at all',
    '            (timer disabled, host down, textfile directory unmounted) rather',
    '            than running and failing. See RUNBOOK-monitoring.md §14.',
    '',
    '      - alert: SNDSCollectorFailing',
    '        expr: snds_collector_last_run_success == 0',
    '        for: 1h',
    '        labels:',
    '          severity: warning',
    '          notify: on-host',
    '        annotations:',
    '          summary: "The SNDS collector\'s last run failed."',
    '          description: >-',
    '            Read straight off a gauge the collector rewrites on every run,',
    '            success or failure, rather than inferred from a timestamp that',
    '            stopped advancing -- so this fires within the hour instead of the',
    '            36h SNDSCollectorStale needs. That gap is the whole point: the',
    '            reputation metrics are deliberately LEFT AT THEIR LAST GOOD VALUES',
    '            across a failure (blanking them would read as "no complaints",',
    '            which is worse), so for those 36 hours a dashboard shows a green',
    '            reputation that nothing is actually refreshing. `for: 1h` rides out',
    '            a single transient fetch failure without paging, since the timer',
    '            runs every 6h and one bad run is not yet a problem. The journal',
    '            line from `journalctl -u snds-collector.service` names the cause;',
    '            an expired or malformed automated-access link is the most likely',
    '            one (RUNBOOK-monitoring.md §14).',
    '',
    '      - alert: SNDSCollectorNotRunning',
    '        expr: >-',
    '          time() - snds_collector_last_attempt_timestamp_seconds > 43200',
    '        labels:',
    '          severity: warning',
    '          notify: on-host',
    '        annotations:',
    '          summary: "The SNDS collector has not attempted a run in over 12 hours."',
    '          description: >-',
    '            Every run rewrites this timestamp before anything else can fail,',
    '            so it stops advancing only if the collector did not run at all --',
    '            a disabled or failed timer, a host that is down, a textfile',
    '            directory that is no longer writable. That is a different fault',
    '            from SNDSCollectorFailing, which means the collector ran and the',
    '            fetch failed, and it is the one case where',
    '            snds_collector_last_run_success cannot be trusted: a process',
    '            killed before it publishes health leaves that gauge frozen at',
    '            whatever the last run wrote, which after a good run is a 1 that',
    '            actively asserts health. 43200s (12h) is two missed 6h ticks.',
    '            Deliberately not paired with `absent()` -- a collector that has',
    '            never run at all has no series here to be stale, and',
    "            SNDSCollectorStale's own `absent(...)` branch is what covers that.",
    '',
    '      - alert: SNDSLinkAgeUnmeasurable',
    '        expr: snds_link_state_readable == 0',
    '        for: 12h',
    '        labels:',
    '          severity: warning',
    '          notify: on-host',
    '        annotations:',
    '          summary: "The SNDS collector cannot persist the access link\'s age, so the expiry warning cannot fire."',
    '          description: >-',
    '            The collector records when it first saw the current',
    '            automated-access URL in a small state file beside its textfile',
    '            output, and measures the 30-day expiry from that. If that file',
    '            cannot be written, the age restarts on every run and',
    '            SNDSAccessLinkExpiringSoon -- the only alert in this group that',
    '            fires BEFORE an outage -- never reaches its threshold and so',
    '            never fires at all. That is a silent loss of the one',
    '            pre-emptive signal here, which is why it is alerted on rather',
    '            than left as a line in the journal. Check the filesystem under',
    '            /var/lib/branchleft/snds-exporter. `for: 12h` because a single',
    '            failed write is recoverable on the next 6h tick.',
    '',
    '      - alert: SNDSAccessLinkExpiringSoon',
    '        expr: time() - snds_access_link_first_seen_timestamp_seconds > 2160000',
    '        labels:',
    '          severity: warning',
    '          notify: on-host',
    '        annotations:',
    '          summary: "The SNDS automated-access link is approaching its 30-day expiry."',
    '          description: >-',
    '            Microsoft expires every SNDS automated-access link 30 days after it',
    '            is generated, and publishes that date in no response -- so this',
    '            measures from when the collector FIRST SAW the URL now configured,',
    '            which is the only observable proxy for it. 2160000s is 25 days,',
    '            leaving five days to rotate before the feed starts answering 404.',
    '            Rotating it is a portal visit and one line in monitoring.env',
    '            (RUNBOOK-monitoring.md §14); the collector notices the new URL by',
    '            itself and restarts this clock, with nothing to update here.',
    '            CAVEAT: first-seen lags generation by however long the new URL sat',
    '            between being generated and being pasted onto the host, so this',
    '            alert is optimistic by exactly that delay -- the five-day margin is',
    '            sized to absorb a normal one, not a link pasted a week late. This',
    '            is the only alert in this group that fires BEFORE an outage rather',
    '            than after one; treat it as a chore, not an incident.',
  ].join('\n')}\n`;
}

/**
 * Alertmanager's config template, its placeholder tokens substituted by
 * `stack/render_alertmanager_config.py` on the host before every start.
 * See render.md#renderalertmanagertemplate for the token list and why
 * `register` defaults to the committed `PAGE_REGISTER`.
 */
export function renderAlertmanagerTemplate(
  register: readonly PageRegisterEntry[] = PAGE_REGISTER
): string {
  const pageRoute = renderPageRoute(register);
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
    // Slow on purpose. Every message the email receiver sends is an external
    // delivery from mx1's IP, and unengaged repeats of machine mail are what
    // spent its Gmail reputation. group_interval bounds how often a group
    // whose membership keeps changing (a flapping target) can re-notify.
    '  group_interval: 1h',
    '  repeat_interval: 24h',
    '  routes:',
    '    - matchers:',
    '        - alertname = "Watchdog"',
    '      receiver: heartbeat',
    '      group_wait: 0s',
    '      group_interval: 1m',
    '      repeat_interval: 1m',
    // No `continue`: an on-host alert must never also reach the root email
    // receiver, whose recipient is off-host. See the notify label's rules.
    '    - matchers:',
    '        - notify = "on-host"',
    '      receiver: email-on-host',
    // Two sibling routes on the same matcher, not one: Alertmanager's route
    // tree falls back to the root's own receiver (email) only when *no*
    // child route matches at all, so a single matching child with
    // continue: true does not also deliver to email -- continue only
    // widens the search to later siblings. The second route below is that
    // later sibling; it is what actually puts email back in the result for
    // these two alertnames. Order matters: continue: true lives on the
    // first, and removing it stops the walk before the second is ever
    // reached, losing email delivery for exactly the two alerts this PR
    // exists to keep reaching someone.
    '    - matchers:',
    '        - alertname =~ "^(MailHostDown|AlertEmailDeliveryFailing)$"',
    '      receiver: mailhost-deadman',
    '      continue: true',
    '    - matchers:',
    '        - alertname =~ "^(MailHostDown|AlertEmailDeliveryFailing)$"',
    '      receiver: email',
    // Warnings never leave mx1: the off-host mailbox gets critical alerts
    // only. After the mail-host pair above, which are critical anyway.
    '    - matchers:',
    '        - severity = "warning"',
    '      receiver: email-on-host',
    // Rendered from the page register and nothing else -- see
    // `pageRegister.ts`. Empty when the register names no alertname to
    // route (every entry dormant or none delivered by Alertmanager), so no
    // stray route sits in the tree matching nothing.
    ...(pageRoute ? [pageRoute] : []),
    '',
    // An alert whose cause is already firing adds nothing but another
    // message. The first two key on `instance`, which both rules inherit
    // unchanged from the same `up` or mysqld series.
    'inhibit_rules:',
    '  - source_matchers:',
    '      - alertname = "HostOrServiceDown"',
    '    target_matchers:',
    '      - alertname = "ServiceFlapping"',
    "    equal: ['instance']",
    '  - source_matchers:',
    '      - alertname = "MySQLUnreachable"',
    '    target_matchers:',
    '      - alertname = "MySQLConnectionsHigh"',
    "    equal: ['instance']",
    '  - source_matchers:',
    '      - alertname = "MailHostDown"',
    '    target_matchers:',
    '      - alertname =~ "^(MailDeliveryFailureRatioHigh|MailDeliveryVolumeSpike|MailDeliveryMetricsMissing)$"',
    '',
    'receivers:',
    renderPageReceiverBlock(),
    '',
    '  - name: email',
    '    email_configs:',
    "      - to: '__ALERT_RECIPIENT_EMAIL__'",
    // false: a resolved notice is a second external delivery per incident,
    // and a flapping alert would send one for every flap.
    '        send_resolved: false',
    '',
    // A mailbox on mx1 itself: mx1 delivers it locally, so it never makes an
    // external delivery attempt and costs no sending reputation.
    '  - name: email-on-host',
    '    email_configs:',
    "      - to: 'rob@branchleft.co.uk'",
    '        send_resolved: true',
    '',
    '  - name: heartbeat',
    '    webhook_configs:',
    "      - url: '__HEALTHCHECKS_PING_URL__'",
    '        send_resolved: false',
    '',
    '  - name: mailhost-deadman',
    '    webhook_configs:',
    "      - url: '__MAILHOST_PING_URL__'",
    // false, not true: the URL is the check's /fail endpoint, which always
    // marks it down regardless of payload -- there is no "/fail but
    // resolved" semantic on the Healthchecks.io side. Sending a resolved
    // notification here would just hit /fail again; recovery on this check
    // only ever comes from a plain ping to its base URL, which nothing in
    // this stack sends, by design -- an operator clears it once the
    // underlying cause is fixed.
    '        send_resolved: false',
  ].join('\n')}\n`;
}
