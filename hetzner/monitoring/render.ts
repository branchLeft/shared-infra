import { APP_HOST_IPS, HOST_IPS, TENANTS_HOST_IPS } from '@branchleft/hetzner-host';

import type { EdgeSite } from '../../siteTypes';
import {
  PAGE_RECEIVER_NAME,
  PAGE_REGISTER,
  holdEdgeBanOwnerStale,
  renderDiscardReceiverBlock,
  renderEdgeBanOwnerStaleDiscardRoute,
  renderOwnedEdgeBanRoute,
  renderPageReceiverBlock,
  renderPageRoute,
  type PageRegisterEntry,
} from './pageRegister';
import {
  hostsScrapedDirectly,
  TENANT_TUNNEL_BIND_ADDRESS,
  TENANT_TUNNEL_TARGETS,
  type TunnelledHost,
} from './tenantTunnel';

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
 * is expected to answer today -- the first four are, so those node targets
 * contribute to `HostOrServiceDown` below; the tenant hosts that follow are
 * not yet. A host's membership and `expectedUp` flip are
 * reviewed, never hand-edited; see
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
  { name: 'app1', address: APP_HOST_IPS.app1, expectedUp: true },
  { name: 'db1', address: HOST_IPS.db1, expectedUp: true },
  { name: 'ops1', address: HOST_IPS.ops1, expectedUp: true },
  // The tenants project's three hosts, quiet until each is enrolled. Their
  // addresses are the tenants network's, which reuses the estate's range, so
  // nothing here is reachable from this stack until a scrape path across the
  // two projects exists; see render.md#the-tenant-hosts-node-targets.
  { name: 'db-t1', address: TENANTS_HOST_IPS.dbT1, expectedUp: false },
  { name: 'app-t1', address: TENANTS_HOST_IPS.appT1, expectedUp: false },
  { name: 'edge-t', address: TENANTS_HOST_IPS.edgeT, expectedUp: false },
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

/**
 * The replica host's MySQL exporter, read on db1's private address through
 * the tunnel's metrics forward (`../provision/branchleft-db-tunnel.service`).
 * See render.md#monitored_replica_host for the flip and the teardown.
 */
export const MONITORED_REPLICA_HOST: MonitoredHost = {
  name: 'db-t1',
  address: HOST_IPS.db1,
  expectedUp: false,
};
export const REPLICA_TUNNEL_JOB = 'db_t1_replica';
export const REPLICA_TUNNEL_METRICS_PORT = 9105;

/**
 * The instant after which the tunnel is no longer accepted: UTC, second
 * precision, `YYYY-MM-DDTHH:MM:SSZ`. Set in the same reviewed change that
 * flips `MONITORED_REPLICA_HOST.expectedUp`; see
 * render.md#replica_tunnel_deadline. Rendering refuses anything else.
 */
export const REPLICA_TUNNEL_DEADLINE = '2026-11-01T00:00:00Z';

/** Whole seconds since the epoch for a deadline, or a thrown error: never a rule that cannot fire. */
export function replicaDeadlineEpoch(deadline: unknown): number {
  const ms = typeof deadline === 'string' ? Date.parse(deadline) : Number.NaN;
  // The round trip rejects every spelling but the one documented above,
  // including impossible dates that Date.parse rolls over.
  if (
    Number.isNaN(ms) ||
    new Date(ms).toISOString() !== (deadline as string).replace('Z', '.000Z')
  ) {
    throw new Error(
      `REPLICA_TUNNEL_DEADLINE must be a UTC timestamp like 2026-11-01T00:00:00Z, got ${String(deadline)}`
    );
  }
  return ms / 1000;
}

const REPLICA_SELECTOR = `job="${REPLICA_TUNNEL_JOB}", expected_up="true"`;

// The classifier's two ways of going quiet: a last-run time more than 900
// seconds old (three timer periods), or no such series at all. `max` drops
// the series' own labels so both branches are the same unlabelled alert and a
// series appearing or vanishing does not restart `for`. The stale alert
// reads the series as absent at once (its `for` is the hold); the
// page-everything fallback reads it as absent only when no sample has been
// seen for ten minutes, so one lost scrape does not page every ban.
const EDGE_BAN_CLASSIFIER_LAST_RUN = 'edge_ban_owner_last_run_timestamp_seconds';
const EDGE_BAN_CLASSIFIER_OLD = `max(time() - ${EDGE_BAN_CLASSIFIER_LAST_RUN}) > 900`;
const EDGE_BAN_CLASSIFIER_STALE = `(${EDGE_BAN_CLASSIFIER_OLD}) or absent(${EDGE_BAN_CLASSIFIER_LAST_RUN})`;
const EDGE_BAN_CLASSIFIER_STALE_HELD = `(${EDGE_BAN_CLASSIFIER_OLD}) or absent_over_time(${EDGE_BAN_CLASSIFIER_LAST_RUN}[10m])`;

/**
 * Whether the edge_ban_owner role is installed on edge1: it must equal
 * `edge_ban_owner_enabled` in `ansible/roles/edge_ban_owner/defaults/main.yml`,
 * and `render.test.ts` fails when they differ. While false there is no
 * classifier, so `EdgeBanOwnerStale` would fire for ever and the Alertmanager
 * template discards it instead of paging; every ban still pages through the
 * fallback. The rules are the same either way. Flip both in one commit and
 * run `pnpm run render`.
 */
export const EDGE_BAN_OWNER_ENABLED = false;

/**
 * db1's own backup freshness rules select on the `host` label its node
 * target carries (`nodeTarget` renders it from `MONITORED_NODE_HOSTS`), so a
 * series that merely shares a metric name never satisfies them.
 */
const DB_BACKUP_HOST = 'db1';
const DB1_SERIES = `host="${DB_BACKUP_HOST}"`;
/** 24h35m is the longest healthy gap between two dumps (timer 03:00 plus 5m of random delay, 30m unit timeout); 30h leaves 5h25m. */
export const DB_DUMP_STALE_SECONDS = 108000;
/** The stale threshold in hours: one run is always due inside it, so a rule deployed before its metric exists stays quiet. */
export const DB_DUMP_ABSENT_FOR = '30h';
/** The binlog timer fires every 15m and the unit stops at 10m: 25m is healthy; 1h is three runs in a row failed or missed. */
export const DB_BINLOG_STALE_SECONDS = 3600;
export const DB_BINLOG_ABSENT_FOR = '1h';
/**
 * The control-plane backup (ansible/roles/control_plane_backup) runs nightly at 02:40 UTC with up to 5m of
 * random delay, and its unit is stopped at 2h, so two healthy successes are at most 26h05m apart. 36h
 * (1.5 x the cadence, as for TenantBackupAgeHigh) leaves 9h55m of margin. Backup copy 1 expires an object
 * 10 days after it is put, so a night missed at 36h still leaves about 8.5 days to put a copy back.
 */
const OPS1_SERIES = 'host="ops1"';
export const CONTROL_PLANE_BACKUP_STALE_SECONDS = 129600;

/**
 * The scanner series reach Prometheus through a host's node_exporter textfile
 * collector, so they carry that node target's labels. `expected_up="true"`
 * is what keeps every scanner rule silent for a host (today `app1`) whose
 * exporter has not been confirmed live; see render.md#the-scanner-rule-group.
 */
const SCANNER_SELECTOR = 'job="node", expected_up="true"';

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
 * The public bucket endpoint of the region the estate's Object Storage lives
 * in (the Pulumi state bucket is on it). The probe needs no credential. The
 * module of the same name is hand-written in stack/blackbox/blackbox.yml.
 */
export const OBJECT_STORAGE_ENDPOINT_HOST = 'hel1.your-objectstorage.com';
export const BLACKBOX_MODULE_OBJECT_STORAGE = 'http_object_storage';

/**
 * mx1 has no entry in the estate address plan -- it is not on this host's
 * private network, so there is no fixed private address to look one up by
 * -- so its DNS name is the address a probe uses, the same way blackbox_http
 * below reaches every sites.ts hostname by name rather than by IP.
 */
const MX1_HOSTNAME = 'mx1.branchleft.co.uk';

/**
 * The mailgun shim's Caddy TLS listener on mx1 (bulk mail from the sending
 * application and the collector drain). It is open to the whole internet
 * (`mail/firewall.ts`), so a probe from edge1 reaches it like any client.
 * Probed with `tls_connect` alongside 465 and 993: a completed handshake with
 * a verified certificate, not a plain TCP connect.
 */
export const MX1_SHIM_TLS_PORT = 8443;

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
 * The release watcher's poll-age gauge. The watcher is a scheduled GitHub
 * Actions run in branchLeft/ghost-platform (no host of ours runs it), and it
 * commits `release-watcher.prom` to that repository's `state/release-watcher`
 * branch. The repository is public, so Prometheus scrapes the file straight
 * from the raw-content host: nothing is pushed, no token is held, and a
 * watcher that stops running leaves the file's timestamp where it was. See
 * render.md#the-release-watcher-scrape-path.
 */
export const RELEASE_WATCHER_HOST = 'raw.githubusercontent.com';
export const RELEASE_WATCHER_METRICS_PATH =
  '/branchLeft/ghost-platform/state/release-watcher/release-watcher.prom';

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

/** One tunnel's target on edge1's private address: its local port, labelled as the direct row would be. */
function tunnelTarget(tunnel: TunnelledHost): string {
  const address = `${TENANT_TUNNEL_BIND_ADDRESS}:${tunnel.localPort}`;
  return `      - targets: ['${address}']\n        labels: ${targetLabels(tunnel)}`;
}

/** Rewrites a tunnel's local address back to the tenant host's own exporter address, so `instance` matches a direct scrape. */
function tunnelRelabelRule(tunnel: TunnelledHost): string[] {
  const localAddress = `${TENANT_TUNNEL_BIND_ADDRESS}:${tunnel.localPort}`;
  return [
    '      - source_labels: [__address__]',
    `        regex: '${localAddress.replace(/\./g, '\\.')}'`,
    '        target_label: instance',
    `        replacement: '${tunnel.address}:${NODE_EXPORTER_PORT}'`,
  ];
}

/** Every hostname in the registry, in registry order -- both a site's serving
 * hostnames and its redirect sources, since a redirect is still a public
 * endpoint someone can hit and expect a 2xx-after-redirect chain from. */
export function blackboxTargets(sites: readonly EdgeSite[]): string[] {
  return sites.flatMap((site) =>
    // A signed object gateway answers 404 at `/` by design; its health path is
    // the one the edge forwards for a probe.
    site.hostnames.map((hostname) =>
      site.signedObjectGateway === true ? `https://${hostname}/healthz` : `https://${hostname}`
    )
  );
}

export function renderPrometheusConfig(sites: readonly EdgeSite[]): string {
  const targets = blackboxTargets(sites);
  const nodeTargets = [
    ...hostsScrapedDirectly(MONITORED_NODE_HOSTS, TENANT_TUNNEL_TARGETS).map(nodeTarget),
    ...TENANT_TUNNEL_TARGETS.map(tunnelTarget),
  ].join('\n');

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
    '    relabel_configs:',
    ...TENANT_TUNNEL_TARGETS.flatMap(tunnelRelabelRule),
    '',
    '  - job_name: mysqld',
    '    static_configs:',
    `      - targets: ['${MONITORED_MYSQLD_HOST.address}:${MYSQLD_EXPORTER_PORT}']`,
    `        labels: ${targetLabels(MONITORED_MYSQLD_HOST)}`,
    '',
    `  - job_name: ${REPLICA_TUNNEL_JOB}`,
    '    static_configs:',
    `      - targets: ['${MONITORED_REPLICA_HOST.address}:${REPLICA_TUNNEL_METRICS_PORT}']`,
    `        labels: ${targetLabels(MONITORED_REPLICA_HOST)}`,
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
    mailProbeStaticConfig([465, 993, MX1_SHIM_TLS_PORT], BLACKBOX_MODULE_TLS_CONNECT),
    '    relabel_configs:',
    '      - source_labels: [__address__]',
    '        target_label: __param_target',
    '      - source_labels: [__param_target]',
    '        target_label: instance',
    '      - target_label: __address__',
    `        replacement: 'blackbox-exporter:${BLACKBOX_EXPORTER_PORT}'`,
    '',
    '  - job_name: blackbox_object_storage',
    '    metrics_path: /probe',
    '    params:',
    `      module: ['${BLACKBOX_MODULE_OBJECT_STORAGE}']`,
    '    static_configs:',
    '      - targets:',
    `          - https://${OBJECT_STORAGE_ENDPOINT_HOST}`,
    `        labels: ${EDGE1_SERVICE_LABELS}`,
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
    '',
    '  - job_name: release_watcher',
    // The raw host caches a file for five minutes, so scraping more often
    // than that reads the same bytes; every two minutes keeps a sample inside
    // Prometheus's five-minute lookback, which a slower interval would not.
    '    scrape_interval: 2m',
    '    scheme: https',
    `    metrics_path: ${RELEASE_WATCHER_METRICS_PATH}`,
    '    static_configs:',
    `      - targets: ['${RELEASE_WATCHER_HOST}:443']`,
    // No expected_up label, on purpose: an outage of GitHub's raw host is not
    // ours to page for. TargetDownUnmarked reads it at 24 hours instead, and
    // ReleaseWatcherStale's absent() branch is the signal that matters.
    '        labels: {host: github}',
  ].join('\n')}\n`;
}

export function renderAlertRules(): string {
  return renderAlertRulesWithDeadline(REPLICA_TUNNEL_DEADLINE);
}

export function renderAlertRulesWithDeadline(replicaDeadline: unknown): string {
  const deadlineEpoch = replicaDeadlineEpoch(replicaDeadline);
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
    '            Scoped to expected_up="true" targets only -- a host carries',
    '            expected_up="false" until its node exporter is provisioned,',
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
    // is 'enforcing', and the expression has no zone label at all, so the
    // general zones are covered with the magic-link one. It deliberately
    // excludes 172.16.0.0/12 keys, so real clients collapsed onto a Docker
    // bridge address would not raise it: the blackbox probes seeing 429 are
    // the tripwire for that.
    //
    // Sustained, not instantaneous: an internet scanner tripping the
    // throttle is the expected, handled case, because CrowdSec bans it
    // (a 4h ban) within a few minutes and the declines stop. CrowdSec's
    // Prometheus metrics, which the `crowdsec` job already scrapes, carry no
    // per-address series (cs_active_decisions has only reason, origin and
    // action labels), so a key with an active ban cannot be subtracted here
    // and a new exporter is not worth it for one warning. The rule requires
    // the decline rate to persist instead: increase() over 10m must stay
    // above zero for 30m running, so a burst fires it only if it lasts more
    // than 20 minutes (30m for, less the 10m window the expression keeps
    // reading true after the last decline). That is longer than a burst
    // CrowdSec bans, and a key that keeps declining past that point is one
    // CrowdSec did not ban. Warning, with no owner_action and no page
    // register entry, so it routes to the on-host mailbox only.
    '      - alert: RateLimitDeclinesSustained',
    '        expr: increase(caddy_rate_limit_declined_requests_total{key!~"172\\\\.(1[6-9]|2\\\\d|3[01])\\\\..*", key!=""}[10m]) > 0',
    '        for: 30m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "Caddy has kept declining rate-limited requests from {{ $labels.key }} for at least 30 minutes."',
    '          description: >-',
    '            A scanner burst that CrowdSec bans stops declining within',
    '            minutes and does not reach this rule: the expression must',
    '            hold for 30 minutes, which takes a burst of more than 20.',
    '            Declines that persist that long come from a key CrowdSec has',
    '            not banned. Check `cscli decisions list` on edge1 for the key',
    '            and the access log for what it is requesting, before',
    '            deciding whether to ban it by hand or raise the zone budget.',
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
    // An owned ban pages after the classifier's next run, up to ~5 minutes,
    // and each owned ban is its own alert (decision_id), so a second ban of a
    // scenario that is already paging is a new alert. Other bans go to email
    // (EdgeBanUnowned). A stale classifier, or one missing for ten minutes,
    // makes every ban page via the fallback branch; EdgeBanOwnerStale pages on
    // its own. Text and labels never carry an address. Why, and the rest:
    // hetzner/edge/render.md, "Being told about a ban".
    '      - alert: EdgeBanIssued',
    `        expr: (sum by (reason, decision_id) (edge_ban_owned{owned="true"}) > 0) or ((sum by (reason) (cs_active_decisions{action="ban"}) > 0) and on() (${EDGE_BAN_CLASSIFIER_STALE_HELD}))`,
    '        labels:',
    '          severity: page',
    '        annotations:',
    '          summary: "The edge is banning {{ $value }} address(es), by {{ $labels.reason }}."',
    '          description: >-',
    '            A banned address gets 403 from every site on edge1 until the ban',
    '            ends (10 minutes for a first ban, up to 4 hours for a repeat).',
    '            This page means the address is one of yours: one that made a',
    '            verified Ghost staff request through the edge in the last 30',
    '            days, or a range holding one. A decision_id label, when there is',
    '            one, is the CrowdSec decision ID, so each owned ban is its own',
    '            alert. It also pages for every ban while the classifier is more',
    '            than 15 minutes stale or has reported nothing for 10 minutes,',
    '            when nothing says whose they are.',
    '            From a network that is not banned, or over SSH to edge1,',
    '            `cscli decisions list` shows the ban and',
    '            `cscli decisions delete --ip ADDRESS` lifts it. The reason is the',
    '            CrowdSec scenario that decided; RUNBOOK-edge.md section 10b says',
    '            what each one reads.',
    '',
    // Not a page: a scanner the edge refused is the system working. Email
    // reaches the off-host mailbox through the owner_action route and the
    // on-host one through the warning route; neither is ntfy.
    '      - alert: EdgeBanUnowned',
    '        expr: sum by (reason) (edge_ban_owned{owned="false"}) > 0',
    '        labels:',
    '          severity: warning',
    '          owner_action: "true"',
    '        annotations:',
    '          summary: "The edge is banning {{ $value }} other address(es), by {{ $labels.reason }}."',
    '          description: >-',
    '            None of them is an address that made a verified Ghost staff',
    '            request through the edge in the last 30 days, so this is email',
    '            only. If one is yours, `cscli decisions list` on edge1 shows the',
    '            ban and `cscli decisions delete --ip ADDRESS` lifts it. The',
    '            reason is the CrowdSec scenario that decided.',
    '',
    '      - alert: EdgeBanOwnerStale',
    `        expr: ${EDGE_BAN_CLASSIFIER_STALE}`,
    '        for: 5m',
    '        labels:',
    '          severity: page',
    '        annotations:',
    '          summary: "The edge ban classifier has not reported for over 15 minutes."',
    '          description: >-',
    '            Until it runs again every ban pages, owned or not. On edge1,',
    '            `systemctl status branchleft-edge-ban-owner.timer` and',
    '            `journalctl -u branchleft-edge-ban-owner` say why. A failed',
    '            `cscli` query leaves the last file in place, so three missed',
    '            runs raise this.',
    '',
    '      - alert: HostMemoryPressure',
    '        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) > 0.75',
    '        for: 24h',
    '        labels:',
    '          severity: warning',
    '          owner_action: "true"',
    '        annotations:',
    '          summary: "{{ $labels.instance }} has used over 75% of memory for 24 hours."',
    '          description: "doc 14 §4 scale-out trigger: app-host memory >75% sustained 24h -> provision the next host."',
    '',
    // Same routing as HostMemoryPressure (warning, owner_action): the owner
    // decides the vCPU count, and the rule covers every node_exporter host.
    // Busy and steal are one alert: either one sustained is the same ceiling.
    '      - alert: HostCPUSaturated',
    '        expr: (1 - avg by (instance, host) (rate(node_cpu_seconds_total{mode="idle"}[5m]))) > 0.85 or avg by (instance, host) (rate(node_cpu_seconds_total{mode="steal"}[5m])) > 0.10',
    '        for: 30m',
    '        labels:',
    '          severity: warning',
    '          owner_action: "true"',
    '        annotations:',
    '          summary: "{{ $labels.host }} ({{ $labels.instance }}) has been short of CPU for 30 minutes: over 85% busy, or over 10% of time stolen by the hypervisor."',
    '          description: "Sizing signal for the tenant hosts: a sustained CPU ceiling means the vCPU count needs to go up. Measured as the 5-minute rate of node_cpu_seconds_total, averaged per instance across its cores."',
    '',
    '      - alert: HostDiskSpaceLow',
    '        expr: >-',
    '          (1 - (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} /',
    '          node_filesystem_size_bytes{fstype!~"tmpfs|overlay"})) > 0.70',
    '        for: 15m',
    '        labels:',
    '          severity: warning',
    '          owner_action: "true"',
    '        annotations:',
    '          summary: "{{ $labels.instance }} filesystem {{ $labels.mountpoint }} is over 70% full."',
    '          description: "doc 14 §4 scale-out trigger: disk >70% anywhere -> grow the volume."',
    '',
    '      - alert: MySQLConnectionsHigh',
    '        expr: mysql_global_status_threads_connected{job="mysqld"} / mysql_global_variables_max_connections{job="mysqld"} > 0.70',
    '        for: 10m',
    '        labels:',
    '          severity: warning',
    '          owner_action: "true"',
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
    // db1's job only: the replica's exporter has its own rule group below.
    '        expr: mysql_up{job="mysqld"} == 0',
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
    '            login, because mysqld_exporter v0.20.0 expands $ in a config value',
    '            as a shell variable, so a password containing one authenticates',
    '            as a truncated string while still serving 200. db/RUNBOOK-db.md',
    '            in branchLeft/ghost-platform carries the rotation.',
    '            for: 10m rather than 5m because a MySQL restart during a db',
    '            stack deploy produces mysql_up 0 legitimately for a minute or two.',
    '',
    // The migration replica on db-t1, read through db1's tunnel. Every rule
    // is scoped to expected_up="true" so nothing fires before the tunnel is
    // installed. See render.md#the-replica-tunnel-rule-group.
    '  - name: replica-tunnel',
    '    rules:',
    '      - alert: ReplicaTunnelDown',
    `        expr: up{${REPLICA_SELECTOR}} == 0`,
    '        for: 5m',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "The tunnel from db1 to db-t1 has been down for 5 minutes."',
    '          description: >-',
    '            This scrape rides the same ssh session as replication, so the',
    "            replica is not receiving db1's changes. It reconnects by itself",
    '            once the tunnel is back. On db1: systemctl status and journalctl',
    '            -u branchleft-db-tunnel.service.',
    '',
    '      - alert: ReplicaNotReplicating',
    '        expr: >-',
    `          mysql_slave_status_slave_io_running{${REPLICA_SELECTOR}} == 0`,
    `          or mysql_slave_status_slave_sql_running{${REPLICA_SELECTOR}} == 0`,
    '        for: 5m',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "A replication thread on db-t1 has been stopped for 5 minutes."',
    '          description: >-',
    '            The tunnel is up but the IO thread is not running (Connecting',
    '            counts as not running) or the SQL thread has stopped. Read',
    '            SHOW REPLICA STATUS on db-t1 for Last_IO_Error and',
    '            Last_SQL_Error.',
    '',
    '      - alert: ReplicaLagHigh',
    `        expr: mysql_slave_status_seconds_behind_master{${REPLICA_SELECTOR}} > 300`,
    '        for: 10m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "db-t1 has been over 5 minutes behind db1 for 10 minutes."',
    '          description: >-',
    '            Both threads are running and the replica is falling behind.',
    '            A NULL lag publishes no series, so it never reads as zero here;',
    '            ReplicaNotReplicating covers that case.',
    '',
    '      - alert: ReplicaStatusMissing',
    '        expr: >-',
    `          up{${REPLICA_SELECTOR}} == 1`,
    `          unless on(instance) mysql_slave_status_slave_io_running{${REPLICA_SELECTOR}}`,
    '        for: 10m',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "db-t1\'s exporter answers but reports no replica status."',
    '          description: >-',
    '            Either the exporter cannot read MySQL on db-t1, or MySQL has no',
    '            replication channel configured. Every other rule in this group',
    '            reads the replica status series, so this is the one that sees',
    '            them vanish.',
    '',
    '      - alert: ReplicaTunnelPastDeadline',
    '        expr: >-',
    `          up{${REPLICA_SELECTOR}} == 1`,
    `          and on() (vector(time()) > ${deadlineEpoch})`,
    '        for: 0m',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "The tunnel from db1 to db-t1 is still up after the cutover deadline."',
    '          description: >-',
    `            The tunnel was accepted only until ${replicaDeadline as string}.`,
    '            Finish the cutover and tear the tunnel down, or have the owner',
    '            move REPLICA_TUNNEL_DEADLINE in hetzner/monitoring/render.ts.',
    '',
    '  - name: backup',
    // One group, not two. Producers: backup_worker.py and state_copy.py,
    // both on ops1; dump_nightly.py on db1 writes the lock gauges under
    // tenant="db1-all-databases" and its own run-status pair, never
    // backup_worker_last_success_timestamp_seconds.
    // TenantBackupAgeHigh is the producer-side signal, not a liveness
    // check; the or absent(...) branch covers the metric family vanishing
    // entirely. Warning, never page, off-host receiver. See
    // render.md#the-backup-rule-group.
    '    rules:',
    '      - alert: TenantBackupAgeHigh',
    '        expr: >-',
    '          (time() - backup_worker_last_success_timestamp_seconds > 129600)',
    '          or label_replace(absent(backup_worker_last_success_timestamp_seconds), "scope", "family", "", "")',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: >-',
    '            {{ if eq $labels.scope "family" }}No tenant\'s backup age is being reported at all.{{ else }}{{ $labels.tenant }}\'s last successful backup is over 36 hours old.{{ end }}',
    '          description: >-',
    '            backup_worker_last_success_timestamp_seconds only advances on',
    '            a floor-verified successful dump, so a stopped or',
    '            consistently-refused worker for one tenant leaves that',
    "            tenant's gauge frozen while every other tenant's keeps",
    '            advancing -- each tenant is its own series, so this fires for',
    '            the stale one alone. The `or label_replace(absent(...))` half',
    '            catches the whole metric family vanishing -- the exporter down,',
    '            or the textfile deleted -- which the time() subtraction alone',
    '            cannot see, since subtracting from an absent series yields no',
    '            series at all, not a large number. That branch is tagged',
    '            scope="family" and carries no tenant label, so its summary says',
    '            no tenant is being reported instead of rendering an empty',
    '            tenant name. 129600s',
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
    '      - alert: StateCopyStale',
    '        expr: >-',
    '          (time() - state_copy_last_success_timestamp_seconds > 129600)',
    '          or (state_copy_bucket_configured unless on(bucket) state_copy_last_success_timestamp_seconds)',
    '          or absent(state_copy_bucket_configured)',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "The nightly copy of the {{ $labels.bucket }} state bucket into backup copy 1 is over 36 hours old."',
    '          description: >-',
    '            state_copy_last_success_timestamp_seconds advances only after a',
    '            copy is encrypted and written to backup copy 1, so a stopped',
    '            timer, a refused bucket read or an empty-looking listing leaves',
    "            that bucket's gauge frozen. Three branches: a stale gauge; a",
    '            bucket the job is configured for that has never succeeded',
    '            (state_copy_bucket_configured is written before any copy); and',
    '            the whole family absent, which means the job has never run or the',
    '            exporter file is gone and carries no bucket label. 129600s (36h)',
    '            is 1.5x the nightly cadence, as for TenantBackupAgeHigh. Warning,',
    '            never page. The estate state has no other off-host copy until',
    '            this runs.',
    '',
    // The weekly restore drill's own failure, from the OnFailure= the backup_restore
    // Ansible role gives the drill unit. systemd runs a small unit that touches
    // restore_drill_unit_failed.prom in the textfile directory; node_exporter reports the
    // file's mtime. The mark counts only while it is newer than the drill's own last-run
    // time, so the next run that writes its metrics clears it, and a drill that has never
    // written any (a crash before the first write) stays marked. Warning with no owner_action,
    // like the rest of this group: the on-host mailbox is the route, and the exact owner_action
    // list in render.test.ts is the owner's call to widen. See render.md#the-backup-rule-group.
    '      - alert: RestoreDrillUnitFailed',
    '        expr: >-',
    '          node_textfile_mtime_seconds{file="restore_drill_unit_failed.prom"}',
    '          unless on(instance)',
    '          (restore_drill_last_run_timestamp_seconds >= on(instance) node_textfile_mtime_seconds{file="restore_drill_unit_failed.prom"})',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "The weekly restore drill on {{ $labels.instance }} failed, and no later run has recorded its result."',
    '          description: >-',
    '            branchleft-restore-drill.service entered a failed state: a crash,',
    '            a kill, the three-hour timeout, or an exit after a failed check.',
    '            systemd then started branchleft-restore-drill-failed.service,',
    '            which touched restore_drill_unit_failed.prom in the textfile',
    '            directory. This rule holds while that file is newer than',
    '            restore_drill_last_run_timestamp_seconds, or the drill has never',
    '            written that series, so it also covers the crash that happens',
    '            before the drill writes any metric. No for: the file is written',
    '            once per failure and is flat otherwise. On ops1, read',
    '            journalctl -u branchleft-restore-drill.service for the reason;',
    '            the next run that records its result clears the alert, and a',
    '            drill run by hand with systemctl start does the same. Until then',
    '            nothing has shown that the latest backup restores.',
    '',
    // Not `notify: on-host`: unlike an SNDS or mail-deferral alert, nothing
    // about this signal depends on a route that avoids mx1.
    //
    // No `for:` -- unlike every other alert in this group. The gauge is
    // written once per tenant per night and otherwise flat, so there is no
    // scrape-to-scrape flapping to debounce, and paging on the very next
    // scrape after a bad wait is the intended behaviour, not a shortcut.
    '      - alert: BackupLockWaitHigh',
    '        expr: backup_worker_lock_wait_seconds > 1',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.tenant }}\'s dump waited over 1s for its table lock."',
    '          description: >-',
    "            Each tenant's nightly dump locks only that tenant's tables, READ,",
    "            and measures the wait in the lock's own session, from LOCK TABLES",
    '            to its grant. The server gives the wait up after 1s and the worker',
    '            after 1.2s, so a recorded wait over 1s means a write transaction',
    '            on this tenant held the lock off almost to the bound, and this',
    "            tenant's writers queued for that long. See branchLeft/ghost-platform",
    '            db/provision/bounded_snapshot.md.',
    '',
    // A counter from the textfile collector: it moves once per nightly
    // attempt, so increase() over a day catches any abort since yesterday.
    '      - alert: BackupLockAbortsRising',
    '        expr: increase(backup_worker_lock_aborts_total[1d]) > 0',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.tenant }}\'s dump gave up a lock attempt in the last day."',
    '          description: >-',
    "            The worker abandons a tenant's table lock when the wait or the",
    '            hold passes its bound, then backs off and retries, so a night can',
    '            end in a stored dump and still have aborted. Repeated aborts mean',
    '            something on this tenant keeps write transactions open for over',
    '            a second; the worker log names each abort and its reason. See',
    '            branchLeft/ghost-platform db/provision/bounded_snapshot.md.',
    '',
    // The source side of db1's own backups: its nightly dump and its binlog
    // shipping, from the status files those two scripts write to db1's
    // textfile directory (branchLeft/ghost-platform db/provision). The rules
    // above read the control host's copy; these read db1 itself. Same
    // severity and route as the rest of this group. Thresholds follow the
    // two systemd timers; the arithmetic is in each description.
    '      - alert: DbNightlyDumpStale',
    '        expr: >-',
    `          time() - db_nightly_dump_last_success_timestamp_seconds{${DB1_SERIES}} > ${DB_DUMP_STALE_SECONDS}`,
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "db1 has stored no nightly dump for over 30 hours."',
    '          description: >-',
    '            db_nightly_dump_last_success_timestamp_seconds is written by',
    "            db1's own dump_nightly.py once the encrypted dump has uploaded,",
    '            so this reads the source, not the copy TenantBackupAgeHigh reads',
    '            on the control host. The timer fires at 03:00 UTC with up to 5',
    '            minutes of random delay and the unit is stopped at 30 minutes,',
    '            so a healthy run is finished by about 03:35 and two successes',
    '            are never more than about 24h35m (88500s) apart. 108000s (30h)',
    '            leaves about 5h25m of margin, so this fires about 6 hours after',
    '            the first missed run was due, well before the 36h copy alert. Warning,',
    '            never page: the previous dump still stands. On db1, read',
    '            journalctl -u branchleft-db-dump.service; the gauge',
    '            db_nightly_dump_last_run_success separates a failed run from a',
    '            run that never started.',
    '',
    // Written once a night and flat otherwise, so no for: -- the same
    // reasoning as BackupLockWaitHigh above. Fires on the first failed run,
    // about 5 hours before the 30h rule would.
    '      - alert: DbNightlyDumpFailed',
    `        expr: db_nightly_dump_last_run_success{${DB1_SERIES}} == 0`,
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "db1\'s latest nightly dump run failed."',
    '          description: >-',
    '            dump_nightly.py ended without storing a dump: a refused lock, a',
    '            broken key, a full disk, an unreachable bucket or a missing',
    '            setting all land here, as does an unexpected crash. The next run',
    '            is 24 hours away and overwrites this gauge, so the dump is',
    '            missing until then unless it is run by hand. On db1, read',
    '            journalctl -u branchleft-db-dump.service for the reason.',
    '',
    '      - alert: DbNightlyDumpMetricAbsent',
    '        expr: >-',
    `          absent(db_nightly_dump_last_success_timestamp_seconds{${DB1_SERIES}})`,
    `        for: ${DB_DUMP_ABSENT_FOR}`,
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "db1 publishes no nightly dump success time."',
    '          description: >-',
    '            The series is not there at all, which time() minus a series',
    "            cannot see: db1's node_exporter is down or does not read the",
    '            textfile directory, the status file was removed, the dump script',
    '            on db1 predates the metric, or no dump has ever succeeded. for:',
    '            30h is the stale threshold: a script delivered after this rule',
    '            writes its first status within about 24h35m, so delivery order',
    '            does not raise a false alert. If db1 itself is down,',
    '            HostOrServiceDown pages first.',
    '',
    '      - alert: DbBinlogShipStale',
    '        expr: >-',
    `          time() - db_binlog_ship_last_success_timestamp_seconds{${DB1_SERIES}} > ${DB_BINLOG_STALE_SECONDS}`,
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "db1 has shipped no binary logs for over an hour."',
    '          description: >-',
    '            The point-in-time window between two dumps is only as complete',
    '            as the shipped binary logs. branchleft-db-binlog-ship.timer',
    '            fires every 15 minutes and the unit is stopped at 10, so a',
    '            healthy run completes within about 25 minutes (1500s) of the',
    '            last. 3600s (1h) fires after three runs in a row have failed or',
    '            not run. db_binlog_ship_last_run_success 0 means runs are',
    '            failing (journalctl -u branchleft-db-binlog-ship.service on',
    '            db1); 1 with a stale time means the timer has stopped. Warning,',
    '            never page: db1 keeps its own binary logs for 7 days, so nothing',
    '            is lost yet, but the off-host copy is falling behind.',
    '',
    '      - alert: DbBinlogShipMetricAbsent',
    '        expr: >-',
    `          absent(db_binlog_ship_last_success_timestamp_seconds{${DB1_SERIES}})`,
    `        for: ${DB_BINLOG_ABSENT_FOR}`,
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "db1 publishes no binlog shipping success time."',
    '          description: >-',
    "            The series is not there at all: db1's node_exporter is down or",
    '            does not read the textfile directory, the status file was',
    '            removed, the shipping script on db1 predates the metric, or no',
    '            run has ever succeeded. for: 1h matches the stale threshold; a',
    '            script delivered after this rule writes its first status within',
    '            one 15 minute timer period. If db1 itself is down,',
    '            HostOrServiceDown pages first.',
    '',
    // The control plane's own database backup, from the two textfile gauges the program writes on
    // ops1 (ansible/roles/control_plane_backup): its per-stage success times, and the time the nightly
    // unit last failed, written by the unit its OnFailure= starts. Warnings, same route as the group.
    // Neither uses absent(): the role's timer is off until the owner's apply turns it on, and a rule
    // that fired for a backup nobody has switched on would be noise. See render.md#the-backup-rule-group.
    '      - alert: ControlPlaneBackupStale',
    '        expr: >-',
    `          time() - control_plane_backup_last_success_timestamp_seconds{${OPS1_SERIES}} > ${CONTROL_PLANE_BACKUP_STALE_SECONDS}`,
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "The control-plane backup has not completed its {{ $labels.stage }} step for over 36 hours."',
    '          description: >-',
    '            control_plane_backup_last_success_timestamp_seconds is written',
    '            on ops1 by the control-plane backup program after each stage',
    '            succeeds: verified_on_host once the copy has been restored into a',
    '            throwaway server and counted equal to live, and shipped_offsite',
    '            once the sealed copy has been put to backup copy 1. The timer fires',
    '            at 02:40 UTC with up to 5 minutes of random delay and the unit is',
    '            stopped at 2 hours, so two healthy successes are at most 26h05m',
    '            apart. 129600s (36h) leaves 9h55m of margin and fires on the first',
    '            missed night. Backup copy 1 expires an object 10 days after it is',
    '            put, so nothing is lost yet and about 8.5 days remain to run the',
    '            backup by hand before copy 1 holds no control-plane backup. On',
    '            ops1, read journalctl -u branchleft-control-plane-backup.service;',
    '            a stopped timer shows in systemctl list-timers. Warning, never',
    '            page. Nothing fires before the first success is written, so a',
    '            timer that has never run is not seen by this rule.',
    '',
    // Written once per failure and flat otherwise, so no for:, as for DbNightlyDumpFailed. The
    // mark counts only while it is strictly newer than the last full success (shipped_offsite), so
    // the next night's success clears it, and a failure after a success (the prune that follows the
    // ship) is not hidden by it. With no success series at all the mark still fires.
    '      - alert: ControlPlaneBackupRunFailed',
    '        expr: >-',
    `          control_plane_backup_last_failure_timestamp_seconds{${OPS1_SERIES}}`,
    '          unless on(instance)',
    `          (control_plane_backup_last_success_timestamp_seconds{${OPS1_SERIES}, stage="shipped_offsite"} > on(instance) control_plane_backup_last_failure_timestamp_seconds{${OPS1_SERIES}})`,
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "The control-plane backup on {{ $labels.instance }} failed and no later run has shipped a copy."',
    '          description: >-',
    '            branchleft-control-plane-backup.service entered a failed state: a',
    '            check that did not pass, a missing precondition, a kill, the',
    '            two-hour timeout or a crash. systemd then started',
    '            branchleft-control-plane-backup-failed.service, which wrote the',
    '            time to control_plane_backup_failed.prom in the textfile',
    '            directory. This rule holds while that time is newer than the last',
    '            shipped_offsite success, so the next run that ships a copy clears',
    '            it, and a failure that comes after a ship (the prune that follows',
    '            it) is not hidden by an earlier success. It fires the night it',
    '            happens, about 36 hours before ControlPlaneBackupStale could.',
    '            On ops1, read journalctl -u branchleft-control-plane-backup.service',
    '            for the reason; a run by hand with systemctl start clears it once',
    '            it ships. The previous proven copies are still on the host.',
    // The compose template's own units (hetzner/provision/branchleft-compose@.service), read from the
    // node exporter's systemd collector, which node-exporter.service limits to those instances and
    // switches the restart counter on for. Both are warnings, so email and never a page, and both are
    // scoped to expected_up="true" as the scanner group is. edge1's exporter is the Compose container
    // and has no systemd bus, so these see app1, db1 and ops1 only. See render.md#the-compose-unit-rule-group.
    '  - name: compose-units',
    '    rules:',
    '      - alert: ComposeUnitRestartLoop',
    '        expr: >-',
    '          increase(node_systemd_service_restart_total{expected_up="true", name=~"branchleft-compose@.+[.]service"}[1h]) >= 2',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.name }} on {{ $labels.host }} has been restarted by systemd twice or more in the last hour."',
    '          description: >-',
    '            node_systemd_service_restart_total counts the automatic restarts of a',
    '            unit (the NRestarts that systemd shows). The compose template retries a',
    '            failed start after 30 seconds, and a stack that hangs until the 600',
    '            second start timeout fails about every ten minutes, so two restarts in',
    '            an hour is that loop, seen from its third start on, well before the start',
    '            limit stops it after five starts (StartLimitBurst=5 inside',
    '            StartLimitIntervalSec=3600). One retry is not a loop: a start that raced',
    '            a containerd restart and succeeded on its retry counts one and stays',
    '            silent. The counter goes back to zero when the unit is stopped or',
    '            reset-failed, and increase() reads that as a reset. On the host, read',
    '            journalctl -u {{ $labels.name }} for the reason the start fails or hangs.',
    '            Warning, never page: the unit is not the stack running, and a live stack',
    '            keeps serving while a restart of it is retried.',
    '',
    '      - alert: ComposeUnitFailed',
    '        expr: >-',
    '          node_systemd_unit_state{expected_up="true", name=~"branchleft-compose@.+[.]service", state="failed"} == 1',
    '        for: 10m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.name }} on {{ $labels.host }} has been failed for 10 minutes."',
    '          description: >-',
    '            A compose unit is failed when the start limit has stopped its retries',
    '            (result start-limit-hit, five starts inside the hour) or when a start',
    '            failed after the retries ran out. systemd keeps it failed until someone',
    '            acts: on the host, read journalctl -u {{ $labels.name }}, then',
    '            systemctl reset-failed {{ $labels.name }} and systemctl restart',
    '            {{ $labels.name }} (or re-run the deploy job). A deploy rollback',
    '            restart is refused as repeated too quickly until the reset-failed.',
    '            The ten minutes keep a deploy that is mid-rollback from alerting.',
    '            Warning, never page.',
    // The scanning storage adapter's own metrics, written by each tenant's
    // Ghost process as a node_exporter textfile. Every rule is scoped to
    // expected_up="true" on the node target, so nothing fires for a host
    // whose exporter is not yet confirmed live, and none uses absent():
    // a host with no scanner series is not a fault. See
    // render.md#the-scanner-rule-group for the series contract.
    '  - name: scanner',
    '    rules:',
    '      - alert: ScannerNotConfigured',
    '        expr: >-',
    `          scanning_storage_unconfigured_instances{${SCANNER_SELECTOR}} > 0`,
    `          and on(instance, tenant) (time() - scanning_storage_metrics_written_timestamp_seconds{${SCANNER_SELECTOR}} < 600)`,
    '        for: 10m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.tenant }} has an upload scanner with no verdict source, so every new upload is refused."',
    '          description: >-',
    '            The adapter booted with no verdict source configured, which',
    '            it treats as a refusal of every new upload rather than an',
    '            allow. This is the metric form of the SCANNER_UNCONFIGURED',
    '            boot line, so it is known before anyone uploads. The',
    '            freshness clause drops a series whose file has stopped',
    '            being rewritten, so a tenant that was torn down cannot hold',
    '            it open. A warning, never a page: it goes to the on-host',
    '            mailbox like every warning, and whether it is carried by',
    "            owner_action or the page register is the owner's call.",
    '',
    '      - alert: ScannerUploadsRefused',
    '        expr: >-',
    `          increase(scanning_storage_uploads_refused_total{reason="unconfigured", ${SCANNER_SELECTOR}}[15m]) > 0`,
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.tenant }} refused an upload in the last 15 minutes for want of a verdict source."',
    '          description: >-',
    '            A person tried to upload and was told no. This is the',
    '            UPLOAD_REFUSED_SCANNER_UNCONFIGURED log line as a counter.',
    '            The adapter writes the counter at zero from boot, so the',
    '            first refusal is visible to increase(). It also stops a',
    '            resized image variant that does not exist yet, which',
    '            errors instead of falling back to the original, so a',
    '            tenant can see broken images without uploading anything.',
    '            Refusals by verdict and repeats of a sealed digest are the',
    '            control working and are deliberately not alerted here.',
    '',
    '      - alert: ScannerVerdictChannelFailing',
    '        expr: >-',
    `          increase(scanning_storage_verdict_errors_total{${SCANNER_SELECTOR}}[5m]) > 0`,
    '        for: 10m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.tenant }}\'s verdict requests have been timing out or failing for 10 minutes."',
    '          description: >-',
    '            Each failed request accepts the upload and holds it',
    '            unserved, so an outage looks like images that never appear',
    '            and nothing else. A request error or timeout in every',
    '            5-minute window for 10 minutes is sustained, where one',
    '            slow answer is not. Held retries keep asking, so a held',
    '            upload keeps this firing until the channel answers; a',
    '            tenant with nothing held and nobody uploading makes no',
    '            requests and so raises none. No threshold is set here: the',
    '            owner sets the targets that would add a rate or an age',
    '            bound. One alert per kind (timeout, error) per tenant.',
    '',
    '  - name: probes',
    '    rules:',
    '      - alert: BlackboxProbeFailed',
    // Excludes blackbox_mail rather than naming blackbox_http: every
    // blackbox job is covered by exactly one alert, and a job with no
    // dedicated alert of its own should still fall through to this one.
    '        expr: probe_success{job!~"blackbox_mail|blackbox_object_storage"} == 0',
    '        for: 5m',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "{{ $labels.instance }} failed its external probe for 5 minutes."',
    '          description: "The blackbox_exporter replacement for the GCP uptime check (doc 14 §9.1), probing every hostname in sites.ts over HTTPS. Excludes blackbox_mail, which has its own MailHostDown alert below, and blackbox_object_storage, which has ObjectStorageProbeFailed."',
    '',
    // Warns before the certificate expires: Caddy renews automatically, so a
    // failed renewal shows only at hard expiry, when probe_success drops and
    // BlackboxProbeFailed fires. Warning, not critical: the certificate still
    // serves until expiry, so this is a chore with a deadline, not an outage.
    '      - alert: TLSCertificateExpiringSoon',
    '        expr: probe_ssl_earliest_cert_expiry{job="blackbox_http"} - time() < 14*86400',
    '        labels:',
    '          severity: warning',
    '          owner_action: "true"',
    '        annotations:',
    '          summary: "{{ $labels.instance }}\'s TLS certificate expires in under 14 days."',
    '          description: >-',
    '            Caddy renews certificates automatically, so a failed renewal shows',
    '            only when the certificate reaches hard expiry and probe_success',
    '            drops. This fires earlier, while there is still time to fix the',
    '            renewal. Scoped to blackbox_http, the public HTTPS probes.',
    '',
    // Warns before mx1's certificate expires. Stalwart renews automatically,
    // so a failed renewal shows only at hard expiry. Warning, not critical:
    // the certificate still serves until expiry. A separate alert from
    // TLSCertificateExpiringSoon because its alertname names the mail path,
    // as MailHostDown does.
    '      - alert: MailCertificateExpiringSoon',
    '        expr: probe_ssl_earliest_cert_expiry{job="blackbox_mail"} - time() < 14*86400',
    '        labels:',
    '          severity: warning',
    '          owner_action: "true"',
    '        annotations:',
    '          summary: "{{ $labels.instance }}\'s mail TLS certificate expires in under 14 days."',
    '          description: >-',
    '            Stalwart (ports 465 and 993) and Caddy (the mailgun shim, port 8443)',
    '            renew their certificates automatically, so a failed renewal shows',
    "            only when the certificate reaches hard expiry and clients' TLS",
    '            fails. This fires earlier, while there is still time to fix the',
    '            renewal. The series comes from the TLS ports 465, 993 and 8443',
    '            only: ports 25 and 587 use smtp_banner, which does no TLS handshake.',
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
    '  - name: object-storage',
    '    rules:',
    '      - alert: ObjectStorageProbeFailed',
    '        expr: probe_success{job="blackbox_object_storage"} == 0',
    '        for: 15m',
    '        labels:',
    '          severity: critical',
    '        annotations:',
    '          summary: "{{ $labels.instance }} failed its object storage probe for 15 minutes."',
    '          description: >-',
    '            The bucket endpoint is probed over HTTPS and the probe reads a 403 as',
    '            up: an anonymous request to the bare endpoint is refused by the service',
    '            itself, which is the liveness signal here. A refused or timed-out',
    '            connection held for 15 minutes is the outage this rule exists for.',
    '            BlackboxProbeFailed excludes blackbox_object_storage, so exactly one of',
    '            the two rules fires for a given probe.',
    '',
    '  - name: target-liveness',
    '    rules:',
    '      - alert: TargetDownUnmarked',
    '        expr: up{expected_up!="false"} == 0',
    '        for: 24h',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "{{ $labels.job }} on {{ $labels.host }} has been unreachable for 24 hours with no expected_up mark."',
    '          description: >-',
    '            Covers what HostOrServiceDown cannot see: that rule reads',
    '            up{expected_up="true"} only, so a target with no expected_up label at all',
    '            had no alert for a sustained outage. A target marked expected_up="false"',
    '            is excluded, because that mark says it is not expected yet;',
    '            ExpectedDownTargetAnswering covers the mark going stale in the other',
    '            direction. A target labelled "true" is also caught here at 24 hours,',
    '            after HostOrServiceDown has paged it at 5 minutes.',
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
    '      - alert: NtfyPagerDisabled',
    '        expr: branchleft_pager_route_configured == 0',
    '        for: 30m',
    '        labels:',
    '          severity: warning',
    '          owner_action: "true"',
    '        annotations:',
    '          summary: "The pager is disabled on {{ $labels.instance }}: email still sends, nothing pages."',
    '          description: >-',
    '            A textfile gauge written by the monitoring_stack role on every',
    '            apply: 0 means /etc/branchleft/ntfy-pager.env is missing or lacks a',
    '            value for one of its four NTFY_ keys, so the renderer switches the',
    '            pager off with only a journal warning and email carries on. That',
    '            is the one failure of the alert path that nothing else here would',
    '            show. The gauge is as fresh as the last apply, not live, and it',
    '            says the keys are present, not that the renderer accepts their',
    '            shape. A host with no pager by design has no business running this',
    '            stack. The fix is the owner placing the values through the',
    '            ntfy_pager inputs and the next gated apply. `for: 30m` rides out a',
    '            run in which ntfy_pager and this role were applied apart.',
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
    '          owner_action: "true"',
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
    '',
    // A GitHub Actions schedule, not a host of ours: see
    // render.md#the-release-watcher-scrape-path. Warning, which Alertmanager
    // routes to the on-host mailbox: a stalled version watcher is an alert,
    // never a page, and its fix is a repository change the agents make.
    '  - name: release-watcher',
    '    rules:',
    '      - alert: ReleaseWatcherStale',
    '        expr: >-',
    '          (time() - ghost_release_watcher_last_success_timestamp_seconds > 86400)',
    '          or absent(ghost_release_watcher_last_success_timestamp_seconds)',
    '        for: 30m',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "The Ghost release watcher has not polled the registry successfully in over 24 hours."',
    '          description: >-',
    '            The watcher runs every six hours as a scheduled GitHub Actions',
    '            workflow in branchLeft/ghost-platform and commits the time of its',
    '            last successful poll to release-watcher.prom on the',
    '            state/release-watcher branch, which the release_watcher scrape job',
    '            reads. 86400s (24h) is four missed ticks, wide enough that one',
    '            late or skipped scheduled run does not alert. The `or absent(...)`',
    '            half covers the file being unreadable or the gauge vanishing, which',
    '            the time() subtraction alone cannot see (subtracting from an absent',
    '            series yields no series at all); `for: 30m` keeps a single failed',
    '            scrape of the raw-content host from firing it. A run that fails',
    '            leaves the timestamp where it was, so a watcher that errors on',
    '            every run and one that is switched off look the same here. Read',
    '            the latest run of release-watcher-run.yml in ghost-platform. A',
    '            repository with no activity for 60 days has its schedules disabled',
    '            by GitHub, which is the other silent stop this alert exists for.',
    '            See render.md#the-release-watcher-scrape-path.',
  ].join('\n')}\n`;
}

/** The name both email receivers' `html:` field points at. */
export const EMAIL_TEMPLATE_NAME = 'branchleft.email.html';

/**
 * The alert email body. Alertmanager's own default template links to
 * `.ExternalURL`, which without --web.external-url is the container's
 * hostname (an address no mail client can open), and to each alert's
 * `GeneratorURL`, which is Prometheus's equally unreachable one. Neither
 * service is exposed, so this body carries no link at all.
 */
export function renderAlertmanagerEmailTemplate(): string {
  return `${[
    '{{/* Generated from hetzner/monitoring/render.ts. Hand edits are overwritten. */}}',
    `{{ define "${EMAIL_TEMPLATE_NAME}" }}`,
    '<html><body>',
    '<p>{{ .Status | toUpper }}: {{ .Alerts.Firing | len }} firing, {{ .Alerts.Resolved | len }} resolved.</p>',
    '{{ range .Alerts }}',
    '<p><b>{{ .Labels.alertname }}</b> ({{ .Labels.severity }}), {{ .Status }}<br/>',
    '{{ .Annotations.summary }}<br/>',
    '{{ .Annotations.description }}<br/>',
    'Started: {{ .StartsAt.Format "2006-01-02 15:04:05 MST" }}<br/>',
    '{{ range .Labels.SortedPairs }}{{ .Name }}={{ .Value }} {{ end }}</p>',
    '{{ end }}',
    '</body></html>',
    '{{ end }}',
  ].join('\n')}\n`;
}

/**
 * Alertmanager's config template, its placeholder tokens substituted by
 * `stack/render_alertmanager_config.py` on the host before every start.
 * See render.md#renderalertmanagertemplate for the token list and why
 * `register` defaults to the committed `PAGE_REGISTER`. While the classifier
 * is not installed (`edgeBanOwnerEnabled` false) the staleness alert is
 * discarded rather than paged.
 */
export function renderAlertmanagerTemplate(
  register: readonly PageRegisterEntry[] = PAGE_REGISTER,
  edgeBanOwnerEnabled: boolean = EDGE_BAN_OWNER_ENABLED
): string {
  const routedRegister = edgeBanOwnerEnabled ? register : holdEdgeBanOwnerStale(register);
  const pageRoute = renderPageRoute(routedRegister);
  const ownedEdgeBanRoute = renderOwnedEdgeBanRoute(routedRegister);
  const discardRoute = edgeBanOwnerEnabled ? '' : renderEdgeBanOwnerStaleDiscardRoute(register);
  return `${[
    ...GENERATED_BANNER,
    '# Rendered into alertmanager.yml at container start by',
    '# render_alertmanager_config.py. This file is never read directly.',
    'templates:',
    "  - '/etc/alertmanager/templates/*.gotmpl'",
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
    // Every critical alert pages the owner's phone, as well as going where it
    // went before. `continue: true` lets the walk go on to the routes below,
    // and the email route that follows exists because a matching child stops
    // the root receiver from applying: without it a plain critical alert
    // would reach ntfy only. It excludes the two mail-host alerts, which have
    // their own email pair below, and on-host alerts, which must never leave
    // mx1.
    '    - matchers:',
    '        - severity = "critical"',
    `      receiver: ${PAGE_RECEIVER_NAME}`,
    '      continue: true',
    '    - matchers:',
    '        - severity = "critical"',
    '        - alertname !~ "^(MailHostDown|AlertEmailDeliveryFailing)$"',
    '        - notify != "on-host"',
    '      receiver: email',
    // `continue: true` on the route above, and this sibling after it: the
    // off-host recipient is host-supplied (ALERT_RECIPIENT_EMAIL) and a
    // critical alert reached no mailbox the owner reads through it. The
    // owner-read mailbox is the local one on mx1 that warnings already
    // reach, so a critical alert also lands there. Mail-host alerts are
    // excluded: they fire when mx1 is down, and have their own pair below.
    '      continue: true',
    '    - matchers:',
    '        - severity = "critical"',
    '        - alertname !~ "^(MailHostDown|AlertEmailDeliveryFailing)$"',
    '        - notify != "on-host"',
    '      receiver: email-on-host',
    // An alert whose fix needs the owner's own hands (a portal visit, a
    // spend, a dated expiry) also reaches the off-host mailbox, which the
    // owner reads; the on-host mailbox alone is one they do not. Label
    // driven (`owner_action`), so adding a rule never touches this tree.
    // `continue: true` sends the walk on to the on-host and warning routes
    // below, which still deliver exactly as before. Criticals are excluded:
    // they reach the off-host mailbox already, and a second route to the
    // same receiver would send the group twice.
    '    - matchers:',
    '        - owner_action = "true"',
    '        - severity != "critical"',
    '      receiver: email',
    '      continue: true',
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
    // While the classifier is not installed its staleness alert is discarded
    // here, before the generic route, which does not list it in that mode.
    // The owned-ban child comes next and does not continue: the generic
    // route below still lists EdgeBanIssued, so removing the child leaves
    // the page in place with the old grouping rather than silencing it.
    ...(discardRoute ? [discardRoute] : []),
    ...(ownedEdgeBanRoute ? [ownedEdgeBanRoute] : []),
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
    '      - alertname = "ReplicaTunnelDown"',
    '    target_matchers:',
    '      - alertname =~ "^(HostOrServiceDown|ServiceFlapping)$"',
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
    `        html: '{{ template "${EMAIL_TEMPLATE_NAME}" . }}'`,
    // false: a resolved notice is a second external delivery per incident,
    // and a flapping alert would send one for every flap.
    '        send_resolved: false',
    '',
    // A mailbox on mx1 itself: mx1 delivers it locally, so it never makes an
    // external delivery attempt and costs no sending reputation.
    '  - name: email-on-host',
    '    email_configs:',
    "      - to: 'rob@branchleft.co.uk'",
    `        html: '{{ template "${EMAIL_TEMPLATE_NAME}" . }}'`,
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
    ...(discardRoute ? ['', renderDiscardReceiverBlock()] : []),
  ].join('\n')}\n`;
}
