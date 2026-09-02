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
 * `mx1` is watched two ways, and the pair is deliberate.
 *
 * **Liveness, from outside.** `mail/firewall.ts` opens 25, 465, 587 and 993
 * to the whole internet, so a blackbox probe from edge1 reaches them the way
 * any other client on the internet does, with no new firewall rule. It
 * cannot be a plain TCP-connect probe: a scan-banned or dead-backend
 * connection still completes the handshake and then EOFs, so every one of
 * those ports can read as healthy while Stalwart serves nothing behind them.
 * `smtp_banner` (25, 587) reads the `220` greeting and sends `QUIT`;
 * `tls_connect` (465, 993, both implicit-TLS) requires a completed
 * handshake. See `mailProbeStaticConfig()` and the `blackbox_mail` job below.
 *
 * **Delivery outcomes, from inside.** A liveness probe cannot distinguish a
 * mail host that is delivering from one that is up and bouncing everything,
 * and that difference is the whole of the sender-reputation question. That
 * needs Stalwart's own counters, which is why `mail/provision/`
 * `configure_stalwart.py` enables its Prometheus exporter on the existing
 * public 443 listener -- see the `stalwart` job below.
 *
 * mx1 is in its own hcloud project (`edge/render.ts`'s `NOT_AN_UPSTREAM`
 * carries the same fact for the edge), so it shares no private network with
 * this host and neither of these can be a private-address scrape. Both cross
 * the public internet, which is why the exporter is authenticated and
 * source-pinned rather than merely enabled.
 */

/**
 * `db1`'s MySQL exporter is live, so unlike the `node` targets above this one
 * is expected to answer and pages when it does not.
 *
 * It was `false` while the exporter did not exist, which was correct then and
 * became wrong the moment the exporter shipped -- the flip is a hand edit in
 * this repo, satisfied by a deploy in another, with nothing connecting the
 * two. That gap hid a four-day crash loop: the suppression that made the
 * target quiet is the same suppression that would have reported it shipped
 * broken. Anything set `false` here is a claim about the present that needs
 * re-checking against `up` on `edge1`, not a permanent property.
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
 * The Stalwart exporter is reached by **address, not by name**, with the
 * hostname carried in `tls_config.server_name` so certificate verification
 * still checks the thing it is supposed to check.
 *
 * mx1 publishes an AAAA record as well as an A record, and Stalwart's
 * access-control rule admits only edge1's public IPv4. The IPv6 half of that
 * rule was dropped when this endpoint was built, because `remote_ip` did not
 * compare equal to the compressed literal and the rendered form was never
 * established -- a rule written against a guess reads as coverage while
 * never matching. A Go dialer handed the hostname resolves both families and
 * may reach for the AAAA first, exactly as `curl` did during that
 * verification, and every scrape that does is refused with a 421. Naming the
 * address removes the choice rather than relying on resolver preference.
 *
 * `instance` is relabelled back to the hostname below, so what a human reads
 * in an alert is still `mx1.branchleft.co.uk`.
 */
const MX1_PUBLIC_IPV4 = '167.233.252.240';

/**
 * Basic auth over TLS, with the password read from a file rather than
 * written into this config: `stack/prometheus/prometheus.yml` is committed
 * to a public repository.
 *
 * That file is not in the committed tree. `stack/render_alertmanager_config.py`
 * writes it on the host from `STALWART_PROMETHEUS_SECRET` in
 * `/etc/branchleft/monitoring.env` before every start, exactly as it writes
 * `alertmanager.yml`, and every deploy's `rsync --delete` removes it for the
 * same reason.
 *
 * A missing file does not stop Prometheus starting. Neither `promtool check
 * config` nor the config loader stats it -- it is read per request -- so the
 * failure mode is `up{job="stalwart"} == 0` and a HostOrServiceDown page.
 * That is the right way round: one unreachable scrape target must never take
 * down the alerting path for the whole estate.
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
 * rather than deriving from MonitoredHost. `HostOrServiceDown`'s `expr`
 * picks up every `up{expected_up="true"}` series without any change to the
 * alert rule itself.
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
    // Microsoft's own feedback-loop data, not a proxy: mail-delivery above
    // reads Stalwart's own counters, which can only see bounces mx1 itself
    // generates. Complaint rate is reported by the receiving provider out of
    // band -- a message that is accepted, delivered and then marked as junk
    // by the recipient never touches any of Stalwart's delivery counters at
    // all, which is exactly the shape of a signup flood aimed at harvested
    // real addresses (RUNBOOK-monitoring.md's SNDS section).
    '  - name: snds-reputation',
    '    rules:',
    '      - alert: SNDSComplaintRateHigh',
    '        expr: >-',
    '          snds_complaint_rate > 0.001',
    '          and',
    '          (snds_message_volume > 50 or on() absent(snds_message_volume))',
    '        labels:',
    '          severity: warning',
    '        annotations:',
    '          summary: "Microsoft SNDS reported a complaint rate over 0.1% for {{ $labels.ip }}."',
    '          description: >-',
    "            SNDS refreshes at most once a day, so this reports yesterday's",
    '            reputation snapshot, not a live rate -- treat "when did this fire"',
    '            as "as of Microsoft\'s last publish", not as the moment of the',
    '            complaints themselves. The volume floor keeps a handful of',
    '            complaints against a trickle of mail from paging, the same shape',
    "            as MailDeliveryFailureRatioHigh's `> 20`, but bypasses itself",
    '            (`or on() absent(...)`) if snds_message_volume is not being',
    '            published at all -- a floor that silently disabled the alert it',
    '            was meant to only quiet would be worse than no floor. Re-tune',
    '            both numbers from observed volume once real data exists. See',
    '            RUNBOOK-monitoring.md for what to do when this fires.',
    '',
    '      - alert: SNDSReputationRed',
    '        expr: snds_reputation_status{status="red"} == 1',
    '        labels:',
    '          severity: warning',
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
    '        annotations:',
    '          summary: "The SNDS collector has not published a successful snapshot in over 36 hours."',
    '          description: >-',
    '            Both rules above go silent, not critical, if this collector stops',
    '            running or its bearer token expires -- an absent-or-stale gauge',
    '            reads exactly like a clean reputation otherwise. 129600s (36h) is',
    "            half again the collector's own ~24h cadence, wide enough that one",
    '            missed run does not page. The `or absent(...)` half catches a',
    '            collector that has never once succeeded, which the time()',
    '            subtraction alone cannot see -- subtracting from an absent series',
    '            yields no series at all, not a large number.',
  ].join('\n')}\n`;
}

/**
 * Alertmanager's config template. `__SMTP_USERNAME__`, `__SMTP_PASSWORD__`,
 * `__HEALTHCHECKS_PING_URL__`, `__ALERT_RECIPIENT_EMAIL__` and
 * `__MAILHOST_PING_URL__` are substituted by
 * `stack/render_alertmanager_config.py` from `/etc/branchleft/monitoring.env`
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
