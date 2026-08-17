import { APP_HOST_IPS, HOST_IPS } from '@branchleft/hetzner-host';

import type { EdgeSite, HostRedirect } from '../../siteTypes';
import {
  RATE_LIMIT_EVENTS,
  RATE_LIMIT_WINDOW_SECONDS,
  TLS_PROTOCOLS,
  type EdgePosture,
} from './posture';

/**
 * Renders the edge VM's Caddy and CrowdSec configuration from the hostname
 * registry in `sites.ts` and the enforcement posture in `posture.ts`.
 *
 * Pure string building, deliberately: the output is committed under `stack/`
 * and copied onto the host by hand, so the only thing that can differ between
 * what a reviewer reads and what the edge runs is the copy step. `render.test.ts`
 * is what keeps the committed files and this file from drifting apart.
 *
 * ## The registry is the only hostname list
 *
 * A hostname written here rather than derived from `sites.ts` is a hostname the
 * GCP edge does not know about, which is precisely the class of stray record
 * the cutover has to find and fix. Everything below is derived.
 */

const GENERATED_BANNER = [
  '# Generated from sites.ts and hetzner/edge/posture.ts.',
  '# Regenerate with `npm run render` in hetzner/. Hand edits are overwritten.',
];

/**
 * Paths exempted from AppSec evaluation on a site flagged
 * `injectionWafPreviewOnly`. Ghost serves its admin UI and admin API under
 * `/ghost`, and an admin request body carries author-written HTML, code and SQL.
 */
const AUTHORING_PATHS = ['/ghost', '/ghost/*'];

/** Where Caddy writes the access log CrowdSec parses. */
const ACCESS_LOG = '/var/log/caddy/access.log';

/**
 * The probe listener's log, deliberately a different file: CrowdSec acquires
 * the access log above, and a rate-limit verification run is several hundred
 * rejected requests from one address in a minute. Fed into the same pipeline it
 * would read as probing and ban the address the host's own container traffic
 * arrives from.
 */
const PROBE_LOG = '/var/log/caddy/probe.log';

/** Loopback-published port the runbook's verification commands talk to. */
const PROBE_PORT = 8080;

/**
 * Service names on the Compose network. The AppSec component is an HTTP server
 * inside the CrowdSec agent, on its own port; neither is published off that
 * network.
 */
const CROWDSEC_LAPI_URL = 'http://crowdsec:8080';
const CROWDSEC_APPSEC_URL = 'http://crowdsec:7422';

/**
 * Bodies larger than this are not forwarded to AppSec. Media upload through the
 * Ghost admin API is tens of megabytes, and copying that into a WAF on a 2-vCPU
 * edge costs more than the inspection is worth on a binary payload.
 */
const APPSEC_MAX_BODY_BYTES = 65536;

/** Bounds the added latency of an AppSec verdict, in the same units Caddy takes. */
const APPSEC_MAX_TIMEOUT = '1s';

/**
 * In-band AppSec configuration: known-exploit shapes, evaluated before the
 * request proceeds. Only loaded when the posture enforces.
 */
const APPSEC_CONFIG_INBAND = 'crowdsecurity/appsec-default';

/**
 * Out-of-band AppSec configuration: OWASP CRS, evaluated after the request has
 * been answered, feeding the scenario that bans a repeat offender. Loaded in
 * every posture, because detection is what the detect-only period is for.
 */
const APPSEC_CONFIG_OUT_OF_BAND = 'crowdsecurity/crs';

/**
 * A hostname is written straight into a Caddyfile site address, where a space
 * or a brace would start a new address or a new block. The registry is
 * reviewed, so this is not the control that stops a hostile entry — it is what
 * stops a malformed one from producing a config that parses into something
 * other than what the entry says.
 */
const HOSTNAME = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

const PRIVATE_ADDRESSES: Record<string, string> = { ...HOST_IPS, ...APP_HOST_IPS };

/**
 * The mail host is on the estate's address plan but not behind this edge: it
 * terminates SMTP, has its own firewall, and is not on the private network at
 * all. Naming it as an upstream is a registry mistake worth failing on rather
 * than rendering.
 */
const NOT_AN_UPSTREAM = new Set(['mx1']);

export function resolvePrivateAddress(host: string, port: number): string {
  if (NOT_AN_UPSTREAM.has(host)) {
    throw new Error(`${host} is not a backend this edge proxies to`);
  }
  const address = PRIVATE_ADDRESSES[host];
  if (address === undefined) {
    throw new Error(`unknown upstream host ${host}; it must be a name in the estate address plan`);
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`upstream port for ${host} must be an integer between 1 and 65535`);
  }
  return `${address}:${port}`;
}

function assertHostname(hostname: string): string {
  if (!HOSTNAME.test(hostname)) {
    throw new Error(`not a hostname this renderer will write into a Caddyfile: ${hostname}`);
  }
  return hostname;
}

/** Sites with somewhere to send traffic. See `PrivateUpstream` for why the rest are dropped. */
export function servableSites(sites: readonly EdgeSite[]): EdgeSite[] {
  return sites.filter((site) => site.privateUpstream !== undefined);
}

interface Block {
  addresses: string[];
  body: string[];
}

function logDirective(path: string): string[] {
  return ['log {', `\toutput file ${path}`, '\tformat json', '}'];
}

function tlsDirective(): string[] {
  return ['tls {', `\tprotocols ${TLS_PROTOCOLS.join(' ')}`, '}'];
}

function rateLimitDirective(zone: string): string[] {
  return [
    'rate_limit {',
    `\tzone ${zone} {`,
    // The edge is the first hop — no proxy in front of it — so the direct peer
    // is the client. `{http.request.client_ip}` would take a forwarded header
    // into account, which here is a header an attacker sets.
    '\t\tkey {http.request.remote.host}',
    `\t\twindow ${RATE_LIMIT_WINDOW_SECONDS}s`,
    `\t\tevents ${RATE_LIMIT_EVENTS}`,
    '\t}',
    '}',
  ];
}

/**
 * The handler chain, in evaluation order.
 *
 * The throttle runs **before** the WAF, which is the one place this edge
 * deliberately reorders the Cloud Armor baseline (whose WAF rules sat at
 * priority 1000–1003, ahead of the throttle at 2000). Cloud Armor evaluated on
 * Google's edge fleet; this evaluates on two vCPUs, so a flood that reached the
 * WAF first would spend exactly the capacity the throttle exists to protect.
 * The observable difference is confined to a client that is both flooding and
 * attacking: it is answered 429 rather than 403.
 */
function protectionChain(
  posture: EdgePosture,
  zone: string,
  options: { appsec: 'none' | 'all' | 'except-authoring' }
): string[] {
  const lines: string[] = [];
  if (posture.rateLimit === 'enforcing') {
    lines.push(...rateLimitDirective(zone));
  }
  if (posture.crowdsec === 'enforcing') {
    lines.push('crowdsec');
  }
  if (options.appsec === 'all') {
    lines.push('appsec');
  } else if (options.appsec === 'except-authoring') {
    lines.push('appsec @inspected');
  }
  return lines;
}

function siteBlock(site: EdgeSite, hostnames: string[], posture: EdgePosture): Block {
  const upstream = site.privateUpstream;
  if (upstream === undefined) {
    throw new Error(`site ${site.name} has no privateUpstream and must not be rendered`);
  }

  const body: string[] = [...logDirective(ACCESS_LOG), ...tlsDirective()];
  if (site.injectionWafPreviewOnly) {
    body.push(`@inspected not path ${AUTHORING_PATHS.join(' ')}`);
  }
  body.push(
    'route {',
    ...protectionChain(posture, `${site.name}_per_ip`, {
      appsec: site.injectionWafPreviewOnly ? 'except-authoring' : 'all',
    }).map((line) => `\t${line}`),
    `\treverse_proxy ${resolvePrivateAddress(upstream.host, upstream.port)}`,
    '}'
  );

  return { addresses: hostnames, body };
}

function redirectBlock(redirect: HostRedirect, zone: string, posture: EdgePosture): Block {
  return {
    addresses: [assertHostname(redirect.from)],
    body: [
      ...logDirective(ACCESS_LOG),
      ...tlsDirective(),
      'route {',
      ...protectionChain(posture, zone, { appsec: 'none' }).map((line) => `\t${line}`),
      `\tredir https://${assertHostname(redirect.to)}{uri} permanent`,
      '}',
    ],
  };
}

/**
 * A listener on loopback only, carrying the same handler chain as the public
 * sites and answering 204.
 *
 * It is what makes the posture observable before any hostname resolves to this
 * host: the throttle and the CrowdSec handlers can be exercised with `curl`
 * against a running edge that serves no public traffic yet. The Hetzner firewall
 * does not open this port and Compose publishes it on `127.0.0.1` only.
 */
function probeBlock(posture: EdgePosture): Block {
  return {
    addresses: [`:${PROBE_PORT}`],
    body: [
      ...logDirective(PROBE_LOG),
      'route {',
      ...protectionChain(posture, 'probe_per_ip', { appsec: 'all' }).map((line) => `\t${line}`),
      '\trespond 204',
      '}',
    ],
  };
}

function globalOptions(): string[] {
  return [
    '{',
    '\tcrowdsec {',
    `\t\tapi_url ${CROWDSEC_LAPI_URL}`,
    '\t\tapi_key {env.CROWDSEC_BOUNCER_KEY}',
    '\t\tticker_interval 15s',
    `\t\tappsec_url ${CROWDSEC_APPSEC_URL}`,
    `\t\tappsec_max_body_bytes ${APPSEC_MAX_BODY_BYTES}`,
    `\t\tappsec_max_timeout ${APPSEC_MAX_TIMEOUT}`,
    // A single-VM edge shares its two vCPUs with the WAF sidecar, so an AppSec
    // restart or stall must degrade inspection rather than answer 500 for every
    // site at once. IP decisions are unaffected: the bouncer serves those from
    // its own cache.
    '\t\tappsec_fail_open true',
    '\t}',
    '}',
  ];
}

function renderBlock(block: Block): string[] {
  return [`${block.addresses.join(', ')} {`, ...block.body.map((line) => `\t${line}`), '}'];
}

export function renderCaddyfile(
  sites: readonly EdgeSite[],
  hostRedirects: readonly HostRedirect[],
  posture: EdgePosture
): string {
  const servable = servableSites(sites);
  const servableHostnames = new Set(servable.flatMap((site) => site.hostnames));

  // A redirect source needs its own certificate before it can redirect
  // anything, so it is only rendered when its target is a hostname this edge
  // actually serves. Rendering it earlier would put the edge into an HTTP-01
  // retry loop for a name whose DNS still points at GCP.
  const redirects = hostRedirects.filter(
    (redirect) => servableHostnames.has(redirect.from) && servableHostnames.has(redirect.to)
  );
  const redirectSources = new Set(redirects.map((redirect) => redirect.from));

  const blocks: Block[] = [];
  for (const site of servable) {
    const serving = site.hostnames
      .filter((hostname) => !redirectSources.has(hostname))
      .map(assertHostname);
    if (serving.length > 0) {
      blocks.push(siteBlock(site, serving, posture));
    }
    for (const redirect of redirects.filter((entry) => site.hostnames.includes(entry.from))) {
      blocks.push(redirectBlock(redirect, `${site.name}_redirect_per_ip`, posture));
    }
  }
  blocks.push(probeBlock(posture));

  const lines = [...GENERATED_BANNER, '', ...globalOptions()];
  for (const block of blocks) {
    lines.push('', ...renderBlock(block));
  }
  return `${lines.join('\n')}\n`;
}

/**
 * The AppSec acquisition file — the other half of the posture, and the reason
 * detect-only is a real mode rather than a claim.
 *
 * In-band versus out-of-band is a property of the AppSec *configuration*, not
 * of the datasource, so which configurations this file names is what decides
 * whether a rule can block. Detect-only names only the out-of-band one.
 */
export function renderAppsecAcquisition(posture: EdgePosture): string {
  const configs =
    posture.crowdsec === 'enforcing'
      ? [APPSEC_CONFIG_INBAND, APPSEC_CONFIG_OUT_OF_BAND]
      : [APPSEC_CONFIG_OUT_OF_BAND];

  return `${[
    ...GENERATED_BANNER,
    'source: appsec',
    'name: edge',
    // Bound to every interface inside the container, reachable only from the
    // Compose network: the AppSec port is published nowhere.
    'listen_addr: 0.0.0.0:7422',
    'appsec_configs:',
    ...configs.map((config) => `  - ${config}`),
    'labels:',
    '  type: appsec',
  ].join('\n')}\n`;
}

/** Caddy's JSON access log, parsed by the `crowdsecurity/caddy` collection. */
export function renderCaddyLogAcquisition(): string {
  return `${[
    ...GENERATED_BANNER,
    'source: file',
    'filenames:',
    `  - ${ACCESS_LOG}`,
    'labels:',
    '  type: caddy',
  ].join('\n')}\n`;
}
