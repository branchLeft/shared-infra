import { APP_HOST_IPS, HOST_IPS } from '@branchleft/hetzner-host';

import type { EdgeSite, HostRedirect } from '../../siteTypes';
import {
  MEMBERS_MAGIC_LINK_RATE_LIMIT_EVENTS,
  MEMBERS_MAGIC_LINK_RATE_LIMIT_WINDOW_SECONDS,
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
 * `injectionWafPreviewOnly`. Ghost's admin API is where author-written HTML,
 * code samples and SQL arrive in a request body; the admin UI around it is a
 * static bundle carrying none, so the prefix is the API and not `/ghost`.
 *
 * The exemption removes **all** AppSec evaluation on these paths, not only the
 * injection rulesets — the Caddy handler is per-request, so there is no way to
 * exempt three rule families and keep a fourth. That is a widening relative to
 * the policy this replaces and it is disclosed in `CLOUD-ARMOR-BASELINE.md`
 * rather than left to be discovered.
 */
const AUTHORING_API_PATHS = ['/ghost/api/*'];

/**
 * Ghost's members send-magic-link route (`ghost/core/core/server/web/members/app.js`,
 * mounted at `/members` by `ghost/core/core/server/web/parent/frontend.js`):
 * `POST /members/api/send-magic-link`. The one unauthenticated route that
 * turns a request into an email send from `mx1` -- see `posture.ts` for why
 * it gets its own, far tighter, throttle.
 *
 * Both forms are listed because Express's default router (`strict: false`) routes
 * a trailing slash identically, and Caddy's `path` matcher does not normalise
 * one away -- an unmatched `/members/api/send-magic-link/` would fall through
 * to the general per-site zone instead, forty times looser. Deliberately two
 * exact patterns rather than a `*` suffix: a wildcard here would also match
 * any *longer* path sharing this prefix, which is wider than the one route
 * this throttle exists for.
 *
 * No case variants listed: confirmed against the exact `2.11.4` tag this
 * edge's image pins (`Dockerfile`'s `CADDY_VERSION`) that Caddy's `path`
 * matcher lowercases both the request path and every pattern before
 * comparing (`modules/caddyhttp/matchers.go`) -- its own stated rationale is
 * that RFC 9110's case-sensitive path matching is a security footgun it
 * deliberately does not reproduce -- so `/Members/API/Send-Magic-Link`
 * already matches without listing it. Not assumed from a general Caddy
 * version claim: checked against this pin specifically.
 *
 * Assumes one Ghost instance per hostname, rooted at `/` -- true of every
 * site in `sites.ts` today. A tenant served from a subdirectory rather than
 * its own hostname would need `/<prefix>` folded into both patterns below;
 * nothing here derives that prefix automatically.
 */
const MEMBERS_MAGIC_LINK_PATHS = ['/members/api/send-magic-link', '/members/api/send-magic-link/'];

/**
 * The same zone name is declared again in every site's own `rate_limit`
 * block below, not shared by reference -- Caddy's directive syntax has no
 * "reference elsewhere" form, so each site block carries its own full zone
 * declaration. What still makes it one shared counter across every tenant
 * hostname, rather than a per-site one like `rateLimitDirective` below: the
 * module's zone state is a process-wide registry keyed by name
 * (`mholt/caddy-ratelimit`'s `LoadOrStore` on the zone map), so re-declaring
 * the identical name attaches to the same counter instead of creating a new
 * one. See `posture.ts` for why that sharing is the property Ghost's own
 * per-instance limiter lacks.
 */
const MEMBERS_MAGIC_LINK_ZONE = 'members_magic_link_per_ip';

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
 * Port carrying Caddy's own Prometheus metrics, on a listener separate from
 * every public site. Compose publishes it on `edge1`'s private address only
 * (`../monitoring/stack/compose.yml`'s Prometheus scrapes it from there) --
 * never on the public interface, and never through the site blocks above, so
 * a metrics request cannot reach it by way of a hostname a client controls.
 */
const METRICS_PORT = 9091;

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

/**
 * Bounds the added latency of an AppSec verdict. The token is `appsec_timeout`;
 * upstream's README documents `appsec_max_timeout`, which its own Caddyfile
 * parser rejects. Read the parser, not the table.
 */
const APPSEC_TIMEOUT = '1s';

/**
 * Certificate issuance is pinned rather than left to Caddy's default issuer
 * list, whose fallback is a second CA that has not been through the supplier
 * rubric every other component here has.
 */
const ACME_DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory';

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
 * `mx1` is not behind this edge and never can be: it lives in its own hcloud
 * project, and networks do not span projects, so it has no address on the
 * plan this renderer resolves against. Named here anyway, because it is a
 * plausible thing to type and the message it earns says why rather than
 * `unknown upstream host`. `edge1` is this host, so naming it produces a proxy
 * loop that answers every request with a timeout after exhausting the
 * connection pool. Both are registry mistakes worth failing on rather than
 * rendering.
 */
const NOT_AN_UPSTREAM = new Set(['mx1', 'edge1']);

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
    //
    // This key and the no-CDN assumption are one decision and must move
    // together. Put any CDN or scrubbing service in front of this edge and
    // every request arrives from a handful of its addresses: a per-IP throttle
    // then counts the whole internet as a few clients and throttles everyone
    // within seconds of the change. Both zones share this key, so that failure
    // would take the magic-link path down with the general one. Whoever
    // evaluates a CDN owns changing this line to a trusted-proxy configuration
    // in the same change, never afterwards.
    '\t\tkey {http.request.remote.host}',
    `\t\twindow ${RATE_LIMIT_WINDOW_SECONDS}s`,
    `\t\tevents ${RATE_LIMIT_EVENTS}`,
    '\t}',
    '}',
  ];
}

/** Named matcher for the members magic-link route, defined at site-block scope. */
function membersMagicLinkMatcher(): string[] {
  return [
    '@members_magic_link {',
    '\tmethod POST',
    `\tpath ${MEMBERS_MAGIC_LINK_PATHS.join(' ')}`,
    '}',
  ];
}

/**
 * The tighter, second throttle on top of the general per-site one above.
 * Independent zone, independent counter: a client can spend its general
 * budget on ordinary page requests and still trip this one separately on the
 * one path that costs mx1 deliverability rather than edge compute.
 */
function membersMagicLinkRateLimitDirective(): string[] {
  return [
    'rate_limit @members_magic_link {',
    `\tzone ${MEMBERS_MAGIC_LINK_ZONE} {`,
    '\t\tkey {http.request.remote.host}',
    `\t\twindow ${MEMBERS_MAGIC_LINK_RATE_LIMIT_WINDOW_SECONDS}s`,
    `\t\tevents ${MEMBERS_MAGIC_LINK_RATE_LIMIT_EVENTS}`,
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
  options: { appsec: 'none' | 'all' | 'except-authoring'; membersMagicLink?: boolean }
): string[] {
  const lines: string[] = [];
  // Two independent conditions, not one nested in the other. The magic-link
  // throttle protects mx1's deliverability and the general one sheds load off
  // two vCPUs; they are the same Caddy module at opposite risk profiles, and
  // nesting them meant the narrow control could not be enabled without the
  // broad one.
  if (posture.rateLimit === 'enforcing') {
    lines.push(...rateLimitDirective(zone));
  }
  if (posture.membersMagicLinkRateLimit === 'enforcing' && options.membersMagicLink) {
    lines.push(...membersMagicLinkRateLimitDirective());
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
    body.push(`@inspected not path ${AUTHORING_API_PATHS.join(' ')}`);
  }
  // Defined for every site, not only Ghost tenants: the matcher only ever
  // matches Ghost's own path, so a non-Ghost site (e.g. the marketing site)
  // carries an inert matcher rather than needing a flag to opt in. That is
  // what makes this apply to a future tenant by construction, with no entry
  // in `sites.ts` needed beyond `privateUpstream`.
  //
  // Gated on the magic-link field, not the general one: the matcher exists only
  // to be referenced by `rate_limit @members_magic_link`, so emitting it under
  // the wrong condition either leaves a dangling reference or an orphan matcher.
  if (posture.membersMagicLinkRateLimit === 'enforcing') {
    body.push(...membersMagicLinkMatcher());
  }
  body.push(
    'route {',
    ...protectionChain(posture, `${site.name}_per_ip`, {
      appsec: site.injectionWafPreviewOnly ? 'except-authoring' : 'all',
      membersMagicLink: true,
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
  const body: string[] = [...logDirective(PROBE_LOG)];
  // Carries the members magic-link matcher too, same as a real site: this is
  // what lets the throttle be trip-tested with a loopback `curl` before any
  // hostname serves the path for real, the same way the general throttle
  // already is (RUNBOOK-edge.md §8a).
  if (posture.membersMagicLinkRateLimit === 'enforcing') {
    body.push(...membersMagicLinkMatcher());
  }
  body.push(
    'route {',
    ...protectionChain(posture, 'probe_per_ip', {
      appsec: 'all',
      membersMagicLink: true,
    }).map((line) => `\t${line}`),
    '\trespond 204',
    '}'
  );
  return { addresses: [`:${PROBE_PORT}`], body };
}

/**
 * Serves the metrics `servers { metrics }` above collects. Address is a bare
 * port, same as `probeBlock` -- Compose, not this file, decides which host
 * interface it is reachable on. No protection chain: this is not
 * user-facing traffic, and there is nothing here for the throttle or
 * CrowdSec to usefully evaluate.
 */
function metricsBlock(): Block {
  return {
    addresses: [`:${METRICS_PORT}`],
    body: ['metrics'],
  };
}

function globalOptions(): string[] {
  return [
    '{',
    // No stable ACME account and no expiry notice without one. Read from the
    // environment rather than committed, for the same reason the bouncer key
    // is: an address in a public tree is an address in a scraper's list.
    '\temail {env.ACME_EMAIL}',
    `\tacme_ca ${ACME_DIRECTORY}`,
    // HTTP/3 is off because the host firewall opens tcp/443 and no UDP port.
    // Left on, Caddy advertises `Alt-Svc: h3` on every response and clients
    // retry QUIC against a port Hetzner drops upstream — which browsers survive
    // by falling back, after caching the advertisement and stalling first
    // connections in a way that looks like anything but a firewall rule.
    //
    // `metrics` here only turns on collection of the per-server request
    // counters; it opens no listener of its own. The `metrics` handler in the
    // dedicated block below is the listener that actually serves them.
    '\tservers {',
    '\t\tprotocols h1 h2',
    '\t\tmetrics',
    '\t}',
    '\tcrowdsec {',
    `\t\tapi_url ${CROWDSEC_LAPI_URL}`,
    '\t\tapi_key {env.CROWDSEC_BOUNCER_KEY}',
    '\t\tticker_interval 15s',
    `\t\tappsec_url ${CROWDSEC_APPSEC_URL}`,
    `\t\tappsec_max_body_bytes ${APPSEC_MAX_BODY_BYTES}`,
    `\t\tappsec_timeout ${APPSEC_TIMEOUT}`,
    // A bare flag: the parser rejects an argument here. Absent, the bouncer
    // fails *closed*, and the appsec handler is in the route in every posture —
    // so a CrowdSec restart would answer 500 for every request on every site,
    // including in the posture that is supposed to be unable to affect one.
    '\t\tappsec_fail_open',
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
  blocks.push(metricsBlock());

  // No blank line between the banner and the global options block: `caddy fmt`
  // removes one, and a rendered file that its own formatter would rewrite makes
  // every future diff ambiguous about whether the config or the layout changed.
  const lines = [...GENERATED_BANNER, ...globalOptions()];
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
