import { createHash } from 'node:crypto';

import { APP_HOST_IPS, HOST_IPS } from '@branchleft/hetzner-host';

import type { EdgeSite, HostRedirect, StaticSite } from '../../siteTypes';
import {
  MEMBERS_MAGIC_LINK_RATE_LIMIT_EVENTS,
  MEMBERS_MAGIC_LINK_RATE_LIMIT_WINDOW_SECONDS,
  RATE_LIMIT_EVENTS,
  RATE_LIMIT_WINDOW_SECONDS,
  TLS_PROTOCOLS,
  type EdgePosture,
} from './posture';
import { PUBLICPRESS_HOLDING_HTML } from './publicpressHolding';

// Why: renders config from sites.ts & posture.ts; pure strings, committed to
// stack/, hand-copied. Registry is the only hostname list. See render.md
// §"Module: Caddy configuration rendering".

const GENERATED_BANNER = [
  '# Generated from sites.ts and hetzner/edge/posture.ts.',
  '# Regenerate with `npm run render` in hetzner/. Hand edits are overwritten.',
];

// Why: exempts author-written HTML/code/SQL from AppSec on preview-only sites;
// removes ALL AppSec evaluation (not just injection). See render.md §"AUTHORING_API_PATHS".
const AUTHORING_API_PATHS = ['/ghost/api/*'];

/**
 * Ghost's members send-magic-link route, both trailing-slash forms, case
 * variants included by Caddy's own path-matcher lowercasing. Why: `render.md`.
 */
const MEMBERS_MAGIC_LINK_PATHS = ['/members/api/send-magic-link', '/members/api/send-magic-link/'];

// Why: zone name re-declared per-site for shared counter via mholt/caddy-ratelimit's
// LoadOrStore. See render.md §"MEMBERS_MAGIC_LINK_ZONE".
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

// Why: host-qualified probe exercises site routing (unlike bare :port); .invalid
// never resolves; global magic-link zone testable. See render.md §"PROBE_HOSTNAME".
const PROBE_HOSTNAME = 'edge-probe.invalid';

// Why: status code alone cannot distinguish delivered config from skipped rsync;
// marker header is the only discriminator. See render.md §"PROBE_MARKER_* constants".
const PROBE_MARKER_HEADER = 'X-Edge-Probe';
const PROBE_MARKER_HOST = 'host-routed';
const PROBE_MARKER_BARE = 'bare-port';

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
 * `unknown upstream host`.
 */
const NOT_AN_UPSTREAM = new Set(['mx1']);

/**
 * `edge1` is this host. Proxying to its own private address on the ports this
 * edge itself listens on produces a proxy loop that answers every request with
 * a timeout after exhausting the connection pool, so those ports fail the
 * render. Any other port is a service published on this host's private address
 * by a different Compose stack (the monitoring stack's pager), which is a
 * backend like any other.
 */
const EDGE_HOST = 'edge1';
const EDGE_LISTEN_PORTS = new Set([80, 443]);

export function resolvePrivateAddress(host: string, port: number): string {
  if (NOT_AN_UPSTREAM.has(host)) {
    throw new Error(`${host} is not a backend this edge proxies to`);
  }
  if (host === EDGE_HOST && EDGE_LISTEN_PORTS.has(port)) {
    throw new Error(`${host}:${port} is this edge's own listener, not a backend it proxies to`);
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

/**
 * `max-age=31536000` (365 days) with `includeSubDomains` is the standard
 * baseline every browser vendor documents for this header. `preload` is
 * deliberately absent -- submitting to a browser's preload list is a
 * separate, slow-to-reverse decision (removal takes months to propagate),
 * not a rendering default this file should choose unilaterally.
 */
const HSTS_VALUE = 'max-age=31536000; includeSubDomains';

// Why: first in route (before reverse_proxy) to survive 429/403 responses; only
// control that emitted response headers before this fix. See render.md §"hstsDirective".
function hstsDirective(): string[] {
  return [`header Strict-Transport-Security "${HSTS_VALUE}"`];
}

// Why: restricts directives to inline-only hashes; img-src/font-src support data: URIs
// when present; CSP does not govern mailto: links. See render.md §"staticSiteCsp".
export function staticSiteCsp(html: string): string {
  const source = (pattern: RegExp): string => {
    const hashes = [...html.matchAll(pattern)].map(
      ([, body]) => `'sha256-${createHash('sha256').update(body, 'utf8').digest('base64')}'`
    );
    return hashes.length > 0 ? hashes.join(' ') : "'none'";
  };
  const scriptSrc = source(/<script>([\s\S]*?)<\/script>/g);
  const styleSrc = source(/<style>([^<]*)<\/style>/g);
  const imgSrc = /<link rel='icon' [^>]*href='data:/.test(html) ? 'data:' : "'none'";
  const fontSrc = /@font-face\{[^}]*src:url\(data:/.test(html) ? 'data:' : "'none'";
  return (
    `default-src 'none'; script-src ${scriptSrc}; style-src ${styleSrc}; img-src ${imgSrc}; ` +
    `font-src ${fontSrc}; connect-src 'none'; frame-src 'none'; frame-ancestors 'none'; ` +
    "base-uri 'none'; form-action 'none'"
  );
}

function cspDirective(value: string): string[] {
  return [`header Content-Security-Policy "${value}"`];
}

/** No form on this page and no legitimate reason for a request body at all. */
const STATIC_SITE_REQUEST_BODY_MAX_SIZE = '1KiB';

const STATIC_SITE_CONTENT_TYPE = 'text/html; charset=utf-8';

/**
 * Page content for each `StaticSite` in `sites.ts`, keyed by `name`. Kept as
 * a map rather than a field on `StaticSite` itself so that registry (hostname
 * and addressing) and content stay in separate files, the same split the
 * rest of `sites.ts` draws.
 */
const STATIC_SITE_CONTENT: Record<string, string> = {
  'publicpress-holding': PUBLICPRESS_HOLDING_HTML,
};

function staticSiteContent(site: StaticSite): string {
  const html = STATIC_SITE_CONTENT[site.name];
  if (html === undefined) {
    throw new Error(
      `static site ${site.name} has no page content registered in render.ts's STATIC_SITE_CONTENT`
    );
  }
  return html;
}

function rateLimitDirective(zone: string): string[] {
  return [
    'rate_limit {',
    `\tzone ${zone} {`,
    // Why: direct peer is client, not forwarded header; no-CDN assumption must move
    // together with this key. See render.md §"rateLimitDirective: client IP key".
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

// Why: throttle runs before WAF (unlike Cloud Armor baseline); order protects vCPUs
// from floods reaching inspection. See render.md §"protectionChain: handler evaluation order".
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

// Why: powers of two only; MB/GB are powers of ten in Caddy (~4.6% smaller); value
// must stay commensurable with tmpfs ceiling. See render.md §"BINARY_SIZE regex".
const BINARY_SIZE = /^[1-9][0-9]*(KiB|MiB|GiB)$/;

function requestBodyDirective(site: EdgeSite): string[] {
  const size = site.requestBodyMaxSize;

  if (size === undefined) {
    // Why: required of all sites, not keyed to injectionWafPreviewOnly (which is
    // temporary). Only bound Ghost tenants have. See render.md §"requestBodyDirective".
    throw new Error(
      `site ${site.name} declares no requestBodyMaxSize. Every site this edge serves needs one: ` +
        "for a tenant take it from that stack's `pulumi stack output edgeRequestBodyMaxSize` " +
        '(RUNBOOK-tenant-onboarding.md section 9); for a non-tenant site choose a bound its own ' +
        'request shapes justify.'
    );
  }

  if (!BINARY_SIZE.test(size)) {
    throw new Error(
      `site ${site.name} has requestBodyMaxSize ${size}, which is not a binary size this ` +
        'renderer will emit (KiB, MiB or GiB) -- Caddy reads MB and GB as powers of ten, and ' +
        'this value must stay commensurable with the tmpfs ceiling it is derived alongside'
    );
  }

  return ['request_body {', `\tmax_size ${size}`, '}'];
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
    // Ahead of everything else, including request_body -- see hstsDirective's
    // own comment for why its position is load-bearing rather than tidiness.
    ...hstsDirective().map((line) => `\t${line}`),
    // Why: does not terminate handler chain; ordering buys tidiness only. AppSec
    // caps at appsec_max_body_bytes anyway. See render.md §"siteBlock: request_body ordering".
    ...requestBodyDirective(site).map((line) => `\t${line}`),
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
      ...hstsDirective().map((line) => `\t${line}`),
      ...protectionChain(posture, zone, { appsec: 'none' }).map((line) => `\t${line}`),
      `\tredir https://${assertHostname(redirect.to)}{uri} permanent`,
      '}',
    ],
  };
}

// Why: fixed-page hostname with same TLS/throttle posture as siteBlock; no upstream,
// no members route; strict CSP (inline only). See render.md §"staticBlock".
function staticBlock(site: StaticSite, posture: EdgePosture): Block {
  const html = staticSiteContent(site);
  return {
    addresses: [assertHostname(site.hostname)],
    body: [
      ...logDirective(ACCESS_LOG),
      ...tlsDirective(),
      'route {',
      // Ahead of everything else, same reasoning as hstsDirective's own
      // comment: both headers must survive a 429 or a 403 from the chain
      // below, not only the 200 this block otherwise always answers.
      ...hstsDirective().map((line) => `\t${line}`),
      ...cspDirective(staticSiteCsp(html)).map((line) => `\t${line}`),
      ...['request_body {', `\tmax_size ${STATIC_SITE_REQUEST_BODY_MAX_SIZE}`, '}'].map(
        (line) => `\t${line}`
      ),
      ...protectionChain(posture, `${site.name}_per_ip`, { appsec: 'all' }).map(
        (line) => `\t${line}`
      ),
      // Set immediately ahead of `respond`, not with the headers above:
      // unlike HSTS and the CSP, this describes the 200 body specifically,
      // and a request the chain above already answered (429, 403) never
      // reaches this line.
      `\theader Content-Type "${STATIC_SITE_CONTENT_TYPE}"`,
      `\trespond "${html}" 200`,
      '}',
    ],
  };
}

// Why: loopback listener makes posture observable before hostnames resolve;
// rendered twice (bare port and host-qualified). See render.md §"probeBlock".
function probeBlock(
  posture: EdgePosture,
  address: string,
  generalZone: string,
  marker: string
): Block {
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
    ...protectionChain(posture, generalZone, {
      appsec: 'all',
      membersMagicLink: true,
    }).map((line) => `\t${line}`),
    // Names which block answered. Without it the two probes are
    // indistinguishable on the wire: a bare `:port` address matches every
    // Host, so it answers a request for the host-qualified name identically
    // whenever that block is missing -- and a verification step that passes
    // with the thing it verifies absent is not a verification step. This is
    // what makes RUNBOOK-edge.md §8b(4a) discriminating, and it is why the
    // marker must survive into the committed posture rather than depending on
    // the separate general zones, which render only under `rateLimit:
    // 'enforcing'`.
    `\theader ${PROBE_MARKER_HEADER} ${marker}`,
    '\trespond 204',
    '}'
  );
  return { addresses: [address], body };
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

// Why: two sites on one upstream = one tenant serves another's content/sessions;
// typo in address is well-formed and wrong. See render.md §"assertUpstreamsAreDistinct".
function assertUpstreamsAreDistinct(servable: readonly EdgeSite[]): void {
  const seen = new Map<string, string>();
  for (const site of servable) {
    const upstream = site.privateUpstream;
    if (upstream === undefined) continue;
    const address = `${upstream.host}:${upstream.port}`;
    const owner = seen.get(address);
    if (owner !== undefined) {
      throw new Error(
        `sites ${owner} and ${site.name} both proxy to ${address}. Two hostnames sharing one ` +
          "backend means each serves the other's content and sessions -- take each site's port " +
          'from its own stack rather than from what is free on the host.'
      );
    }
    seen.set(address, site.name);
  }
}

/**
 * A static site's hostname must not be one an `EdgeSite` already serves --
 * Caddy would happily bind two site blocks to the same address, and whichever
 * one it picked would silently shadow the other. Optional and defaulted to
 * `[]` in `renderCaddyfile` so every existing caller -- committed fixtures
 * and every test that predates this registry -- keeps rendering unchanged.
 */
function assertStaticHostnamesAreDistinct(
  staticSites: readonly StaticSite[],
  servableHostnames: ReadonlySet<string>
): void {
  const seen = new Set<string>();
  for (const site of staticSites) {
    if (servableHostnames.has(site.hostname)) {
      throw new Error(
        `static site ${site.name} declares ${site.hostname}, which an EdgeSite in sites.ts ` +
          'already serves -- one hostname cannot be both proxied and answered statically.'
      );
    }
    if (seen.has(site.hostname)) {
      throw new Error(`two static sites both declare ${site.hostname}.`);
    }
    seen.add(site.hostname);
  }
}

export function renderCaddyfile(
  sites: readonly EdgeSite[],
  hostRedirects: readonly HostRedirect[],
  posture: EdgePosture,
  staticSites: readonly StaticSite[] = []
): string {
  const servable = servableSites(sites);
  assertUpstreamsAreDistinct(servable);
  const servableHostnames = new Set(servable.flatMap((site) => site.hostnames));
  assertStaticHostnamesAreDistinct(staticSites, servableHostnames);

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
  for (const site of staticSites) {
    blocks.push(staticBlock(site, posture));
  }
  // Host-qualified first, bare port second. Caddy picks the most specific
  // matching site regardless of order, so this is for the reader, not for it.
  blocks.push(
    probeBlock(
      posture,
      `http://${PROBE_HOSTNAME}:${PROBE_PORT}`,
      'probe_host_per_ip',
      PROBE_MARKER_HOST
    )
  );
  blocks.push(probeBlock(posture, `:${PROBE_PORT}`, 'probe_per_ip', PROBE_MARKER_BARE));
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
