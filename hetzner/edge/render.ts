import { createHash } from 'node:crypto';

import { APP_HOST_IPS, HOST_IPS } from '@branchleft/hetzner-host';

import type { EdgeSite, HostRedirect, SiteMedia, StaticSite } from '../../siteTypes';
import {
  BAN_LADDER_MINUTES,
  BAN_LADDER_WINDOW,
  MEMBERS_MAGIC_LINK_RATE_LIMIT_EVENTS,
  MEMBERS_MAGIC_LINK_RATE_LIMIT_WINDOW_SECONDS,
  NEXTCLOUD_RATE_LIMIT_EVENTS,
  RATE_LIMIT_EVENTS,
  RATE_LIMIT_WINDOW_SECONDS,
  TLS_PROTOCOLS,
  WEBHOOK_RATE_LIMIT_EVENTS,
  WATCH_ONLY_SCENARIOS,
  WEBHOOK_RATE_LIMIT_WINDOW_SECONDS,
  type EdgePosture,
} from './posture';
import { SHARED_TENANT_FILES, type StaticTextFile } from './sharedTenantFiles';

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

/**
 * Ghost's first-run owner setup, in the unversioned
 * form and the versioned form (`/ghost/api/<version>/admin/...`). A fresh
 * Ghost has no owner, and this route creates one for whoever calls it first.
 * Caddy's path matcher lowercases, cleans dot segments and decodes escapes
 * before matching, and `*` stops at a slash, hence the `/*` forms for deeper
 * paths. Why: `render.md`.
 */
const GHOST_SETUP_PATHS = [
  '/ghost/api/admin/authentication/setup',
  '/ghost/api/admin/authentication/setup/*',
  '/ghost/api/*/admin/authentication/setup',
  '/ghost/api/*/admin/authentication/setup/*',
];

/**
 * POST is the claim and PUT is the second setup step. GET is the status read
 * Ghost's own admin sign-in makes before it shows a form, so refusing it would
 * break every tenant's admin login.
 */
const GHOST_SETUP_METHODS = ['POST', 'PUT'];

const GHOST_SETUP_REFUSAL_STATUS = 403;

/**
 * Ghost serves what a tenant uploads from the tenant's own origin, under these
 * three prefixes, so an uploaded `.js` satisfies `script-src 'self'` and an
 * uploaded `.html` or `.svg` is a document that runs script. The edge refuses
 * the request for any file of an active type below them. Why, and why a
 * refusal and not a download: `render.md`.
 */
const UPLOAD_PATH_PREFIXES = ['/content/files/', '/content/images/', '/content/media/'];
const ACTIVE_CONTENT_EXTENSIONS = [
  'js',
  'mjs',
  'cjs',
  'html',
  'htm',
  'shtml',
  'xhtml',
  'xht',
  'xml',
  'xsl',
  'xslt',
  'css',
  'svg',
  'svgz',
  'kml',
  'gpx',
];

/**
 * Over the path as received: any depth below a prefix, any case, any run of
 * slashes. The glob matchers cover what Caddy cleans (dot segments, escapes)
 * that this one does not.
 */
const UPLOAD_ACTIVE_PATH_REGEXP = `(?i)^/+content/+(?:files|images|media)/.*\\.(?:${ACTIVE_CONTENT_EXTENSIONS.join('|')})/*$`;

const UPLOAD_REFUSAL_STATUS = 403;

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
 * request proceeds. Loaded unless the posture is detect-only.
 */
const APPSEC_CONFIG_INBAND = 'crowdsecurity/appsec-default';

/**
 * Out-of-band AppSec configuration: OWASP CRS, evaluated after the request has
 * been answered, feeding the scenario that bans a repeat offender. Loaded in
 * every posture, because detection is what the detect-only period is for.
 */
const APPSEC_CONFIG_OUT_OF_BAND = 'crowdsecurity/crs';

/**
 * Our own AppSec configuration: hooks only, no rules. It narrows two Core Rule
 * Set rules on one Ghost admin request shape and nothing else. Named first in
 * the acquisition, because CrowdSec merges the named configurations in order
 * and the last one's options (`default_remediation`) win; the hub's stay last.
 * Why, and what it narrows: `render.md`, "Ghost admin preview exclusion".
 */
const APPSEC_CONFIG_GHOST_ADMIN = 'branchleft/ghost-admin-previews';

/**
 * The Core Rule Set rules Ghost admin's design and announcement-bar previews
 * trip, found by replaying the request in CI (`test_crowdsec_replay.py`):
 * 920420 (request content type not allowed: `text/html`) and 920180 (a POST
 * with no Content-Length, which is how the bouncer forwards a bodiless POST).
 */
const GHOST_PREVIEW_CRS_RULE_IDS = [920420, 920180] as const;

/** Ghost's admin API prefix, as Caddy's access log writes the request URI. */
const GHOST_ADMIN_API_PREFIX = '/ghost/api/admin/';

/**
 * Our own scenario that bans an address for repeated failed Ghost admin
 * sign-ins and admin API key failures. Its name is deliberately not
 * `HUB_ADMIN_PROBING_SCENARIO`, so the post-overflow that silences that one
 * never drops it. Why, and
 * what each number is: `render.md`, "Ghost admin brute force".
 */
const GHOST_BRUTE_FORCE_SCENARIO = 'branchleft/ghost-admin-login-bruteforce';

/**
 * The tenth failure inside the bucket bans (capacity 9), and one failure drains
 * every 30 seconds. Ghost's own limiter allows five sign-in attempts per address
 * and then answers 429, so a person who mistypes does not reach ten; a burst does.
 */
const GHOST_BRUTE_FORCE_CAPACITY = 9;
const GHOST_BRUTE_FORCE_LEAKSPEED = '30s';

/**
 * The statuses Ghost answers a failed sign-in (`POST /ghost/api/admin/session/`)
 * with: 422 a wrong password, 404 an unknown email address, 401 no credentials
 * or a locked account, 429 its own limiter. Not 403: a right password from a new
 * device is answered 403 (2FA_NEW_DEVICE_DETECTED) and is not a failure.
 */
const GHOST_FAILED_SIGNIN_STATUSES = [401, 404, 422, 429] as const;

/**
 * The hub scenario that reads a 403 or 404 on any path containing `/admin` as a
 * probe. Ours below reads the same requests; this one is silenced so that only
 * ours bans.
 */
const HUB_ADMIN_PROBING_SCENARIO = 'crowdsecurity/http-admin-interface-probing';

/**
 * Our copy of the hub's admin-interface probing scenario, which does not count
 * Ghost's own admin API on a Ghost hostname. The only admin-probing scenario
 * that bans. Why: `render.md`, "Ghost admin API and admin-interface probing".
 */
const ADMIN_PROBING_SCENARIO = 'branchleft/http-admin-interface-probing';

/**
 * The Caddy variable a verified session sets, and the top-level access-log
 * field it is written to. Only the verification call's 2xx JSON answer sets it
 * to `1`. Why it cannot be forged from a request: `render.md`, "Verified
 * sessions".
 */
export const TRUSTED_SESSION_VAR = 'edge_trusted';

/** Ghost's staff session cookie. Scoped by Ghost to `/ghost`. */
const GHOST_STAFF_SESSION_COOKIE = 'ghost-admin-api-session';

/**
 * Where a Ghost staff session is checked: Ghost's own "who am I" endpoint,
 * which answers 2xx JSON only for a signed-in, origin-matching, verified staff
 * session. The trailing `?` empties the query, so nothing the client sent
 * reaches Ghost's handler but the headers.
 */
const GHOST_STAFF_VERIFY_URI = '/ghost/api/admin/users/me/?';

/** The paths a Ghost staff session is checked on: where its cookie is sent. */
const GHOST_STAFF_PATHS = ['/ghost/*'];

/**
 * Bounds of the verification call. Generous, so a slow Ghost is not cut off:
 * a timeout gives no trust and the request fails as the origin itself would.
 */
const TRUSTED_SESSION_DIAL_TIMEOUT = '3s';
const TRUSTED_SESSION_RESPONSE_TIMEOUT = '10s';

/** Where the whitelist that keeps verified requests out of every bucket sits. */
const TRUSTED_SESSION_WHITELIST = 'branchleft/edge-trusted-session';

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
 * `edge1` is this host, so it is refused as an upstream except on the ports a
 * service on this host is deliberately published for: the monitoring stack's
 * pager (2586) and the Sweego receiver's webhook port (18080, the
 * `sweego_receiver_port` of `ansible/owner_vars/edge1.yml`). The receiver's
 * drain port (18081) is never listed: it is reachable from ops1 alone, and an
 * edge upstream on it would put it on a public route. Any other port on its own
 * address is the edge's own listener (a proxy loop) or an internal service
 * (Grafana, Prometheus) that must not be exposed by a registry typo. Widening
 * this is a decision, not a convenience.
 */
const EDGE_HOST = 'edge1';
export const EDGE_HOST_ALLOWED_PORTS: ReadonlySet<number> = new Set([2586, 18080]);

export function resolvePrivateAddress(host: string, port: number): string {
  if (NOT_AN_UPSTREAM.has(host)) {
    throw new Error(`${host} is not a backend this edge proxies to`);
  }
  if (host === EDGE_HOST && !EDGE_HOST_ALLOWED_PORTS.has(port)) {
    throw new Error(
      `${host}:${port} is not a backend this edge proxies to: only ${[...EDGE_HOST_ALLOWED_PORTS].join(', ')} is published on this host for it`
    );
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

// Why: the single-use break-glass sign-in token travels in this query parameter.
// See render.md §"logDirective: break-glass token redaction and strip".
const BREAK_GLASS_PARAM = 'bl_break_glass';

/**
 * The one place the parameter name is spelled. Each character is itself or its
 * percent form, with either hex case accepted for the percent form; letters stay
 * case-sensitive. Uses no backslash or brace, so Caddyfile quoting leaves it alone.
 */
function paramNamePattern(): string {
  return [...BREAK_GLASS_PARAM]
    .map((ch) => {
      const hex = ch.charCodeAt(0).toString(16).toUpperCase();
      const spelled = [...hex]
        .map((digit) => (/[A-F]/.test(digit) ? `[${digit}${digit.toLowerCase()}]` : digit))
        .join('');
      return `(?:${ch}|%${spelled})`;
    })
    .join('');
}

/** The log fields the token can appear in: the request line, a refused sign-in's Referer, Ghost's 302. */
const BREAK_GLASS_LOG_FIELDS = ['request>uri', 'request>headers>Referer', 'resp_headers>Location'];

/**
 * Retention of every edge log, set explicitly rather than left to Caddy's own
 * defaults. The owner decided 30 days on 2026-08-24: well inside the 90-day
 * ceiling the website privacy notice commits to, and far
 * longer than abuse investigation or incident response needs. Caddy's default
 * happens to be about 90 days, so leaving it unset would keep the notice true by
 * coincidence rather than by policy.
 */
const LOG_RETENTION = '720h';

/**
 * Rotation. `roll_keep_for` only prunes files that have already been rolled, so a
 * roll must happen even on a quiet edge. `roll_at 00:00` (UTC) rolls daily on the
 * clock; `roll_interval` would not, because it rolls only on the next write. Caddy
 * v2.11.4 accepts `roll_at` (github.com/DeRuina/timberjack v1.4.2, rotation on a
 * background timer). The count is 31, so 30 daily rolls are kept: Caddy's default
 * of 10 would cap a daily roll at 10 days and silently shorten the retention.
 */
const LOG_ROLL_AT = '00:00';
const LOG_ROLL_SIZE = '100MiB';
const LOG_ROLL_KEEP = 31;

/**
 * The encoder every edge log shares: Caddy's JSON, with the break-glass parameter's
 * value replaced in the fields the token can reach. Unindented, so each caller
 * nests it at its own depth.
 */
function redactingFormat(): string[] {
  // Any parameter whose name starts with the token's, in any case, loses its value.
  const pattern = `(?i)([?&]${paramNamePattern()})[^&#]*`;
  return [
    'format filter {',
    '\twrap json',
    ...BREAK_GLASS_LOG_FIELDS.map((field) => `\t${field} regexp "${pattern}" "$1=REDACTED"`),
    '}',
  ];
}

function logDirective(path: string): string[] {
  return [
    'log {',
    `\toutput file ${path} {`,
    `\t\troll_size ${LOG_ROLL_SIZE}`,
    `\t\troll_keep ${LOG_ROLL_KEEP}`,
    `\t\troll_keep_for ${LOG_RETENTION}`,
    `\t\troll_at ${LOG_ROLL_AT}`,
    '\t}',
    ...redactingFormat().map((line) => `\t${line}`),
    '}',
  ];
}

/**
 * Caddy's default logger, set in the global options. Two lines reach it that no
 * site's `log` block sees: the `http.log.error` line written when a handler fails
 * (a 502 from a refused upstream), which carries the whole request including its
 * URI and headers, and the line for a request whose Host matches no site block.
 * Left alone it writes both to stderr, and so to the container log, with a
 * break-glass token in clear. Same encoder and fields as `logDirective`, so no log
 * path the token can reach is left unfiltered. See render.md
 * §"defaultLogDirective: the error and no-site lines".
 */
function defaultLogDirective(): string[] {
  return ['log {', '\toutput stderr', ...redactingFormat().map((line) => `\t${line}`), '}'];
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
const STATIC_SITE_CONTENT: Record<string, string> = {};

function staticSiteContent(site: StaticSite): string {
  const html = STATIC_SITE_CONTENT[site.name];
  if (html === undefined) {
    throw new Error(
      `static site ${site.name} has no page content registered in render.ts's STATIC_SITE_CONTENT`
    );
  }
  return html;
}

function rateLimitDirective(zone: string, events: number = RATE_LIMIT_EVENTS): string[] {
  return [
    'rate_limit {',
    `\tzone ${zone} {`,
    // Why: direct peer is client, not forwarded header; no-CDN assumption must move
    // together with this key. See render.md §"rateLimitDirective: client IP key".
    '\t\tkey {http.request.remote.host}',
    `\t\twindow ${RATE_LIMIT_WINDOW_SECONDS}s`,
    `\t\tevents ${events}`,
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

/** Named matcher for Ghost's first-run owner setup, defined at site-block scope. */
function ghostSetupMatcher(): string[] {
  return [
    '@ghost_setup {',
    `\tmethod ${GHOST_SETUP_METHODS.join(' ')}`,
    `\tpath ${GHOST_SETUP_PATHS.join(' ')}`,
    '}',
  ];
}

/**
 * Answers the matcher above with a refusal and nothing else. After the
 * protection chain on purpose: a client probing for an open setup is
 * throttled, and CrowdSec still sees it, rather than being answered for free.
 */
function ghostSetupRefusal(): string {
  return `respond @ghost_setup ${GHOST_SETUP_REFUSAL_STATUS}`;
}

/**
 * The refusal of an uploaded file a browser would run, as lines for a Ghost
 * site's `route`. Two overlapping matchers, each followed by a 403: Caddy's
 * cleaning, case-insensitive `path` (a nested `route` makes the prefix and the
 * extension an AND, since two `path` lines in one matcher are an OR), and a
 * `path_regexp` over the path as received. Every method is refused. Placed
 * after the protection chain, so a client probing for an upload is throttled
 * and CrowdSec still sees it. The refusal names active types only; `nosniff`
 * (below) is what covers every other type Ghost lets a tenant upload.
 */
function uploadGuard(): string[] {
  const prefixes = UPLOAD_PATH_PREFIXES.map((prefix) => `${prefix}*`).join(' ');
  const extensions = ACTIVE_CONTENT_EXTENSIONS.map((extension) => `*.${extension}`).join(' ');
  return [
    '@uploads_by_path {',
    `\tpath ${prefixes}`,
    '}',
    'route @uploads_by_path {',
    '\t@active_upload_by_path {',
    `\t\tpath ${extensions}`,
    '\t}',
    `\trespond @active_upload_by_path ${UPLOAD_REFUSAL_STATUS}`,
    '}',
    '@active_upload_by_pattern {',
    `\tpath_regexp ${UPLOAD_ACTIVE_PATH_REGEXP}`,
    '}',
    `respond @active_upload_by_pattern ${UPLOAD_REFUSAL_STATUS}`,
  ];
}

/**
 * Ghost's front-end widgets (Portal, search, comments, the announcement bar,
 * the signup form, the admin toolbar), served from the tenant's own hostname so
 * a reader's browser contacts no CDN. The files are the pinned bundles of
 * `branchLeft/ghost-platform`'s `widgets/dist/`, baked into the edge image at
 * `/srv/bl-assets/` by `hetzner/edge/Dockerfile`; the tenant environment names
 * them as `<siteUrl>/bl-assets/<file>`. A name the image does not hold is a
 * 404 from here, never passed to Ghost. The cache is an hour, not a year: the
 * names are not content-addressed, and a re-pin replaces the bytes under them.
 * Why each line: `render.md`, "Widget assets".
 */
export const WIDGET_ASSET_PATH = '/bl-assets/';
export const WIDGET_ASSET_ROOT = '/srv';
const WIDGET_ASSET_CACHE_CONTROL = 'public, max-age=3600';

function widgetAssets(): string[] {
  return [
    '@widget_assets {',
    '\tmethod GET HEAD',
    `\tpath ${WIDGET_ASSET_PATH}*`,
    '}',
    'encode @widget_assets zstd gzip',
    `header @widget_assets Cache-Control "${WIDGET_ASSET_CACHE_CONTROL}"`,
    'file_server @widget_assets {',
    `\troot ${WIDGET_ASSET_ROOT}`,
    '}',
  ];
}

/**
 * A Ghost tenant's uploads (`/content/images/`, `/content/media/`,
 * `/content/files/`) answered from the tenant's own hostname by fetching them
 * from its object-storage bucket, so a reader's browser contacts no storage
 * host. Ghost's S3 adapter answers these paths with a 301 to the bucket; this
 * route answers first, and a bucket object is read exactly as Ghost would have
 * linked it (path-style, key = the request path). Only `GET` and `HEAD`, never
 * a client query string (an S3 query selects a version or a sub-resource), never
 * a cookie or credential, and none of the bucket's own response headers. A
 * missing object is a 404 here; a missing resized copy (`/content/images/size/`)
 * is first asked of Ghost, which makes it, and then read again from the bucket,
 * once. Why each line: `render.md`, "Tenant media".
 */
const MEDIA_PATHS = ['/content/images/*', '/content/media/*', '/content/files/*'];
const MEDIA_RESIZE_PATH = '/content/images/size/*';
const MEDIA_BUCKET = /^branchleft-media-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const MEDIA_CACHE_CONTROL = 'public, max-age=31536000, immutable';
const MEDIA_STRIPPED_RESPONSE_HEADERS = [
  'x-amz-request-id',
  'x-amz-version-id',
  'x-amz-expiration',
  'x-amz-storage-class',
  'x-rgw-object-type',
  'Strict-Transport-Security',
];
/**
 * Three reads of the one request, because the bucket path is built from the
 * decoded one (`{http.request.uri.path}`) and Caddy's `path` matcher cleans
 * its own copy, so no single read sees every form. The URI as received: a
 * `..` segment, plain or percent-encoded, after a slash plain or encoded.
 * The decoded path: a `..` segment, however the separators and dots were
 * written. The decoded path again: an escape left in it (`%2e`, `%2f`, `%25`)
 * was escaped twice, and the edge's own rewrites (to the bucket after a Ghost
 * round, to Ghost on a missing resized copy) read it a second time into a
 * dot segment. Ghost writes no `%` into an upload's name.
 */
const MEDIA_TRAVERSAL_EXPRESSION = [
  "{http.request.orig_uri}.matches('(?i)(?:^|/|%2f)(?:[.]|%2e){2}(?:/|%2f|[?]|$)')",
  "{http.request.uri.path}.matches('(?:^|/)[.]{2}(?:/|$)')",
  "{http.request.uri.path}.matches('(?i)%(?:2e|2f|25)')",
].join(' || ');

function mediaBucketProxy(media: SiteMedia, suffix: string, onMiss: string[]): string[] {
  return [
    `rewrite * /${media.bucket}{http.request.uri.path}?`,
    `reverse_proxy https://${media.host} {`,
    '\theader_up Host {upstream_hostport}',
    '\theader_up -Cookie',
    '\theader_up -Authorization',
    ...MEDIA_STRIPPED_RESPONSE_HEADERS.map((name) => `\theader_down -${name}`),
    `\t@media_hit_${suffix} status 2xx 304 416`,
    `\thandle_response @media_hit_${suffix} {`,
    `\t\theader Cache-Control "${MEDIA_CACHE_CONTROL}"`,
    '\t\tcopy_response',
    '\t}',
    `\t@media_miss_${suffix} status 403 404`,
    `\thandle_response @media_miss_${suffix} {`,
    ...onMiss.map((line) => `\t\t${line}`),
    '\t}',
    '}',
  ];
}

function tenantMedia(media: SiteMedia, ghostAddress: string): string[] {
  if (!HOSTNAME.test(media.host)) {
    throw new Error(`media host "${media.host}" is not a plain hostname`);
  }
  if (!MEDIA_BUCKET.test(media.bucket)) {
    throw new Error(
      `media bucket "${media.bucket}" must be a tenant media bucket name, "branchleft-media-" ` +
        'followed by the tenant slug: the edge reads no other bucket'
    );
  }
  const resizeMiss = [
    'rewrite * {http.request.orig_uri.path}',
    `reverse_proxy ${ghostAddress} {`,
    '\t@media_bounce status 301 302 307 308',
    '\thandle_response @media_bounce {',
    ...mediaBucketProxy(media, 'retry', ['respond 404']).map((line) => `\t\t${line}`),
    '\t}',
    '}',
  ];
  return [
    '@tenant_media_traversal {',
    `\tpath ${MEDIA_PATHS.join(' ')}`,
    `\texpression \`${MEDIA_TRAVERSAL_EXPRESSION}\``,
    '}',
    'respond @tenant_media_traversal 404',
    '@tenant_media_resize {',
    '\tmethod GET HEAD',
    `\tpath ${MEDIA_RESIZE_PATH}`,
    '}',
    '@tenant_media {',
    '\tmethod GET HEAD',
    `\tpath ${MEDIA_PATHS.join(' ')}`,
    '}',
    'route @tenant_media_resize {',
    ...mediaBucketProxy(media, 'resize', resizeMiss).map((line) => `\t${line}`),
    '}',
    'route @tenant_media {',
    ...mediaBucketProxy(media, 'plain', ['respond 404']).map((line) => `\t${line}`),
    '}',
  ];
}

/**
 * `nosniff` on every response of a Ghost-backed site, deferred (`>`) so it
 * replaces Ghost's own copy instead of doubling it. The extension refusal
 * cannot list every type Ghost accepts (`.txt`, `.md`, `.json`, `.pdf`, `.zip`,
 * `.py` too), and a browser runs a same-origin `<script src>` of any response
 * not typed image, audio, video or text/csv unless this header is set.
 */
function nosniffDirective(): string[] {
  return ['header >X-Content-Type-Options "nosniff"'];
}

/**
 * The same header on an error Caddy writes itself (502, no healthy upstream),
 * which the route's `header` never reaches. Site level: Caddy refuses a
 * `handle_errors` inside a `route`.
 */
function nosniffErrorBlock(): string[] {
  return ['handle_errors {', '\theader >X-Content-Type-Options "nosniff"', '}'];
}

// Why: the token is read only on /ghost/, so anywhere else it is stripped before
// any other handler. The gate reads the raw request target (Caddy's path matcher
// decodes and cleans, Express does not). See render.md §"logDirective: break-glass
// token redaction and strip".
function breakGlassStripMatcher(): string[] {
  const target = '{http.request.orig_uri}';
  const hasToken = `^[^?]*[?](?:[^&]*&)*${paramNamePattern()}(?:=|&|$)`;
  const onGhost = '^/ghost(?:[/?]|$)';
  const dotSegment = '^[^?]*(?:[.]|%2[Ee])(?:[.]|%2[Ee])';
  const fires = `${target}.matches('${hasToken}') && (!${target}.matches('${onGhost}') || ${target}.matches('${dotSegment}'))`;
  return [`@break_glass_strip expression \`${fires}\``];
}

function breakGlassStrip(): string {
  return `uri @break_glass_strip query -${BREAK_GLASS_PARAM}`;
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
 * The tight, dedicated throttle of an inbound-webhook site, in a zone no other
 * block names and keyed on the direct peer like the others. Not keyed on
 * posture: it guards a route that is public the moment it exists, so no
 * setting in `posture.ts` can switch it off. See `render.md`.
 */
function webhookRateLimitDirective(zone: string): string[] {
  return [
    'rate_limit @webhook {',
    `\tzone ${zone} {`,
    '\t\tkey {http.request.remote.host}',
    `\t\twindow ${WEBHOOK_RATE_LIMIT_WINDOW_SECONDS}s`,
    `\t\tevents ${WEBHOOK_RATE_LIMIT_EVENTS}`,
    '\t}',
    '}',
  ];
}

// Why: throttle runs before WAF (unlike Cloud Armor baseline); order protects vCPUs
// from floods reaching inspection. See render.md §"protectionChain: handler evaluation order".
function protectionChain(
  posture: EdgePosture,
  zone: string,
  options: {
    appsec: 'none' | 'all' | 'except-authoring';
    /** The general throttle's budget; `RATE_LIMIT_EVENTS` when absent. */
    rateLimitEvents?: number;
    membersMagicLink?: boolean;
    webhookZone?: string;
    beforeAppsec?: string[];
    /**
     * The session verification (`sessionVerification`), placed after the
     * throttles and before the bouncer. When present, the bouncer and AppSec
     * run only on a request it did not verify.
     */
    verification?: string[];
  }
): string[] {
  const lines: string[] = [];
  // Two independent conditions, not one nested in the other. The magic-link
  // throttle protects mx1's deliverability and the general one sheds load off
  // two vCPUs; they are the same Caddy module at opposite risk profiles, and
  // nesting them meant the narrow control could not be enabled without the
  // broad one.
  if (posture.rateLimit === 'enforcing') {
    lines.push(...rateLimitDirective(zone, options.rateLimitEvents));
  }
  if (posture.membersMagicLinkRateLimit === 'enforcing' && options.membersMagicLink) {
    lines.push(...membersMagicLinkRateLimitDirective());
  }
  if (options.webhookZone !== undefined) {
    lines.push(...webhookRateLimitDirective(options.webhookZone));
  }
  // After the throttles, so they still count every request, verified or not,
  // and cap how many verification calls one address can cause.
  const verified = options.verification !== undefined;
  lines.push(...(options.verification ?? []));
  const unlessVerified = verified ? ' @edge_untrusted' : '';
  if (posture.crowdsec === 'enforcing') {
    lines.push(`crowdsec${unlessVerified}`);
  }
  lines.push(...(options.beforeAppsec ?? []));
  if (options.appsec === 'all') {
    lines.push(`appsec${unlessVerified}`);
  } else if (options.appsec === 'except-authoring') {
    // `@inspected` itself carries the verified-session condition on such a site.
    lines.push('appsec @inspected');
  }
  return lines;
}

/**
 * Site-scope matchers for a site whose sessions the edge verifies: which
 * requests are worth a verification call, and which were not verified. Why:
 * `render.md`, "Verified sessions".
 */
function sessionVerificationMatchers(site: EdgeSite): string[] {
  if (site.trustedSession !== 'ghost-staff') {
    return [];
  }
  return [
    '@edge_session_candidate {',
    `\tpath ${GHOST_STAFF_PATHS.join(' ')}`,
    `\theader Cookie *${GHOST_STAFF_SESSION_COOKIE}=*`,
    '}',
    `@edge_untrusted not vars ${TRUSTED_SESSION_VAR} 1`,
  ];
}

/**
 * The verification call, written out as `reverse_proxy` by hand rather than
 * `forward_auth`: `forward_auth` sends a non-2xx answer to the browser, which
 * would break Ghost's own sign-in page for an expired cookie. Here a 2xx JSON
 * answer sets the variable and any other answer leaves it at 0; either way the
 * request carries on down the route. `method GET` drops the body from the
 * verification call only; the request itself keeps it. Why each line:
 * `render.md`, "Verified sessions".
 */
function sessionVerification(site: EdgeSite, upstream: string): string[] | undefined {
  if (site.trustedSession === undefined) {
    return undefined;
  }
  if (site.backend !== 'ghost') {
    throw new Error(
      `site ${site.name} sets trustedSession ${site.trustedSession}, which only a Ghost site (backend 'ghost') can verify`
    );
  }
  return [
    `vars ${TRUSTED_SESSION_VAR} 0`,
    `log_append ${TRUSTED_SESSION_VAR} {http.vars.${TRUSTED_SESSION_VAR}}`,
    `reverse_proxy @edge_session_candidate ${upstream} {`,
    '\tmethod GET',
    `\trewrite ${GHOST_STAFF_VERIFY_URI}`,
    // A Ghost Admin API key authenticates too; only the session cookie may.
    '\theader_up -Authorization',
    '\ttransport http {',
    `\t\tdial_timeout ${TRUSTED_SESSION_DIAL_TIMEOUT}`,
    `\t\tresponse_header_timeout ${TRUSTED_SESSION_RESPONSE_TIMEOUT}`,
    '\t}',
    '\t@edge_session_verified {',
    '\t\tstatus 2xx',
    '\t\theader Content-Type application/json*',
    '\t}',
    '\thandle_response @edge_session_verified {',
    `\t\tvars ${TRUSTED_SESSION_VAR} 1`,
    '\t}',
    '\thandle_response {',
    `\t\tvars ${TRUSTED_SESSION_VAR} 0`,
    '\t}',
    '}',
  ];
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

/**
 * A site's discard route (`EdgeSite.discardRoute`): matchers for the one path.
 * Why the path is exempt from AppSec only, and where the answers sit: `render.md`.
 */
function discardRouteMatchers(path: string): string[] {
  if (!/^\/[A-Za-z0-9_\-/]+$/.test(path)) {
    throw new Error(`discardRoute ${path} must be a plain literal path (letters, digits, _ - /)`);
  }
  return [
    '@discard {',
    `\tpath ${path}`,
    '}',
    '@discard_post {',
    '\tmethod POST',
    `\tpath ${path}`,
    '}',
  ];
}

function discardRouteResponses(): string[] {
  return ['header @discard Allow POST', 'respond @discard_post 204', 'respond @discard 405'];
}

const WEBHOOK_METHOD = 'POST';

/**
 * A site that only receives signed callbacks (`EdgeSite.inboundWebhookPath`).
 * Deliberately not a Ghost block with a path matcher added: it carries none of
 * the Ghost matchers, so it names no zone, matcher or path of the login-mail
 * route. Why each line is where it is, and what it lets through: `render.md`.
 */
function webhookSiteBlock(
  site: EdgeSite,
  path: string,
  hostnames: string[],
  posture: EdgePosture
): Block {
  const upstream = site.privateUpstream;
  if (upstream === undefined) {
    throw new Error(`site ${site.name} has no privateUpstream and must not be rendered`);
  }
  if (site.discardRoute !== undefined || site.injectionWafPreviewOnly) {
    throw new Error(
      `site ${site.name} is an inbound webhook site and cannot also declare a discardRoute or injectionWafPreviewOnly`
    );
  }
  if (!/^\/[A-Za-z0-9_\-/]+$/.test(path)) {
    throw new Error(
      `inboundWebhookPath ${path} must be a plain literal path (letters, digits, _ - /)`
    );
  }
  return {
    addresses: hostnames,
    body: [
      ...logDirective(ACCESS_LOG),
      ...tlsDirective(),
      '@webhook {',
      `\tmethod ${WEBHOOK_METHOD}`,
      `\tpath ${path}`,
      '}',
      '@webhook_wrong_method {',
      `\tnot method ${WEBHOOK_METHOD}`,
      `\tpath ${path}`,
      '}',
      'route {',
      ...hstsDirective().map((line) => `\t${line}`),
      ...requestBodyDirective(site).map((line) => `\t${line}`),
      ...protectionChain(posture, `${site.name}_per_ip`, {
        appsec: 'all',
        webhookZone: `${site.name}_inbound_per_ip`,
      }).map((line) => `\t${line}`),
      `\theader @webhook_wrong_method Allow ${WEBHOOK_METHOD}`,
      '\trespond @webhook_wrong_method 405',
      `\treverse_proxy @webhook ${resolvePrivateAddress(upstream.host, upstream.port)}`,
      // Last, matcher-less: whatever the lines above did not answer or proxy is
      // refused here, so a missed case fails closed rather than reaching upstream.
      '\trespond 404',
      '}',
    ],
  };
}

/**
 * The request methods a signed object gateway is sent: the reads, `PUT` for an
 * object and a multipart part, `POST` for the multipart calls, `DELETE` for a
 * lock object. Any other method is answered by the edge. Why each, and what the
 * gateway itself still refuses: `render.md`, "`siteBlock`: signed object gateway".
 */
const GATEWAY_READ_METHODS = ['GET', 'HEAD'] as const;
const GATEWAY_WRITE_METHODS = ['PUT', 'POST', 'DELETE'] as const;
const GATEWAY_METHODS = [...GATEWAY_READ_METHODS, ...GATEWAY_WRITE_METHODS] as const;

/** The two paths the gateway answers for the edge's own probes; reads only. */
const GATEWAY_PROBE_PATHS = ['/healthz', '/readyz'] as const;

/**
 * A path-style request is `/<bucket>` or `/<bucket>/<key>`: one non-empty first
 * segment. `/` (a bucket listing) and `//x` (an empty first segment) are not
 * request shapes the gateway serves, so they do not match. The probe paths
 * match too, which is why a write to one is answered before this matcher is
 * reached.
 */
const GATEWAY_PATH_REGEXP = '^/[^/]+(?:/.*)?$';

/**
 * A `.` or `..` segment in the path of the request as it arrived, written
 * literally or percent-encoded. Matched on the original URI and not with
 * `path_regexp`, because Caddy matches `path` and `path_regexp` against the path
 * with its dot segments already resolved while it proxies the path as it was
 * sent: a request for `/bucket/..` is matched as `/` and forwarded as
 * `/bucket/..`. A signature covers the path as the client canonicalised it, so
 * a server that resolves dot segments differently from the client reads a
 * different object than the one the client signed for. The expression carries
 * no brace, because a placeholder reads one.
 */
const GATEWAY_DOT_SEGMENT_REGEXP = '^[^?]*/(?:[.]|%2[Ee])(?:[.]|%2[Ee])?(?:/|[?]|$)';

/**
 * Upstream timeouts of a gateway route. A checkpoint is a few hundred
 * kilobytes, so neither bound is generous: the dial is a hop on the private
 * network, and the first response byte of a state write is bounded by the
 * object store behind the gateway.
 */
const GATEWAY_DIAL_TIMEOUT = '5s';
const GATEWAY_RESPONSE_HEADER_TIMEOUT = '30s';

/**
 * A signed object gateway (`EdgeSite.signedObjectGateway`). Deliberately not the
 * generic block with matchers added: it carries none of the Ghost matchers, and
 * it forwards a request unchanged or answers it itself. It sets no `header_up`,
 * rewrites no path and strips no query parameter, because the client's
 * signature covers the method, the path, the query and the signed headers, and
 * the gateway recomputes it. Why each line is where it is: `render.md`.
 */
function gatewaySiteBlock(site: EdgeSite, hostnames: string[], posture: EdgePosture): Block {
  const upstream = site.privateUpstream;
  if (upstream === undefined) {
    throw new Error(`site ${site.name} has no privateUpstream and must not be rendered`);
  }
  if (
    site.inboundWebhookPath !== undefined ||
    site.discardRoute !== undefined ||
    site.injectionWafPreviewOnly ||
    site.trustedSession !== undefined ||
    (site.backend !== undefined && site.backend !== 'other')
  ) {
    throw new Error(
      `site ${site.name} is a signed object gateway and cannot also be a webhook, Ghost or Nextcloud site, or declare a discardRoute, injectionWafPreviewOnly or trustedSession`
    );
  }
  const address = resolvePrivateAddress(upstream.host, upstream.port);
  return {
    addresses: hostnames,
    body: [
      ...logDirective(ACCESS_LOG),
      ...tlsDirective(),
      '@gateway_probe_write {',
      `\tmethod ${GATEWAY_WRITE_METHODS.join(' ')}`,
      `\tpath ${GATEWAY_PROBE_PATHS.join(' ')}`,
      '}',
      '@gateway_wrong_method {',
      `\tnot method ${GATEWAY_METHODS.join(' ')}`,
      '}',
      '@gateway_dot_segments {',
      `\texpression \`{http.request.orig_uri}.matches('${GATEWAY_DOT_SEGMENT_REGEXP}')\``,
      '}',
      '@gateway {',
      `\tmethod ${GATEWAY_METHODS.join(' ')}`,
      `\tpath_regexp ${GATEWAY_PATH_REGEXP}`,
      '}',
      'route {',
      ...hstsDirective().map((line) => `\t${line}`),
      // Deferred (`>`), so it replaces a Cache-Control the gateway sends rather
      // than adding a second value beside it, and it reaches the edge's own
      // 404 and 405 too.
      '\theader >Cache-Control "no-store"',
      ...requestBodyDirective(site).map((line) => `\t${line}`),
      ...protectionChain(posture, `${site.name}_per_ip`, { appsec: 'all' }).map(
        (line) => `\t${line}`
      ),
      `\theader @gateway_probe_write Allow "${GATEWAY_READ_METHODS.join(', ')}"`,
      '\trespond @gateway_probe_write 405',
      `\theader @gateway_wrong_method Allow "${GATEWAY_METHODS.join(', ')}"`,
      '\trespond @gateway_wrong_method 405',
      '\trespond @gateway_dot_segments 400',
      `\treverse_proxy @gateway ${address} {`,
      '\t\ttransport http {',
      `\t\t\tdial_timeout ${GATEWAY_DIAL_TIMEOUT}`,
      `\t\t\tresponse_header_timeout ${GATEWAY_RESPONSE_HEADER_TIMEOUT}`,
      '\t\t}',
      '\t}',
      // Last, matcher-less: whatever the lines above did not answer or proxy is
      // refused here, so a missed case fails closed rather than reaching upstream.
      '\trespond 404',
      '}',
    ],
  };
}

function siteBlock(site: EdgeSite, hostnames: string[], posture: EdgePosture): Block {
  const upstream = site.privateUpstream;
  if (upstream === undefined) {
    throw new Error(`site ${site.name} has no privateUpstream and must not be rendered`);
  }
  // Checked first, so a site that is both refuses to render instead of
  // silently becoming a webhook site.
  if (site.signedObjectGateway === true) {
    return gatewaySiteBlock(site, hostnames, posture);
  }
  if (site.inboundWebhookPath !== undefined) {
    return webhookSiteBlock(site, site.inboundWebhookPath, hostnames, posture);
  }

  const address = resolvePrivateAddress(upstream.host, upstream.port);
  const verification = sessionVerification(site, address);
  const body: string[] = [...logDirective(ACCESS_LOG), ...tlsDirective()];
  if (site.injectionWafPreviewOnly && verification !== undefined) {
    body.push(
      '@inspected {',
      `\tnot path ${AUTHORING_API_PATHS.join(' ')}`,
      `\tnot vars ${TRUSTED_SESSION_VAR} 1`,
      '}'
    );
  } else if (site.injectionWafPreviewOnly) {
    body.push(`@inspected not path ${AUTHORING_API_PATHS.join(' ')}`);
  }
  body.push(...sessionVerificationMatchers(site));
  if (site.discardRoute !== undefined) {
    body.push(...discardRouteMatchers(site.discardRoute));
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
  // Unconditional, unlike the throttle matcher: it is a refusal, not a
  // posture, so no posture setting may switch it off.
  body.push(...ghostSetupMatcher());
  body.push(...breakGlassStripMatcher());
  const isGhost = site.backend === 'ghost';
  body.push(
    'route {',
    // Ahead of everything else, including request_body -- see hstsDirective's
    // own comment for why its position is load-bearing rather than tidiness.
    ...hstsDirective().map((line) => `\t${line}`),
    ...(isGhost ? nosniffDirective().map((line) => `\t${line}`) : []),
    // Before the body cap and the protection chain, so the WAF hop never carries it.
    `\t${breakGlassStrip()}`,
    // Why: does not terminate handler chain; ordering buys tidiness only. AppSec
    // caps at appsec_max_body_bytes anyway. See render.md §"siteBlock: request_body ordering".
    ...requestBodyDirective(site).map((line) => `\t${line}`),
    ...protectionChain(posture, `${site.name}_per_ip`, {
      appsec: site.injectionWafPreviewOnly ? 'except-authoring' : 'all',
      ...(site.backend === 'nextcloud' ? { rateLimitEvents: NEXTCLOUD_RATE_LIMIT_EVENTS } : {}),
      membersMagicLink: true,
      beforeAppsec: site.discardRoute === undefined ? [] : discardRouteResponses(),
      ...(verification === undefined ? {} : { verification }),
    }).map((line) => `\t${line}`),
    `\t${ghostSetupRefusal()}`,
    ...(isGhost ? uploadGuard().map((line) => `\t${line}`) : []),
    ...(isGhost ? widgetAssets().map((line) => `\t${line}`) : []),
    ...(isGhost && site.media !== undefined
      ? tenantMedia(site.media, address).map((line) => `\t${line}`)
      : []),
    `\treverse_proxy ${address}`,
    '}'
  );
  if (isGhost) {
    body.push(...nosniffErrorBlock());
  }

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

// Why: the heredoc marker a fixed file's body is closed by. A body line equal to it
// would end the heredoc early, so the renderer refuses one. See render.md §"staticFilesBlock".
const SHARED_FILE_HEREDOC = 'SHARED_TENANT_FILE_EOF';

// Why: a fixed-file hostname with the same TLS, throttle, HSTS and body-size posture as
// staticBlock, and its own CSP (no script, style or font of any kind, since a text file
// runs none). Each file is one literal path answered with its own media type; every other
// path gets 404. Bodies are heredocs, whose lines are not indented, so each body line is
// written at column 0 and only the `respond` line carries the block's indentation. See
// render.md §"staticFilesBlock".
function staticFilesBlock(
  site: StaticSite,
  files: readonly StaticTextFile[],
  posture: EdgePosture
): Block {
  const routes = files.flatMap((file, index) => {
    if (!/^\/[A-Za-z0-9_./-]+$/.test(file.path) || file.path.includes('..')) {
      throw new Error(
        `static file path ${file.path} must be a plain literal path (letters, digits, _ . - /)`
      );
    }
    if (!file.body.endsWith('\n')) {
      throw new Error(
        `static file ${file.path} must end with a newline, so its heredoc closes on its own line`
      );
    }
    if (file.body.split('\n').includes(SHARED_FILE_HEREDOC)) {
      throw new Error(
        `static file ${file.path} has a body line equal to the heredoc marker ${SHARED_FILE_HEREDOC}`
      );
    }
    const matcher = `@file_${index}`;
    return [
      `${matcher} path ${file.path}`,
      `header ${matcher} Content-Type "${file.contentType}"`,
      `respond ${matcher} <<${SHARED_FILE_HEREDOC}\n${file.body}${SHARED_FILE_HEREDOC}`,
    ];
  });
  return {
    addresses: [assertHostname(site.hostname)],
    body: [
      ...logDirective(ACCESS_LOG),
      ...tlsDirective(),
      'route {',
      ...[
        ...hstsDirective(),
        ...cspDirective(staticSiteCsp('')),
        'request_body {',
        `\tmax_size ${STATIC_SITE_REQUEST_BODY_MAX_SIZE}`,
        '}',
        ...protectionChain(posture, `${site.name}_per_ip`, { appsec: 'all' }),
        ...routes,
        'respond 404',
      ].map((line) => `\t${line}`),
      '}',
    ],
  };
}

// Why: fixed-page hostname with same TLS/throttle posture as siteBlock; no upstream,
// no members route; strict CSP (inline only). See render.md §"staticBlock".
function staticBlock(site: StaticSite, posture: EdgePosture): Block {
  const files: readonly StaticTextFile[] | undefined = SHARED_TENANT_FILES[site.name];
  if (files !== undefined) {
    return staticFilesBlock(site, files, posture);
  }
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
  // Same refusal as a real site, so a loopback `curl` can prove it before any
  // hostname serves the path for real.
  body.push(...ghostSetupMatcher());
  body.push(...breakGlassStripMatcher());
  body.push(
    'route {',
    `\t${breakGlassStrip()}`,
    ...protectionChain(posture, generalZone, {
      appsec: 'all',
      membersMagicLink: true,
    }).map((line) => `\t${line}`),
    `\t${ghostSetupRefusal()}`,
    // Names which block answered. Without it the two probes are
    // indistinguishable on the wire: a bare `:port` address matches every
    // Host, so it answers a request for the host-qualified name identically
    // whenever that block is missing -- and a verification step that passes
    // with the thing it verifies absent is not a verification step. This is
    // what makes RUNBOOK-edge.md §8b(4a) discriminating, and it is why the
    // marker is a plain `header` line here rather than something that depends
    // on the general throttle zones: those render only under `rateLimit:
    // 'enforcing'`, and a marker has to survive a posture that turns them off.
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
    ...defaultLogDirective().map((line) => `\t${line}`),
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

// Why: two sites claiming one hostname = Caddy renders two site blocks for it and
// silently lets one shadow the other. See render.md §"assertHostnamesAreDistinct".
function assertHostnamesAreDistinct(servable: readonly EdgeSite[]): void {
  const seen = new Map<string, string>();
  for (const site of servable) {
    for (const hostname of site.hostnames) {
      const owner = seen.get(hostname);
      if (owner !== undefined) {
        throw new Error(
          `sites ${owner} and ${site.name} both claim ${hostname}; Caddy would let one ` +
            'site block silently shadow the other.'
        );
      }
      seen.set(hostname, site.name);
    }
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
  assertHostnamesAreDistinct(servable);
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
 * whether a rule can block. Detect-only names only the out-of-band one; the
 * in-band one is named in every posture past it, with or without the
 * IP-decision handler.
 */
export function renderAppsecAcquisition(posture: EdgePosture): string {
  const configs =
    posture.crowdsec !== 'detect-only'
      ? [APPSEC_CONFIG_GHOST_ADMIN, APPSEC_CONFIG_INBAND, APPSEC_CONFIG_OUT_OF_BAND]
      : [APPSEC_CONFIG_GHOST_ADMIN, APPSEC_CONFIG_OUT_OF_BAND];

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

/**
 * The hostnames of every Ghost tenant, for the two CrowdSec files below. Each
 * is checked against `HOSTNAME`, which admits no quote, so it can be written
 * into an expression as a quoted literal.
 */
function ghostHostnames(entries: EdgeSite[]): string[] {
  const hostnames = entries
    .filter((site) => site.backend === 'ghost')
    .flatMap((site) => site.hostnames);
  for (const host of hostnames) {
    if (!HOSTNAME.test(host)) {
      throw new Error(`Ghost hostname ${host} is not a plain lower-case hostname`);
    }
  }
  return hostnames;
}

const quotedList = (values: readonly string[]): string =>
  `[${values.map((value) => `'${value}'`).join(', ')}]`;

/**
 * The AppSec configuration that lets Ghost admin's previews through the Core
 * Rule Set without a ban (`APPSEC_CONFIG_GHOST_ADMIN`). Every condition narrows:
 * out-of-band only, a Ghost hostname, a bodiless POST to the site root with
 * exactly the preview's content type and the preview header. Any other request,
 * including the same one with a body, is evaluated by every rule. Why:
 * `render.md`, "Ghost admin preview exclusion".
 */
export function renderGhostAdminAppsecConfig(entries: EdgeSite[]): string {
  const hosts = ghostHostnames(entries);
  return `${[
    ...GENERATED_BANNER,
    `name: ${APPSEC_CONFIG_GHOST_ADMIN}`,
    // No `description:`: CrowdSec reads an appsec-config strictly and has no such field.
    '# Ghost admin design and announcement previews, on our Ghost hostnames only.',
    'pre_eval:',
    '  - filter: >-',
    '      IsOutBand == true &&',
    `      req.Host in ${quotedList(hosts)} &&`,
    "      req.Method == 'POST' &&",
    "      req.URL.Path == '/' &&",
    '      req.ContentLength == 0 &&',
    "      req.Header.Get('Content-Type') == 'text/html;charset=utf-8' &&",
    "      req.Header.Get('X-Ghost-Preview') != ''",
    '    apply:',
    ...GHOST_PREVIEW_CRS_RULE_IDS.map((id) => `      - RemoveOutBandRuleByID(${id})`),
  ].join('\n')}\n`;
}

/**
 * The post-overflow whitelist that drops every overflow of the hub's
 * admin-interface probing scenario, so that `renderAdminProbingScenario`, which
 * reads the same requests, is the only one that bans. The hub item stays
 * installed and untouched, so its upgrades are unaffected. The file keeps the
 * name `ghost-admin-api-postoverflow.yaml` from when it did something narrower:
 * the lists the edge stack is applied from carry that path. Why:
 * `render.md`, "Ghost admin API and admin-interface probing".
 */
export function renderHubAdminProbingPostoverflow(): string {
  return `${[
    ...GENERATED_BANNER,
    'name: branchleft/hub-admin-interface-probing-is-silenced',
    'description: The hub admin-interface probing scenario never bans; branchleft/http-admin-interface-probing does',
    'whitelist:',
    `  reason: replaced by ${ADMIN_PROBING_SCENARIO}`,
    '  expression:',
    `    - evt.Overflow.Alert.GetScenario() == '${HUB_ADMIN_PROBING_SCENARIO}'`,
  ].join('\n')}\n`;
}

/**
 * The admin-interface probing scenario: the hub's, line for line, but a 403 or
 * 404 on Ghost's own admin API prefix, on a Ghost hostname and with no dot
 * segment (literal or percent-encoded), is not counted at all. Not pouring those
 * requests into the bucket is the point: a post-overflow that drops an overflow
 * after the fact leaves the scenario's blackhole running, and the blackhole is
 * kept per address across every host, so three admin API answers would mute the
 * scenario for that address everywhere for a minute. Why, and what the copy
 * costs: `render.md`, "Ghost admin API and admin-interface probing".
 */
export function renderAdminProbingScenario(entries: EdgeSite[]): string {
  const hosts = ghostHostnames(entries);
  return `${[
    ...GENERATED_BANNER,
    'type: leaky',
    `name: ${ADMIN_PROBING_SCENARIO}`,
    'description: Generic HTTP admin interface probing, not counting the Ghost admin API on a Ghost hostname',
    'filter: >-',
    "  evt.Meta.service == 'http' &&",
    "  evt.Meta.log_type in ['http_access-log', 'http_error-log'] &&",
    "  evt.Meta.http_status in ['404', '403'] &&",
    '  any(File("admin_interfaces.txt"), { Lower(evt.Meta.http_path) contains # }) &&',
    '  not (',
    `    evt.Meta.target_fqdn in ${quotedList(hosts)} &&`,
    `    evt.Meta.http_path startsWith '${GHOST_ADMIN_API_PREFIX}' &&`,
    "    not (evt.Meta.http_path matches '(?i)[.][.]|%2e')",
    '  )',
    'groupby: evt.Meta.source_ip',
    'distinct: evt.Meta.http_path',
    'data:',
    '  - source_url: https://hub-data.crowdsec.net/web/admin_interfaces.txt',
    '    dest_file: admin_interfaces.txt',
    '    type: string',
    'capacity: 2',
    'leakspeed: 10s',
    'blackhole: 1m',
    'labels:',
    '  confidence: 3',
    '  spoofable: 0',
    '  classification:',
    '    - attack.T1595',
    '  behavior: "http:scan"',
    '  label: "HTTP Admin Interface Probing"',
    '  service: http',
    '  remediation: true',
  ].join('\n')}\n`;
}

/**
 * The `s02-enrich` whitelist that keeps a verified request out of every
 * CrowdSec bucket. It drops a Caddy access-log line whose top-level
 * `TRUSTED_SESSION_VAR` field is `1`, before any scenario reads it. Only Caddy
 * writes a top-level field: everything a client sends is escaped into the line
 * under `request`, where `JsonExtract` on a top-level key never looks. Why:
 * `render.md`, "Verified sessions".
 */
export function renderTrustedSessionWhitelist(): string {
  return `${[
    ...GENERATED_BANNER,
    `name: ${TRUSTED_SESSION_WHITELIST}`,
    'description: Requests whose signed-in session the edge verified with the site itself',
    "filter: evt.Line.Labels.type == 'caddy'",
    'whitelist:',
    '  reason: a session the edge verified',
    '  expression:',
    `    - JsonExtract(evt.Line.Raw, '${TRUSTED_SESSION_VAR}') == '1'`,
  ].join('\n')}\n`;
}

/**
 * The scenario that bans an address after repeated failed Ghost admin sign-ins
 * or admin API 401s (a bad or unknown Admin API key, a wrong sign-in
 * verification code) on our Ghost hostnames. Separate from the hub's admin
 * probing scenario so the post-overflow that silences that one cannot drop it,
 * and from ours, which does not count these paths at all. Why, and the
 * limits it carries: `render.md`, "Ghost admin brute force".
 */
export function renderGhostBruteForceScenario(entries: EdgeSite[]): string {
  const hosts = ghostHostnames(entries);
  return `${[
    ...GENERATED_BANNER,
    'type: leaky',
    `name: ${GHOST_BRUTE_FORCE_SCENARIO}`,
    'description: Repeated failed Ghost admin sign-ins or admin API key failures from one address',
    'filter: >-',
    "  evt.Meta.service == 'http' &&",
    "  evt.Meta.log_type == 'http_access-log' &&",
    `  evt.Meta.target_fqdn in ${quotedList(hosts)} &&`,
    '  (',
    "    (evt.Meta.http_verb == 'POST' &&",
    "     evt.Meta.http_path matches '(?i)^/ghost/api/(?:[^/?]+/)?admin/session/?(?:[?]|$)' &&",
    `     evt.Meta.http_status in ${quotedList(GHOST_FAILED_SIGNIN_STATUSES.map(String))}) ||`,
    "    (evt.Meta.http_status == '401' &&",
    "     evt.Meta.http_path matches '(?i)^/ghost/api/(?:[^/?]+/)?admin/')",
    '  )',
    'groupby: evt.Meta.source_ip',
    `capacity: ${GHOST_BRUTE_FORCE_CAPACITY}`,
    `leakspeed: ${GHOST_BRUTE_FORCE_LEAKSPEED}`,
    'blackhole: 1m',
    'labels:',
    '  confidence: 3',
    '  spoofable: 0',
    '  classification:',
    '    - attack.T1110',
    '  behavior: "http:bruteforce"',
    '  label: "Ghost admin brute force"',
    '  service: http',
    '  remediation: true',
  ].join('\n')}\n`;
}

/**
 * Where the two remediation files below are mounted in the CrowdSec container,
 * outside `/etc/crowdsec` for the reason the acquisition mount gives in
 * `compose.yml`. `config.yaml.local` points CrowdSec at both.
 */
export const REMEDIATION_DIR = '/etc/crowdsec-remediation';

/** The hub's out-of-band Core Rule Set scenario, the "sixth note bans" rule. */
const OUT_OF_BAND_SCENARIO = 'crowdsecurity/crowdsec-appsec-outofband';

/**
 * CrowdSec's profiles: every ban lasts the next rung of `BAN_LADDER_MINUTES`,
 * chosen by how many decisions the address already had within
 * `BAN_LADDER_WINDOW`. Replaces the image's flat four hours. Why: `posture.md`,
 * "Ban length", and `render.md`, "Ban length and watch-only scenarios".
 *
 * One profile for both scopes the image's two default profiles covered, an
 * address and a range: a decision with no `scope` takes its alert's, so one
 * document does what the image's two did, and the file stays a single YAML
 * document.
 */
export function renderProfiles(): string {
  const rungs = BAN_LADDER_MINUTES.join(', ');
  const last = BAN_LADDER_MINUTES.length - 1;
  const durationExpr =
    `Sprintf('%dm', [${rungs}][min(GetDecisionsSinceCount(Alert.GetValue(), ` +
    `'${BAN_LADDER_WINDOW}'), ${last})])`;
  return `${[
    ...GENERATED_BANNER,
    'name: branchleft_remediation',
    'filters:',
    '  - Alert.Remediation == true && Alert.GetScope() in ["Ip", "Range"]',
    'decisions:',
    '  - type: ban',
    // The first rung, used only if the expression below cannot be evaluated.
    `    duration: ${BAN_LADDER_MINUTES[0]}m`,
    `duration_expr: "${durationExpr}"`,
    'on_success: break',
  ].join('\n')}\n`;
}

/**
 * CrowdSec's simulation file: the scenarios in `WATCH_ONLY_SCENARIOS` record
 * their would-be bans as simulated decisions that no bouncer receives; every
 * other scenario bans. Why: `posture.md`, "Watch-only scenarios".
 */
export function renderSimulation(): string {
  if (!WATCH_ONLY_SCENARIOS.every((name) => name === OUT_OF_BAND_SCENARIO)) {
    throw new Error(
      `only ${OUT_OF_BAND_SCENARIO} may be watch-only until the false-alarm review names another`
    );
  }
  return `${[
    ...GENERATED_BANNER,
    'simulation: false',
    'exclusions:',
    ...WATCH_ONLY_SCENARIOS.map((name) => `  - ${name}`),
  ].join('\n')}\n`;
}

/** The hostnames of every Nextcloud site, checked as `ghostHostnames` checks Ghost's. */
function nextcloudHostnames(entries: EdgeSite[]): string[] {
  const hostnames = entries
    .filter((site) => site.backend === 'nextcloud')
    .flatMap((site) => site.hostnames);
  for (const host of hostnames) {
    if (!HOSTNAME.test(host)) {
      throw new Error(`Nextcloud hostname ${host} is not a plain lower-case hostname`);
    }
  }
  return hostnames;
}

/**
 * Nextcloud's own normal traffic that the hub's log scenarios read as probing:
 * WebDAV sync and file browsing, Talk's API, and previews, avatars and
 * thumbnails. Each is a path family Nextcloud itself answers, with the
 * statuses it answers a signed-in client; a 401 is never in a list, so password
 * guessing still counts. Why each line: `render.md`, "Nextcloud profile".
 */
const NEXTCLOUD_NORMAL_TRAFFIC: readonly { path: string; statuses: readonly number[] }[] = [
  {
    path: '^/(?:remote|public)[.]php/(?:web)?dav(?:/|[?]|$)',
    statuses: [200, 201, 204, 207, 304, 404, 409, 412, 423],
  },
  {
    path: '^/ocs/v[12][.]php/apps/spreed/',
    statuses: [200, 201, 304, 400, 403, 404, 409, 412],
  },
  {
    path:
      '^(?:/index[.]php)?/(?:core/preview|avatar/|apps/(?:files/api/v1/thumbnail|' +
      'files_trashbin/preview|files_versions/preview|photos/api/v1/preview|' +
      'files_sharing/publicpreview|theming/))',
    statuses: [200, 304, 404],
  },
];

/**
 * The `s02-enrich` whitelist that keeps Nextcloud's own normal traffic out of
 * every log scenario, on our Nextcloud hostnames only. A request whose path has
 * a dot segment, encoded or not, is never dropped. Why: `render.md`,
 * "Nextcloud profile".
 */
export function renderNextcloudWhitelist(entries: EdgeSite[]): string {
  const hosts = nextcloudHostnames(entries);
  if (hosts.length === 0) {
    throw new Error('no site has backend nextcloud, so there is no Nextcloud profile to render');
  }
  return `${[
    ...GENERATED_BANNER,
    'name: branchleft/nextcloud-profile',
    "description: Nextcloud's own normal traffic on our Nextcloud hostnames",
    'filter: >-',
    "  evt.Meta.service == 'http' &&",
    "  evt.Meta.log_type == 'http_access-log' &&",
    `  evt.Meta.target_fqdn in ${quotedList(hosts)} &&`,
    "  not (evt.Meta.http_path matches '(?i)[.][.]|%2e')",
    'whitelist:',
    "  reason: Nextcloud's own traffic on a Nextcloud hostname",
    '  expression:',
    ...NEXTCLOUD_NORMAL_TRAFFIC.map(
      ({ path, statuses }) =>
        `    - evt.Meta.http_path matches '${path}' && ` +
        `evt.Meta.http_status in ${quotedList(statuses.map(String))}`
    ),
  ].join('\n')}\n`;
}
