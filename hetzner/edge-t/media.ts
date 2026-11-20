import type { EdgePosture } from '../edge/posture';
import { ACCESS_LOG, logDirective, protectionChain, renderBlock, type Block } from '../edge/render';

// Why: the media address of the tenant edge. Pure strings, spliced into the tenant
// Caddyfile. See render.md, "The media address".

/** One shared bucket. Its name identifies no tenant; the host is the bucket's S3 endpoint. */
export interface MediaShard {
  /** The name the folder register uses for this shard. */
  readonly name: string;
  /** The S3 endpoint, a plain hostname. */
  readonly host: string;
  /** The bucket, read path-style. */
  readonly bucket: string;
}

/** The three shared buckets, once they exist. Empty: every media request is refused until then. */
export const MEDIA_SHARDS: readonly MediaShard[] = [];

const SHARD_NAME = /^[a-z][a-z0-9]{0,15}$/;
const BUCKET_NAME = /^(?!-)[a-z0-9-]{3,63}(?<!-)$/;
const HOSTNAME = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

/** Where the host puts what the tenant register decides, mounted read-only into Caddy. */
export const MEDIA_DATA_DIR = '/etc/caddy-media';
/** The site blocks that name the media address: `<name> { import tenant_media }`. */
export const MEDIA_SITES_GLOB = `${MEDIA_DATA_DIR}/*.caddy`;
/** One `<folder> <shard>` pair per line. */
export const MEDIA_FOLDERS_GLOB = `${MEDIA_DATA_DIR}/folders/*.map`;
export const MEDIA_SNIPPET = 'tenant_media';

/** The cache service's name and port on the Compose network, and the one Caddy server it reads from. */
export const MEDIA_CACHE_ADDRESS = 'media-cache:8080';
export const MEDIA_SHARD_PORT = 18080;
export const MEDIA_SHARD_SERVER = 'media_shard';
const SHARD_HOST_SUFFIX = 'media-shard.invalid';

/** A folder is the tenant's opaque prefix. The register is the real gate; this only bounds the shape. */
const FOLDER_PATTERN = '[A-Za-z0-9_-]{8,64}';
const MEDIA_RATE_LIMIT_EVENTS = 1200;
const MEDIA_RATE_LIMIT_ZONE = 'media_per_ip';

/** What readers' browsers keep, and what the edge keeps; a missing object is remembered briefly. */
export const MEDIA_BROWSER_MAX_AGE = 86400;
export const MEDIA_EDGE_TTL_SECONDS = 604800;
export const MEDIA_MISSING_TTL_SECONDS = 30;
/** What a reader is told to wait when the bucket says it is busy. */
export const MEDIA_RETRY_AFTER_SECONDS = 2;

/** Active content is refused on this address as on a tenant's own: Ghost's extension list. */
const ACTIVE_EXTENSIONS = [
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
const ACTIVE_PATH_REGEXP = `(?i)[.](?:${ACTIVE_EXTENSIONS.join('|')})/*$`;
const TRAVERSAL_EXPRESSION =
  "{http.request.orig_uri}.matches('(?i)(?:^|/)(?:[.]|%2e){2}(?:/|%2f|[?]|$)')";
const INERT_HEADERS = [
  'header >X-Content-Type-Options "nosniff"',
  `header >Content-Security-Policy "default-src 'none'; sandbox"`,
];
const BUCKET_HEADERS_STRIPPED = [
  'x-amz-request-id',
  'x-amz-version-id',
  'x-amz-expiration',
  'x-amz-storage-class',
  'x-rgw-object-type',
  'Strict-Transport-Security',
  'Set-Cookie',
];

/** The refusal of a shard list that could write a wrong route. Names and buckets must be distinct. */
export function assertShards(shards: readonly MediaShard[]): void {
  const names = new Set<string>();
  const buckets = new Set<string>();
  for (const shard of shards) {
    if (!SHARD_NAME.test(shard.name)) {
      throw new Error(`media shard name "${shard.name}" must be a short lower-case word`);
    }
    if (!HOSTNAME.test(shard.host)) {
      throw new Error(`media shard host "${shard.host}" is not a plain hostname`);
    }
    if (!BUCKET_NAME.test(shard.bucket)) {
      throw new Error(`media shard bucket "${shard.bucket}" is not a bucket name`);
    }
    if (names.has(shard.name)) {
      throw new Error(`media shard name "${shard.name}" is used twice`);
    }
    if (buckets.has(`${shard.host}/${shard.bucket}`)) {
      throw new Error(`media shard bucket "${shard.bucket}" is used twice`);
    }
    names.add(shard.name);
    buckets.add(`${shard.host}/${shard.bucket}`);
  }
}

const tab = (lines: readonly string[], depth = 1): string[] =>
  lines.map((line) => `${'\t'.repeat(depth)}${line}`);

/**
 * The snippet every media address imports. Nothing here names an address or a folder:
 * the address comes from a site block the host holds, and the folders from the register's
 * map. A folder the map does not hold, a query string, a method other than GET and HEAD,
 * a dot segment and an active content type are each refused before the cache is asked.
 */
export function renderMediaSnippet(shards: readonly MediaShard[], posture: EdgePosture): string[] {
  assertShards(shards);
  const known =
    shards.length === 0
      ? 'false'
      : `{media_shard} in [${shards.map((shard) => `'${shard.name}'`).join(', ')}]`;
  const body: string[] = [
    ...logDirective(ACCESS_LOG),
    'route {',
    ...tab(
      protectionChain(posture, MEDIA_RATE_LIMIT_ZONE, {
        appsec: 'none',
        rateLimitEvents: MEDIA_RATE_LIMIT_EVENTS,
      })
    ),
    '\t@media_method not method GET HEAD',
    '\trespond @media_method 405',
    '\t@media_query expression `{http.request.uri.query} != ""`',
    '\trespond @media_query 400',
    '\t@media_traversal expression `' + TRAVERSAL_EXPRESSION + '`',
    '\trespond @media_traversal 404',
    '\t@media_active path_regexp ' + ACTIVE_PATH_REGEXP,
    '\trespond @media_active 403',
    `\t@media_object path_regexp media_object ^/(${FOLDER_PATTERN})/[^/]`,
    '\thandle @media_object {',
    '\t\tmap {http.regexp.media_object.1} {media_shard} {',
    '\t\t\tdefault ""',
    `\t\t\timport ${MEDIA_FOLDERS_GLOB}`,
    '\t\t}',
    `\t\t@media_known expression \`${known}\``,
    '\t\thandle @media_known {',
    ...tab(INERT_HEADERS, 3),
    `\t\t\treverse_proxy ${MEDIA_CACHE_ADDRESS} {`,
    `\t\t\t\theader_up Host {media_shard}.${SHARD_HOST_SUFFIX}`,
    '\t\t\t\theader_up -Cookie',
    '\t\t\t\theader_up -Authorization',
    '\t\t\t\theader_down -Server',
    '\t\t\t\ttransport http {',
    '\t\t\t\t\tdial_timeout 3s',
    '\t\t\t\t\tresponse_header_timeout 20s',
    '\t\t\t\t}',
    '\t\t\t}',
    '\t\t}',
    '\t\trespond 404',
    '\t}',
    '\trespond 404',
    '}',
  ];
  return [`(${MEDIA_SNIPPET}) {`, ...tab(body), '}'];
}

/** The listener each shard's server answers on, and the name its metrics carry. */
export function mediaGlobalOptions(): string[] {
  return [
    `\tservers :${MEDIA_SHARD_PORT} {`,
    `\t\tname ${MEDIA_SHARD_SERVER}`,
    '\t\tmetrics {',
    '\t\t\tper_host',
    '\t\t}',
    '\t}',
  ];
}

/** What the bucket's answer becomes on the way to the cache. See render.md, "What the cache stores". */
function shardResponses(): string[] {
  return [
    '@media_found status 2xx 304',
    'handle_response @media_found {',
    `\theader Cache-Control "public, max-age=${MEDIA_BROWSER_MAX_AGE}"`,
    `\theader X-Accel-Expires ${MEDIA_EDGE_TTL_SECONDS}`,
    '\tcopy_response',
    '}',
    '@media_busy status 429 503',
    'handle_response @media_busy {',
    `\theader Retry-After ${MEDIA_RETRY_AFTER_SECONDS}`,
    '\theader Cache-Control "no-store"',
    '\trespond "The media store is busy. Try again shortly." 503',
    '}',
    '@media_missing status 403 404',
    'handle_response @media_missing {',
    `\theader Cache-Control "public, max-age=${MEDIA_MISSING_TTL_SECONDS}"`,
    `\theader X-Accel-Expires ${MEDIA_MISSING_TTL_SECONDS}`,
    '\trespond 404',
    '}',
    'handle_response {',
    '\theader Cache-Control "no-store"',
    '\trespond 502',
    '}',
  ];
}

/**
 * One block per shard on the internal listener, and a catch-all that refuses a host no
 * shard owns: without it Caddy answers an unmatched host with an empty 200 the cache
 * would keep. Each block is the only thing that talks to its bucket, so its request
 * counter is that bucket's upstream request rate.
 */
export function renderMediaShardBlocks(shards: readonly MediaShard[]): Block[] {
  assertShards(shards);
  const blocks: Block[] = shards.map((shard) => ({
    addresses: [`http://${shard.name}.${SHARD_HOST_SUFFIX}:${MEDIA_SHARD_PORT}`],
    body: [
      'route {',
      `\trewrite * /${shard.bucket}{http.request.uri.path}?`,
      `\treverse_proxy https://${shard.host} {`,
      '\t\theader_up Host {upstream_hostport}',
      '\t\theader_up -Cookie',
      '\t\theader_up -Authorization',
      ...tab(
        BUCKET_HEADERS_STRIPPED.map((name) => `header_down -${name}`),
        2
      ),
      '\t\ttransport http {',
      '\t\t\tdial_timeout 3s',
      '\t\t\tresponse_header_timeout 15s',
      '\t\t}',
      ...tab(shardResponses(), 2),
      '\t}',
      '}',
    ],
  }));
  blocks.push({
    addresses: [`http://:${MEDIA_SHARD_PORT}`],
    body: ['header Cache-Control "no-store"', 'respond 404'],
  });
  return blocks;
}

/** The snippet, the host's own sites and register, and the shard listener, as Caddyfile text. */
export function renderMediaCaddyfileSections(
  shards: readonly MediaShard[],
  posture: EdgePosture
): string[] {
  const lines: string[] = [...renderMediaSnippet(shards, posture)];
  for (const block of renderMediaShardBlocks(shards)) {
    lines.push('', ...renderBlock(block));
  }
  lines.push('', `import ${MEDIA_SITES_GLOB}`);
  return lines;
}
