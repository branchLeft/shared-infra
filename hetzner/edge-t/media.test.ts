import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  MEDIA_CACHE_ADDRESS,
  MEDIA_CACHE_PORT,
  MEDIA_SHARDS,
  MEDIA_SHARD_PORT,
  MEDIA_SITES_GLOB,
  assertShards,
  renderMediaInternalBlocks,
  renderMediaSnippet,
  type MediaShard,
} from './media';
import { TENANT_POSTURE, renderTenantCaddyfile } from './render';

// Why: render.md, "The media address". The behaviour these strings describe was run on
// Caddy 2.11 and nginx 1.30 against a stand-in bucket; the CI Caddy validation reads the
// rendered file with the real image.

const SHARDS: readonly MediaShard[] = [
  { name: 'a', host: 'objects-a.example.test', bucket: 'shard-bucket-a' },
  { name: 'b', host: 'objects-b.example.test', bucket: 'shard-bucket-b' },
];

const STACK = path.join(__dirname, 'stack');
const compose = readFileSync(path.join(STACK, 'compose.yml'), 'utf8');

const snippet = renderMediaSnippet(SHARDS, TENANT_POSTURE).join('\n');
const shardBlocks = renderMediaInternalBlocks(SHARDS);
const shardBlock = (name: string): string => {
  const block = shardBlocks.find((candidate) => candidate.addresses[0]?.includes(`//${name}.`));
  expect(block, `shard ${name} has a block`).toBeDefined();
  return (block?.body ?? []).join('\n');
};
const at = (text: string, needle: string): number => {
  const index = text.indexOf(needle);
  expect(index, `"${needle}" is present`).toBeGreaterThanOrEqual(0);
  return index;
};

/** The cache's nginx configuration as the Compose file holds it, with Compose's `$$` undone. */
function nginxConfig(): string {
  const start = at(compose, '    content: |\n') + '    content: |\n'.length;
  const end = compose.indexOf('\nvolumes:', start);
  return compose
    .slice(start, end)
    .split('\n')
    .map((line) => line.replace(/^ {6}/, ''))
    .join('\n')
    .replaceAll('$$', '$');
}

describe('a shard list is checked before it reaches a Caddyfile', () => {
  it('accepts the shards the repository holds', () => {
    expect(() => assertShards(MEDIA_SHARDS)).not.toThrow();
    expect(() => assertShards(SHARDS)).not.toThrow();
  });

  it.each([
    ['a name with a dot', { ...SHARDS[0], name: 'a.b' }, /shard name/],
    ['a name with a brace', { ...SHARDS[0], name: 'a{' }, /shard name/],
    ['an upper-case name', { ...SHARDS[0], name: 'A' }, /shard name/],
    ['a host with a path', { ...SHARDS[0], host: 'objects.example.test/x' }, /shard host/],
    ['a host with a brace', { ...SHARDS[0], host: 'objects.example.test {' }, /shard host/],
    ['a bucket with a path', { ...SHARDS[0], bucket: 'bucket/../other' }, /shard bucket/],
    ['a bucket ending in a hyphen', { ...SHARDS[0], bucket: 'bucket-' }, /shard bucket/],
  ])('refuses %s', (_name, shard, message) => {
    expect(() => assertShards([shard as MediaShard])).toThrow(message);
  });

  it('refuses two shards of one name, or two of one bucket', () => {
    expect(() => assertShards([SHARDS[0] as MediaShard, SHARDS[0] as MediaShard])).toThrow(
      /used twice/
    );
    expect(() =>
      assertShards([SHARDS[0] as MediaShard, { ...(SHARDS[0] as MediaShard), name: 'c' }])
    ).toThrow(/used twice/);
  });
});

describe('the media snippet refuses before it asks the cache', () => {
  it('refuses an unknown folder: the cache is reached only inside the known-shard handle', () => {
    expect(snippet).toContain('default ""');
    expect(snippet).toContain("@media_known expression `{media_shard} in ['a', 'b']`");
    expect(snippet.match(/reverse_proxy/g)).toHaveLength(1);
    const handle = snippet.slice(at(snippet, 'handle @media_known {'));
    expect(handle.indexOf('reverse_proxy')).toBeGreaterThan(0);
    // Whatever the handle does not answer is a 404, never a pass-through.
    expect(snippet.trimEnd().endsWith('\t\t\trespond 404\n\t\t}\n\t\trespond 404\n\t}\n}')).toBe(
      true
    );
  });

  it('knows no shard at all when none is configured, and so refuses every folder', () => {
    const none = renderMediaSnippet([], TENANT_POSTURE).join('\n');
    expect(none).toContain('@media_known expression `false`');
  });

  it('refuses a query string before any folder is read: no version link, no listing', () => {
    expect(snippet).toContain('@media_query expression `{http.request.uri.query} != ""`');
    expect(snippet).toContain('respond @media_query 400');
    expect(at(snippet, 'respond @media_query 400')).toBeLessThan(at(snippet, 'map {'));
    expect(at(snippet, 'respond @media_query 400')).toBeLessThan(at(snippet, 'reverse_proxy'));
  });

  it('refuses a request with no folder, and one with a folder and no object name', () => {
    expect(snippet).toContain(
      '@media_object path_regexp media_object ^/([A-Za-z0-9_-]{8,64})/[^/]'
    );
    expect(at(snippet, 'handle @media_object {')).toBeGreaterThan(at(snippet, '@media_object'));
  });

  it('answers only GET and HEAD, and refuses a dot segment', () => {
    expect(snippet).toContain('@media_method not method GET HEAD');
    expect(snippet).toContain('respond @media_method 405');
    expect(snippet).toContain('respond @media_traversal 404');
    expect(at(snippet, 'respond @media_traversal 404')).toBeLessThan(at(snippet, 'map {'));
  });

  it('refuses a file a browser would run, and marks every answer inert', () => {
    expect(snippet).toMatch(/@media_active path_regexp \(\?i\)\[\.\]\(\?:[a-z|]*svg[a-z|]*\)/);
    expect(snippet).toContain('respond @media_active 403');
    expect(snippet).toContain('header >X-Content-Type-Options "nosniff"');
    expect(snippet).toContain(`header >Content-Security-Policy "default-src 'none'; sandbox"`);
  });

  it('puts the throttle and the bouncer before every refusal, and sends no cookie on', () => {
    expect(snippet).toContain('zone media_per_ip');
    expect(at(snippet, 'crowdsec')).toBeLessThan(at(snippet, '@media_method'));
    expect(snippet).not.toContain('appsec');
    expect(snippet).toContain('header_up -Cookie');
    expect(snippet).toContain('header_up -Authorization');
  });

  it('reads the folder map from the host’s data and names no folder itself', () => {
    expect(snippet).toContain('import /etc/caddy-media/folders/*.map');
    expect(snippet).not.toMatch(/\b[a-z0-9]{12,}\b\s+[a-z]\n/);
  });
});

describe('the shard blocks read each bucket and nothing else', () => {
  it('give each shard its own bucket and its own endpoint, path-style, with no query', () => {
    const a = shardBlock('a');
    const b = shardBlock('b');
    expect(a).toContain('rewrite * /shard-bucket-a{http.request.uri.path}?');
    expect(a).toContain('reverse_proxy https://objects-a.example.test {');
    expect(a).not.toContain('shard-bucket-b');
    expect(b).toContain('rewrite * /shard-bucket-b{http.request.uri.path}?');
    expect(b).toContain('reverse_proxy https://objects-b.example.test {');
    expect(b).not.toContain('shard-bucket-a');
  });

  it('are addressed by the Host the snippet sends for that shard', () => {
    const sent = /header_up Host \{media_shard\}\.([a-z.-]+)\n/.exec(snippet)?.[1];
    expect(sent).toBeDefined();
    for (const shard of SHARDS) {
      const addresses = shardBlocks.flatMap((block) => block.addresses);
      expect(addresses).toContain(`http://${shard.name}.${sent}:${MEDIA_SHARD_PORT}`);
    }
  });

  it('count every request to the cache on a listener of its own, which is the only way to it', () => {
    const cache = shardBlocks.find((block) => block.addresses[0] === `http://:${MEDIA_CACHE_PORT}`);
    expect(cache?.body.join('\n')).toContain(`reverse_proxy ${MEDIA_CACHE_ADDRESS} {`);
    expect(snippet).toContain(`reverse_proxy 127.0.0.1:${MEDIA_CACHE_PORT} {`);
    expect(snippet).not.toContain(`reverse_proxy ${MEDIA_CACHE_ADDRESS}`);
  });

  it('end in a catch-all that refuses a host no shard owns, so the cache keeps no empty answer', () => {
    const last = shardBlocks[shardBlocks.length - 1];
    expect(last?.addresses).toEqual([`http://:${MEDIA_SHARD_PORT}`]);
    expect(last?.body).toEqual(['header Cache-Control "no-store"', 'respond 404']);
  });

  it('turn the bucket’s busy answer into a retryable 503 that is never stored', () => {
    const block = shardBlock('a');
    const busy = block.slice(at(block, 'handle_response @media_busy'), at(block, '@media_missing'));
    expect(block).toContain('@media_busy status 429 503');
    expect(busy).toContain('header Retry-After 2');
    expect(busy).toContain('header Cache-Control "no-store"');
    expect(busy).not.toContain('X-Accel-Expires');
    expect(busy).toContain('respond "The media store is busy. Try again shortly." 503');
  });

  it('store a found object and a missing one, and no other answer', () => {
    const block = shardBlock('a');
    expect(block).toContain('@media_found status 2xx 304');
    expect(block).toContain('@media_missing status 403 404');
    const rest = block.slice(block.lastIndexOf('handle_response {'));
    expect(rest).toContain('header Cache-Control "no-store"');
    expect(rest).toContain('respond 502');
    const stored = block.split('\n').filter((line) => line.includes('X-Accel-Expires'));
    expect(stored).toHaveLength(2);
  });

  it('send no cookie or credential to the bucket and pass none of its own back', () => {
    const block = shardBlock('a');
    expect(block).toContain('header_up -Cookie');
    expect(block).toContain('header_up -Authorization');
    expect(block).toContain('header_down -Set-Cookie');
    expect(block).toContain('header_down -x-amz-version-id');
  });

  it('bound the wait for a bucket, so a silent one cannot hold a reader', () => {
    const block = shardBlock('a');
    expect(block).toContain('dial_timeout 3s');
    expect(block).toContain('response_header_timeout 15s');
  });
});

describe('the tenant Caddyfile carries the media address', () => {
  const caddyfile = renderTenantCaddyfile(TENANT_POSTURE, SHARDS);
  const empty = renderTenantCaddyfile();

  it('defines the snippet before it imports the host’s sites, which Caddy requires', () => {
    expect(at(caddyfile, '(tenant_media) {')).toBeLessThan(
      at(caddyfile, `import ${MEDIA_SITES_GLOB}`)
    );
    expect(at(empty, '(tenant_media) {')).toBeLessThan(at(empty, `import ${MEDIA_SITES_GLOB}`));
  });

  it('names both listeners, so one counter is the cache’s requests and the other each bucket’s', () => {
    expect(caddyfile).toContain(`servers :${MEDIA_CACHE_PORT} {\n\t\tname media_cache`);
    expect(caddyfile).toContain(`servers :${MEDIA_SHARD_PORT} {\n\t\tname media_shard`);
    expect(caddyfile).toContain('metrics {\n\t\t\tper_host');
  });

  it('holds no shard until the buckets exist, and so reaches no bucket', () => {
    expect(MEDIA_SHARDS).toEqual([]);
    expect(empty).not.toMatch(/reverse_proxy https:/);
  });

  it('holds one shard block per shard', () => {
    expect(caddyfile.match(/^http:\/\/[a-z]+\.media-shard\.invalid:18080 \{$/gm)).toHaveLength(2);
  });
});

describe('the media cache in the tenant Compose file', () => {
  const nginx = nginxConfig();

  it('keeps every answer under the key of its host and its raw request path', () => {
    expect(nginx).toContain('proxy_cache_key $host$request_uri;');
  });

  it('lets the answer’s own headers decide what is stored, with no fixed lifetime for a status', () => {
    expect(nginx).not.toContain('proxy_cache_valid');
    expect(nginx).not.toContain('proxy_ignore_headers');
  });

  it('collapses concurrent misses, serves stale on an upstream error and fills whole objects', () => {
    expect(nginx).toContain('proxy_cache_lock on;');
    expect(nginx).toContain(
      'proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;'
    );
    expect(nginx).toContain('proxy_set_header Range "";');
    expect(nginx).toContain('proxy_force_ranges on;');
  });

  it('reads only the shard listener and answers only GET and HEAD', () => {
    expect(nginx).toContain(`set $shard_upstream caddy:${MEDIA_SHARD_PORT};`);
    expect(nginx).toContain('limit_except GET HEAD');
    expect(nginx).toContain('proxy_set_header Host $host;');
    expect(nginx).toContain('proxy_set_header Cookie "";');
    expect(nginx).toContain('proxy_set_header Authorization "";');
  });

  it('listens where the counted listener sends, and keeps its health page on another port', () => {
    expect(nginx).toContain(`listen ${MEDIA_CACHE_ADDRESS.split(':')[1]} default_server;`);
    expect(nginx).toContain('listen 8081;');
    expect(compose).toContain('http://127.0.0.1:8081/stub_status');
  });

  it('escapes every nginx variable from Compose, which would otherwise blank it', () => {
    expect(compose).not.toMatch(/(?<!\$)\$(?!\$)[a-z_]+/);
  });

  it('pins the image by digest and publishes no port: only Caddy reaches it', () => {
    expect(compose).toMatch(
      /image: docker\.io\/nginxinc\/nginx-unprivileged:[\d.]+-alpine@sha256:[0-9a-f]{64}/
    );
    const cacheService = compose.slice(at(compose, '  media-cache:\n'), at(compose, '\nconfigs:'));
    expect(cacheService).not.toContain('ports:');
  });

  it('gives Caddy the host’s media directory read-only and nothing else writable of it', () => {
    expect(compose).toContain('- /etc/branchleft/edge-media:/etc/caddy-media:ro');
  });
});
