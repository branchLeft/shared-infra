import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { EdgeSite } from '../../siteTypes';
import {
  CONTAINER_LIMITS,
  IMAGE_LIMITS,
  ensureImage,
  probeEngineSync,
  removeByName,
  startContainer,
  takeSlot,
  type Slot,
} from './dockerHarness';
import { POSTURE } from './posture';
import { renderCaddyfile } from './render';

// Why: see render.md section "Tenant media". The renderer's own media lines run
// under a real Caddy in front of an upstream that echoes the request line it
// receives, so what is asserted is what the bucket host would be sent, not what
// the Caddyfile text contains. The paths below are the oracle; none is derived
// from a constant in render.ts.

const MEDIA = { host: 'objects.example.test', bucket: 'branchleft-media-example' };
const BUCKET_PREFIX = `/${MEDIA.bucket}`;

const site: EdgeSite = {
  name: 'ghost-example',
  hostnames: ['ghost.example.test'],
  cloudRunService: 'example-service',
  privateUpstream: { host: 'app1', port: 2368 },
  requestBodyMaxSize: '1MiB',
  backend: 'ghost',
  media: MEDIA,
};

/** A request target that must never reach the bucket host, with the form it takes. */
const REFUSED: [string, string][] = [
  ['a plain dot segment', '/content/images/a/../b.png'],
  ['an encoded dot segment', '/content/images/a/%2e%2e/b.png'],
  ['an upper-case encoded dot segment', '/content/images/a/%2E%2E/b.png'],
  ['a half-encoded dot segment', '/content/images/a/.%2e/b.png'],
  ['another half-encoded dot segment', '/content/images/a/%2e./b.png'],
  ['an encoded dot segment and encoded slash', '/content/images/a/%2e%2e%2fb.png'],
  ['an encoded slash before a dot segment', '/content/images/a%2f../b.png'],
  ['an upper-case encoded slash before a dot segment', '/content/images/a%2F../b.png'],
  ['an encoded slash after a dot segment', '/content/images/a/..%2fb.png'],
  ['encoded slashes either side', '/content/images/a%2f..%2fb.png'],
  [
    'the climb out of the bucket the reviewer sent',
    '/content/images/a%2f..%2f..%2f..%2fcontent/images/b',
  ],
  ['a dot segment under the media prefix', '/content/media/a%2f..%2fb.mp4'],
  ['a dot segment under the files prefix', '/content/files/a%2f..%2fb.pdf'],
  ['a dot segment in a resized path', '/content/images/size/w600/a%2f..%2fb.png'],
  // Escaped twice. The first read of the path leaves `%2e` in it, and the edge's
  // own rewrite (to the bucket again after a Ghost round, and to Ghost on a
  // missing resized copy) reads it a second time, so a dot segment appears that
  // no check on the request as received could see.
  ['a double-encoded dot segment', '/content/images/a/%252e%252e/b.png'],
  ['a double-encoded slash around dots', '/content/images/a%252f..%252fb.png'],
  ['a double-encoded slash around encoded dots', '/content/images/a%252f%252e%252e%252fb.png'],
  ['a triple-encoded dot segment', '/content/images/a/%25252e%25252e/b.png'],
  [
    'a double-encoded dot segment in a missing resized copy',
    '/content/images/size/w600/absent/%252e%252e/b.png',
  ],
];

/**
 * Targets Caddy's own path matcher cleans back out of the upload paths before
 * any route sees them, so they fall to the site's Ghost proxy (the stand-in
 * answers 418) and are never read from the bucket.
 */
const CLEANED_OFF: [string, string][] = [
  ['a trailing dot segment', '/content/images/a/..'],
  ['a dot segment straight after the prefix', '/content/images/../b.png'],
  ['a dot segment with a query', '/content/images/a/..?x=1'],
  [
    'an encoded slash and encoded dots that climb out',
    '/content/images/a%2f%2e%2e%2f%2e%2e%2fother-bucket/key',
  ],
  ['encoded slashes that climb out of the prefix', '/content/images/x/..%2f..%2f..%2fother/b'],
  ['encoded slashes that climb out of its own name', '/content/images/a%2f..%2f..%2fb.png'],
];

/** A request target that is an ordinary upload and must still be read from the bucket. */
const ALLOWED: [string, string][] = [
  ['a dated upload', '/content/images/2026/11/photo.png'],
  ['two dots inside a name', '/content/images/2026/11/a..b/c.png'],
  ['two dots in a version-like name', '/content/images/v1.2..3/c.png'],
  ['a name starting with two dots', '/content/images/..hidden/c.png'],
  ['a run of three dots', '/content/images/.../c.png'],
  ['a name ending in two dots', '/content/images/a../c.png'],
  ['an encoded space', '/content/images/a%20b.png'],
  ['an encoded non-ASCII letter', '/content/images/%C3%A9.png'],
  ['a resized copy', '/content/images/size/w600/2026/11/photo.png'],
  ['a media file', '/content/media/2026/11/clip.mp4'],
  ['a file', '/content/files/2026/11/paper.pdf'],
];

const CADDY_IMAGE =
  'caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648';
const LABEL = 'branchleft.agent=edge-tenant-media-traversal-test';

/** The renderer's own media lines, from the first matcher to the end of the plain route, as the site block emits them. */
function renderedMediaLines(rendered: string): string[] {
  const start = rendered.indexOf(`\n${site.hostnames[0]!} {`);
  expect(start, 'the site block must be rendered').toBeGreaterThanOrEqual(0);
  const lines = rendered.slice(start + 1, rendered.indexOf('\n}\n', start)).split('\n');
  const from = lines.findIndex((l) => l.trim() === '@tenant_media_traversal {');
  expect(from, 'the site block must carry the traversal matcher').toBeGreaterThanOrEqual(0);
  const open = lines.findIndex((l) => l.trim() === 'route @tenant_media {');
  expect(open, 'the site block must carry the plain media route').toBeGreaterThan(from);
  const depth = lines[open]!.length - lines[open]!.trimStart().length;
  const close = lines.findIndex((l, i) => i > open && l === `${'\t'.repeat(depth)}}`);
  expect(close, 'the plain media route must close').toBeGreaterThan(open);
  const cut = lines[from]!.length - lines[from]!.trimStart().length;
  return lines.slice(from, close + 1).map((l) => l.slice(cut));
}

/** The Caddyfile under test: the media lines in front of an upstream standing in for the bucket host. */
function caddyfile(rendered: string): string {
  const media = renderedMediaLines(rendered).map((l) =>
    l
      .replace(`reverse_proxy https://${MEDIA.host} {`, 'reverse_proxy 127.0.0.1:9000 {')
      .replace(/reverse_proxy 10\.20\.1\.100:\d+ \{/, 'reverse_proxy 127.0.0.1:9001 {')
  );
  return [
    '{',
    '\tadmin off',
    '\tauto_https off',
    '}',
    ':8081 {',
    '\troute {',
    ...media.map((l) => `\t\t${l}`),
    '\t\trespond "not a media path" 418',
    '\t}',
    '}',
    ':9000 {',
    '\t@absent path *absent*',
    '\trespond @absent "no such key" 404',
    '\trespond "{http.request.uri}" 200',
    '}',
    ':9001 {',
    '\trespond "ghost {http.request.uri}" 200',
    '}',
    '',
  ].join('\n');
}

interface Answer {
  status: number;
  body: string;
  cacheControl: string | undefined;
}

function get(port: number, rawPath: string): Promise<Answer> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port,
        path: rawPath,
        headers: { host: site.hostnames[0]! },
        timeout: 5_000,
      },
      (res) => {
        let body = '';
        res.on('data', (d: Buffer) => (body += d.toString()));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            body,
            cacheControl: res.headers['cache-control'],
          })
        );
      }
    );
    req.on('timeout', () => req.destroy(new Error('no answer from the container within 5s')));
    req.on('error', reject);
    req.end();
  });
}

const engine = probeEngineSync();
const dockerUp = engine.up;
if (!dockerUp && process.env.CI) {
  throw new Error(
    `docker is required for the live-Caddy media traversal check in CI: ${engine.reason}`
  );
}
if (!dockerUp) {
  console.warn(
    `SKIPPED: the live-Caddy media traversal check did not run (${engine.reason}). CI runs this block.`
  );
}

const title = `the media traversal guard under a real Caddy${dockerUp ? '' : ` (SKIPPED: ${engine.reason})`}`;

describe.skipIf(!dockerUp)(title, { timeout: 180_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'tenant-media-traversal-'));
  const name = `bl-tenant-media-traversal-${process.pid}`;
  let slot: Slot | undefined;
  let port = 0;

  const SLOT_WAIT_MS = 90_000;
  const setupBudgetMs =
    SLOT_WAIT_MS +
    IMAGE_LIMITS.inspectMs +
    IMAGE_LIMITS.pullMs +
    CONTAINER_LIMITS.createMs +
    CONTAINER_LIMITS.startMs +
    CONTAINER_LIMITS.portMs +
    CONTAINER_LIMITS.removeMs +
    60_000;

  afterAll(async () => {
    try {
      await removeByName(name);
    } finally {
      slot?.release();
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  beforeAll(async () => {
    slot = await takeSlot({ waitMs: SLOT_WAIT_MS, label: 'edge-tenant-media-traversal-test' });
    await ensureImage(CADDY_IMAGE);
    writeFileSync(join(dir, 'Caddyfile'), caddyfile(renderCaddyfile([site], [], POSTURE)));
    port = await startContainer({
      name,
      label: LABEL,
      image: CADDY_IMAGE,
      containerPort: 8081,
      mountSource: dir,
      mountTarget: '/etc/caddy',
    });
    for (let i = 0; ; i += 1) {
      try {
        await get(port, '/');
        break;
      } catch (e) {
        if (i >= 50) throw new Error(`caddy did not start: ${String(e)}`);
        await new Promise((r) => setTimeout(r, 200));
      }
    }
  }, setupBudgetMs);

  it('reads an ordinary upload from the bucket, path-style, with a year of cache', async () => {
    const answer = await get(port, '/content/images/2026/11/photo.png');
    expect(answer.status).toBe(200);
    expect(answer.body).toBe(`${BUCKET_PREFIX}/content/images/2026/11/photo.png`);
    expect(answer.cacheControl).toBe('public, max-age=31536000, immutable');
  });

  it.each(ALLOWED)('still reads %s', async (_form, target) => {
    const answer = await get(port, target);
    expect(answer.status, `${target} reached no bucket read: ${answer.body}`).toBe(200);
    expect(answer.body).toBe(`${BUCKET_PREFIX}${target}`);
  });

  it.each(REFUSED)('answers 404 and asks the bucket nothing for %s', async (_form, target) => {
    const answer = await get(port, target);
    expect(
      answer.body,
      `${target} was sent on to the bucket host, which would be asked for ${answer.body}`
    ).toBe('');
    expect(answer.status).toBe(404);
  });

  it.each(CLEANED_OFF)('leaves %s to Ghost and never reads the bucket', async (_form, target) => {
    const answer = await get(port, target);
    expect(answer.body).not.toContain(BUCKET_PREFIX);
    expect(answer.status).toBe(418);
  });

  it.each([
    ['an ordinary resized copy', '/content/images/size/w600/absent.png'],
    ['an encoded space', '/content/images/size/w600/absent%20b.png'],
  ])('asks Ghost for a missing resized copy with %s', async (_form, target) => {
    const answer = await get(port, target);
    expect(answer.status).toBe(200);
    expect(answer.body).toMatch(/^ghost \/content\/images\/size\/w600\/absent/);
    expect(answer.body).not.toMatch(/(?:^|\s|\/)\.\.(?:\/|$)/);
  });
});
