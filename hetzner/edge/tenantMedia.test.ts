import { describe, expect, it } from 'vitest';

import type { EdgeSite } from '../../siteTypes';
import { sites } from '../../sites';
import { POSTURE } from './posture';
import { renderCaddyfile } from './render';

const MEDIA = { host: 'objects.example.test', bucket: 'branchleft-media-example' };

const ghostSite = (backend: EdgeSite['backend'], media?: EdgeSite['media']): EdgeSite => ({
  name: backend === 'ghost' ? 'ghost-example' : 'other-example',
  hostnames: [backend === 'ghost' ? 'ghost.example.test' : 'other.example.test'],
  cloudRunService: 'example-service',
  privateUpstream: { host: 'app1', port: backend === 'ghost' ? 2368 : 2369 },
  requestBodyMaxSize: '1MiB',
  backend,
  ...(media === undefined ? {} : { media }),
});

function blockOf(caddyfile: string, hostname: string): string {
  const start = caddyfile.indexOf(`${hostname} {`);
  expect(start).toBeGreaterThanOrEqual(0);
  const end = caddyfile.indexOf('\n}\n', start);
  return caddyfile.slice(start, end);
}

const render = (list: EdgeSite[]): string => renderCaddyfile(list, [], POSTURE);

describe('a Ghost site with a media bucket answers its upload paths itself', () => {
  const block = blockOf(render([ghostSite('ghost', MEDIA)]), 'ghost.example.test');

  it('reads the bucket path-style, GET and HEAD only, and nothing of the client but the path', () => {
    expect(block).toContain('rewrite * /branchleft-media-example{http.request.uri.path}?');
    expect(block).toContain('reverse_proxy https://objects.example.test {');
    expect(block).toContain('header_up Host {upstream_hostport}');
    expect(block).toContain('header_up -Cookie');
    expect(block).toContain('header_up -Authorization');
    expect(block).toContain(
      '@tenant_media {\n\t\t\tmethod GET HEAD\n\t\t\tpath /content/images/* /content/media/* /content/files/*\n\t\t}'
    );
  });

  it('refuses a dot segment under the upload paths before the bucket is asked', () => {
    expect(block).toContain('@tenant_media_traversal {');
    expect(block).toContain('(?:[.]|%2e){2}');
    expect(block).toContain('respond @tenant_media_traversal 404');
    expect(block.indexOf('respond @tenant_media_traversal 404')).toBeLessThan(
      block.indexOf('route @tenant_media_resize')
    );
  });

  it('caches a found object for a year and passes none of the bucket internals on', () => {
    expect(block).toContain('header Cache-Control "public, max-age=31536000, immutable"');
    for (const name of ['x-amz-request-id', 'x-amz-version-id', 'x-amz-expiration']) {
      expect(block).toContain(`header_down -${name}`);
    }
    expect(block).toContain('header_down -Strict-Transport-Security');
  });

  it('answers a missing object 404 and never sends it to Ghost, except a resized copy', () => {
    const fromPlain = block.slice(block.indexOf('route @tenant_media {'));
    const plain = fromPlain.slice(0, fromPlain.lastIndexOf('\t\treverse_proxy 10.20.1.100'));
    expect(plain).toContain('respond 404');
    expect(plain).not.toContain('10.20.1.100');
    const resize = block.slice(
      block.indexOf('route @tenant_media_resize'),
      block.indexOf('route @tenant_media {')
    );
    expect(resize.match(/reverse_proxy 10\.20\.1\.100:\d+ \{/g)).toHaveLength(1);
  });

  it('reads the bucket once more after Ghost makes a resized copy, and a miss then is a 404, not another Ghost round', () => {
    const resize = block.slice(
      block.indexOf('route @tenant_media_resize'),
      block.indexOf('route @tenant_media {')
    );
    expect(resize).toContain('@media_bounce status 301 302 307 308');
    const afterBounce = resize.slice(resize.indexOf('handle_response @media_bounce'));
    expect(afterBounce).toContain('reverse_proxy https://objects.example.test {');
    expect(afterBounce).toContain('@media_miss_retry status 403 404');
    expect(afterBounce.match(/10\.20\.1\.100/g)).toBeNull();
  });

  it('comes after the protection chain and the upload refusal, and before the proxy to Ghost', () => {
    const at = (needle: string): number => block.indexOf(needle);
    expect(at('route @tenant_media_resize')).toBeGreaterThan(at('crowdsec'));
    expect(at('route @tenant_media_resize')).toBeGreaterThan(at('@active_upload_by_pattern'));
    expect(at('route @tenant_media_resize')).toBeGreaterThan(at('file_server @widget_assets'));
    expect(block.lastIndexOf('reverse_proxy 10.20.1.100:2368')).toBeGreaterThan(
      at('route @tenant_media {')
    );
  });
});

describe('a site without the field, or that is not Ghost, is unchanged', () => {
  const rendered = render([
    ghostSite('ghost'),
    { ...ghostSite('other', MEDIA), name: 'other-with-media' },
  ]);

  it('has no media route on a Ghost site with no bucket', () => {
    expect(blockOf(rendered, 'ghost.example.test')).not.toContain('tenant_media');
  });

  it('has none on a site that is not Ghost, even with a bucket named', () => {
    expect(blockOf(rendered, 'other.example.test')).not.toContain('tenant_media');
  });
});

describe('the registry entry is checked before it reaches a Caddyfile', () => {
  it.each([
    [
      'a bucket that is not a tenant media bucket',
      { ...MEDIA, bucket: 'branchleft-tenant-backups' },
    ],
    ['a bucket with a path in it', { ...MEDIA, bucket: 'branchleft-media-a/../b' }],
    ['a bucket ending in a hyphen', { ...MEDIA, bucket: 'branchleft-media-a-' }],
    ['a host with a brace', { ...MEDIA, host: 'objects.example.test {' }],
    ['a host with a path', { ...MEDIA, host: 'objects.example.test/x' }],
  ])('refuses %s', (_name, media) => {
    expect(() => render([ghostSite('ghost', media)])).toThrow(/media (bucket|host)/);
  });
});

describe('the blog entry in sites.ts', () => {
  it('names its own bucket, the one the tenant stack derives from the slug "blog"', () => {
    const blog = sites.find((site) => site.name === 'blog');
    expect(blog?.media).toEqual({
      host: 'hel1.your-objectstorage.com',
      bucket: 'branchleft-media-blog',
    });
  });
});
