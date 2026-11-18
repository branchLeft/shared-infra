import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import type { EdgeSite } from '../../siteTypes';
import { POSTURE } from './posture';
import { WIDGET_ASSET_PATH, WIDGET_ASSET_ROOT, renderCaddyfile } from './render';

// The seven files `branchLeft/ghost-platform`'s `widgets/pins.json` pins and
// `render-core` points a tenant's Ghost at (`OWN_ORIGIN_WIDGETS`).
const WIDGET_FILES = [
  'admin-toolbar.min.js',
  'announcement-bar.min.js',
  'comments-ui.min.js',
  'portal.min.js',
  'signup-form.min.js',
  'sodo-search.min.css',
  'sodo-search.min.js',
];

const dockerfile = readFileSync(join(__dirname, 'Dockerfile'), 'utf8');
const adds = dockerfile.split('\n').filter((line) => /^ADD\s/.test(line));

const ghostSite = (backend: EdgeSite['backend']): EdgeSite => ({
  name: backend === 'ghost' ? 'ghost-example' : 'other-example',
  hostnames: [backend === 'ghost' ? 'ghost.example.test' : 'other.example.test'],
  cloudRunService: 'example-service',
  privateUpstream: { host: 'app1', port: backend === 'ghost' ? 2368 : 2369 },
  requestBodyMaxSize: '1MiB',
  backend,
});

function blockOf(caddyfile: string, hostname: string): string {
  const start = caddyfile.indexOf(`${hostname} {`);
  expect(start).toBeGreaterThanOrEqual(0);
  const end = caddyfile.indexOf('\n}\n', start);
  return caddyfile.slice(start, end);
}

describe('the edge image carries the pinned widget files', () => {
  it('adds exactly the seven pinned files, each by sha256 and from one commit', () => {
    expect(adds).toHaveLength(WIDGET_FILES.length);
    const named = adds.map((line) => {
      const match =
        /^ADD --checksum=sha256:([0-9a-f]{64}) --chmod=0644 \$\{WIDGET_BASE_URL\}\/(\S+) (\S+)$/.exec(
          line
        );
      expect(match, line).not.toBeNull();
      const [, , source, destination] = match!;
      expect(destination).toBe(`${WIDGET_ASSET_ROOT}${WIDGET_ASSET_PATH}${source}`);
      return source;
    });
    expect([...named].sort()).toEqual([...WIDGET_FILES].sort());
    expect(dockerfile).toMatch(/^ARG WIDGET_SOURCE_COMMIT=[0-9a-f]{40}$/m);
    expect(dockerfile).toMatch(
      /^ARG WIDGET_BASE_URL=https:\/\/raw\.githubusercontent\.com\/branchLeft\/ghost-platform\/\$\{WIDGET_SOURCE_COMMIT\}\/widgets\/dist$/m
    );
  });

  it('puts them where the rendered file server looks', () => {
    expect(`${WIDGET_ASSET_ROOT}${WIDGET_ASSET_PATH}`).toBe('/srv/bl-assets/');
  });
});

describe('the Ghost site block serves /bl-assets/ itself', () => {
  const rendered = renderCaddyfile([ghostSite('ghost'), ghostSite('other')], [], POSTURE);

  it('answers GET and HEAD of the path from the image, compressed and cached an hour', () => {
    const block = blockOf(rendered, 'ghost.example.test');
    expect(block).toContain(
      '\t\t@widget_assets {\n\t\t\tmethod GET HEAD\n\t\t\tpath /bl-assets/*\n\t\t}'
    );
    expect(block).toContain('\t\tencode @widget_assets zstd gzip');
    expect(block).toContain('\t\theader @widget_assets Cache-Control "public, max-age=3600"');
    expect(block).toContain('\t\tfile_server @widget_assets {\n\t\t\troot /srv\n\t\t}');
  });

  it('comes after the protection chain and before the proxy, so a probe is still throttled', () => {
    const block = blockOf(rendered, 'ghost.example.test');
    const at = (needle: string): number => block.indexOf(needle);
    expect(at('crowdsec')).toBeGreaterThan(-1);
    expect(at('file_server @widget_assets')).toBeGreaterThan(at('crowdsec'));
    expect(at('file_server @widget_assets')).toBeGreaterThan(at('@active_upload_by_pattern'));
    expect(at('file_server @widget_assets')).toBeLessThan(at('reverse_proxy'));
  });

  it('is on a Ghost site and no other', () => {
    expect(blockOf(rendered, 'other.example.test')).not.toContain('widget_assets');
    expect(blockOf(rendered, 'other.example.test')).not.toContain('file_server');
  });
});
