import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { hostRedirects, sites, staticSites } from '../../sites';
import type { EdgeSite } from '../../siteTypes';
import { POSTURE, type EdgePosture } from './posture';
import { renderCaddyfile } from './render';

// Why: see render.md section "siteBlock: Ghost first-run setup refusal".

const DETECT_ONLY: EdgePosture = {
  crowdsec: 'detect-only',
  rateLimit: 'off',
  membersMagicLinkRateLimit: 'off',
};
const ENFORCING: EdgePosture = {
  crowdsec: 'enforcing',
  rateLimit: 'enforcing',
  membersMagicLinkRateLimit: 'enforcing',
};

const tenant = (overrides: Partial<EdgeSite> = {}): EdgeSite => ({
  name: 'tenant-one',
  hostnames: ['tenant-one.test'],
  privateUpstream: { host: 'app1', port: 2368 },
  requestBodyMaxSize: '64MiB',
  injectionWafPreviewOnly: true,
  ...overrides,
});

const render = (posture: EdgePosture, entries: EdgeSite[] = [tenant()]) =>
  renderCaddyfile(entries, [], posture);

/** The text of the first top-level block whose address line starts with `address`. */
function blockOf(rendered: string, address: string): string {
  const start = rendered.indexOf(`\n${address} {`);
  expect(start, `block ${address} must be rendered`).toBeGreaterThanOrEqual(0);
  const end = rendered.indexOf('\n}\n', start);
  return rendered.slice(start, end);
}

const MATCHER = '@ghost_setup {';
const REFUSAL = 'respond @ghost_setup 403';

describe('the Ghost first-run setup refusal in a rendered site block', () => {
  it.each([
    ['detect-only', DETECT_ONLY],
    ['enforcing', ENFORCING],
    ['the committed posture', POSTURE],
  ])('is present under %s', (_name, posture) => {
    const block = blockOf(render(posture), 'tenant-one.test');
    expect(block).toContain(MATCHER);
    expect(block).toContain(REFUSAL);
  });

  it('matches the unversioned and versioned paths, with and without a trailing slash', () => {
    const block = blockOf(render(ENFORCING), 'tenant-one.test');
    const pathLine = block.split('\n').find((l) => l.includes('/authentication/setup'));
    expect(pathLine?.trim().split(/\s+/)).toEqual([
      'path',
      '/ghost/api/admin/authentication/setup',
      '/ghost/api/admin/authentication/setup/*',
      '/ghost/api/*/admin/authentication/setup',
      '/ghost/api/*/admin/authentication/setup/*',
    ]);
  });

  it('refuses after the protection chain and before the upstream, so a prober is still throttled', () => {
    const block = blockOf(render(ENFORCING), 'tenant-one.test');
    const route = block.slice(block.indexOf('route {'));
    const chain = route.indexOf('appsec @inspected');
    const refusal = route.indexOf(REFUSAL);
    const upstream = route.indexOf('reverse_proxy');
    expect(chain).toBeGreaterThanOrEqual(0);
    expect(refusal).toBeGreaterThan(chain);
    expect(upstream).toBeGreaterThan(refusal);
  });

  it('is not keyed on a site flag: a non-authoring site carries it too', () => {
    const block = blockOf(
      render(ENFORCING, [tenant({ injectionWafPreviewOnly: false })]),
      'tenant-one.test'
    );
    expect(block).toContain(REFUSAL);
  });

  it('is on every served registry site, so a tenant added later has it by construction', () => {
    const rendered = renderCaddyfile(sites, hostRedirects, ENFORCING, staticSites);
    const served = sites.filter((s) => s.privateUpstream !== undefined);
    expect(served.length).toBeGreaterThan(0);
    for (const s of served) {
      const block = blockOf(rendered, s.hostnames[0]!);
      expect(block, `${s.name} must refuse Ghost's setup route`).toContain(REFUSAL);
    }
  });

  it('is on the loopback probe listeners too, so it can be proven before any site serves', () => {
    const rendered = render(ENFORCING);
    expect(blockOf(rendered, ':8080')).toContain(REFUSAL);
    expect(blockOf(rendered, 'http://edge-probe.invalid:8080')).toContain(REFUSAL);
  });

  it('is absent from redirect and static blocks, which are not Ghost', () => {
    const rendered = renderCaddyfile(
      [tenant({ hostnames: ['apex.test', 'www.apex.test'] })],
      [{ from: 'www.apex.test', to: 'apex.test' }],
      ENFORCING,
      staticSites
    );
    expect(blockOf(rendered, 'www.apex.test')).not.toContain('ghost_setup');
    for (const s of staticSites) {
      expect(blockOf(rendered, s.hostname)).not.toContain('ghost_setup');
    }
  });
});

// A real Caddy, built from the public pinned image, loading the renderer's
// own matcher and refusal lines. The full edge image needs two modules this
// check has no use for; the matcher and `respond` are core Caddy.
const CADDY_IMAGE =
  'caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648';
const LABEL = 'branchleft.agent=edge-ghost-setup-test';

function docker(...args: string[]) {
  return spawnSync('docker', args, { encoding: 'utf8', timeout: 120_000 });
}

const dockerUp = spawnSync('docker', ['info'], { timeout: 30_000 }).status === 0;
if (!dockerUp && process.env.CI) {
  throw new Error('docker is required for the live-Caddy refusal check in CI');
}

/** Extract the matcher and refusal exactly as the renderer emits them. */
function setupSnippet(rendered: string): string {
  const block = blockOf(rendered, 'tenant-one.test');
  const from = block.indexOf(MATCHER);
  const matcher = block.slice(from, block.indexOf('}', from) + 1);
  const refusal = block.split('\n').find((line) => line.trim().startsWith('respond @ghost_setup'));
  expect(refusal, 'the site block must carry the refusal line').toBeDefined();
  return `${matcher}\n\t${refusal!.trim()}`;
}

function get(port: number, rawPath: string, method = 'GET'): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path: rawPath, method }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on('error', reject);
    req.end(method === 'POST' ? '{}' : undefined);
  });
}

describe.skipIf(!dockerUp)('the refusal under a real Caddy', { timeout: 180_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'ghost-setup-'));
  const name = `bl-ghost-setup-${process.pid}`;
  let port = 0;

  const start = (snippet: string) => {
    writeFileSync(
      join(dir, 'Caddyfile'),
      `{\n\tadmin off\n\tauto_https off\n}\n:8081 {\n\t${snippet.replace(/\n/g, '\n\t')}\n\trespond "reached the upstream" 200\n}\n`
    );
    const run = docker(
      'run',
      '--rm',
      '-d',
      '--name',
      name,
      '--label',
      LABEL,
      '-p',
      '127.0.0.1::8081',
      '-v',
      `${join(dir, 'Caddyfile')}:/etc/caddy/Caddyfile:ro`,
      CADDY_IMAGE
    );
    expect(run.status, run.stderr).toBe(0);
    const mapped = docker('port', name, '8081/tcp').stdout.trim().split('\n')[0] ?? '';
    port = Number(mapped.split(':').pop());
    expect(port).toBeGreaterThan(0);
  };
  const stop = () => {
    docker('rm', '-f', '-v', name);
  };

  async function waitUp() {
    for (let i = 0; i < 50; i += 1) {
      try {
        await get(port, '/');
        return;
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    throw new Error('caddy did not start');
  }

  afterAll(() => {
    stop();
    rmSync(dir, { recursive: true, force: true });
  });

  const REFUSED = [
    '/ghost/api/admin/authentication/setup',
    '/ghost/api/admin/authentication/setup/',
    '/ghost/api/admin/authentication/setup/three/',
    '/GHOST/API/ADMIN/AUTHENTICATION/SETUP/',
    '//ghost/api/admin/authentication/setup/',
    '/ghost/api/v5/admin/authentication/setup/',
    '/ghost/api/canary/admin/authentication/setup/',
    '/ghost/api/admin/authentication/setup/../setup/',
    '/ghost/api/admin/authentication/%73etup/',
    '/ghost/api/admin/./authentication/setup/',
    '/ghost/api/admin/authentication/setup/?x=1',
  ];
  const PASSED = [
    '/',
    '/ghost/api/admin/site/',
    '/ghost/api/admin/authentication/session/',
    '/ghost/api/admin/authentication/password_reset/',
    '/ghost/api/content/posts/',
  ];

  beforeAll(async () => {
    start(setupSnippet(render(ENFORCING)));
    await waitUp();
  });

  it.each(REFUSED)('refuses %s, for a read and for the owner-creating write', async (path) => {
    expect(await get(port, path, 'GET')).toBe(403);
    expect(await get(port, path, 'POST')).toBe(403);
  });

  it.each(PASSED)('leaves %s reachable', async (path) => {
    expect(await get(port, path)).toBe(200);
  });

  // The sabotage case: with the rule removed the same probe reaches the
  // upstream. Without this, a green run above would also be what a Caddy that
  // ignored the config produced.
  it('SABOTAGE: with the rule removed, the owner-creating request reaches the upstream', async () => {
    stop();
    start('');
    await waitUp();
    expect(await get(port, '/ghost/api/admin/authentication/setup/', 'POST')).toBe(200);
  });
});
