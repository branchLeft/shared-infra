import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { hostRedirects, sites, staticSites } from '../../sites';
import type { EdgeSite } from '../../siteTypes';
import {
  BLOCKED_PAGE_PLACEHOLDERS,
  BLOCKED_PAGE_STATUS,
  BLOCKED_PAGE_TIME_PLACEHOLDER,
  blockedPageHtml,
} from './blockedPage';
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
import { POSTURE, type EdgePosture } from './posture';
import { renderCaddyfile, resolvePrivateAddress } from './render';

// Why: see render.md section "Blocked page".

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
  backend: 'ghost',
  ...overrides,
});

const rendered = (posture: EdgePosture = ENFORCING) =>
  renderCaddyfile(sites, hostRedirects, posture, staticSites);

interface Block {
  address: string;
  text: string;
}

/** Every top-level block after the global options, each with its address line. */
function topLevelBlocks(text: string): Block[] {
  const blocks: Block[] = [];
  let current: Block | undefined;
  for (const line of text.split('\n')) {
    if (/^\S.* \{$/.test(line) && !line.startsWith('#')) {
      current = { address: line.slice(0, -2), text: `${line}\n` };
      blocks.push(current);
    } else if (current !== undefined) {
      current.text += `${line}\n`;
    }
  }
  return blocks;
}

/** A block's site-level `handle_errors`, from its first line to its closing brace. */
function errorBlockOf(block: string): string {
  const start = block.indexOf('\n\thandle_errors {');
  expect(start, 'the block must carry a handle_errors').toBeGreaterThanOrEqual(0);
  const end = block.indexOf('\n\t}\n', start + 1);
  return block.slice(start + 1, end + 3);
}

const METRICS_ADDRESS = ':9091';

describe('the global bouncer options', () => {
  it.each([
    ['detect-only', DETECT_ONLY],
    ['enforcing', ENFORCING],
    ['the committed posture', POSTURE],
  ])('make a refusal a Caddy error under %s, as a bare flag', (_name, posture) => {
    const text = renderCaddyfile([tenant()], [], posture);
    const from = text.indexOf('\tcrowdsec {');
    expect(from).toBeGreaterThan(0);
    const crowdsec = text.slice(from, text.indexOf('\n\t}\n', from));
    // A bare flag: the parser rejects an argument. Without it the bouncer writes a
    // bodiless 403 itself and no error block ever sees it.
    expect(crowdsec).toMatch(/^\t\tenable_caddy_error$/m);
  });
});

describe('the page a refused visitor sees, in the rendered config', () => {
  it('is on every block except the metrics listener, so every protected site and probe carries it', () => {
    const blocks = topLevelBlocks(rendered());
    expect(blocks.length).toBeGreaterThan(sites.length);
    const without = blocks.filter((b) => !b.text.includes('\n\thandle_errors {'));
    expect(without.map((b) => b.address)).toEqual([METRICS_ADDRESS]);
    for (const block of blocks.filter((b) => b.address !== METRICS_ADDRESS)) {
      expect(errorBlockOf(block.text), block.address).toContain(blockedPageHtml());
      expect(block.text.match(/\n\thandle_errors \{/g), block.address).toHaveLength(1);
    }
  });

  it('is on every kind of block a registry can render: site, redirect, static, webhook and probe', () => {
    const text = renderCaddyfile(
      [
        tenant({ hostnames: ['apex.test', 'www.apex.test'] }),
        tenant({
          name: 'hook',
          hostnames: ['hook.test'],
          privateUpstream: { host: 'app1', port: 2369 },
          backend: 'other',
          injectionWafPreviewOnly: false,
          inboundWebhookPath: '/webhook',
        }),
      ],
      [{ from: 'www.apex.test', to: 'apex.test' }],
      ENFORCING,
      staticSites
    );
    const blocks = topLevelBlocks(text);
    const addresses = blocks.map((b) => b.address);
    for (const expected of [
      'apex.test',
      'www.apex.test',
      'hook.test',
      ':8080',
      'http://edge-probe.invalid:8080',
    ]) {
      expect(addresses, expected).toContain(expected);
    }
    for (const block of blocks.filter((b) => b.address !== METRICS_ADDRESS)) {
      expect(errorBlockOf(block.text), block.address).toContain('handle @refused {');
    }
  });

  it('answers only a Caddy error of status 403, with the status it replaces', () => {
    const block = errorBlockOf(topLevelBlocks(rendered())[0]!.text);
    expect(block).toContain(
      `@refused expression \`{http.error.status_code} == ${BLOCKED_PAGE_STATUS}\``
    );
    expect(block).toContain(`EDGE_BLOCKED_PAGE_EOF ${BLOCKED_PAGE_STATUS}\n`);
    expect(BLOCKED_PAGE_STATUS).toBe(403);
    // Not a catch-all: every other error keeps what it had.
    expect(block.match(/\bhandle\b/g)).toHaveLength(1);
  });

  it('carries nosniff for a Ghost site only, first in the block, and the page for all', () => {
    const text = rendered();
    const blocks = topLevelBlocks(text);
    for (const entry of sites.filter((s) => s.privateUpstream !== undefined)) {
      const block = blocks.find((b) => b.address.split(', ').includes(entry.hostnames[0]!));
      expect(block, entry.name).toBeDefined();
      const errors = errorBlockOf(block!.text);
      const nosniff = '\theader >X-Content-Type-Options "nosniff"';
      expect(errors.includes(nosniff), entry.name).toBe(entry.backend === 'ghost');
      if (entry.backend === 'ghost') {
        expect(errors.split('\n')[1], entry.name).toBe(`\t${nosniff}`);
      }
    }
  });

  it('is unchanged when the bouncer is not enforcing, so the posture flip adds no new directive', () => {
    const detect = errorBlockOf(
      topLevelBlocks(renderCaddyfile([tenant()], [], DETECT_ONLY))[0]!.text
    );
    const enforcing = errorBlockOf(
      topLevelBlocks(renderCaddyfile([tenant()], [], ENFORCING))[0]!.text
    );
    expect(detect).toBe(enforcing);
  });
});

describe('the page itself', () => {
  const page = blockedPageHtml();

  it('is words the owner has not supplied yet: only ALL_CAPS placeholders, all of them present', () => {
    const found = [...new Set(page.match(/BLOCKED_PAGE_[A-Z_]+/g))].sort();
    expect(found).toEqual([...BLOCKED_PAGE_PLACEHOLDERS].sort());
    // No other sentence on the page: strip the markup and the placeholders, nothing is left.
    const text = page
      .replace(/<[^>]*>/g, ' ')
      .replace(/BLOCKED_PAGE_[A-Z_]+/g, ' ')
      .replace(BLOCKED_PAGE_TIME_PLACEHOLDER, ' ')
      .replace(/[\s:]+/g, ' ')
      .trim();
    expect(text).toBe('');
  });

  it('loads nothing: no script, stylesheet, font, image, frame or URL of any kind', () => {
    for (const forbidden of [
      /<script/i,
      /<link/i,
      /<img/i,
      /<iframe/i,
      /<object/i,
      /<embed/i,
      /<style/i,
      /<form/i,
      /<base/i,
      /@import/i,
      /url\(/i,
      /\bsrc\s*=/i,
      /\bhref\s*=/i,
      /\bon[a-z]+\s*=/i,
      /https?:/i,
      /\/\//,
    ]) {
      expect(page, String(forbidden)).not.toMatch(forbidden);
    }
    const csp = errorBlockOf(topLevelBlocks(rendered())[0]!.text).match(
      /header Content-Security-Policy "([^"]*)"/
    )?.[1];
    expect(csp?.split('; ')[0]).toBe("default-src 'none'");
    // No source list names a host, a scheme or a wildcard.
    expect(csp).not.toMatch(/https?:|\*|\/\//);
    expect(csp).not.toContain('script-src');
  });

  it('has one runtime value, the time, and nothing from the request, the decision or the rule', () => {
    expect(page.match(/\{[^}]*\}/g)).toEqual([BLOCKED_PAGE_TIME_PLACEHOLDER]);
    for (const reveal of [
      /http\.vars/i,
      /http\.error/i,
      /http\.request/i,
      /remote/i,
      /crowdsec/i,
      /appsec/i,
      /decision/i,
      /scenario/i,
      /\bban\b/i,
      /\brule\b/i,
      /cscli/i,
    ]) {
      expect(page, String(reveal)).not.toMatch(reveal);
    }
  });

  it('names no hostname, upstream or private address of the estate', () => {
    const names = new Set<string>();
    for (const entry of sites) {
      entry.hostnames.forEach((h) => names.add(h));
      if (entry.privateUpstream !== undefined) {
        names.add(entry.privateUpstream.host);
        const address = resolvePrivateAddress(
          entry.privateUpstream.host,
          entry.privateUpstream.port
        );
        names.add(address);
        names.add(address.split(':')[0]!);
      }
    }
    staticSites.forEach((s) => names.add(s.hostname));
    expect(names.size).toBeGreaterThan(5);
    for (const name of names) {
      expect(page, name).not.toContain(name);
    }
    expect(page).not.toMatch(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
  });

  it('ends in a newline and has no line equal to its heredoc marker', () => {
    expect(page.endsWith('\n')).toBe(true);
    expect(page.split('\n')).not.toContain('EDGE_BLOCKED_PAGE_EOF');
  });

  it('is served uncached, unindexed and as HTML', () => {
    const block = errorBlockOf(topLevelBlocks(rendered())[0]!.text);
    expect(block).toContain('header Content-Type "text/html; charset=utf-8"');
    expect(block).toContain('header Cache-Control "no-store"');
    expect(block).toContain('header X-Robots-Tag "noindex"');
  });
});

// A real Caddy, built from the public pinned image, loading the renderer's own
// error block with the errors the bouncer and AppSec raise. The full edge image
// needs two modules this check has no use for: the module's refusal, with
// `enable_caddy_error` set, is `caddyhttp.Error(403, ...)`, which the `error`
// directive raises the same way. CI loads every rendered file through the real
// image (`edge-config-validate`) and replays a real ban against it
// (`test_trusted_session_replay.py`).
const CADDY_IMAGE =
  'caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648';
const LABEL = 'branchleft.agent=edge-blocked-page-test';

const engine = probeEngineSync();
const dockerUp = engine.up;
if (!dockerUp && process.env.CI) {
  throw new Error(
    `docker is required for the live-Caddy blocked-page check in CI: ${engine.reason}`
  );
}
if (!dockerUp) {
  console.warn(
    `SKIPPED: the live-Caddy blocked-page check did not run (${engine.reason}). ` +
      'The rendered-output tests above still ran; CI runs this block.'
  );
}

interface Answer {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function get(port: number, host: string, path: string, headers: Record<string, string> = {}) {
  return new Promise<Answer>((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: 'GET',
        headers: { host, ...headers },
        timeout: 5_000,
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => (body += chunk));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      }
    );
    req.on('timeout', () => req.destroy(new Error('no answer from the container within 5s')));
    req.on('error', reject);
    req.end();
  });
}

const GHOST_HOST = 'ghost.test';
const PLAIN_HOST = 'plain.test';

/**
 * One site per kind of error block, each answering what the renderer's own block
 * does, behind a route that raises the errors the bouncer, AppSec and the proxy
 * raise. The `vars` are the ones the bouncer sets on a refusal: the page must not
 * show them.
 */
function liveCaddyfile(): string {
  const ghost = errorBlockOf(topLevelBlocks(renderCaddyfile([tenant()], [], ENFORCING))[0]!.text);
  const plain = errorBlockOf(
    topLevelBlocks(renderCaddyfile([tenant({ backend: 'other' })], [], ENFORCING))[0]!.text
  );
  const site = (host: string, errors: string) =>
    [
      `http://${host}:8081 {`,
      '\t@banned header X-Case banned',
      '\t@appsec header X-Case appsec',
      '\t@throttled header X-Case throttled',
      '\t@down header X-Case down',
      '\t@setup path /setup-refusal',
      '\troute {',
      '\t\tvars @banned crowdsec.module bouncer',
      '\t\tvars @banned crowdsec.remediation ban',
      '\t\tvars @banned crowdsec.origin cscli',
      '\t\tvars @appsec crowdsec.module appsec',
      '\t\tvars @appsec crowdsec.remediation ban',
      '\t\terror @banned 403',
      '\t\terror @appsec 403',
      '\t\terror @throttled 429',
      '\t\terror @down 502',
      '\t\trespond @setup 403',
      '\t\trespond "reached the upstream" 200',
      '\t}',
      errors,
      '}',
    ].join('\n');
  return `{\n\tadmin off\n\tauto_https off\n}\n${site(GHOST_HOST, ghost)}\n${site(PLAIN_HOST, plain)}\n`;
}

const caddyTitle = `the page under a real Caddy${dockerUp ? '' : ` (SKIPPED: ${engine.reason})`}`;

describe.skipIf(!dockerUp)(caddyTitle, { timeout: 180_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'blocked-page-'));
  const name = `bl-blocked-page-${process.pid}`;
  let port = 0;
  let slot: Slot | undefined;

  afterAll(async () => {
    try {
      await removeByName(name);
    } finally {
      slot?.release();
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  const SLOT_WAIT_MS = 90_000;
  const setupBudgetMs =
    SLOT_WAIT_MS +
    IMAGE_LIMITS.inspectMs +
    IMAGE_LIMITS.pullMs +
    CONTAINER_LIMITS.createMs +
    CONTAINER_LIMITS.startMs +
    CONTAINER_LIMITS.portMs +
    CONTAINER_LIMITS.removeMs +
    30_000;
  beforeAll(async () => {
    slot = await takeSlot({ waitMs: SLOT_WAIT_MS, label: 'edge-blocked-page-test' });
    await ensureImage(CADDY_IMAGE);
    writeFileSync(join(dir, 'Caddyfile'), liveCaddyfile());
    port = await startContainer({
      name,
      label: LABEL,
      image: CADDY_IMAGE,
      containerPort: 8081,
      mountSource: join(dir, 'Caddyfile'),
      mountTarget: '/etc/caddy/Caddyfile',
    });
    for (let i = 0; i < 50; i += 1) {
      try {
        await get(port, PLAIN_HOST, '/');
        return;
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    throw new Error('caddy did not start');
  }, setupBudgetMs);

  const hosts = [GHOST_HOST, PLAIN_HOST];

  it.each(hosts)('serves the page, with status 403, to a banned address on %s', async (host) => {
    const answer = await get(port, host, '/anything?x=1', { 'X-Case': 'banned' });
    expect(answer.status).toBe(403);
    expect(answer.headers['content-type']).toBe('text/html; charset=utf-8');
    expect(answer.headers['cache-control']).toBe('no-store');
    expect(answer.headers['content-security-policy']).toContain("default-src 'none'");
    expect(answer.headers['x-robots-tag']).toBe('noindex');
    for (const placeholder of BLOCKED_PAGE_PLACEHOLDERS) {
      expect(answer.body, placeholder).toContain(placeholder);
    }
    // The one placeholder the page fills in is the time, an HTTP date.
    expect(answer.body).toMatch(
      /BLOCKED_PAGE_REFERENCE_LABEL: \w{3}, \d{2} \w{3} \d{4} [\d:]{8} GMT/
    );
    expect(answer.body).not.toContain('{');
  });

  it.each(hosts)('serves the same page for an in-band AppSec refusal on %s', async (host) => {
    const banned = await get(port, host, '/', { 'X-Case': 'banned' });
    const appsec = await get(port, host, '/', { 'X-Case': 'appsec' });
    expect(appsec.status).toBe(403);
    const withoutTime = (body: string) => body.replace(/: \w{3}, [^<]*GMT/, '');
    expect(withoutTime(appsec.body)).toBe(withoutTime(banned.body));
    expect(appsec.body).toContain('BLOCKED_PAGE_HEADING');
  });

  it.each(hosts)('shows nothing of the address, the request or why on %s', async (host) => {
    const answer = await get(port, host, '/secret-path?token=abc123', {
      'X-Case': 'banned',
      'X-Forwarded-For': '203.0.113.9',
      Cookie: 'session=abc123',
    });
    const everything = answer.body + JSON.stringify(answer.headers);
    for (const leak of [
      'secret-path',
      'abc123',
      '203.0.113.9',
      '127.0.0.1',
      host,
      'bouncer',
      'cscli',
      'appsec',
      'crowdsec',
      'ban',
    ]) {
      expect(everything, leak).not.toContain(leak);
    }
  });

  it.each(hosts)('does not replace any other answer on %s', async (host) => {
    const ok = await get(port, host, '/', {});
    expect(ok.status).toBe(200);
    expect(ok.body).toBe('reached the upstream');
    // A throttle and a down upstream keep their own status and carry no page.
    const throttled = await get(port, host, '/', { 'X-Case': 'throttled' });
    expect(throttled.status).toBe(429);
    expect(throttled.body).toBe('');
    const down = await get(port, host, '/', { 'X-Case': 'down' });
    expect(down.status).toBe(502);
    expect(down.body).toBe('');
    // The renderer's own 403 (the Ghost setup refusal) is not a Caddy error and stays bare.
    const refusal = await get(port, host, '/setup-refusal', {});
    expect(refusal.status).toBe(403);
    expect(refusal.body).toBe('');
  });

  it('keeps nosniff on a Ghost site for the page and for the errors without one, and not elsewhere', async () => {
    const ghostPage = await get(port, GHOST_HOST, '/', { 'X-Case': 'banned' });
    const ghostDown = await get(port, GHOST_HOST, '/', { 'X-Case': 'down' });
    const plainPage = await get(port, PLAIN_HOST, '/', { 'X-Case': 'banned' });
    expect(ghostPage.headers['x-content-type-options']).toBe('nosniff');
    expect(ghostDown.headers['x-content-type-options']).toBe('nosniff');
    expect(plainPage.headers['x-content-type-options']).toBeUndefined();
  });
});
