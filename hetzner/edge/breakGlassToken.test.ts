import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { hostRedirects, sites, staticSites } from '../../sites';
import type { EdgeSite } from '../../siteTypes';
import {
  CONTAINER_LIMITS,
  IMAGE_LIMITS,
  docker,
  ensureImage,
  probeEngineSync,
  removeByName,
  startContainer,
  takeSlot,
  type Slot,
} from './dockerHarness';
import { POSTURE, type EdgePosture } from './posture';
import { renderCaddyfile } from './render';

// Why: see render.md section "logDirective: break-glass token redaction and strip".
// The parameter name is spelled out here on purpose, as an oracle that does not
// share a constant with the renderer.

const ENFORCING: EdgePosture = {
  crowdsec: 'enforcing',
  rateLimit: 'enforcing',
  membersMagicLinkRateLimit: 'enforcing',
};

const tenant: EdgeSite = {
  name: 'tenant-one',
  hostnames: ['tenant-one.test'],
  privateUpstream: { host: 'app1', port: 2368 },
  requestBodyMaxSize: '64MiB',
  injectionWafPreviewOnly: true,
};

/** The first top-level block of `rendered` whose address line is `address`, as its inner lines. */
function blockLines(rendered: string, address: string): string[] {
  const start = rendered.indexOf(`\n${address} {`);
  expect(start, `block ${address} must be rendered`).toBeGreaterThanOrEqual(0);
  const end = rendered.indexOf('\n}\n', start);
  return rendered
    .slice(start + 1, end)
    .split('\n')
    .slice(1);
}

/** The renderer's own `log { }` block, cut by indentation depth (the first `}` is the nested one). */
function renderedLogBlock(rendered: string): string[] {
  const lines = blockLines(rendered, 'tenant-one.test');
  const from = lines.indexOf('\tlog {');
  expect(from, 'the site block must carry a log block').toBeGreaterThanOrEqual(0);
  const to = lines.indexOf('\t}', from);
  return lines.slice(from, to + 1).map((l) => l.slice(1));
}

/** The strip lines as emitted, or nothing when the renderer has none (the state before the fix). */
function renderedStripLines(rendered: string): { matcher: string[]; rule: string[] } {
  const lines = blockLines(rendered, 'tenant-one.test');
  return {
    matcher: lines.filter((l) => l.startsWith('\t@break_glass_strip ')).map((l) => l.slice(1)),
    rule: lines.filter((l) => l.startsWith('\t\turi @break_glass_strip ')).map((l) => l.slice(2)),
  };
}

// The directive as it was before redaction existed: the key-set oracle.
const OLD_LOG = ['log {', '\toutput file /var/log/caddy/old.log', '\tformat json', '}'];

interface Row {
  id: string;
  /** The raw request target, exactly as sent. */
  path: string;
  headers?: Record<string, string>;
  /** Fragments of the fake tokens: none may survive in the log line. */
  secrets: string[];
  /** A Location header the stand-in upstream sets on this row's response. */
  location?: string;
  logUri?: string;
  logLocation?: string;
  logReferer?: string;
  /** What the upstream must see: untouched, or with the token removed. */
  upstream?:
    { kind: 'unchanged' } | { kind: 'stripped'; entries?: [string, string][]; noQuery?: boolean };
}

let counter = 0;
const fake = () => {
  counter += 1;
  return {
    token: `FAKE_CLAIMS_${counter}.FAKE_SIG_${counter}`,
    secrets: [`FAKE_CLAIMS_${counter}`, `FAKE_SIG_${counter}`],
  };
};

/** A row whose path and expectations are built from one fresh fake token. */
function row(
  id: string,
  make: (token: string) => Omit<Row, 'id' | 'secrets'> & { path: string }
): Row {
  const t = fake();
  return { id, secrets: t.secrets, ...make(t.token) };
}

const NAME = 'bl_break_glass';
const RED = `${NAME}=REDACTED`;
const ENC_UPPER = '%62%6C%5F%62%72%65%61%6B%5F%67%6C%61%73%73';
const ENC_LOWER = '%62%6c%5f%62%72%65%61%6b%5f%67%6c%61%73%73';

// The log is checked for every spelling the strip also removes, and a few more
// that Ghost does not read but that cost nothing to hide.
const LOG_ROWS: Row[] = [
  row('log-ghost-slash', (t) => ({
    path: `/ghost/?${NAME}=${t}`,
    logUri: `/ghost/?${RED}`,
    upstream: { kind: 'unchanged' },
  })),
  row('log-ghost-bare', (t) => ({
    path: `/ghost?${NAME}=${t}`,
    logUri: `/ghost?${RED}`,
    upstream: { kind: 'unchanged' },
  })),
  row('log-ghost-admin-api', (t) => ({
    path: `/ghost/api/admin/site/?${NAME}=${t}`,
    logUri: `/ghost/api/admin/site/?${RED}`,
  })),
  row('log-root', (t) => ({ path: `/?${NAME}=${t}`, logUri: `/?${RED}` })),
  row('log-others-kept-in-order', (t) => ({
    path: `/blog/?a=1&${NAME}=${t}&b=2`,
    logUri: `/blog/?a=1&${RED}&b=2`,
  })),
  {
    id: 'log-twice',
    ...(() => {
      const one = fake();
      const two = fake();
      return {
        path: `/ghost/?${NAME}=${one.token}&${NAME}=${two.token}`,
        secrets: [...one.secrets, ...two.secrets],
        logUri: `/ghost/?${RED}&${RED}`,
      };
    })(),
  },
  row('log-name-encoded-upper-hex', (t) => ({
    path: `/ghost/?bl%5Fbreak_glass=${t}`,
    logUri: '/ghost/?bl%5Fbreak_glass=REDACTED',
  })),
  row('log-name-encoded-lower-hex', (t) => ({
    path: `/ghost/?bl%5fbreak_glass=${t}`,
    logUri: '/ghost/?bl%5fbreak_glass=REDACTED',
  })),
  row('log-name-encoded-mixed-hex', (t) => ({
    path: `/ghost/?b%6c%5fbreak_glass=${t}`,
    logUri: '/ghost/?b%6c%5fbreak_glass=REDACTED',
  })),
  row('log-name-fully-encoded-upper', (t) => ({
    path: `/ghost/?${ENC_UPPER}=${t}`,
    logUri: `/ghost/?${ENC_UPPER}=REDACTED`,
  })),
  row('log-name-fully-encoded-lower', (t) => ({
    path: `/ghost/?${ENC_LOWER}=${t}`,
    logUri: `/ghost/?${ENC_LOWER}=REDACTED`,
  })),
  // Ghost's adapter reads exactly `bl_break_glass` (case-sensitive), so this is
  // not a token to it; it is hidden in the log all the same.
  row('log-name-capitals', (t) => ({
    path: `/ghost/?BL_BREAK_GLASS=${t}`,
    logUri: '/ghost/?BL_BREAK_GLASS=REDACTED',
  })),
  row('log-name-brackets', (t) => ({
    path: `/ghost/?${NAME}[]=${t}`,
    logUri: `/ghost/?${RED}`,
  })),
  { id: 'log-bare-name', path: `/ghost/?${NAME}`, secrets: [], logUri: `/ghost/?${RED}` },
  { id: 'log-empty-value', path: `/ghost/?${NAME}=`, secrets: [], logUri: `/ghost/?${RED}` },
  (() => {
    const t = fake();
    const head = `${t.token.split('.')[0]!}_`;
    const tail = `.${t.token.split('.')[1]!}`;
    const long =
      head + 'LONGTOKENPART'.repeat(400).slice(0, 4096 - head.length - tail.length) + tail;
    expect(long.length).toBe(4096);
    return {
      id: 'log-4096-char-token',
      path: `/ghost/?${NAME}=${long}`,
      secrets: [...t.secrets, 'LONGTOKENPART'],
      logUri: `/ghost/?${RED}`,
    };
  })(),
  row('log-location-relative', (t) => ({
    path: '/__location/log-location-relative',
    location: `/ghost/#/?${NAME}=${t}`,
    logLocation: `/ghost/#/?${RED}`,
  })),
  row('log-location-absolute', (t) => ({
    path: '/__location/log-location-absolute',
    location: `https://example.test/ghost/?${NAME}=${t}`,
    logLocation: `https://example.test/ghost/?${RED}`,
  })),
  row('log-referer', (t) => ({
    path: '/ghost/',
    headers: { Referer: `https://example.test/ghost/?${NAME}=${t}` },
    logReferer: `https://example.test/ghost/?${RED}`,
  })),
  row('log-referer-with-fragment-and-more', (t) => ({
    path: '/ghost/',
    headers: { Referer: `https://example.test/ghost/?a=1&${NAME}=${t}&b=2#/?${NAME}=${t}` },
    logReferer: `https://example.test/ghost/?a=1&${RED}&b=2#/?${RED}`,
  })),
];

// Off /ghost/ the token is removed before the upstream sees it. Each path is
// sent with other parameters around the token; the upstream must see the same
// path and the same decoded parameters, in any order (Caddy re-encodes a query
// it rewrites, and sorts it).
const OTHERS: [string, string][] = [
  ['a', '~'],
  ['b', '1 2'],
];
const stripRow = (id: string, path: string, name = NAME): Row =>
  row(id, (t) => ({
    path: `${path}?a=%7E&${name}=${t}&b=1+2`,
    upstream: { kind: 'stripped', entries: OTHERS },
  }));
const STRIP_PATHS: [string, string][] = [
  ['root', '/'],
  ['blog', '/blog/'],
  ['members-api', '/members/api/member/'],
  ['ghostly', '/ghostly/'],
  ['ghost-dash-x', '/ghost-x/'],
  ['ghost-capitals', '/GHOST/'],
  ['ghost-capitals-dot-dot', '/GHOST/../'],
  ['double-slash', '//'],
  ['ghost-dot-dot', '/ghost/../'],
  ['ghost-encoded-dot-dot', '/ghost/%2e%2E/'],
  ['encoded-g-slash', '/%67host/'],
  ['encoded-g-sub-path', '/%67host/x'],
  ['encoded-slash-in-ghost', '/ghost%2Fx'],
];
const STRIP_ROWS: Row[] = [
  ...STRIP_PATHS.map(([id, p]) => stripRow(`strip-${id}`, p)),
  stripRow('strip-name-encoded-upper-hex', '/blog/', 'bl%5Fbreak_glass'),
  stripRow('strip-name-encoded-lower-hex', '/blog/', 'bl%5fbreak_glass'),
  stripRow('strip-name-encoded-mixed-hex', '/blog/', 'b%6c%5fbreak_glass'),
  stripRow('strip-name-fully-encoded-upper', '/blog/', ENC_UPPER),
  stripRow('strip-name-fully-encoded-lower', '/blog/', ENC_LOWER),
  row('strip-name-first-param', (t) => ({
    path: `/blog/?${NAME}=${t}&a=%7E&b=1+2`,
    upstream: { kind: 'stripped', entries: OTHERS },
  })),
  // The text "/ghost/" in a value does not make the request a /ghost/ request.
  row('strip-ghost-lookalike-in-query', (t) => ({
    path: `/blog/?next=/ghost/&a=1&${NAME}=${t}`,
    upstream: {
      kind: 'stripped',
      entries: [
        ['next', '/ghost/'],
        ['a', '1'],
      ],
    },
  })),
  row('strip-token-only-root', (t) => ({
    path: `/?${NAME}=${t}`,
    upstream: { kind: 'stripped', entries: [], noQuery: true },
  })),
  row('strip-token-only-blog', (t) => ({
    path: `/blog/?${NAME}=${t}`,
    upstream: { kind: 'stripped', entries: [], noQuery: true },
  })),
  row('strip-bare-name', () => ({
    path: `/blog/?a=%7E&${NAME}&b=1+2`,
    upstream: { kind: 'stripped', entries: OTHERS },
  })),
  row('strip-empty-value', () => ({
    path: `/blog/?a=%7E&${NAME}=&b=1+2`,
    upstream: { kind: 'stripped', entries: OTHERS },
  })),
  row('strip-twice', (t) => ({
    path: `/blog/?${NAME}=${t}&a=%7E&${NAME}=${t}x&b=1+2`,
    upstream: { kind: 'stripped', entries: OTHERS },
  })),
  // Measured: Go's query parser drops a pair with an invalid escape, so the
  // rewrite loses `c=%ZZ` along with the token (render.md records this).
  row('strip-invalid-escape-elsewhere', (t) => ({
    path: `/blog/?c=%ZZ&${NAME}=${t}`,
    upstream: { kind: 'stripped', entries: [], noQuery: true },
  })),
];

// On /ghost/ the break-glass login depends on the token arriving as sent, and
// a query with no token is never rewritten: both must be byte for byte.
const CONTROL_ROWS: Row[] = [
  row('control-ghost-slash', (t) => ({
    path: `/ghost/?${NAME}=${t}`,
    upstream: { kind: 'unchanged' },
  })),
  row('control-ghost-bare', (t) => ({
    path: `/ghost?${NAME}=${t}`,
    upstream: { kind: 'unchanged' },
  })),
  row('control-ghost-admin-api', (t) => ({
    path: `/ghost/api/admin/site/?${NAME}=${t}`,
    upstream: { kind: 'unchanged' },
  })),
  row('control-ghost-sub-path-with-others', (t) => ({
    path: `/ghost/x?a=1&${NAME}=${t}&b=2`,
    upstream: { kind: 'unchanged' },
  })),
  row('control-ghost-encoded-name-lower-hex', (t) => ({
    path: `/ghost/?bl%5fbreak_glass=${t}`,
    upstream: { kind: 'unchanged' },
  })),
  row('control-ghost-encoded-name-upper-hex', (t) => ({
    path: `/ghost/?bl%5Fbreak_glass=${t}`,
    upstream: { kind: 'unchanged' },
  })),
  row('control-ghost-odd-query-no-token', () => ({
    path: '/ghost/?z=%7E&a=1+2',
    upstream: { kind: 'unchanged' },
  })),
  row('control-no-token-odd-encoding', () => ({
    path: '/blog/?z=%7E&a=1+2&q=%E2%82%AC&r=a%2Bb&dup=2&dup=1',
    upstream: { kind: 'unchanged' },
  })),
  row('control-no-token-empty-query', () => ({
    path: '/blog/?',
    upstream: { kind: 'unchanged' },
  })),
  row('control-capitals-name-off-ghost', (t) => ({
    path: `/blog/?a=1&BL_BREAK_GLASS=${t}`,
    upstream: { kind: 'unchanged' },
  })),
  // Not tokens to Ghost, so not stripped; the values are decoys, not fake tokens,
  // because the log filter does not claim to hide a name that is not at the start
  // of a parameter.
  row('control-longer-name-off-ghost', () => ({
    path: `/blog/?${NAME}_extra=DECOY&x${NAME}=DECOY`,
    upstream: { kind: 'unchanged' },
  })),
  row('control-name-inside-a-value-off-ghost', () => ({
    path: `/blog/?a=${NAME}=DECOY&b=?${NAME}=DECOY`,
    upstream: { kind: 'unchanged' },
  })),
];

const ROWS = [...LOG_ROWS, ...STRIP_ROWS, ...CONTROL_ROWS];

// A request with no token, sent to both log formats, for the shape comparison.
const SHAPE_PATH = '/blog/?z=%7E&a=1+2&q=%E2%82%AC';
const SHAPE_HEADERS = { Referer: 'https://example.test/blog/?x=1', 'X-Shape': 'yes' };

const CADDY_IMAGE =
  'caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648';
const LABEL = 'branchleft.agent=edge-break-glass-token-test';
const NEW_LOG = '/var/log/caddy/access.log';
const OLD_LOG_PATH = '/var/log/caddy/old.log';

const AUTHORING: EdgeSite = {
  name: 'authoring',
  hostnames: ['authoring.invalid'],
  privateUpstream: { host: 'app1', port: 2368 },
  requestBodyMaxSize: '64MiB',
  injectionWafPreviewOnly: true,
};

/** The three generated files' content (rendered fresh), plus one badly laid out file as a control. */
const FMT_FILES: Record<string, string> = {
  'stack.Caddyfile': renderCaddyfile(sites, hostRedirects, POSTURE, staticSites),
  'enforcing.Caddyfile': renderCaddyfile(sites, hostRedirects, ENFORCING, staticSites),
  'authoring.Caddyfile': renderCaddyfile([AUTHORING], [], ENFORCING),
  'unformatted.Caddyfile': 'example.test {\n        respond "x"\n}\n',
};

const engine = probeEngineSync();
const dockerUp = engine.up;
if (!dockerUp && process.env.CI) {
  throw new Error(`docker is required for the live-Caddy token check in CI: ${engine.reason}`);
}
if (!dockerUp) {
  console.warn(
    `SKIPPED: the live-Caddy token check did not run (${engine.reason}). CI runs this block.`
  );
}

const indent = (lines: string[], tabs: number) =>
  lines.map((l) => '\t'.repeat(tabs) + l).join('\n');

/** The Caddyfile under test: the renderer's own log and strip lines in front of an echoing upstream. */
function caddyfile(rendered: string): string {
  const log = renderedLogBlock(rendered);
  const strip = renderedStripLines(rendered);
  const locations = ROWS.filter((r) => r.location !== undefined).flatMap((r) => {
    const m = `loc_${r.id.replace(/[^a-z0-9]/gi, '_')}`;
    return [`@${m} path /__location/${r.id}`, `header @${m} Location "${r.location}"`];
  });
  return [
    '{',
    '\tadmin off',
    '\tauto_https off',
    '}',
    'http://new.test:8081 {',
    indent(log, 1),
    indent(strip.matcher, 1),
    '\troute {',
    indent(strip.rule, 2),
    '\t\treverse_proxy 127.0.0.1:9000',
    '\t}',
    '}',
    'http://old.test:8081 {',
    indent(OLD_LOG, 1),
    '\treverse_proxy 127.0.0.1:9000',
    '}',
    ':9000 {',
    indent(locations, 1),
    '\trespond "{http.request.uri}"',
    '}',
    '',
  ].join('\n');
}

interface Answer {
  status: number;
  body: string;
}

function get(port: number, rawPath: string, headers: Record<string, string>): Promise<Answer> {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: '127.0.0.1', port, path: rawPath, headers, timeout: 5_000 },
      (res) => {
        let body = '';
        res.on('data', (d: Buffer) => (body += d.toString()));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      }
    );
    req.on('timeout', () => req.destroy(new Error('no answer from the container within 5s')));
    req.on('error', reject);
    req.end();
  });
}

type Json = Record<string, unknown>;
const asJson = (v: unknown) => v as Json;

/** Every key path of a parsed log line, nested keys included. */
function keyPaths(value: unknown, prefix = ''): string[] {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return [];
  return Object.entries(value as Json).flatMap(([k, v]) => [
    `${prefix}${k}`,
    ...keyPaths(v, `${prefix}${k}.`),
  ]);
}

const splitUri = (uri: string) => {
  const i = uri.indexOf('?');
  return i < 0
    ? { path: uri, query: undefined }
    : { path: uri.slice(0, i), query: uri.slice(i + 1) };
};
const sortPairs = (pairs: [string, string][]) =>
  [...pairs].sort((x, y) => (x[0] === y[0] ? x[1].localeCompare(y[1]) : x[0].localeCompare(y[0])));

const caddyTitle = `the break-glass token under a real Caddy${dockerUp ? '' : ` (SKIPPED: ${engine.reason})`}`;

describe.skipIf(!dockerUp)(caddyTitle, { timeout: 180_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'break-glass-token-'));
  const name = `bl-break-glass-token-${process.pid}`;
  let slot: Slot | undefined;
  const answers = new Map<string, Answer>();
  const lines = new Map<string, { raw: string; json: Json }>();
  let shape: { oldLine: { raw: string; json: Json }; newLine: { raw: string; json: Json } };
  let rawNewLog = '';

  const rendered = renderCaddyfile([tenant], [], ENFORCING);
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

  const readLog = async (path: string) => {
    const r = await docker(['exec', name, 'cat', path], 10_000);
    expect(r.status, `reading ${path}: ${r.stderr}`).toBe(0);
    return r.stdout;
  };

  afterAll(async () => {
    try {
      await removeByName(name);
    } finally {
      slot?.release();
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  beforeAll(async () => {
    slot = await takeSlot({ waitMs: SLOT_WAIT_MS, label: 'edge-break-glass-token-test' });
    await ensureImage(CADDY_IMAGE);
    writeFileSync(join(dir, 'Caddyfile'), caddyfile(rendered));
    for (const [file, text] of Object.entries(FMT_FILES)) {
      writeFileSync(join(dir, file), text);
    }
    const port = await startContainer({
      name,
      label: LABEL,
      image: CADDY_IMAGE,
      containerPort: 8081,
      mountSource: dir,
      mountTarget: '/etc/caddy',
    });
    for (let i = 0; ; i += 1) {
      try {
        await get(port, '/', { host: 'new.test' });
        break;
      } catch (e) {
        if (i >= 50) throw new Error(`caddy did not start: ${String(e)}`);
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    for (const r of ROWS) {
      const path = r.location === undefined ? r.path : `/__location/${r.id}`;
      answers.set(r.id, await get(port, path, { ...r.headers, host: 'new.test', 'X-Row': r.id }));
    }
    await get(port, SHAPE_PATH, { ...SHAPE_HEADERS, host: 'old.test', 'X-Row': 'shape-old' });
    await get(port, SHAPE_PATH, { ...SHAPE_HEADERS, host: 'new.test', 'X-Row': 'shape-new' });

    rawNewLog = await readLog(NEW_LOG);
    const all = [...rawNewLog.split('\n'), ...(await readLog(OLD_LOG_PATH)).split('\n')];
    for (const raw of all.filter((l) => l.trim() !== '')) {
      const json = asJson(JSON.parse(raw));
      const id = (asJson(asJson(json.request).headers)['X-Row'] as string[] | undefined)?.[0];
      if (id !== undefined) lines.set(id, { raw, json });
    }
    shape = { oldLine: lines.get('shape-old')!, newLine: lines.get('shape-new')! };
  }, setupBudgetMs);

  const line = (id: string) => {
    const l = lines.get(id);
    expect(l, `row ${id} must have been logged`).toBeDefined();
    return l!;
  };

  describe('the access log', () => {
    it.each(LOG_ROWS.filter((r) => r.secrets.length > 0))(
      'holds no part of the token: $id',
      (r) => {
        const { raw } = line(r.id);
        for (const secret of r.secrets) {
          expect(raw, `${r.id} leaked ${secret}`).not.toContain(secret);
        }
      }
    );

    it.each(LOG_ROWS.filter((r) => r.logUri !== undefined))(
      'replaces the parameter in request.uri: $id',
      (r) => {
        expect(asJson(line(r.id).json.request).uri).toBe(r.logUri);
      }
    );

    it.each(LOG_ROWS.filter((r) => r.logLocation !== undefined))(
      'replaces the parameter in resp_headers.Location: $id',
      (r) => {
        expect(asJson(line(r.id).json.resp_headers).Location).toEqual([r.logLocation]);
      }
    );

    it.each(LOG_ROWS.filter((r) => r.logReferer !== undefined))(
      'replaces the parameter in request.headers.Referer: $id',
      (r) => {
        expect(asJson(asJson(line(r.id).json.request).headers).Referer).toEqual([r.logReferer]);
      }
    );

    it('holds no fake token anywhere in the whole file', () => {
      expect(rawNewLog).not.toMatch(/FAKE_(CLAIMS|SIG)_/);
    });

    it('leaves a token-free uri, Referer and the rest of the line exactly as the old format wrote them', () => {
      const oldReq = asJson(shape.oldLine.json.request);
      const newReq = asJson(shape.newLine.json.request);
      expect(newReq.uri).toBe(SHAPE_PATH);
      expect(newReq.uri).toBe(oldReq.uri);
      expect(asJson(newReq.headers).Referer).toEqual(asJson(oldReq.headers).Referer);
      expect(asJson(newReq.headers)['X-Shape']).toEqual(['yes']);
    });

    it('has the same JSON key set as the old format, nested keys included', () => {
      const oldKeys = keyPaths(shape.oldLine.json).sort();
      const newKeys = keyPaths(shape.newLine.json).sort();
      expect(oldKeys.length).toBeGreaterThan(10);
      expect(newKeys).toEqual(oldKeys);
    });

    it('keeps the fields the CrowdSec parser and the rate-limit derivation read, with their types', () => {
      const j = shape.newLine.json;
      const o = shape.oldLine.json;
      expect(typeof j.ts).toBe('number');
      expect(typeof asJson(j.request).remote_ip).toBe('string');
      expect(typeof asJson(j.request).uri).toBe('string');
      expect(typeof j.status).toBe('number');
      for (const k of ['ts', 'status'] as const) expect(typeof j[k]).toBe(typeof o[k]);
      for (const k of ['remote_ip', 'uri', 'method', 'host'] as const) {
        expect(typeof asJson(j.request)[k]).toBe(typeof asJson(o.request)[k]);
      }
    });

    it('is still one JSON object per line', () => {
      const physical = rawNewLog.split('\n').filter((l) => l.trim() !== '');
      expect(physical.length).toBeGreaterThan(ROWS.length);
      for (const l of physical) expect(() => JSON.parse(l) as unknown).not.toThrow();
    });
  });

  describe('the rendered files in the layout caddy fmt writes', () => {
    // `caddy fmt` only parses, so the plain image can check files that need the
    // custom build to run. CI also loads every file through the custom build.
    // `--diff` prints the whole file as context; a line the formatter would
    // change starts with "+" or "-".
    const changedLines = async (file: string) => {
      const r = await docker(
        ['exec', name, 'caddy', 'fmt', '--diff', `/etc/caddy/${file}`],
        20_000
      );
      const output = `${r.stdout}${r.stderr}`;
      return { output, changed: output.split('\n').filter((l) => /^[+-]/.test(l)) };
    };

    it('reports a change for a file that is not formatted, so a clean result means something', async () => {
      const r = await changedLines('unformatted.Caddyfile');
      expect(r.changed, r.output).not.toEqual([]);
    });

    it.each(Object.keys(FMT_FILES).filter((f) => f !== 'unformatted.Caddyfile'))(
      '%s needs no reformatting',
      async (file) => {
        const r = await changedLines(file);
        expect(r.output, 'caddy fmt must have printed the file').toContain('wrap json');
        expect(r.changed).toEqual([]);
      }
    );
  });

  describe('what the upstream receives', () => {
    const upstreamRows = ROWS.filter((r) => r.upstream !== undefined);
    expect(upstreamRows.length).toBeGreaterThan(30);

    it.each(upstreamRows)('$id', (r) => {
      const answer = answers.get(r.id)!;
      expect(answer.status).toBe(200);
      const seen = splitUri(answer.body);
      const sent = splitUri(r.path);
      const up = r.upstream!;
      if (up.kind === 'unchanged') {
        expect(answer.body, `${r.id} must reach the upstream byte for byte`).toBe(r.path);
        return;
      }
      for (const secret of r.secrets) {
        expect(answer.body, `${r.id} forwarded ${secret}`).not.toContain(secret);
      }
      expect(seen.path, 'the path must be forwarded as sent').toBe(sent.path);
      const pairs = [...new URLSearchParams(seen.query ?? '')] as [string, string][];
      expect(pairs.map(([k]) => k)).not.toContain(NAME);
      if (up.noQuery) expect(seen.query, 'a token-only query leaves no "?" at all').toBeUndefined();
      if (up.entries !== undefined) expect(sortPairs(pairs)).toEqual(sortPairs(up.entries));
    });
  });
});
