import { readFileSync } from 'node:fs';
import path from 'node:path';

import prettier from 'prettier';
import { describe, expect, it } from 'vitest';

import { sites } from '../../sites';
import type { EdgeSite } from '../../siteTypes';
import { blackboxTargets } from '../monitoring/render';
import { STATUS_TEST_COMPONENT } from '../monitoring/statusIncidents';
import {
  GATUS_CONTAINER_PORT,
  PASS_CONDITION,
  PROBE_INTERVAL,
  PROBE_TIMEOUT,
  renderStatusConfig,
  renderTargetConfig,
  STATUS_TEST_TARGET_COMPONENT,
  TEST_TARGET_SERVICE,
} from './render';

/**
 * `stack/` is what the `status_page` role copies onto ops1, so the committed
 * files are the deployment. `npm run render` rewrites them; `npm test` fails
 * if they drift, and if Prettier would rewrite them.
 */

const site = (overrides: Partial<EdgeSite> = {}): EdgeSite => ({
  name: 'example',
  hostnames: ['example.test'],
  cloudRunService: 'example-service',
  ...overrides,
});

const ROLE_COMPOSE = path.resolve(
  __dirname,
  '../../ansible/roles/status_page/templates/compose.yml.j2'
);

/** The text of each probe, split on the line that opens it. */
const probeBlocks = (config: string): string[] =>
  config
    .split('\nendpoints:\n')[1]!
    .split(/^(?= {2}- name: )/m)
    .filter((block) => block.length > 0);

const field = (block: string, key: string): string | undefined =>
  block.match(new RegExp(`^ +(?:- )?${key}: (.*)$`, 'm'))?.[1];

describe('renderStatusConfig', () => {
  it('probes every hostname of the registry, in order, then TEST', () => {
    const entries = [
      site({ hostnames: ['a.test', 'b.test'] }),
      site({ name: 'other', hostnames: ['c.test'] }),
    ];
    const blocks = probeBlocks(renderStatusConfig(entries));
    expect(blocks.map((block) => field(block, 'url'))).toEqual([
      'https://a.test',
      'https://b.test',
      'https://c.test',
      STATUS_TEST_TARGET_COMPONENT.probeUrl,
    ]);
  });

  it('takes its hostnames from blackboxTargets, so no target is written by hand', () => {
    const targets = blackboxTargets(sites);
    const urls = probeBlocks(renderStatusConfig(sites)).map((block) => field(block, 'url'));
    expect(urls.slice(0, -1)).toEqual(targets);
    expect(targets.length).toBeGreaterThan(0);
  });

  it('names the TEST probe from the rule and points it at the compose target', () => {
    const last = probeBlocks(renderStatusConfig([site()])).at(-1)!;
    expect(field(last, 'name')).toBe(STATUS_TEST_COMPONENT.name);
    expect(field(last, 'group')).toBe('TEST');
    expect(field(last, 'url')).toBe(`http://${TEST_TARGET_SERVICE}:${GATUS_CONTAINER_PORT}/health`);
    expect(STATUS_TEST_TARGET_COMPONENT.probeUrl).not.toBe(STATUS_TEST_COMPONENT.probeUrl);
  });

  it('gives every probe the one interval, a timeout and the 2xx rule', () => {
    for (const block of probeBlocks(renderStatusConfig(sites))) {
      expect(field(block, 'interval')).toBe(PROBE_INTERVAL);
      expect(field(block, 'timeout')).toBe(PROBE_TIMEOUT);
      expect(block).toContain(`- '${PASS_CONDITION}'`);
    }
    expect(PROBE_INTERVAL).toBe('60s');
  });

  it('keeps each probe name unique within its group', () => {
    const keys = probeBlocks(renderStatusConfig(sites)).map(
      (block) => `${field(block, 'group')}/${field(block, 'name')}`
    );
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('keeps history in the sqlite volume', () => {
    const config = renderStatusConfig([site()]);
    expect(config).toContain('storage:\n  type: sqlite\n  path: /data/data.db\n');
  });

  it('sets no alerting block, no threshold and no ui block', () => {
    for (const config of [renderStatusConfig(sites), renderTargetConfig()]) {
      expect(config).not.toMatch(/^ *alerting:/m);
      expect(config).not.toMatch(/threshold/);
      expect(config).not.toMatch(/^ui:/m);
    }
  });
});

describe('renderTargetConfig', () => {
  it('is one probe of itself and keeps no history', () => {
    const config = renderTargetConfig();
    expect(probeBlocks(config)).toHaveLength(1);
    expect(config).not.toMatch(/^storage:/m);
    expect(config).toContain(`url: http://127.0.0.1:${GATUS_CONTAINER_PORT}/health`);
  });
});

describe('the compose file of the role', () => {
  const compose = readFileSync(ROLE_COMPOSE, 'utf8');

  it('names the TEST target service the page probes', () => {
    expect(compose).toContain(`${TEST_TARGET_SERVICE}:`);
  });

  it('publishes only the page, and only on the listen address variable', () => {
    const published = compose.match(/^ +- '\{\{ \w+ \}\}:\{\{ \w+ \}\}:\d+'$/gm) ?? [];
    expect(published).toHaveLength(1);
    expect(published[0]).toContain('status_page_listen_address');
    expect(published[0]).toContain(`:${GATUS_CONTAINER_PORT}`);
  });
});

describe('committed output', () => {
  const prettierOptions = async (file: string) => ({
    ...(await prettier.resolveConfig(path.join(__dirname, file))),
    parser: 'yaml' as const,
  });

  it('leaves the page config as Prettier would have it', async () => {
    const text = renderStatusConfig(sites);
    expect(await prettier.format(text, await prettierOptions('stack/config.yaml'))).toBe(text);
  });

  it('leaves the target config as Prettier would have it', async () => {
    const text = renderTargetConfig();
    expect(await prettier.format(text, await prettierOptions('stack/target.yaml'))).toBe(text);
  });

  it('keeps stack/config.yaml equal to the renderer output', async () => {
    await expect(renderStatusConfig(sites)).toMatchFileSnapshot('./stack/config.yaml');
  });

  it('keeps stack/target.yaml equal to the renderer output', async () => {
    await expect(renderTargetConfig()).toMatchFileSnapshot('./stack/target.yaml');
  });
});
