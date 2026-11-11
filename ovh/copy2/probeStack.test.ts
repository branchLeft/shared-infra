import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import * as pulumi from '@pulumi/pulumi';
import { load } from 'js-yaml';
import { beforeAll, describe, expect, it } from 'vitest';

import { PROBE_PREFIX, type Settings } from './configGuard';
import { buildStack } from './stack';

/**
 * The committed probe stack file, read as the engine would read it. It ships
 * with the project id unset, so the first test is the one that matters most
 * today: nothing can be created from this file until the owner's id replaces
 * the marker. The rest prove the file is already correct, so that supplying the
 * id is the only edit left.
 */

const NS = 'branchleft-ovh-copy2';
const FILE = join(__dirname, 'Pulumi.probe.yaml');
const PROJECT = '0123456789abcdef0123456789abcdef';

type StackFile = { config: Record<string, unknown> };

const file = load(readFileSync(FILE, 'utf8')) as StackFile;
const own = (key: string): unknown => file.config[`${NS}:${key}`];

const settings = (allowedProjectId: string): Settings => ({
  allowedProjectId,
  users: own('users') as Settings['users'],
  buckets: own('buckets') as Settings['buckets'],
});

beforeAll(async () => {
  await pulumi.runtime.setMocks(
    {
      newResource: (args) => ({ id: `${args.name}-id`, state: { ...args.inputs } }),
      call: () => ({}),
    },
    NS,
    'probe',
    false
  );
});

describe('Pulumi.probe.yaml', () => {
  it('ships the project id unset, and the program refuses it', () => {
    expect(own('allowedProjectId')).toBe('UNSET');
    expect(() =>
      buildStack(settings(String(own('allowedProjectId'))), {
        OVH_CLOUD_PROJECT_SERVICE: PROJECT,
      })
    ).toThrow(/allowedProjectId is not set/);
  });

  it('is accepted by every guard once the owner supplies a project id', () => {
    const stack = buildStack(settings(PROJECT), { OVH_CLOUD_PROJECT_SERVICE: PROJECT });
    expect(Object.keys(stack.buckets)).toEqual(['zz-probe-a', 'zz-probe-b', 'zz-probe-c']);
  });

  it('names only probe buckets, each locked for one day at most', () => {
    const buckets = settings(PROJECT).buckets;
    expect(buckets.every((bucket) => bucket.name.startsWith(PROBE_PREFIX))).toBe(true);
    expect(buckets.every((bucket) => (bucket.objectLock?.retentionDays ?? 1) <= 1)).toBe(true);
  });

  it('gives the probe credential a policy over bucket A and over no other bucket', () => {
    const users = settings(PROJECT).users;
    const rw = users.find((user) => user.name === 'zz-probe-rw');
    expect(rw?.statements?.flatMap((statement) => statement.buckets)).toEqual(['zz-probe-a']);
    expect(users.find((user) => user.name === 'zz-probe-owner')?.s3Credential).toBe(false);
  });

  it('carries no salt, no ciphertext and no run-specific suffix', () => {
    expect(Object.keys(file)).toEqual(['config']);
    expect(JSON.stringify(file.config)).not.toContain('secure');
    expect(own('nameSuffix')).toBeUndefined();
  });
});
