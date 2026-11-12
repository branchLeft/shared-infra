import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import * as pulumi from '@pulumi/pulumi';
import { load } from 'js-yaml';
import { beforeAll, describe, expect, it } from 'vitest';

import { PROBE_PREFIX, type Settings } from './configGuard';
import { buildStack } from './stack';

/**
 * The committed probe stack file, read as the engine would read it. It carries
 * the owner's project id. The first tests pin that the committed file names a
 * well-formed id, that the program refuses the UNSET marker and any other value
 * the environment may carry, accepts a well-formed id only when the config and
 * the environment agree, and refuses a mismatch, a missing variable and a
 * malformed id.
 */

const NS = 'branchleft-ovh-copy2';
const FILE = join(__dirname, 'Pulumi.probe.yaml');
// The probe project's id, reported by the owner; not a secret.
const COMMITTED = '5dd5eda4165c48fa80428816500bc992';
// Fixtures shaped like project ids, not any real project.
const PROJECT = '0123456789abcdef0123456789abcdef';
const OTHER_PROJECT = 'fedcba9876543210fedcba9876543210';
const UNSET = 'UNSET';

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
  it('commits the owner-reported project id as allowedProjectId', () => {
    expect(own('allowedProjectId')).toBe(COMMITTED);
    expect(COMMITTED).toMatch(/^[0-9a-f]{32}$/);
  });

  it('is accepted as committed only when the environment names the same project', () => {
    const committed = settings(own('allowedProjectId') as string);
    const stack = buildStack(committed, { OVH_CLOUD_PROJECT_SERVICE: COMMITTED });
    expect(Object.keys(stack.buckets)).toEqual(['zz-probe-a', 'zz-probe-b', 'zz-probe-c']);
    expect(() => buildStack(committed, { OVH_CLOUD_PROJECT_SERVICE: PROJECT })).toThrow(
      /not the allowed project/
    );
    expect(() => buildStack(committed, {})).toThrow(/is not set/);
  });

  it('refuses the UNSET marker, whatever the environment names', () => {
    const unset = settings(UNSET);
    expect(() => buildStack(unset, { OVH_CLOUD_PROJECT_SERVICE: PROJECT })).toThrow(
      /allowedProjectId is not set/
    );
    expect(() => buildStack(unset, { OVH_CLOUD_PROJECT_SERVICE: UNSET })).toThrow(
      /allowedProjectId is not set/
    );
    expect(() => buildStack(unset, {})).toThrow(/allowedProjectId is not set/);
  });

  it('is accepted only when the config and the environment name the same well-formed project', () => {
    expect(PROJECT).toMatch(/^[0-9a-f]{32}$/);
    const stack = buildStack(settings(PROJECT), { OVH_CLOUD_PROJECT_SERVICE: PROJECT });
    expect(Object.keys(stack.buckets)).toEqual(['zz-probe-a', 'zz-probe-b', 'zz-probe-c']);
  });

  it('refuses a mismatch, a missing variable and a malformed id', () => {
    expect(() =>
      buildStack(settings(PROJECT), { OVH_CLOUD_PROJECT_SERVICE: OTHER_PROJECT })
    ).toThrow(/not the allowed project/);
    expect(() => buildStack(settings(PROJECT), {})).toThrow(/is not set/);
    expect(() =>
      buildStack(settings(PROJECT.slice(1)), { OVH_CLOUD_PROJECT_SERVICE: PROJECT.slice(1) })
    ).toThrow(/32-character lower-case hex/);
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

  it('gives the lock-attempt credential reach over buckets B and C only, and no object access', () => {
    const admin = settings(PROJECT).users.find((user) => user.name === 'zz-probe-admin');
    expect(admin?.s3Credential).toBe(true);
    const statements = admin?.statements ?? [];
    expect(new Set(statements.flatMap((statement) => statement.buckets))).toEqual(
      new Set(['zz-probe-b', 'zz-probe-c'])
    );
    expect(statements.every((statement) => statement.effect === 'Allow')).toBe(true);
    const actions = statements.flatMap((statement) => statement.actions);
    expect(actions.filter((action) => /Object(?!LockConfiguration)|Bypass/.test(action))).toEqual(
      []
    );
    const forC = statements.filter((statement) => statement.buckets.includes('zz-probe-c'));
    expect(forC.flatMap((statement) => statement.actions)).not.toContain(
      's3:PutBucketObjectLockConfiguration'
    );
  });

  it('carries no salt, no ciphertext and no run-specific suffix', () => {
    expect(Object.keys(file)).toEqual(['config']);
    expect(JSON.stringify(file.config)).not.toContain('secure');
    expect(own('nameSuffix')).toBeUndefined();
  });
});
