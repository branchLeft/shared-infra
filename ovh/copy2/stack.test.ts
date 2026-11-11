import * as pulumi from '@pulumi/pulumi';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { Settings } from './configGuard';
import { buildStack } from './stack';

/** `Settings` with its arrays writable, so a scenario can edit the fixture it starts from. */
type Draft = {
  -readonly [K in keyof Settings]: Settings[K] extends readonly (infer Item)[]
    ? Item[]
    : Settings[K];
};

/**
 * `buildStack` under Pulumi's mock runtime. The guard tests prove each rule's
 * decision; this file proves the decision reaches the engine: a refused
 * configuration must register no resource at all, and an accepted one must
 * carry the project id and the protection the guards promised on every
 * resource that was registered.
 */

const PROJECT = '0123456789abcdef0123456789abcdef';
const OTHER_PROJECT = 'fedcba9876543210fedcba9876543210';

interface Registered {
  type: string;
  name: string;
  inputs: Record<string, unknown>;
}

const registered: Registered[] = [];

interface RegisterRequest {
  getName(): string;
  getProtect(): boolean | undefined;
  getRetainondelete(): boolean | undefined;
}

/** The options each resource was registered with, read off the register request. */
const options = new Map<string, { protect?: boolean; retainOnDelete?: boolean }>();

function urnOf(resource: pulumi.Resource): Promise<string> {
  return (resource.urn as unknown as { promise(): Promise<string> }).promise();
}

const settings = (overrides: Partial<Draft> = {}): Draft => ({
  allowedProjectId: PROJECT,
  users: [
    { name: 'zz-probe-owner', s3Credential: false },
    {
      name: 'zz-probe-rw',
      s3Credential: true,
      statements: [
        {
          sid: 'ProbeA',
          effect: 'Allow',
          actions: ['s3:GetObject', 's3:PutObject', 's3:ListBucket'],
          buckets: ['zz-probe-a'],
        },
      ],
    },
  ],
  buckets: [
    {
      name: 'zz-probe-a',
      region: 'UK',
      versioning: 'ENABLED',
      ownerUser: 'zz-probe-owner',
      objectLock: { mode: 'GOVERNANCE', retentionDays: 1 },
    },
    { name: 'zz-probe-b', region: 'UK', versioning: 'ENABLED' },
    {
      name: 'zz-probe-c',
      region: 'UK',
      versioning: 'ENABLED',
      objectLock: { mode: 'COMPLIANCE', retentionDays: 1 },
    },
  ],
  ...overrides,
});

const env = { OVH_CLOUD_PROJECT_SERVICE: PROJECT };

beforeAll(async () => {
  await pulumi.runtime.setMocks(
    {
      newResource(args: pulumi.runtime.MockResourceArgs) {
        registered.push({ type: args.type, name: args.name, inputs: args.inputs });
        const state: Record<string, unknown> = { ...args.inputs };
        if (args.type === 'ovh:CloudProject/s3Credential:S3Credential') {
          state.accessKeyId = 'ACCESSKEYID';
          state.secretAccessKey = 'SECRETACCESSKEY';
        }
        return { id: `${args.name}-id`, state };
      },
      call() {
        return {};
      },
    },
    'branchleft-ovh-copy2',
    'probe',
    false
  );

  // The mock runtime hands `newResource` the inputs and nothing of the options,
  // so the register request is read where it enters the monitor.
  const monitor = pulumi.runtime.getMonitor() as unknown as {
    registerResource(request: RegisterRequest, callback: unknown): Promise<void>;
  };
  const original = monitor.registerResource.bind(monitor);
  monitor.registerResource = (request, callback) => {
    options.set(request.getName(), {
      protect: request.getProtect(),
      retainOnDelete: request.getRetainondelete(),
    });
    return original(request, callback);
  };
});

beforeEach(() => {
  registered.length = 0;
  options.clear();
});

describe('buildStack, a refused configuration', () => {
  it('registers nothing when the addressed project is not the allowed one', () => {
    expect(() => buildStack(settings(), { OVH_CLOUD_PROJECT_SERVICE: OTHER_PROJECT })).toThrow(
      /not the allowed project/
    );
    expect(registered).toEqual([]);
  });

  it('registers nothing when the allowed project is still the unset marker', () => {
    expect(() => buildStack(settings({ allowedProjectId: 'UNSET' }), env)).toThrow(
      /allowedProjectId is not set/
    );
    expect(registered).toEqual([]);
  });

  it('registers nothing when a probe bucket asks for more than one day', () => {
    const bad = settings();
    bad.buckets[2] = {
      name: 'zz-probe-c',
      region: 'UK',
      versioning: 'ENABLED',
      objectLock: { mode: 'COMPLIANCE', retentionDays: 14 },
    };
    expect(() => buildStack(bad, env)).toThrow(/exceeds the probe limit/);
    expect(registered).toEqual([]);
  });

  it('registers nothing when a non-probe bucket asks for Compliance', () => {
    const bad = settings();
    bad.buckets.push({
      name: 'backup-copy-two',
      region: 'UK',
      versioning: 'ENABLED',
      protect: true,
      objectLock: { mode: 'COMPLIANCE', retentionDays: 14 },
    });
    expect(() => buildStack(bad, env)).toThrow(/COMPLIANCE is allowed only/);
    expect(registered).toEqual([]);
  });

  it('registers nothing when a non-probe bucket is not protected', () => {
    const bad = settings();
    bad.buckets.push({ name: 'backup-copy-two', region: 'UK', versioning: 'ENABLED' });
    expect(() => buildStack(bad, env)).toThrow(/protect: true/);
    expect(registered).toEqual([]);
  });

  it('registers nothing when a bucket or policy names a user or bucket that is not configured', () => {
    const noOwner = settings();
    noOwner.buckets[0] = { ...noOwner.buckets[0]!, ownerUser: 'nobody' };
    expect(() => buildStack(noOwner, env)).toThrow(/owner user nobody is not configured/);

    const noBucket = settings();
    noBucket.users[1] = {
      ...noBucket.users[1]!,
      statements: [{ sid: 'X', effect: 'Allow', actions: ['s3:GetObject'], buckets: ['missing'] }],
    };
    expect(() => buildStack(noBucket, env)).toThrow(/bucket missing is not configured/);
    expect(registered).toEqual([]);
  });
});

describe('buildStack, an accepted configuration', () => {
  it('addresses the allowed project explicitly on every resource', async () => {
    const stack = buildStack(settings(), env);
    await Promise.all(stack.resources.map(urnOf));

    expect(registered.length).toBe(stack.resources.length);
    expect(registered.map((resource) => resource.type).sort()).toEqual(
      [
        'ovh:CloudProject/s3Credential:S3Credential',
        'ovh:CloudProject/s3Policy:S3Policy',
        'ovh:CloudProject/user:User',
        'ovh:CloudProject/user:User',
        'ovh:index/cloudStorageObjectBucket:CloudStorageObjectBucket',
        'ovh:index/cloudStorageObjectBucket:CloudStorageObjectBucket',
        'ovh:index/cloudStorageObjectBucket:CloudStorageObjectBucket',
      ].sort()
    );
    for (const resource of registered) {
      expect(resource.inputs.serviceName).toBe(PROJECT);
    }
  });

  it('passes the lock, the versioning and the region through to the bucket', async () => {
    const stack = buildStack(settings(), env);
    await Promise.all(stack.resources.map(urnOf));

    const bucket = (name: string) =>
      registered.find((resource) => resource.inputs.name === name)?.inputs;
    expect(bucket('zz-probe-a')).toMatchObject({
      region: 'UK',
      versioning: { status: 'ENABLED' },
      objectLock: { mode: 'GOVERNANCE', retentionDays: 1 },
    });
    expect(bucket('zz-probe-b')?.objectLock).toBeUndefined();
    expect(bucket('zz-probe-c')).toMatchObject({
      objectLock: { mode: 'COMPLIANCE', retentionDays: 1 },
    });
  });

  it('creates S3 credentials only for users that ask for one, and a policy only where given', async () => {
    const stack = buildStack(settings(), env);
    await Promise.all(stack.resources.map(urnOf));

    expect(registered.filter((r) => r.type.endsWith('S3Credential'))).toHaveLength(1);
    const policy = registered.find((r) => r.type.endsWith('S3Policy'));
    const document = JSON.parse(String(policy?.inputs.policy)) as {
      Statement: { Sid: string; Effect: string; Action: string[]; Resource: string[] }[];
    };
    expect(document.Statement).toEqual([
      {
        Sid: 'ProbeA',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:PutObject', 's3:ListBucket'],
        Resource: ['arn:aws:s3:::zz-probe-a', 'arn:aws:s3:::zz-probe-a/*'],
      },
    ]);
  });

  it('sets protect and retainOnDelete on a non-probe bucket and neither on a probe bucket', async () => {
    const config = settings();
    config.buckets.push({
      name: 'backup-copy-two',
      region: 'UK',
      versioning: 'ENABLED',
      protect: true,
      objectLock: { mode: 'GOVERNANCE', retentionDays: 14 },
    });
    const stack = buildStack(config, env);
    await Promise.all(stack.resources.map(urnOf));

    expect(options.get('bucket-backup-copy-two')).toEqual({ protect: true, retainOnDelete: true });
    expect(options.get('bucket-zz-probe-a')).toEqual({ protect: false, retainOnDelete: false });
  });

  it('appends the run suffix to every bucket name and the policy follows it', async () => {
    const stack = buildStack(settings({ nameSuffix: 'run42' }), env);
    await Promise.all(stack.resources.map(urnOf));

    expect(Object.keys(stack.buckets).sort()).toEqual([
      'zz-probe-a-run42',
      'zz-probe-b-run42',
      'zz-probe-c-run42',
    ]);
    const policy = registered.find((r) => r.type.endsWith('S3Policy'));
    expect(String(policy?.inputs.policy)).toContain('arn:aws:s3:::zz-probe-a-run42/*');
  });

  it('applies the guards to the suffixed names, not the configured ones', () => {
    const long = `zz-probe-${'a'.repeat(40)}`;
    expect(() =>
      buildStack(
        settings({
          nameSuffix: 'b'.repeat(20),
          users: [],
          buckets: [{ name: long, region: 'UK', versioning: 'ENABLED' }],
        }),
        env
      )
    ).toThrow(/bucket name must be 3 to 63/);
    expect(registered).toEqual([]);
  });

  it('refuses a suffix that is not a short lower-case token', () => {
    expect(() => buildStack(settings({ nameSuffix: 'Run_42' }), env)).toThrow(/nameSuffix/);
    expect(registered).toEqual([]);
  });

  it('exports no secret in the clear', async () => {
    const stack = buildStack(settings(), env);
    await Promise.all(stack.resources.map(urnOf));
    expect(await isSecret(stack.secretAccessKeys)).toBe(true);
    expect(await isSecret(stack.accessKeyIds)).toBe(false);
  });
});

function isSecret(output: pulumi.Output<unknown>): Promise<boolean> {
  return (output as unknown as { isSecret: Promise<boolean> }).isSecret;
}
