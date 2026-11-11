import * as pulumi from '@pulumi/pulumi';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

/**
 * `index.ts` under the mock runtime: the stack config it reads is the real
 * path from the committed probe stack file to the guards. A program that
 * stopped calling `buildStack`, or read the wrong config key, would pass every
 * unit test of the guards and refuse nothing.
 */

const PROJECT = '0123456789abcdef0123456789abcdef';
const NS = 'branchleft-ovh-copy2';

interface Registered {
  type: string;
  name: string;
}
const registered: Registered[] = [];

const probeBuckets = JSON.stringify([{ name: 'zz-probe-a', region: 'UK', versioning: 'ENABLED' }]);

function configure(values: Record<string, string>): void {
  pulumi.runtime.setAllConfig(
    Object.fromEntries(Object.entries(values).map(([key, value]) => [`${NS}:${key}`, value]))
  );
}

/**
 * Each scenario needs its own copy of the module, evaluated fresh against that
 * scenario's config, not the memoised export of a previous one.
 */
let scenario = 0;
const loadProgram = async (): Promise<typeof import('./index.js')> =>
  (await import(
    /* @vite-ignore */ `./index.js?scenario=${++scenario}`
  )) as typeof import('./index.js');

beforeAll(() => {
  pulumi.runtime.setMocks(
    {
      newResource(args: pulumi.runtime.MockResourceArgs) {
        registered.push({ type: args.type, name: args.name });
        return { id: `${args.name}-id`, state: { ...args.inputs } };
      },
      call() {
        return {};
      },
    },
    NS,
    'probe',
    false
  );
});

afterEach(() => {
  registered.length = 0;
  delete process.env.OVH_CLOUD_PROJECT_SERVICE;
});

describe('the program reading its stack config', () => {
  it('refuses the committed unset marker and registers nothing', async () => {
    process.env.OVH_CLOUD_PROJECT_SERVICE = PROJECT;
    configure({ allowedProjectId: 'UNSET', users: '[]', buckets: probeBuckets });
    await expect(loadProgram()).rejects.toThrow(/allowedProjectId is not set/);
    expect(registered).toEqual([]);
  });

  it('refuses a project in the environment that the stack config does not allow', async () => {
    process.env.OVH_CLOUD_PROJECT_SERVICE = 'fedcba9876543210fedcba9876543210';
    configure({ allowedProjectId: PROJECT, users: '[]', buckets: probeBuckets });
    await expect(loadProgram()).rejects.toThrow(/not the allowed project/);
    expect(registered).toEqual([]);
  });

  it('refuses a bucket configuration the guards refuse', async () => {
    process.env.OVH_CLOUD_PROJECT_SERVICE = PROJECT;
    configure({
      allowedProjectId: PROJECT,
      users: '[]',
      buckets: JSON.stringify([
        {
          name: 'zz-probe-a',
          region: 'UK',
          versioning: 'ENABLED',
          objectLock: { mode: 'COMPLIANCE', retentionDays: 14 },
        },
      ]),
    });
    await expect(loadProgram()).rejects.toThrow(/exceeds the probe limit/);
    expect(registered).toEqual([]);
  });

  it('registers the buckets when the project and the buckets are accepted', async () => {
    process.env.OVH_CLOUD_PROJECT_SERVICE = PROJECT;
    configure({ allowedProjectId: PROJECT, users: '[]', buckets: probeBuckets });
    const program = await loadProgram();
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(program.bucketNames).toBeDefined();
    expect(registered.map((resource) => resource.name)).toEqual(['bucket-zz-probe-a']);
  });
});
