import * as pulumi from '@pulumi/pulumi';
import { beforeAll, describe, expect, it } from 'vitest';
import { createMediaBuckets, mediaProvider } from './mediaBucketResources';
import { makeMediaKeys } from './mediaBuckets';

/**
 * Pulumi mocks, as in hetznerHost.test.ts. Each resource's inputs are recorded,
 * so the assertions read what the program would send to the provider.
 */
type Created = { type: string; name: string; inputs: Record<string, any> };

const created: Created[] = [];

beforeAll(() => {
  pulumi.runtime.setMocks(
    {
      newResource(args: pulumi.runtime.MockResourceArgs) {
        created.push({ type: args.type, name: args.name, inputs: args.inputs });
        return { id: `${args.name}-id`, state: { ...args.inputs } };
      },
      call() {
        return {};
      },
    },
    'media-test',
    'test',
    false
  );
  // Resources are built after the mocks are installed, never at module load.
  const provider = mediaProvider('hetzner-object-storage', {
    accessKey: 'ADMINACCESSKEYTEST0001',
    secretKey: 'test-secret',
  });
  createMediaBuckets(provider, keys);
});

const keys = makeMediaKeys({
  gateway: '111111:GATEWAYKEY0000001',
  reader: '222222:READERKEY00000002',
  erasure: '333333:ERASUREKEY0000003',
  admin: '444444:ADMINKEY000000004',
});

// Registration is asynchronous and a resource that depends on another waits for
// its id, so poll until the expected count of a type has been registered.
async function ofType(type: string, count: number) {
  for (let i = 0; i < 200 && created.filter((r) => r.type === type).length < count; i++) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return created.filter((r) => r.type === type);
}

describe('media buckets, as the provider is asked to create them', () => {
  it('configures the provider for nbg1 Object Storage, path-style, with no AWS lookups', async () => {
    const [p] = await ofType('pulumi:providers:aws', 1);
    // The mock returns scalar inputs as strings; compare their text.
    expect(String(p.inputs.region)).toBe('nbg1');
    // The mock hands the list of objects back as its JSON encoding.
    const endpoints =
      typeof p.inputs.endpoints === 'string' ? JSON.parse(p.inputs.endpoints) : p.inputs.endpoints;
    expect(endpoints).toEqual([{ s3: 'https://nbg1.your-objectstorage.com' }]);
    expect(String(p.inputs.s3UsePathStyle)).toBe('true');
    expect(String(p.inputs.skipCredentialsValidation)).toBe('true');
    expect(String(p.inputs.skipRequestingAccountId)).toBe('true');
    expect(String(p.inputs.skipRegionValidation)).toBe('true');
    expect(String(p.inputs.skipMetadataApiCheck)).toBe('true');
  });

  it('creates exactly the three named buckets, none force-destroyed', async () => {
    const buckets = await ofType('aws:s3/bucket:Bucket', 3);
    expect(buckets.map((b) => b.inputs.bucket)).toEqual([
      'branchleft-shared-media-1',
      'branchleft-shared-media-2',
      'branchleft-shared-media-3',
    ]);
    for (const b of buckets) expect(b.inputs.forceDestroy).toBe(false);
  });

  it('turns versioning on for every bucket', async () => {
    const versioning = await ofType('aws:s3/bucketVersioning:BucketVersioning', 3);
    expect(versioning).toHaveLength(3);
    for (const v of versioning) {
      expect(v.inputs.versioningConfiguration).toEqual({ status: 'Enabled' });
    }
  });

  it('sets the 30-day noncurrent and 7-day multipart lifecycle on every bucket', async () => {
    const lifecycle = await ofType(
      'aws:s3/bucketLifecycleConfiguration:BucketLifecycleConfiguration',
      3
    );
    expect(lifecycle).toHaveLength(3);
    for (const l of lifecycle) {
      expect(l.inputs.rules).toEqual([
        {
          id: 'shared-media-retention',
          status: 'Enabled',
          filter: { prefix: '' },
          noncurrentVersionExpiration: { noncurrentDays: 30 },
          abortIncompleteMultipartUpload: { daysAfterInitiation: 7 },
        },
      ]);
    }
  });

  it('attaches the access policy to every bucket, carrying the gateway Allow and no delete for it', async () => {
    const policies = await ofType('aws:s3/bucketPolicy:BucketPolicy', 3);
    expect(policies).toHaveLength(3);
    for (const p of policies) {
      const doc = JSON.parse(p.inputs.policy);
      const gateway = doc.Statement.find((s: any) => s.Sid === 'GatewayPutAndReadObjects');
      expect(gateway.Principal.AWS).toEqual([keys.gateway]);
      expect(gateway.Action).not.toContain('s3:DeleteObject');
      expect(gateway.Action).not.toContain('s3:DeleteObjectVersion');
    }
  });
});
