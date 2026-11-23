import { describe, expect, it } from 'vitest';
import {
  CONFIGURATION_ACTIONS,
  DELETE_ACTIONS,
  GATEWAY_OBJECT_ACTIONS,
  LIFECYCLE_RULE_ID,
  LISTING_ACTIONS,
  MEDIA_ENDPOINT,
  MEDIA_LOCATION,
  MediaKeys,
  PARSER_REJECTS,
  SHARED_BUCKET_NAMES,
  makeMediaKeys,
  mediaLifecycleRules,
  renderMediaPolicy,
} from './mediaBuckets';

const texts = {
  gateway: '111111:GATEWAYKEY0000001',
  reader: '222222:READERKEY00000002',
  erasure: '333333:ERASUREKEY0000003',
  admin: '444444:ADMINKEY000000004',
};

const keys: MediaKeys = makeMediaKeys(texts);

function statement(bucket: string, sid: string) {
  const found = renderMediaPolicy(bucket, keys).Statement.find((s) => s.Sid === sid);
  if (!found) throw new Error(`no statement ${sid}`);
  return found;
}

describe('the three shared buckets', () => {
  it('are named exactly as the design sets, with no tenant identifier in any name', () => {
    expect([...SHARED_BUCKET_NAMES]).toEqual([
      'branchleft-shared-media-1',
      'branchleft-shared-media-2',
      'branchleft-shared-media-3',
    ]);
    for (const name of SHARED_BUCKET_NAMES) {
      expect(name).toMatch(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/);
      expect(name).not.toMatch(/tenant|blog|ghost|hel1|fsn1/);
    }
  });

  it('live in nbg1, addressed at the nbg1 Object Storage endpoint', () => {
    expect(MEDIA_LOCATION).toBe('nbg1');
    expect(MEDIA_ENDPOINT).toBe('https://nbg1.your-objectstorage.com');
  });
});

describe('lifecycle', () => {
  it('expires noncurrent versions after 30 days and aborts incomplete uploads after 7', () => {
    const [rule] = mediaLifecycleRules();
    expect(rule.id).toBe(LIFECYCLE_RULE_ID);
    expect(rule.status).toBe('Enabled');
    expect(rule.filter).toEqual({ prefix: '' });
    expect(rule.noncurrentVersionExpiration).toEqual({ noncurrentDays: 30 });
    expect(rule.abortIncompleteMultipartUpload).toEqual({ daysAfterInitiation: 7 });
  });
});

describe('policy', () => {
  it('grants anonymous readers only GetObject and GetObjectVersion, and never a listing', () => {
    const publicRead = statement('branchleft-shared-media-1', 'PublicReadObjectsAndVersions');
    expect(publicRead.Effect).toBe('Allow');
    expect(publicRead.Principal).toEqual({ AWS: '*' });
    expect([...publicRead.Action].sort()).toEqual(['s3:GetObject', 's3:GetObjectVersion']);
    expect(publicRead.Resource).toBe('arn:aws:s3:::branchleft-shared-media-1/*');
  });

  it('admits the gateway key by an explicit Allow, with no delete right', () => {
    const gateway = statement('branchleft-shared-media-2', 'GatewayPutAndReadObjects');
    expect(gateway.Effect).toBe('Allow');
    expect(gateway.Principal).toEqual({ AWS: [keys.gateway] });
    expect(gateway.Principal).toEqual({ AWS: ['arn:aws:iam:::user/p111111:GATEWAYKEY0000001'] });
    expect(gateway.Action).toEqual([...GATEWAY_OBJECT_ACTIONS]);
    for (const action of DELETE_ACTIONS) {
      expect(gateway.Action).not.toContain(action);
    }
  });

  it('denies delete to every principal except the erasure key and the operator', () => {
    const deny = statement('branchleft-shared-media-3', 'DenyDeleteExceptErasureAndOperator');
    expect(deny.Effect).toBe('Deny');
    expect(deny.NotPrincipal).toEqual({ AWS: [keys.erasure, keys.admin] });
    expect([...deny.Action].sort()).toEqual([...DELETE_ACTIONS].sort());
  });

  it('denies listing to all but the reader, the erasure key and the operator', () => {
    const deny = statement('branchleft-shared-media-1', 'DenyListingExceptReaderErasureOperator');
    expect(deny.Effect).toBe('Deny');
    expect(deny.NotPrincipal).toEqual({ AWS: [keys.reader, keys.erasure, keys.admin] });
    expect([...deny.Action].sort()).toEqual([...LISTING_ACTIONS].sort());
  });

  it('reserves bucket configuration to the operator, and names no parser-rejected action', () => {
    const deny = statement('branchleft-shared-media-1', 'DenyBucketConfigurationExceptOperator');
    expect(deny.NotPrincipal).toEqual({ AWS: [keys.admin] });
    expect([...deny.Action]).toEqual([...CONFIGURATION_ACTIONS]);
    expect(CONFIGURATION_ACTIONS).not.toContain('s3:ListBucketVersions');
    for (const bucket of SHARED_BUCKET_NAMES) {
      for (const s of renderMediaPolicy(bucket, keys).Statement) {
        for (const action of s.Action) expect(PARSER_REJECTS.has(action)).toBe(false);
      }
    }
  });

  it('scopes every statement to its own bucket, with no trailing wildcard on the bucket name', () => {
    for (const bucket of SHARED_BUCKET_NAMES) {
      const policy = renderMediaPolicy(bucket, keys);
      expect(policy.Id).toBe(bucket);
      for (const s of policy.Statement) {
        expect(
          s.Resource === `arn:aws:s3:::${bucket}` || s.Resource === `arn:aws:s3:::${bucket}/*`
        ).toBe(true);
      }
    }
  });
});

describe('keys', () => {
  it('refuses a key whose text could change the principal it names', () => {
    expect(() => makeMediaKeys({ ...texts, gateway: '111111:GATEWAY/0000001XX' })).toThrow();
    expect(() => makeMediaKeys({ ...texts, gateway: '11a111:GATEWAYKEY0000001' })).toThrow();
    expect(() => makeMediaKeys({ ...texts, gateway: 'no-colon-here' })).toThrow();
  });

  it('refuses two keys in one Hetzner project, since object ownership is by project', () => {
    expect(() => makeMediaKeys({ ...texts, reader: '111111:READERKEY00000002' })).toThrow(
      /project/
    );
  });

  it('refuses the same key twice', () => {
    expect(() => makeMediaKeys({ ...texts, reader: texts.gateway })).toThrow();
  });
});
