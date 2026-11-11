import { describe, expect, it } from 'vitest';

import {
  assertBuckets,
  PROBE_MAX_RETENTION_DAYS,
  PROBE_PREFIX,
  type BucketConfig,
} from './configGuard';

const probe = (overrides: Partial<BucketConfig> = {}): BucketConfig => ({
  name: `${PROBE_PREFIX}a`,
  region: 'UK',
  versioning: 'ENABLED',
  objectLock: { mode: 'GOVERNANCE', retentionDays: 1 },
  ...overrides,
});

const real = (overrides: Partial<BucketConfig> = {}): BucketConfig => ({
  name: 'backup-copy-two',
  region: 'UK',
  versioning: 'ENABLED',
  protect: true,
  ...overrides,
});

describe('assertBuckets, retention', () => {
  it('names the probe limit as one day', () => {
    expect(PROBE_MAX_RETENTION_DAYS).toBe(1);
  });

  it('accepts a probe bucket at one day, in either mode', () => {
    expect(() => assertBuckets([probe()])).not.toThrow();
    expect(() =>
      assertBuckets([probe({ objectLock: { mode: 'COMPLIANCE', retentionDays: 1 } })])
    ).not.toThrow();
  });

  it('refuses a probe bucket above one day, in either mode', () => {
    for (const mode of ['GOVERNANCE', 'COMPLIANCE'] as const) {
      expect(() => assertBuckets([probe({ objectLock: { mode, retentionDays: 2 } })])).toThrow(
        /retention of 2 days exceeds the probe limit of 1 day/
      );
    }
    expect(() =>
      assertBuckets([probe({ objectLock: { mode: 'COMPLIANCE', retentionDays: 14 } })])
    ).toThrow(/exceeds the probe limit/);
  });

  it('refuses a retention that is not a whole number of days of at least one', () => {
    for (const retentionDays of [0, -1, 1.5, Number.NaN]) {
      expect(() =>
        assertBuckets([probe({ objectLock: { mode: 'GOVERNANCE', retentionDays } })])
      ).toThrow(/whole number of days/);
    }
  });
});

describe('assertBuckets, Compliance mode', () => {
  it('refuses Compliance on a bucket whose name does not start with the probe prefix', () => {
    expect(() =>
      assertBuckets([real({ objectLock: { mode: 'COMPLIANCE', retentionDays: 14 } })])
    ).toThrow(/COMPLIANCE is allowed only on buckets named zz-probe-/);
  });

  it('matches the prefix at the start only', () => {
    expect(() =>
      assertBuckets([
        real({
          name: 'x-zz-probe-a',
          objectLock: { mode: 'COMPLIANCE', retentionDays: 1 },
        }),
      ])
    ).toThrow(/COMPLIANCE is allowed only/);
  });

  it('refuses Compliance on a non-probe bucket even at one day', () => {
    expect(() =>
      assertBuckets([real({ objectLock: { mode: 'COMPLIANCE', retentionDays: 1 } })])
    ).toThrow(/COMPLIANCE is allowed only/);
  });

  it('allows Governance on a non-probe bucket', () => {
    expect(() =>
      assertBuckets([real({ objectLock: { mode: 'GOVERNANCE', retentionDays: 14 } })])
    ).not.toThrow();
  });

  it('refuses a mode that is neither Compliance nor Governance', () => {
    expect(() =>
      assertBuckets([
        probe({ objectLock: { mode: 'compliance' as 'COMPLIANCE', retentionDays: 1 } }),
      ])
    ).toThrow(/mode must be COMPLIANCE or GOVERNANCE/);
  });
});

describe('assertBuckets, protect', () => {
  it('refuses a non-probe bucket that does not set protect to true', () => {
    expect(() => assertBuckets([real({ protect: false })])).toThrow(/protect: true/);
    expect(() => assertBuckets([real({ protect: undefined })])).toThrow(/protect: true/);
    expect(() => assertBuckets([real({ protect: 'true' as unknown as boolean })])).toThrow(
      /protect: true/
    );
  });

  it('accepts a protected non-probe bucket, and a probe bucket without protect', () => {
    expect(() => assertBuckets([real(), probe()])).not.toThrow();
  });
});

describe('assertBuckets, shape', () => {
  it('refuses a lock on a bucket whose versioning is not enabled', () => {
    expect(() => assertBuckets([probe({ versioning: 'SUSPENDED' })])).toThrow(
      /object lock needs versioning ENABLED/
    );
  });

  it('refuses duplicate, malformed and lower-case region names', () => {
    expect(() => assertBuckets([probe(), probe()])).toThrow(/duplicate bucket name/);
    expect(() => assertBuckets([probe({ name: 'zz-probe-UPPER' })])).toThrow(/bucket name/);
    expect(() => assertBuckets([probe({ region: 'uk' })])).toThrow(/upper-case/);
  });

  it('reports every violation in one message', () => {
    let message = '';
    try {
      assertBuckets([
        probe({ objectLock: { mode: 'COMPLIANCE', retentionDays: 9 } }),
        real({ protect: false, objectLock: { mode: 'COMPLIANCE', retentionDays: 14 } }),
      ]);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/exceeds the probe limit/);
    expect(message).toMatch(/COMPLIANCE is allowed only/);
    expect(message).toMatch(/protect: true/);
  });
});
