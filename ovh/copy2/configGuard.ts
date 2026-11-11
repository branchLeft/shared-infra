/**
 * Refuses a bucket configuration that could lock something for longer than a
 * probe may, or that leaves a real bucket unprotected.
 *
 * An object written under Compliance retention cannot be deleted by anyone,
 * and neither can the bucket that holds it, until the retention ends. So the
 * limits here are about what may be *declared*, not about what is written:
 *
 * - a bucket named `zz-probe-` may lock for at most one day;
 * - Compliance mode exists only on a `zz-probe-` bucket;
 * - every other bucket sets `protect: true`.
 *
 * The rules run over the final names, suffix included, and report every
 * violation in one message so one preview shows the whole list.
 */

export const PROBE_PREFIX = 'zz-probe-';
export const PROBE_MAX_RETENTION_DAYS = 1;

export type LockMode = 'COMPLIANCE' | 'GOVERNANCE';
export type VersioningStatus = 'ENABLED' | 'DISABLED' | 'SUSPENDED';

export interface ObjectLockConfig {
  readonly mode: LockMode;
  readonly retentionDays: number;
}

export interface BucketConfig {
  readonly name: string;
  readonly region: string;
  readonly versioning: VersioningStatus;
  readonly objectLock?: ObjectLockConfig;
  readonly ownerUser?: string;
  readonly protect?: boolean;
}

export interface PolicyStatement {
  readonly sid: string;
  readonly effect: 'Allow' | 'Deny';
  readonly actions: readonly string[];
  /** Bucket names as configured; each gets its bucket ARN and its object ARN. */
  readonly buckets: readonly string[];
}

export interface UserConfig {
  readonly name: string;
  readonly s3Credential: boolean;
  readonly statements?: readonly PolicyStatement[];
}

export interface Settings {
  readonly allowedProjectId: string;
  /** Appended to every bucket name as `-<suffix>`; a probe run sets its run id here. */
  readonly nameSuffix?: string;
  readonly users: readonly UserConfig[];
  readonly buckets: readonly BucketConfig[];
}

const BUCKET_NAME = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const REGION = /^[A-Z0-9]+$/;
/** The only region this project may address: OVHcloud London (S3 region `uk`). */
export const ALLOWED_REGION = 'UK';
const MODES: readonly string[] = ['COMPLIANCE', 'GOVERNANCE'];

export const isProbe = (name: string): boolean => name.startsWith(PROBE_PREFIX);

/** Every violation in `buckets`, one string each. Empty when the list is acceptable. */
export function bucketViolations(buckets: readonly BucketConfig[]): string[] {
  const problems: string[] = [];
  const seen = new Set<string>();
  for (const bucket of buckets) {
    const label = `bucket ${bucket.name}`;
    if (!BUCKET_NAME.test(bucket.name)) {
      problems.push(
        `${label}: bucket name must be 3 to 63 lower-case letters, digits, dots and hyphens`
      );
    }
    if (seen.has(bucket.name)) {
      problems.push(`${label}: duplicate bucket name`);
    }
    seen.add(bucket.name);
    if (!REGION.test(bucket.region)) {
      problems.push(`${label}: region must be upper-case, such as UK`);
    } else if (bucket.region !== ALLOWED_REGION) {
      problems.push(
        `${label}: region must be ${ALLOWED_REGION}, the only region this project may address`
      );
    }

    const lock = bucket.objectLock;
    if (lock !== undefined) {
      if (!MODES.includes(lock.mode)) {
        problems.push(`${label}: lock mode must be COMPLIANCE or GOVERNANCE`);
      }
      if (!Number.isInteger(lock.retentionDays) || lock.retentionDays < 1) {
        problems.push(`${label}: retention must be a whole number of days, at least 1`);
      } else if (isProbe(bucket.name) && lock.retentionDays > PROBE_MAX_RETENTION_DAYS) {
        problems.push(
          `${label}: retention of ${lock.retentionDays} days exceeds the probe limit of ${PROBE_MAX_RETENTION_DAYS} day`
        );
      }
      if (lock.mode === 'COMPLIANCE' && !isProbe(bucket.name)) {
        problems.push(`${label}: COMPLIANCE is allowed only on buckets named ${PROBE_PREFIX}*`);
      }
      if (bucket.versioning !== 'ENABLED') {
        problems.push(`${label}: object lock needs versioning ENABLED`);
      }
    }

    if (!isProbe(bucket.name) && bucket.protect !== true) {
      problems.push(`${label}: every bucket outside ${PROBE_PREFIX}* must set protect: true`);
    }
  }
  return problems;
}

/** Throws one error listing every violation, or returns when there is none. */
export function assertBuckets(buckets: readonly BucketConfig[]): void {
  const problems = bucketViolations(buckets);
  if (problems.length > 0) {
    throw new Error(`bucket configuration refused:\n- ${problems.join('\n- ')}`);
  }
}
