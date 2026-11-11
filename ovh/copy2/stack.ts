import * as ovh from '@ovhcloud/pulumi-ovh';
import * as pulumi from '@pulumi/pulumi';

import {
  assertBuckets,
  isProbe,
  type BucketConfig,
  type PolicyStatement,
  type Settings,
} from './configGuard';
import { assertProject, PROJECT_ENV } from './projectGuard';

/**
 * The role OVHcloud documents for a user that works with Object Storage. The
 * user's actual reach is the S3 policy attached to it, not this role.
 */
const OBJECT_STORE_ROLE = 'objectstore_operator';

const SUFFIX = /^[a-z0-9][a-z0-9-]{0,19}$/;

export interface Stack {
  /** Every resource registered, in registration order. */
  readonly resources: pulumi.Resource[];
  /** Registered buckets by their final name. */
  readonly buckets: Record<string, ovh.CloudStorageObjectBucket>;
  readonly accessKeyIds: pulumi.Output<Record<string, string>>;
  /** Secret: only the job that created a credential ever reads this. */
  readonly secretAccessKeys: pulumi.Output<Record<string, string>>;
  readonly s3Endpoints: Record<string, string>;
}

/** The stack config with the run suffix applied to every bucket name. */
function withSuffix(settings: Settings): Settings {
  const suffix = settings.nameSuffix;
  if (suffix === undefined || suffix === '') {
    return settings;
  }
  if (!SUFFIX.test(suffix)) {
    throw new Error('nameSuffix must be 1 to 20 lower-case letters, digits and hyphens');
  }
  return {
    ...settings,
    buckets: settings.buckets.map((bucket) => ({ ...bucket, name: `${bucket.name}-${suffix}` })),
    users: settings.users.map((user) => ({
      ...user,
      statements: user.statements?.map((statement) => ({
        ...statement,
        buckets: statement.buckets.map((name) => `${name}-${suffix}`),
      })),
    })),
  };
}

/** Throws when a bucket names an owner, or a policy a bucket, that the config does not declare. */
function assertReferences(settings: Settings): void {
  const users = new Set(settings.users.map((user) => user.name));
  const buckets = new Set(settings.buckets.map((bucket) => bucket.name));
  const problems: string[] = [];
  for (const bucket of settings.buckets) {
    if (bucket.ownerUser !== undefined && !users.has(bucket.ownerUser)) {
      problems.push(`bucket ${bucket.name}: owner user ${bucket.ownerUser} is not configured`);
    }
  }
  for (const user of settings.users) {
    for (const statement of user.statements ?? []) {
      for (const name of statement.buckets) {
        if (!buckets.has(name)) {
          problems.push(`user ${user.name}: bucket ${name} is not configured`);
        }
      }
    }
  }
  if (problems.length > 0) {
    throw new Error(`stack configuration refused:\n- ${problems.join('\n- ')}`);
  }
}

function policyDocument(statements: readonly PolicyStatement[]): string {
  return JSON.stringify({
    Statement: statements.map((statement) => ({
      Sid: statement.sid,
      Effect: statement.effect,
      Action: statement.actions,
      Resource: statement.buckets.flatMap((name) => [
        `arn:aws:s3:::${name}`,
        `arn:aws:s3:::${name}/*`,
      ]),
    })),
  });
}

const endpointFor = (region: string): string =>
  `https://s3.${region.toLowerCase()}.io.cloud.ovh.net`;

/**
 * Runs both guards, then registers users, S3 credentials, user policies and
 * buckets from the stack config. Nothing is registered until every guard has
 * passed, and every resource carries the allowed project id explicitly so none
 * of them falls back to the environment variable.
 */
export function buildStack(
  rawSettings: Settings,
  env: Readonly<Record<string, string | undefined>>
): Stack {
  const serviceName = assertProject(rawSettings.allowedProjectId, env[PROJECT_ENV]);
  const settings = withSuffix(rawSettings);
  assertBuckets(settings.buckets);
  assertReferences(settings);

  const resources: pulumi.Resource[] = [];

  const users: Record<string, ovh.cloudproject.User> = {};
  const credentials: Record<string, ovh.cloudproject.S3Credential> = {};
  for (const config of settings.users) {
    const user = new ovh.cloudproject.User(`user-${config.name}`, {
      serviceName,
      description: config.name,
      roleNames: [OBJECT_STORE_ROLE],
    });
    users[config.name] = user;
    resources.push(user);

    if (config.s3Credential) {
      const credential = new ovh.cloudproject.S3Credential(`s3cred-${config.name}`, {
        serviceName,
        userId: user.id,
      });
      credentials[config.name] = credential;
      resources.push(credential);
    }

    if (config.statements !== undefined && config.statements.length > 0) {
      resources.push(
        new ovh.cloudproject.S3Policy(`policy-${config.name}`, {
          serviceName,
          userId: user.id,
          policy: policyDocument(config.statements),
        })
      );
    }
  }

  const buckets: Record<string, ovh.CloudStorageObjectBucket> = {};
  const s3Endpoints: Record<string, string> = {};
  for (const config of settings.buckets) {
    buckets[config.name] = registerBucket(config, serviceName, users);
    resources.push(buckets[config.name]!);
    s3Endpoints[config.name] = endpointFor(config.region);
  }

  const idsOf = (pick: (credential: ovh.cloudproject.S3Credential) => pulumi.Output<string>) =>
    pulumi.output(
      Object.fromEntries(Object.entries(credentials).map(([name, cred]) => [name, pick(cred)]))
    );

  return {
    resources,
    buckets,
    accessKeyIds: idsOf((credential) => credential.accessKeyId),
    secretAccessKeys: pulumi.secret(idsOf((credential) => credential.secretAccessKey)),
    s3Endpoints,
  };
}

function registerBucket(
  config: BucketConfig,
  serviceName: string,
  users: Record<string, ovh.cloudproject.User>
): ovh.CloudStorageObjectBucket {
  const probe = isProbe(config.name);
  const owner = config.ownerUser === undefined ? undefined : users[config.ownerUser];
  return new ovh.CloudStorageObjectBucket(
    `bucket-${config.name}`,
    {
      serviceName,
      name: config.name,
      region: config.region,
      versioning: { status: config.versioning },
      objectLock:
        config.objectLock === undefined
          ? undefined
          : { mode: config.objectLock.mode, retentionDays: config.objectLock.retentionDays },
      ownerUserId: owner?.id,
    },
    // A probe bucket is built to be destroyed in the same job. Every other
    // bucket outlives its Pulumi resource: dropping it from the config must
    // never delete data, and the guard has already required protect: true.
    { protect: config.protect === true, retainOnDelete: !probe }
  );
}
