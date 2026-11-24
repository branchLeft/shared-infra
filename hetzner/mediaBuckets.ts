/**
 * The estate's three shared media buckets, as data and as pure policy.
 *
 * The design is `ghost-platform-docs/21-storage-decision.md`, decision 1 ("Buckets")
 * and "One Hetzner project per storage key". The access policy here is the same
 * statement set as `ghost-platform/infra/provisioning/scripts/render-shared-media-buckets.py`,
 * the renderer that prints it today; this module is its Pulumi-side twin and must
 * stay statement-for-statement equal to it. Nothing in this file talks to Hetzner.
 *
 * Why there is no `Principal: *` write or delete anywhere: the buckets are public
 * for reads only (`GetObject`, `GetObjectVersion`, by unsigned URL). Every other
 * right is named to one key, and the key is alone in its own Hetzner project,
 * because object ownership is by project and a bucket policy cannot tell two keys
 * of one project apart.
 */

export const SHARED_BUCKET_NAMES = [
  'branchleft-shared-media-1',
  'branchleft-shared-media-2',
  'branchleft-shared-media-3',
] as const;

/** Decision 4 of page 21: live media in `nbg1`, next to the hosts. */
export const MEDIA_LOCATION = 'nbg1';

export const MEDIA_ENDPOINT = `https://${MEDIA_LOCATION}.your-objectstorage.com`;

export const NONCURRENT_VERSION_DAYS = 30;
export const INCOMPLETE_UPLOAD_DAYS = 7;
export const LIFECYCLE_RULE_ID = 'shared-media-retention';

/** Anonymous readers get exactly these; a versioned bucket needs `GetObjectVersion` beside `GetObject`. */
export const PUBLIC_OBJECT_ACTIONS = ['s3:GetObject', 's3:GetObjectVersion'] as const;

/** The gateway's real key: put, the multipart calls, head and get. No delete, no list (#1937 open). */
export const GATEWAY_OBJECT_ACTIONS = [
  's3:PutObject',
  's3:AbortMultipartUpload',
  's3:ListMultipartUploadParts',
  's3:GetObject',
] as const;

/** The backup reader: read and list, never write. */
export const READER_OBJECT_ACTIONS = ['s3:GetObject', 's3:GetObjectVersion'] as const;
export const READER_BUCKET_ACTIONS = ['s3:ListBucket', 's3:ListBucketVersions'] as const;

/** The erasure key: list versions and delete versions. */
export const ERASURE_BUCKET_ACTIONS = ['s3:ListBucketVersions'] as const;
export const ERASURE_OBJECT_ACTIONS = ['s3:DeleteObject', 's3:DeleteObjectVersion'] as const;

export const DELETE_ACTIONS = ['s3:DeleteObject', 's3:DeleteObjectVersion'] as const;

/** Every bucket action that enumerates keys. Denied to all but the reader, the erasure key and the operator. */
export const LISTING_ACTIONS = [
  's3:ListBucket',
  's3:ListBucketVersions',
  's3:ListBucketMultipartUploads',
] as const;

/**
 * Bucket configuration actions the parser accepts, minus the listing reads
 * (`LISTING_ACTIONS` handles those). Mirrors `BUCKET_CONFIGURATION_ACTIONS` in
 * `ghost-platform/infra/provisioning/scripts/bucketpolicy.py`. Every name here is
 * one the engine's parser knows: one unknown name rejects the whole document.
 */
export const CONFIGURATION_ACTIONS = [
  's3:GetBucketPolicy',
  's3:PutBucketPolicy',
  's3:DeleteBucketPolicy',
  's3:GetBucketPolicyStatus',
  's3:GetBucketAcl',
  's3:PutBucketAcl',
  's3:GetBucketPublicAccessBlock',
  's3:PutBucketPublicAccessBlock',
  's3:DeleteBucketPublicAccessBlock',
  's3:GetLifecycleConfiguration',
  's3:PutLifecycleConfiguration',
  's3:GetBucketVersioning',
  's3:PutBucketVersioning',
  's3:GetBucketObjectLockConfiguration',
  's3:PutBucketObjectLockConfiguration',
  's3:GetBucketCORS',
  's3:PutBucketCORS',
  's3:CreateBucket',
  's3:DeleteBucket',
  's3:GetBucketNotification',
  's3:PutBucketNotification',
  's3:GetReplicationConfiguration',
  's3:PutReplicationConfiguration',
  's3:DeleteReplicationConfiguration',
  's3:GetBucketLogging',
  's3:PutBucketLogging',
  's3:GetBucketTagging',
  's3:PutBucketTagging',
  's3:GetBucketWebsite',
  's3:PutBucketWebsite',
  's3:DeleteBucketWebsite',
  's3:GetAccelerateConfiguration',
  's3:PutAccelerateConfiguration',
  's3:GetBucketRequestPayment',
  's3:PutBucketRequestPayment',
] as const;

/** Parser-rejected names, measured live (bucketpolicy.py `PARSER_REJECTS`). None may appear in a statement. */
export const PARSER_REJECTS: ReadonlySet<string> = new Set([
  's3:GetEncryptionConfiguration',
  's3:PutEncryptionConfiguration',
  's3:DeleteBucketTagging',
  's3:DeleteBucketOwnershipControls',
  's3:GetBucketOwnershipControls',
  's3:PutBucketOwnershipControls',
  's3:GetAnalyticsConfiguration',
  's3:PutAnalyticsConfiguration',
  's3:GetInventoryConfiguration',
  's3:PutInventoryConfiguration',
  's3:GetMetricsConfiguration',
  's3:PutMetricsConfiguration',
  's3:GetIntelligentTieringConfiguration',
  's3:PutIntelligentTieringConfiguration',
  's3:GetObjectAttributes',
  's3:GetObjectVersionAttributes',
  's3:ReplicateObject',
  's3:ReplicateDelete',
  's3:ReplicateTags',
  's3:GetObjectVersionForReplication',
  's3:ObjectOwnerOverrideToBucketOwner',
]);

const PROJECT_ID_PATTERN = /^[0-9]{1,20}$/;
const ACCESS_KEY_PATTERN = /^[A-Za-z0-9]{16,64}$/;

/** The four principals, each a Hetzner IAM-style ARN naming one key in one project. */
export interface MediaKeys {
  readonly gateway: string;
  readonly reader: string;
  readonly erasure: string;
  readonly admin: string;
}

/** Refuses anything that would change which principal the ARN names. */
export function keyPrincipal(projectId: string, accessKey: string): string {
  if (!PROJECT_ID_PATTERN.test(projectId)) {
    throw new Error(`project id ${JSON.stringify(projectId)} must be digits only`);
  }
  if (!ACCESS_KEY_PATTERN.test(accessKey)) {
    throw new Error(
      `access key ${JSON.stringify(accessKey)} must be 16-64 alphanumerics; anything else would change which principal the ARN names`
    );
  }
  return `arn:aws:iam:::user/p${projectId}:${accessKey}`;
}

/** `PROJECT:ACCESS_KEY` into a principal, as the stack's config is written. */
export function parseKey(text: string): string {
  const parts = text.split(':');
  if (parts.length !== 2) {
    throw new Error(
      `key ${JSON.stringify(text)} must be written PROJECT:ACCESS_KEY, with one colon`
    );
  }
  return keyPrincipal(parts[0], parts[1]);
}

/** Four distinct keys, each alone in its own project: a shared project would let one key rewrite another's objects. */
export function makeMediaKeys(texts: {
  gateway: string;
  reader: string;
  erasure: string;
  admin: string;
}): MediaKeys {
  const keys: MediaKeys = {
    gateway: parseKey(texts.gateway),
    reader: parseKey(texts.reader),
    erasure: parseKey(texts.erasure),
    admin: parseKey(texts.admin),
  };
  const principals = Object.values(keys);
  if (new Set(principals).size !== principals.length) {
    throw new Error('two of the four keys are the same credential; each must be its own key');
  }
  const projects = principals.map((p) => p.split('/')[1].split(':')[0]);
  if (new Set(projects).size !== projects.length) {
    throw new Error(
      'two of the four keys sit in one Hetzner project; each key needs a project of its own'
    );
  }
  return keys;
}

export interface PolicyStatement {
  Sid: string;
  Effect: 'Allow' | 'Deny';
  Principal?: { AWS: string | string[] };
  NotPrincipal?: { AWS: string[] };
  Action: string[];
  Resource: string;
}

export interface BucketPolicy {
  Version: '2012-10-17';
  Id: string;
  Statement: PolicyStatement[];
}

/** Refuses a policy the engine would store and not enforce, or reject whole. */
export function assertEnforceable(policy: BucketPolicy): BucketPolicy {
  for (const statement of policy.Statement) {
    const refused = statement.Action.filter((a) => PARSER_REJECTS.has(a));
    if (refused.length > 0) {
      throw new Error(
        `statement ${statement.Sid} names ${refused.join(', ')}, which the policy parser refuses`
      );
    }
  }
  return policy;
}

/** The whole access policy for one shared bucket. */
export function renderMediaPolicy(bucket: string, keys: MediaKeys): BucketPolicy {
  // Object actions match `<bucket>/*`; bucket actions match the bare bucket ARN.
  // Neither takes a trailing `*` on the bucket name, which would match a sibling.
  const bucketArn = `arn:aws:s3:::${bucket}`;
  const objectsArn = `arn:aws:s3:::${bucket}/*`;
  return assertEnforceable({
    Version: '2012-10-17',
    Id: bucket,
    Statement: [
      {
        Sid: 'PublicReadObjectsAndVersions',
        Effect: 'Allow',
        Principal: { AWS: '*' },
        Action: [...PUBLIC_OBJECT_ACTIONS],
        Resource: objectsArn,
      },
      {
        Sid: 'GatewayPutAndReadObjects',
        Effect: 'Allow',
        Principal: { AWS: [keys.gateway] },
        Action: [...GATEWAY_OBJECT_ACTIONS],
        Resource: objectsArn,
      },
      {
        Sid: 'ReaderReadsObjects',
        Effect: 'Allow',
        Principal: { AWS: [keys.reader] },
        Action: [...READER_OBJECT_ACTIONS],
        Resource: objectsArn,
      },
      {
        Sid: 'ReaderListsBucket',
        Effect: 'Allow',
        Principal: { AWS: [keys.reader] },
        Action: [...READER_BUCKET_ACTIONS],
        Resource: bucketArn,
      },
      {
        Sid: 'ErasureListsVersions',
        Effect: 'Allow',
        Principal: { AWS: [keys.erasure] },
        Action: [...ERASURE_BUCKET_ACTIONS],
        Resource: bucketArn,
      },
      {
        Sid: 'ErasureDeletesVersions',
        Effect: 'Allow',
        Principal: { AWS: [keys.erasure] },
        Action: [...ERASURE_OBJECT_ACTIONS],
        Resource: objectsArn,
      },
      {
        // Explicit Deny: an explicit Deny is not overcome by a public bucket ACL.
        Sid: 'DenyListingExceptReaderErasureOperator',
        Effect: 'Deny',
        NotPrincipal: { AWS: [keys.reader, keys.erasure, keys.admin] },
        Action: [...LISTING_ACTIONS],
        Resource: bucketArn,
      },
      {
        Sid: 'DenyBucketConfigurationExceptOperator',
        Effect: 'Deny',
        NotPrincipal: { AWS: [keys.admin] },
        Action: [...CONFIGURATION_ACTIONS],
        Resource: bucketArn,
      },
      {
        Sid: 'DenyDeleteExceptErasureAndOperator',
        Effect: 'Deny',
        NotPrincipal: { AWS: [keys.erasure, keys.admin] },
        Action: [...DELETE_ACTIONS],
        Resource: objectsArn,
      },
    ],
  });
}

/** The lifecycle rules every shared bucket carries. */
export function mediaLifecycleRules() {
  return [
    {
      id: LIFECYCLE_RULE_ID,
      status: 'Enabled' as const,
      filter: { prefix: '' },
      noncurrentVersionExpiration: { noncurrentDays: NONCURRENT_VERSION_DAYS },
      abortIncompleteMultipartUpload: { daysAfterInitiation: INCOMPLETE_UPLOAD_DAYS },
    },
  ];
}
