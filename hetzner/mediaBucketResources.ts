import * as aws from '@pulumi/aws';
import * as pulumi from '@pulumi/pulumi';
import {
  MEDIA_ENDPOINT,
  MEDIA_LOCATION,
  MediaKeys,
  SHARED_BUCKET_NAMES,
  mediaLifecycleRules,
  renderMediaPolicy,
} from './mediaBuckets';

/**
 * The Pulumi resources for the three shared media buckets. Pure policy lives in
 * `mediaBuckets.ts`; this file only wires it to the S3-compatible provider.
 *
 * Hetzner Object Storage is S3-compatible, not AWS, so the provider skips every
 * AWS-only lookup: credential validation, account id, region validation and the
 * instance metadata probe. Path-style addressing, because the endpoint's wildcard
 * certificate covers one label only.
 */
export function mediaProvider(
  name: string,
  credentials: { accessKey: pulumi.Input<string>; secretKey: pulumi.Input<string> }
): aws.Provider {
  return new aws.Provider(name, {
    region: MEDIA_LOCATION,
    accessKey: credentials.accessKey,
    secretKey: credentials.secretKey,
    endpoints: [{ s3: MEDIA_ENDPOINT }],
    skipCredentialsValidation: true,
    skipRequestingAccountId: true,
    skipRegionValidation: true,
    skipMetadataApiCheck: true,
    s3UsePathStyle: true,
  });
}

/**
 * One bucket per name, each with versioning, lifecycle, private ACL and the policy.
 * `forceDestroy` stays false: a bucket with objects in it is never deleted by an apply.
 */
export function createMediaBuckets(provider: aws.Provider, keys: MediaKeys): aws.s3.Bucket[] {
  return SHARED_BUCKET_NAMES.map((bucketName) => {
    const bucket = new aws.s3.Bucket(
      bucketName,
      { bucket: bucketName, forceDestroy: false },
      { provider }
    );
    new aws.s3.BucketAcl(`${bucketName}-acl`, { bucket: bucket.id, acl: 'private' }, { provider });

    const versioning = new aws.s3.BucketVersioning(
      `${bucketName}-versioning`,
      { bucket: bucket.id, versioningConfiguration: { status: 'Enabled' } },
      { provider }
    );

    // Lifecycle noncurrent-version expiry needs versioning to be on first.
    new aws.s3.BucketLifecycleConfiguration(
      `${bucketName}-lifecycle`,
      { bucket: bucket.id, rules: mediaLifecycleRules() },
      { provider, dependsOn: [versioning] }
    );

    new aws.s3.BucketPolicy(
      `${bucketName}-policy`,
      { bucket: bucket.id, policy: JSON.stringify(renderMediaPolicy(bucketName, keys)) },
      { provider, dependsOn: [versioning] }
    );

    return bucket;
  });
}
