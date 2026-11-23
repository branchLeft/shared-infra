import * as pulumi from '@pulumi/pulumi';
import { makeMediaKeys } from './mediaBuckets';
import { createMediaBuckets, mediaProvider } from './mediaBucketResources';

/**
 * Entry point of the `branchleft-hetzner-media` project (`media/Pulumi.yaml`).
 *
 * Configuration, none of it committed (see `media/Pulumi.yaml`):
 * - `mediaBuckets:accessKey`, `mediaBuckets:secretKey` (secret): the bucket-admin
 *   key, from the password manager entry `hetzner object storage / branchleft-storage / bucket-admin`.
 * - `mediaBuckets:gatewayKey`, `mediaBuckets:readerKey`, `mediaBuckets:erasureKey`,
 *   `mediaBuckets:adminKey`: each `PROJECT:ACCESS_KEY`, the project's numeric id and
 *   the key's access key id. Identifiers, not secrets, and the policy carries them.
 *
 * Excluded from unit coverage like `estate.ts`: it only reads config. The
 * resources it builds are tested in `mediaBucketResources.test.ts`.
 */
const config = new pulumi.Config('mediaBuckets');

const provider = mediaProvider('hetzner-object-storage', {
  accessKey: config.requireSecret('accessKey'),
  secretKey: config.requireSecret('secretKey'),
});

const keys = makeMediaKeys({
  gateway: config.require('gatewayKey'),
  reader: config.require('readerKey'),
  erasure: config.require('erasureKey'),
  admin: config.require('adminKey'),
});

const buckets = createMediaBuckets(provider, keys);

export const bucketNames = buckets.map((b) => b.bucket);
