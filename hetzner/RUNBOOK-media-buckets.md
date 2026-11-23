# RUNBOOK: the three shared media buckets

Stack `branchleft-hetzner-media` (`hetzner/media/Pulumi.yaml`, program `hetzner/media.ts`).
Creates `branchleft-shared-media-1`, `-2` and `-3` in `nbg1` with versioning, the
lifecycle rule, a private ACL and the access policy from `hetzner/mediaBuckets.ts`.
Design: `ghost-platform-docs/21-storage-decision.md`, decision 1. Issue: branchLeft/workspace#1772.

## Who runs `pulumi up`

Hetzner has no API for projects or S3 keys, so the owner makes those in the Console.
With them in hand, this stack is applied by hand, once, by an operator or an agent
holding the bucket-admin key. It is first-time provisioning, not steady state.
CI does not run this stack yet; a CI job is a follow-up, to be added only after this
first apply has been read back.

Do not run it before the owner's keys exist.

## Before the first apply

1. The owner has made the six Console projects and keys (ghost-platform-docs page 21,
   "One Hetzner project per storage key"). Only `branchLeft storage` (`bucket-admin`) and
   the three keys this stack names are needed here: the gateway, the reader and the erasure
   key. The tenant-state and estate-state keys are not part of this stack.
2. Each key's Hetzner project id and access key id are known to the operator.
3. Stack init follows `RUNBOOK-new-stack.md`. Pulumi's passphrase provider and the salt
   come from there, not from this file.

## Config (set per run, never committed)

From `hetzner/media/`, with `pulumi stack select production`:

    pulumi config set --secret mediaBuckets:accessKey    # bucket-admin access key id
    pulumi config set --secret mediaBuckets:secretKey    # bucket-admin secret
    pulumi config set mediaBuckets:adminKey   'PROJECT:ACCESS_KEY'   # bucket-admin principal
    pulumi config set mediaBuckets:gatewayKey 'PROJECT:ACCESS_KEY'   # gateway-upstream
    pulumi config set mediaBuckets:readerKey  'PROJECT:ACCESS_KEY'   # media-reader
    pulumi config set mediaBuckets:erasureKey 'PROJECT:ACCESS_KEY'   # media-erasure

The bucket-admin secret and access key id come from the password manager entry
`hetzner object storage / branchleft-storage / bucket-admin`. Each `PROJECT:ACCESS_KEY`
is the numeric project id and the key's access key id, with one colon between.

The four `PROJECT:ACCESS_KEY` values are identifiers, not secrets; they still stay out of
the repository because they name every principal the policy admits.

## Apply

    pulumi preview
    pulumi up

Read the preview first. Three buckets, three versioning, three lifecycle, three policy
and three ACL resources, and no delete. `forceDestroy` is false on every bucket, so a
bucket that holds objects is never removed by an apply.

## Read-back proof

The apply is not proof. Read each bucket back from Hetzner, with the bucket-admin key, and
check it against the stack:

    aws --endpoint-url https://nbg1.your-objectstorage.com s3api get-bucket-versioning --bucket BUCKET
    aws --endpoint-url https://nbg1.your-objectstorage.com s3api get-bucket-lifecycle-configuration --bucket BUCKET
    aws --endpoint-url https://nbg1.your-objectstorage.com s3api get-bucket-policy --bucket BUCKET --output text

Versioning reads `Enabled`; the lifecycle reads 30 noncurrent days and 7 days for an
incomplete upload; the policy equals `renderMediaPolicy(BUCKET, keys)`. Hetzner can store
something other than what was sent, so the comparison is against the read-back, not the
request.

Then, unauthenticated, an anonymous list of each bucket must be refused. The gateway key
must write and must not delete. The reader key must list and read, and must not write.
These probes are the `Done when` of workspace#1772 and are recorded on that issue.

## If the read-back differs

Stop. Do not re-apply over it. Record the read-back on the issue, and fix the program
through a pull request, not by hand in the Console.
