# probe-object-storage

Exercises a Hetzner Object Storage bucket and reports what it actually does.
Narrative for `probe-object-storage.py`; the script's docstring points here.

## Usage

    export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
    probe-object-storage.py --bucket branchleft-lab-probe \
        --endpoint hel1.your-objectstorage.com --region hel1

Settles the storage properties a state backend depends on: versioning, object
lifecycle, and whether anonymous read can be granted without also granting
listing. Only a live bucket can answer these. It prints a dated markdown block
to paste into whatever register tracks them. Each probe records what was
observed, including a failure. A probe that cannot run is reported as UNKNOWN,
and UNKNOWN is not a passing exit code.

## What it writes

This script writes, and one of the things it writes is a policy granting
anonymous reads. Three properties bound that:

* It refuses any bucket whose name ends in `-pulumi-state`
  (`PROTECTED_SUFFIX` in the script). This refusal is the script's own, and it
  is its only protection against operating on a state-backend bucket. The
  same-named `scripts/assert-no-provisioning-deletes.py` in ghost-platform is a
  different system: it evaluates a Pulumi plan for a retired GCP bucket, and it
  never sees this script's calls. It is not a second layer here. The refusal
  covers per-tenant state buckets the provisioning flow mints, as well as the
  ones that exist today.
* The public-read grant names `<bucket>/_probe/*`, never `<bucket>/*`. It proves
  the same property (`s3:GetObject` granted, `s3:ListBucket` absent) without
  making anything else in the bucket anonymously readable.
* It refuses a bucket that already carries a bucket policy or a lifecycle
  configuration. Both are whole-document replacements at the API, and the script
  cannot put back what it would overwrite.

Run it against a scratch bucket. The state backend and the probe target are
deliberately two different buckets. Object Storage bills per account rather
than per bucket.

## Why stdlib

The script is stdlib only, so it runs on a workstation with no S3 client
installed. That is deliberate: a `brew install` standing between the platform
owner and a spike is a cost. SigV4 is implemented in the script rather than
delegated. A signer that is subtly wrong fails as an opaque 403, which looks
the same as a wrong key, a wrong region or a wrong-location endpoint.
