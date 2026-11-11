# ovh/copy2

The Pulumi project `branchleft-ovh-copy2`: the second backup copy at OVHcloud London. It declares Object Storage users, their S3 credentials, their S3 policies and the buckets, all from stack config, behind two guards.

Only the probe stack exists. The probe makes three throwaway buckets, exercises object lock against them and destroys everything in the same job. There is no production stack yet and no persistent state backend: the probe's workflow (`.github/workflows/ovh-copy2-probe.yml`, below) supplies an ephemeral `file://` backend of its own.

## Files

| File                   | What it holds                                                                                        |
| ---------------------- | ---------------------------------------------------------------------------------------------------- |
| `index.ts`             | Reads the stack config and the environment, calls `buildStack`, exports the outputs.                 |
| `stack.ts`             | `buildStack`: runs both guards, then registers users, credentials, policies, buckets.                |
| `projectGuard.ts`      | Refuses any OVHcloud project other than the one the stack config allows.                             |
| `configGuard.ts`       | Refuses bucket configuration that could lock too long or leave a real bucket exposed.                |
| `Pulumi.probe.yaml`    | The probe stack's config. `allowedProjectId` is the owner's OVHcloud project id.                     |
| `probe_object_lock.py` | The probe workflow's own steps: preflight, backend, probe, cleanup, finish (`probe_object_lock.md`). |
| `*.test.ts`            | Mock-runtime tests for each guard, for the wiring, and for the committed probe config.               |

## The project guard

A resource that omits `serviceName` falls back to the `OVH_CLOUD_PROJECT_SERVICE` environment variable. The program therefore requires that variable to equal `allowedProjectId` in the stack config, and passes the allowed id as `serviceName` on every resource. `UNSET`, a missing variable, or any other value stops the run before a resource is registered. The allowed id must be 32 lower-case hex characters.

## The config guard

Applied to the final bucket names, suffix included, and reported all at once:

- a bucket named `zz-probe-*` may lock for one day at most;
- Compliance mode is allowed only on a `zz-probe-*` bucket, and there is no override;
- every other bucket must set `protect: true`, and is also created with `retainOnDelete`;
- an object lock needs versioning `ENABLED`, a whole number of days and a known mode;
- names are unique and well formed, and the region is exactly `UK` (OVHcloud London): `GRA`, `SBG` and every other region are refused.

Compliance retention cannot be shortened or removed, and a bucket holding a locked version cannot be deleted until it expires. That is why the limit is on what may be declared rather than on what is written.

## Stack config

All keys sit under the project namespace `branchleft-ovh-copy2`.

| Key                | Type   | Meaning                                                                        |
| ------------------ | ------ | ------------------------------------------------------------------------------ |
| `allowedProjectId` | string | The one project this stack may address.                                        |
| `nameSuffix`       | string | Optional, appended to every bucket name as `-<suffix>`; a run id.              |
| `users`            | list   | `name`, `s3Credential`, optional policy `statements` over named buckets.       |
| `buckets`          | list   | `name`, `region`, `versioning`, optional `objectLock`, `ownerUser`, `protect`. |

Credentials for the provider come from the environment (`OVH_ENDPOINT`, `OVH_CLIENT_ID`, `OVH_CLIENT_SECRET`) and are never written to config. The S3 secret each credential resource generates is exported as a secret output.

## The probe workflow

`.github/workflows/ovh-copy2-probe.yml` is dispatched by hand and runs in the `ovh-copy2-probe` environment, which holds `OVH_CLIENT_ID` and `OVH_CLIENT_SECRET` and pauses for the owner's approval. It refuses to run while `allowedProjectId` is `UNSET`, creates the probe stack on an ephemeral backend, probes object lock, purges and destroys in `always()` steps, and uploads the result as a workflow artifact and a job summary. Only three steps see the secrets. The workflow and the script are owner paths.

## Provider

`@ovhcloud/pulumi-ovh` is pinned to an exact version in `package.json`. Object lock can only be armed when a bucket is created, and the provider documents that adding, changing or removing the lock block replaces the bucket. Both are unproven against a live account until the probe runs.

## Checks

```sh
cd ovh/copy2
pnpm install --frozen-lockfile
pnpm run typecheck
pnpm run test
```

CI runs the same in the `ovh-copy2-checks` job. It uses mocks only and contacts no OVHcloud API.
