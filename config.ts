import * as pulumi from '@pulumi/pulumi';

const config = new pulumi.Config();
const gcpConfig = new pulumi.Config('gcp');

export const projectId = gcpConfig.require('project');

/**
 * Default region for regional resources in this stack.
 *
 * Only the serverless NEGs are regional — everything else on this edge is
 * global. A NEG must sit in the same region as the Cloud Run service it
 * targets, so this is the default a site entry inherits rather than a
 * property of the edge itself. A site in another region overrides it.
 */
export const region = config.get('region') ?? 'europe-west1';

/** Federated by `workloadIdentity.ts`; the only repo allowed to apply this stack. */
export const githubRepo = 'branchLeft/shared-infra';

/**
 * Workload Identity Pool IDs are unique per GCP project and `github-actions`
 * is already taken by `website/infra`. A deleted pool ID is unavailable for
 * 30 days, so renaming this is not reversible within a working day.
 */
export const workloadIdentityPoolId = 'shared-infra-gha';
