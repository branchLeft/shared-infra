import * as pulumi from '@pulumi/pulumi';
import * as gcp from '@pulumi/gcp';
import { githubRepo, workloadIdentityPoolId } from './config';
import { deployerSa } from './serviceAccounts';

export const pool = new gcp.iam.WorkloadIdentityPool('shared-infra-gha-pool', {
  workloadIdentityPoolId,
  // Max 32 characters (GCP API limit); this is 30.
  displayName: 'GitHub Actions (shared-infra)',
  description: 'CI identity federation for the branchLeft/shared-infra repo',
});

export const provider = new gcp.iam.WorkloadIdentityPoolProvider('shared-infra-gha-provider', {
  workloadIdentityPoolId: pool.workloadIdentityPoolId,
  workloadIdentityPoolProviderId: 'github',
  displayName: 'GitHub',

  // An attribute must be mapped before a principalSet can reference it;
  // naming it in the condition below is not enough.
  attributeMapping: {
    'google.subject': 'assertion.sub',
    'attribute.repository': 'assertion.repository',
    'attribute.ref': 'assertion.ref',
  },

  // The branch clause is the gate, not belt-and-braces: this repo is private
  // on a plan with no branch protection, so without it anyone with push
  // access to any branch could add a workflow requesting `id-token: write`
  // and impersonate the deployer with no PR and no merge.
  //
  // On `assertion.ref` rather than `sub`: the deploy job's `environment:` key
  // rewrites `sub` to `repo:OWNER/REPO:environment:NAME`, leaving `ref`
  // intact. The cost, accepted, is that a PR-time preview job cannot federate
  // here — it needs its own provider and a read-only identity.
  attributeCondition: `assertion.repository == "${githubRepo}" && assertion.ref == "refs/heads/main"`,

  oidc: {
    issuerUri: 'https://token.actions.githubusercontent.com',
  },
});

/**
 * `pool.name` — the full `projects/<number>/locations/global/
 * workloadIdentityPools/<id>` resource name — and not
 * `pool.workloadIdentityPoolId`. A principalSet built from the bare ID is
 * accepted at apply time and matches nothing at token-exchange time.
 */
export const deployerImpersonation = new gcp.serviceaccount.IAMMember(
  'shared-infra-gha-can-impersonate-deployer',
  {
    serviceAccountId: deployerSa.name,
    role: 'roles/iam.workloadIdentityUser',
    member: pulumi.interpolate`principalSet://iam.googleapis.com/${pool.name}/attribute.repository/${githubRepo}`,
  }
);

export const workloadIdentityProvider = provider.name;
