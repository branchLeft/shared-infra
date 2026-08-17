import * as pulumi from '@pulumi/pulumi';
import * as gcp from '@pulumi/gcp';
import { projectId } from './config';

/**
 * The identity GitHub Actions assumes to apply this stack. Its own, not
 * `website/infra`'s `github-actions-deployer`: that one is federated to
 * `branchLeft/website` and carries Cloud Run, Secret Manager and KMS roles
 * this stack has no resources for.
 *
 * Roles and omissions are argued in RUNBOOK-ci-bootstrap.md; the two IAM
 * grants CI cannot make for itself (state bucket, KMS key) are there too.
 */
export const deployerSa = new gcp.serviceaccount.Account('shared-infra-deployer-sa', {
  accountId: 'shared-infra-deployer',
  displayName: 'branchLeft shared edge - GitHub Actions CI/CD identity',
});

export const deployerMember = pulumi.interpolate`serviceAccount:${deployerSa.email}`;

/**
 * Project-level roles. **Adding one here is not applicable by CI** — the
 * deployer holds no `resourcemanager.projects.setIamPolicy`, so a new entry
 * 403s and aborts the whole update, unrelated changes included. Grant it with
 * `gcloud projects add-iam-policy-binding`, `pulumi import` it, then merge.
 */
const projectRoles: Array<[string, string]> = [
  // Every compute resource in edge.ts. No predefined role separates creating
  // a backend service from deleting one, which is why the delete guard in
  // scripts/assert-no-edge-deletes.py is load-bearing rather than belt-and-
  // braces. Also carries `securityPolicies.use`, needed to attach the Cloud
  // Armor policy, but not `securityPolicies.update` — that is the role below.
  ['deployer-load-balancer-admin', 'roles/compute.loadBalancerAdmin'],

  // The Cloud Armor policy and its rules.
  ['deployer-security-admin', 'roles/compute.securityAdmin'],

  // Certificate Manager, deliberately `editor` and not `owner`. The two
  // differ only in that owner adds `.delete` on certs, cert maps, cert map
  // entries and DNS authorizations. Withholding it means no CI run can
  // detach a hostname's certificate from the edge, whatever the plan says —
  // a guarantee the delete guard cannot make, because it holds against any
  // API call this identity can issue rather than only the ones Pulumi makes.
  // Consequence: removing a site from sites.ts 403s in CI, by design.
  ['deployer-certificate-manager-editor', 'roles/certificatemanager.editor'],
];

for (const [name, role] of projectRoles) {
  new gcp.projects.IAMMember(name, {
    project: projectId,
    role,
    member: deployerMember,
  });
}

export const deployerServiceAccountEmail = deployerSa.email;
