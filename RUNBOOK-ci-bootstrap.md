# RUNBOOK — bootstrapping CI applies for the shared edge

`.github/workflows/ci.yml` applies this stack on every push to `main`. It can
only do that once a CI identity exists, and that identity cannot create itself:
the deployer holds no permission to grant itself a role, and Pulumi cannot log
in to the state bucket it must be granted access to first.

So the first apply is by hand, once, by the platform owner. Everything after it
is CI's.

Run every command from a checkout of the branch that introduces this file,
**before merging it**. Merging first leaves one red CI run — the deploy job
fails at the token exchange, because the provider it names does not exist yet.

---

## Step 1 — create the identity, and nothing else

```bash
pulumi login gs://branchleft-pulumi-state
pulumi stack select production

STACK=urn:pulumi:production::branchleft-shared-infra

pulumi up \
  --target "$STACK::gcp:serviceaccount/account:Account::shared-infra-deployer-sa" \
  --target "$STACK::gcp:projects/iAMMember:IAMMember::deployer-load-balancer-admin" \
  --target "$STACK::gcp:projects/iAMMember:IAMMember::deployer-security-admin" \
  --target "$STACK::gcp:projects/iAMMember:IAMMember::deployer-certificate-manager-editor" \
  --target "$STACK::gcp:iam/workloadIdentityPool:WorkloadIdentityPool::shared-infra-gha-pool" \
  --target "$STACK::gcp:iam/workloadIdentityPoolProvider:WorkloadIdentityPoolProvider::shared-infra-gha-provider" \
  --target "$STACK::gcp:serviceaccount/iAMMember:IAMMember::shared-infra-gha-can-impersonate-deployer"
```

Expect **7 to create** and nothing else. The type tokens are as GCP's Pulumi
provider emits them, `iAMMember` casing included — they were taken from a real
`pulumi preview --json` of this program rather than constructed from the
resource class names, which do not match.

`--target` is doing real work here, not tidiness. An untargeted `pulumi up`
would also apply every other pending change in the program, and the first thing
CI should be seen to do is apply one. If the preview shows anything beyond
those seven resources, the target list is wrong — stop rather than continue.

## Step 2 — read the identity back out

```bash
pulumi stack output ciWorkloadIdentityProvider
pulumi stack output ciDeployerServiceAccountEmail
```

The first embeds the GCP project number, which is why it is a stack output and
not a committed literal. Keep both for step 5.

## Step 3 — let the deployer decrypt this stack's secrets provider

```bash
gcloud kms keys add-iam-policy-binding pulumi-secrets \
  --keyring=pulumi \
  --location=europe-west1 \
  --project=branchleft-prod \
  --member="serviceAccount:shared-infra-deployer@branchleft-prod.iam.gserviceaccount.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"
```

**Do not skip this because the stack has no secret config values.**
`Pulumi.production.yaml` carries an `encryptedkey` — a KMS-wrapped per-stack
data key — and Pulumi decrypts it every time it loads the stack, before it does
anything else. Without this binding CI fails at `pulumi preview` on the first
run, with a KMS permission error and nothing applied.

It stays a `gcloud` grant permanently, not just for bootstrap. Declaring it as a
`gcp.kms.CryptoKeyIAMMember` fails with `Permission
'cloudkms.cryptoKeys.getIamPolicy' denied`, and the only role that fixes that is
`roles/cloudkms.admin` — which would let the pipeline rewrite who may decrypt
its own secrets. `website/infra/KNOWN_ISSUES.md` records the same trap.

Verify:

```bash
gcloud kms keys get-iam-policy pulumi-secrets \
  --keyring=pulumi --location=europe-west1 --project=branchleft-prod \
  --format=json | grep shared-infra-deployer
```

## Step 4 — let the deployer read and write the state bucket

```bash
gcloud storage buckets add-iam-policy-binding gs://branchleft-pulumi-state \
  --member="serviceAccount:shared-infra-deployer@branchleft-prod.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"
```

Without it every CI run fails at `pulumi login` with a 403. Pulumi cannot grant
itself access to the bucket it must log in to before it can grant anything, so
this binding can never come from the program.

Bucket-scoped on purpose — `serviceAccounts.ts` gives the deployer no
project-level storage role that would shortcut it. **Disclosed residual:**
`gs://branchleft-pulumi-state` holds the state for every stack in the project,
so `objectAdmin` on it lets a compromised run here read or corrupt the website's
and the platform's state too. Narrowing that needs one bucket per stack, which
is a change to four repos and their runbooks, not to this one. It is the same
grant `website/infra`'s and the platform's deployers already hold.

Verify:

```bash
gcloud storage buckets get-iam-policy gs://branchleft-pulumi-state \
  --format=json | grep shared-infra-deployer
```

## Step 5 — point the workflow at the identity

```bash
gh variable set GCP_PROJECT_ID --repo branchLeft/shared-infra --body "branchleft-prod"
gh variable set GCP_WORKLOAD_IDENTITY_PROVIDER --repo branchLeft/shared-infra --body "<step 2 output>"
gh variable set GCP_DEPLOYER_SA_EMAIL --repo branchLeft/shared-infra --body "<step 2 output>"
```

Variables, not secrets, and deliberately: none of the three is a credential, all
three appear in run logs anyway, and a masked value is much harder to debug a
failed token exchange with. What stops another repo using them is the provider's
`attributeCondition`, not their obscurity.

## Step 6 — merge

The push to `main` runs the deploy job. Its first apply is whatever was pending
in the program at that point — the seven identity resources are already in state
from step 1, so they show as unchanged.

---

## Verifying an apply

`pulumi preview` compares the program to Pulumi _state_, never to live GCP, so a
clean preview is evidence about the checkpoint and not about the edge. For the
Cloud Armor policy in particular the provider writes rules as independent
per-priority API calls, and a partial failure leaves live and state disagreeing
with no diff to show for it — `RUNBOOK-edge-state-move.md` appendix A is that
incident. After any apply that changed the policy, read the policy itself:

```bash
gcloud compute security-policies describe branchleft-edge-armor \
  --project=branchleft-prod \
  --format="table(rules[].priority,rules[].action,rules[].preview)"
```

---

## What CI can and cannot do

The deployer's roles are in `serviceAccounts.ts`. Three things follow that are
easy to mistake for bugs when they surface:

**A PR that adds a project-level role cannot be applied by CI.** The deployer
has no `resourcemanager.projects.setIamPolicy`, so the new `IAMMember` 403s, and
because a failed resource aborts the update it takes every unrelated change in
that run with it. Grant it with `gcloud projects add-iam-policy-binding`,
`pulumi import` it, then merge.

**A PR that edits `workloadIdentity.ts` cannot be applied by CI either.** No
`roles/iam.workloadIdentityPoolAdmin` and no `roles/iam.serviceAccountAdmin`,
deliberately: with them, any run in this repo could widen `attributeCondition`
to admit another repository and hand it the deployer. The control the federation
exists to provide would be modifiable by the thing it controls. Apply changes to
that file the way step 1 applies them.

**Removing a site from `sites.ts` cannot be applied by CI.** The deployer holds
`roles/certificatemanager.editor` rather than `owner`; the two differ only in
that owner adds `.delete` on certs, cert maps, cert map entries and DNS
authorizations. That makes "no CI run can detach a hostname's certificate from
the edge" true against any API call this identity can issue, not merely against
the plans Pulumi generates — a stronger statement than the delete guard can
make. Taking a site off the edge is a gated migration.

The compute roles carry no equivalent narrowing. `roles/compute.loadBalancerAdmin`
is the only predefined role that can create a backend service, and it can delete
one; there is nothing weaker to drop to. That is what
`scripts/assert-no-edge-deletes.py` is for, and why it protects the per-site
resource _types_ rather than a list of site names that would have to be edited
on every onboarding and would be forgotten on one.
