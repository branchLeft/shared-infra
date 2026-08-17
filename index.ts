import { createEdge } from './edge';
import { sites, hostRedirects } from './sites';

// The shared edge load balancer. Every branchLeft-operated hostname on the
// public internet is served through this one LB — the marketing site today,
// Ghost tenants as they are onboarded. Sites join by adding an entry to
// `sites.ts`; nothing in this file changes when one does.
const edge = createEdge(sites, hostRedirects);

// The A-record target for every hostname on the edge. Cutting a hostname's
// DNS to this is the point of no easy return in any onboarding or migration.
export const edgeIpAddress = edge.ipAddress;

// `_acme-challenge.*` CNAMEs to publish at the registrar (IONOS today).
// Certificates sit in AUTHORIZING until these resolve; allow 15–20 minutes
// for issuance after they do, then ~2 more minutes before the edge actually
// serves the certificate.
export const certificateDnsAuthorizationRecords = edge.dnsAuthorizationRecords;

// For polling issuance and for reading Cloud Armor's preview-mode verdicts:
//   gcloud certificate-manager certificates describe <name> --project=...
//   gcloud logging read 'jsonPayload.enforcedSecurityPolicy.name="<policy>"'
export const certificateNames = edge.certificateNames;
export const securityPolicyName = edge.securityPolicyName;

// Set as the `GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_DEPLOYER_SA_EMAIL` repo
// variables, which is how the CI deploy job reaches this stack — see
// RUNBOOK-ci-bootstrap.md. Outputs rather than committed literals: the
// provider's resource name embeds the GCP project number.
export { workloadIdentityProvider as ciWorkloadIdentityProvider } from './workloadIdentity';
export { deployerServiceAccountEmail as ciDeployerServiceAccountEmail } from './serviceAccounts';
