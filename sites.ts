import type { EdgeSite, HostRedirect } from './siteTypes';

/**
 * The site registry — everything this load balancer serves.
 *
 * **Hostnames and service addressing only.** Nothing else about a site belongs
 * in this file: no member counts, no commercial terms, no contact details, no
 * personal data. A site appears here only if whoever it belongs to is content
 * to be served from a hostname anyone can read, and the entry says nothing
 * about them beyond the hostname itself.
 *
 * ## Two edges read this file
 *
 * `edge.ts` derives the GCP load balancer from it, and `hetzner/edge/render.ts`
 * derives the Caddy and CrowdSec configuration for the replacement edge VM from
 * the same entries. During the migration both are true at once, which is why a
 * site carries both a `cloudRunService` and a `privateUpstream`: the first is
 * where it is served from today, the second is where it will be served from,
 * and a site gains the second only when its Hetzner backend actually exists.
 *
 * ## Onboarding a site
 *
 * One entry. Everything else is derived: a serverless NEG, a backend service
 * carrying the shared Cloud Armor policy, one DNS authorization and one
 * managed certificate per hostname, a certificate-map entry per hostname, and
 * a URL-map host rule.
 *
 * Before adding an entry:
 *
 * 1. Confirm the Cloud Run service name and region are exactly right. Nothing
 *    in this program validates them — `cloudRunService` is a plain string by
 *    design, so that this stack has no dependency on any product's stack. A
 *    wrong name applies cleanly and then 404s in production.
 *
 *        gcloud run services list --project=branchleft-prod \
 *          --format='table(metadata.name,metadata.labels."cloud.googleapis.com/location")'
 *
 * 2. Set that service's ingress to `internal-and-cloud-load-balancing` — in
 *    the product's own stack, not here. Without it the `run.app` hostnames
 *    stay publicly reachable and bypass this LB, Cloud Armor and the TLS
 *    configuration entirely. Cloud Run issues **two** `run.app` hostnames per
 *    service and both must be checked; the blocked response is 404, not 403.
 *
 * 3. After `pulumi up`, publish the `_acme-challenge` CNAME this program
 *    outputs for each new hostname. Certificates sit in AUTHORIZING until it
 *    resolves. Allow 15–20 minutes for issuance, not the 5 the sandbox
 *    measured — production took ~13 — and then a further ~2 minutes after
 *    ACTIVE before the edge actually presents the certificate. Poll the
 *    handshake, not the certificate's `state` field.
 *
 * 4. Only cut the hostname's **A** record to the edge's global IP once the
 *    handshake succeeds, and wait a full DNS TTL before locking
 *    ingress. Traffic counters are *not* a safe signal for that — they read
 *    as drained roughly 45 minutes before it is actually safe, because what
 *    they measure is bot traffic turning over, not resolver caches expiring.
 * 5. Confirm no **AAAA** record exists for the hostname (`dig AAAA <host>`
 *    against several public resolvers). The edge is IPv4-only by design — no
 *    IPv6 forwarding rule exists — so a stray AAAA (e.g. one a prior Cloud
 *    Run Domain Mapping auto-published) sends IPv6-preferring clients to a
 *    dead address once ingress locks, and presents as intermittent TLS
 *    failure rather than as a DNS problem. This has happened here: a Cloud
 *    Run Domain Mapping had auto-published an AAAA nobody was tracking.
 *
 * ## Ordering
 *
 * The first entry's backend service is the URL map's `defaultService` — the
 * fallback for a request whose Host matches no rule. Keep the marketing site
 * first so that fallback is never a tenant's service.
 */
export const sites: EdgeSite[] = [
  {
    name: 'website',
    hostnames: ['branchleft.co.uk', 'www.branchleft.co.uk'],
    cloudRunService: 'branchleft-website',
  },

  {
    name: 'blog',
    hostnames: ['blog.branchleft.co.uk'],
    cloudRunService: 'ghost-tenant-blog',
    // Ghost-backed: its admin API carries author-written HTML and code, which
    // trips the injection signatures. Every Ghost tenant added here needs this
    // until there is enough admin-API traffic to prove otherwise.
    injectionWafPreviewOnly: true,
  },
];

/**
 * Canonical-domain redirects (e.g. www → apex; apex is canonical here,
 * matching SITE_URL in the website's `app/lib/meta.ts`). A redirect source
 * must still appear in its site's `hostnames` above: it needs its own
 * certificate so the TLS handshake succeeds before the URL map redirects it.
 */
export const hostRedirects: HostRedirect[] = [
  { from: 'www.branchleft.co.uk', to: 'branchleft.co.uk' },
];
