/**
 * The shape of the hostname registry in `sites.ts`.
 *
 * **This file must not import anything.** Two edges consume the registry — the
 * GCP load balancer in `edge.ts`, and the Hetzner Caddy renderer in
 * `hetzner/edge/` — and they live in separate npm packages with disjoint
 * dependency trees. A single import of `@pulumi/gcp` or of `./config` here
 * makes the registry unreadable from the other side, and the alternative to
 * reading it is a second copy of the hostname list.
 */

/** Where a site's traffic goes on the Hetzner private network. */
export interface PrivateUpstream {
  /**
   * A host name from the estate address plan (`@branchleft/hetzner-host`), not
   * an address. The renderer resolves it and fails on an unknown name, so a
   * typo is a failed render rather than a Caddy config proxying to nothing.
   */
  host: string;
  /** Port the service listens on over the private network. */
  port: number;
}

export interface EdgeSite {
  /** Prefix for this site's Pulumi resource names and GCP resource names. */
  name: string;
  /** Every hostname routed to this site. Each gets a certificate-map entry. */
  hostnames: string[];
  /**
   * The *name* of the Cloud Run service to route to — a plain string, not a
   * resource reference. See "No dependency on any product stack" in `edge.ts`.
   *
   * Absent means the site has no GCP backend: it is skipped entirely by
   * `edge.ts`, the mirror of what an absent `privateUpstream` does on the
   * Hetzner side. Without the option, a site born on Hetzner cannot be
   * registered at all — adding one derives a serverless NEG, a backend
   * service, a DNS authorization, a managed certificate and a URL-map rule
   * for a Cloud Run service that does not exist, and the certificate then
   * sits in AUTHORIZING forever because the hostname's A record points at the
   * Hetzner edge and no `_acme-challenge` CNAME is ever published for it.
   *
   * **This is for a site that never had a GCP backend, not for retiring one.**
   * Dropping the field from an existing GCP-served site makes `edge.ts` stop
   * declaring its NEG, backend service, DNS authorization, certificate and
   * certificate-map entry — all five are in `PROTECTED_TYPES` in
   * `scripts/assert-no-edge-deletes.py`, so `deploy-plan` refuses the plan and
   * the apply never runs. If that site is the *first* registry entry, the
   * assertion in `edge.ts` fails the stack outright instead. Retiring a site
   * from the GCP edge is its own procedure and needs the delete guard consulted
   * deliberately; it is not this field.
   */
  cloudRunService?: string;
  /**
   * Region the Cloud Run service lives in — the serverless NEG must match.
   * Omitted means the edge stack's own `region` config value.
   */
  region?: string;
  /**
   * Keep the injection WAF rules (sqli/xss/rce) in preview for this site's
   * hostnames instead of enforcing them. Set it for any site with an
   * authenticated authoring surface: a Ghost admin API request body carries
   * author-written HTML, code samples and SQL, which is indistinguishable from
   * an injection payload at sensitivity 1. A false positive there locks the
   * owner out of publishing rather than degrading a page.
   *
   * The two edges honour this flag differently, and the difference is not
   * only one of scope:
   *
   * - **GCP.** The three injection rulesets go to preview for the whole
   *   hostname. `lfi` enforces regardless — its signatures match filesystem
   *   paths (`.env`, `.git/config`, `../`), which no legitimate request here
   *   contains.
   * - **Hetzner.** The exemption is one path prefix rather than a hostname,
   *   but on that prefix it removes *every* AppSec rule, the `lfi` analogues
   *   included — the handler is per-request, so a rule family cannot be kept
   *   back. Narrower in one direction, wider in the other, and recorded as such
   *   in `CLOUD-ARMOR-BASELINE.md`'s named differences.
   */
  injectionWafPreviewOnly?: boolean;
  /**
   * Where the Hetzner edge proxies this site. Absent means the site has no
   * private-network backend yet: it is skipped entirely by the Caddy renderer,
   * which is what keeps the edge from requesting a certificate for a hostname
   * it could not serve — a failed HTTP-01 validation loop costs Let's Encrypt
   * failure budget for the whole account, not just for that hostname.
   */
  privateUpstream?: PrivateUpstream;
}

/** A host-level redirect, e.g. `www.example.com` → `example.com`. */
export interface HostRedirect {
  /** The hostname that should redirect rather than serve content. */
  from: string;
  /** The hostname to redirect to. */
  to: string;
}
