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
   */
  cloudRunService: string;
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
