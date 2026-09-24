/**
 * The shape of the hostname registry in `sites.ts`.
 *
 * **This file must not import anything.** The Hetzner Caddy renderer in
 * `hetzner/edge/` consumes the registry, in its own npm package with its own
 * dependency tree — an import here would make the registry unreadable from
 * there. A GCP load balancer (`edge.ts`) used to read it too, until it was
 * deleted once the GCP estate it described was destroyed; this constraint
 * predates that and outlives it.
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
  /** This site's identifier in generated config and log output. */
  name: string;
  /** Every hostname routed to this site. Each gets a certificate-map entry. */
  hostnames: string[];
  /**
   * The *name* of the Cloud Run service the now-deleted GCP edge (`edge.ts`)
   * used to route to — a plain string, not a resource reference. Vestigial:
   * `edge.ts` was deleted once the GCP estate it described was destroyed,
   * so nothing reads this field any more.
   * Existing entries keep it rather than have it stripped as a side effect of
   * that deletion; pruning it from the type and every entry is its own pass.
   */
  cloudRunService?: string;
  /**
   * Vestigial, same reasoning as `cloudRunService` above: the region the GCP
   * edge's serverless NEG had to match. Nothing reads it any more.
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
   * The Hetzner edge honours this as one path prefix rather than a whole
   * hostname, and on that prefix it removes *every* AppSec rule, `lfi`
   * included — the handler is per-request, so a rule family cannot be kept
   * back individually.
   */
  injectionWafPreviewOnly?: boolean;
  /**
   * Maximum request body this edge will accept for the site, as a Caddy size
   * string — the tenant stack's `edgeRequestBodyMaxSize` output, copied
   * verbatim. `RUNBOOK-tenant-onboarding.md` §9 in `branchLeft/ghost-platform`
   * is where it comes from; it is derived there from the same input as the
   * container's `/tmp` ceiling so the two cannot disagree, and setting a
   * different number here by hand defeats that.
   *
   * **Binary units only — `MiB`, never `MB`.** Caddy reads `MB` as a power of
   * ten while every other number in that derivation is a power of two, and a
   * ~4.4% disagreement in a set of values whose whole purpose is that they
   * cannot disagree is still a disagreement. The renderer rejects `MB`.
   *
   * **Required for every site this edge serves**, and the renderer refuses to
   * emit a site block without it. For a Ghost tenant it is the only bound that
   * exists on the image, media, file and content-import paths — Ghost's
   * generic upload middleware sets none, and the tmpfs `size=` is a backstop
   * that fails one upload with `ENOSPC` rather than a control. For a
   * non-tenant site it is a bound chosen from that site's own request shapes.
   *
   * Optional in the type because a site with no `privateUpstream` is not
   * rendered by this edge at all and needs none.
   */
  requestBodyMaxSize?: string;
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

/**
 * A hostname the Hetzner edge answers directly with a fixed page, proxying
 * nowhere. Distinct from `EdgeSite` rather than an `EdgeSite` with an absent
 * `privateUpstream`, because that combination already means something else
 * here: `privateUpstream` absent is how a site is *skipped* by the renderer
 * (see its own doc comment). A static site is the opposite -- always
 * rendered, never proxied.
 *
 * Hostname and addressing only, same rule as the rest of this registry: the
 * page content itself lives in a file under `hetzner/edge/`, keyed by `name`,
 * so that changing the words on the page never touches this file.
 */
export interface StaticSite {
  /** This site's identifier in generated config and log output, and the key its page content is looked up by. */
  name: string;
  /** The single hostname this page answers on. No `www`, no subdomain, no wildcard -- each needs its own deliberate entry. */
  hostname: string;
}
