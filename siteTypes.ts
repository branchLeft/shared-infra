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
   * Set for any site with an authenticated authoring surface: the edge then
   * drops all AppSec rules on the admin API path prefix only. Why, and what
   * it costs: `sites.md` section "The authoring exemption".
   */
  injectionWafPreviewOnly?: boolean;
  /**
   * Maximum request body the edge accepts, as a Caddy size string in binary
   * units (`MiB`, never `MB`). Required for every site served. Why and where
   * the value comes from: `sites.md` section "The request body ceiling".
   */
  requestBodyMaxSize?: string;
  /**
   * One literal path the edge answers itself, never proxied: `POST` gets an
   * empty 204, any other method 405. It runs before AppSec. See `render.md`.
   */
  discardRoute?: string;
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
 * nowhere. Always rendered, never proxied; hostname and addressing only.
 * Why it is distinct from `EdgeSite`: `sites.md` section "Static sites".
 */
export interface StaticSite {
  /** This site's identifier in generated config and log output, and the key its page content is looked up by. */
  name: string;
  /** The single hostname this page answers on. No `www`, no subdomain, no wildcard -- each needs its own deliberate entry. */
  hostname: string;
}
