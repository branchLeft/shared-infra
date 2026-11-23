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

/** Where a Ghost site's uploads are stored: an S3-compatible host and one bucket on it. */
export interface SiteMedia {
  /** The object-storage host, a bare hostname (path-style: the bucket is the first path segment). */
  host: string;
  /** The tenant's own bucket, `branchleft-media-<slug>`. */
  bucket: string;
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
   * Set for any site with an authenticated authoring surface. With
   * `trustedSession` only a verified staff session skips AppSec; without it the
   * edge drops all AppSec rules on the admin API path prefix only, never the
   * Content API. Why, and what it costs: `sites.md` section "The authoring
   * exemption".
   */
  injectionWafPreviewOnly?: boolean;
  /**
   * What the site runs, declared by every entry that has a `privateUpstream`
   * (a registry test fails for one that does not). `ghost` is a Ghost tenant:
   * the edge refuses an uploaded script, document or stylesheet under Ghost's
   * upload paths and sets `nosniff` on every response, because Ghost serves a
   * tenant's uploads from the tenant's own origin. `nextcloud` is a Nextcloud
   * instance: the edge gives it a larger throttle budget and keeps its own
   * normal traffic out of CrowdSec's log scenarios (`hetzner/edge/render.md`,
   * "Nextcloud profile"). `other` is anything else and gets none of these. Why,
   * and what it leaves alone: `sites.md` section "What the site runs".
   */
  backend?: 'ghost' | 'nextcloud' | 'other';
  /**
   * A `ghost` site's media bucket. The edge then answers Ghost's upload paths
   * (`/content/images/`, `/content/media/`, `/content/files/`) itself, reading
   * the object from this bucket, so a reader's browser never contacts the
   * storage host. Absent: those paths reach Ghost, whose S3 adapter redirects
   * the browser to the bucket. The bucket name is derived from the tenant slug
   * in `branchLeft/ghost-platform` and copied here by hand, like the port and
   * the body ceiling. Why: `hetzner/edge/render.md`, "Tenant media".
   */
  media?: SiteMedia;
  /**
   * A signed-in session the edge verifies with the site itself before the
   * CrowdSec bouncer and AppSec. A request whose session the site confirms is
   * never refused by an IP ban or an AppSec verdict, and its access-log line is
   * whitelisted out of every CrowdSec bucket; a request without one, or whose
   * session the site refuses, is treated as if this field were absent.
   * `ghost-staff` (a Ghost site only): the staff session cookie on `/ghost/*`,
   * checked against that site's own Ghost. Ghost members are never trusted.
   * Why, and what still protects a stolen session: `hetzner/edge/render.md`,
   * "Verified sessions".
   */
  trustedSession?: 'ghost-staff';
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
   * One literal path of a site that exists only to receive signed callbacks
   * from an outside sender. Set, the edge proxies `POST` on that path alone,
   * answers 405 to any other method on it and 404 to every other path, and
   * throttles it in a zone of its own. Why, and what it lets through:
   * `hetzner/edge/render.md`, "`siteBlock`: inbound webhook".
   */
  inboundWebhookPath?: string;
  /**
   * Set on a site that is a signed object-store gateway: a service that speaks
   * path-style S3 requests signed by the client, and answers `/healthz` and
   * `/readyz`. The edge then forwards only those request shapes, byte for byte
   * (it rewrites no path and touches no header the signature covers), never
   * caches a response, and answers 404 or 405 itself to everything else. Why,
   * and what it lets through: `hetzner/edge/render.md`, "`siteBlock`: signed
   * object gateway".
   */
  signedObjectGateway?: boolean;
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
 * A hostname the Hetzner edge answers directly with a fixed page, or a fixed
 * set of text files, proxying nowhere. Always rendered, never proxied;
 * hostname and addressing only. Why it is distinct from `EdgeSite`: `sites.md`
 * section "Static sites".
 */
export interface StaticSite {
  /** This site's identifier in generated config and log output, and the key its content (page or files) is looked up by. */
  name: string;
  /** The single hostname this content answers on. No `www`, no wildcard -- each needs its own deliberate entry; a named subdomain such as `sites.` is one such entry. */
  hostname: string;
}
