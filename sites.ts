import type { EdgeSite, HostRedirect, StaticSite } from './siteTypes';

/**
 * The site registry: everything the Hetzner edge serves. Hostnames and service
 * addressing only; nothing else about a site belongs in this file.
 *
 * What the registry may hold, which renderers read it, why `cloudRunService`
 * and `region` linger, and how to onboard a site: see `sites.md`.
 */
export const sites: EdgeSite[] = [
  {
    name: 'website',
    hostnames: ['branchleft.co.uk', 'www.branchleft.co.uk'],
    cloudRunService: 'branchleft-website',
    // Port matches deploy/compose.yml's `website` service in
    // branchLeft/website -- the two must move together, and each states so.
    privateUpstream: { host: 'app1', port: 8080 },
    // Not derived from a tenant stack -- this site has none. An SSR marketing
    // site whose only request bodies are contact-form posts; 1MiB is orders of
    // magnitude above anything legitimate and replaces no ceiling at all,
    // which is what this site had. Raise it deliberately if a real upload
    // surface is ever added here.
    requestBodyMaxSize: '1MiB',
  },

  {
    name: 'blog',
    hostnames: ['blog.branchleft.co.uk'],
    // Vestigial: the GCP edge this named a Cloud Run service for is gone —
    // edge.ts was deleted once the GCP estate it described was destroyed —
    // and nothing reads `cloudRunService` any more. Left in place rather
    // than stripped as a side effect of that deletion; pruning it is its
    // own pass.
    cloudRunService: 'ghost-tenant-blog',
    // Port and ceiling both belong to the tenant's own stack and are copied
    // here by hand: see "Copying a tenant's port and ceiling" in `sites.md`.
    privateUpstream: { host: 'app1', port: 8101 },
    requestBodyMaxSize: '64MiB',
    // Ghost-backed: its admin API carries author-written HTML and code, which
    // trips the injection signatures. Every Ghost tenant added here needs this
    // until there is enough admin-API traffic to prove otherwise.
    injectionWafPreviewOnly: true,
  },

  {
    // The site keeps the Nextcloud stack's name, `nextcloud1`, not the host's:
    // it names the workload, and the edge's rate-limit zones derive from it.
    name: 'nextcloud1',
    // Renamed from book.branchleft.co.uk: the site outgrew the booking-page
    // name it launched with -- Calendar, Talk/video and Files are all in use
    // now -- and cloud.<domain> is this estate's convention for a
    // self-hosted Nextcloud instance. book.branchleft.co.uk stays listed
    // here, not dropped outright, purely so it keeps a certificate and can
    // still appear as a redirect source below -- see the hostRedirects entry
    // for why. Once the old DNS record is confirmed unused and removed at
    // the registrar, both this entry and that redirect should be deleted in
    // a follow-up change.
    hostnames: ['cloud.branchleft.co.uk', 'book.branchleft.co.uk'],
    // No cloudRunService: this site was born on Hetzner and never had a GCP
    // backend, per this field's own doc in siteTypes.ts.
    //
    // Plain Nextcloud (official image over ordinary Compose), not AIO --
    // see estate.ts's ops1 comment for why AIO is ruled out on this
    // host. 11000 is an arbitrary host-side port chosen for this deploy,
    // bound to ops1's private IP in its compose file, not a value
    // Nextcloud itself picks -- the two must move together, same convention
    // as the blog entry above.
    privateUpstream: { host: 'ops1', port: 11000 },
    // Calendar/Talk attachments and avatars, not general file sync. Raise
    // deliberately if a real bulk-upload use case shows up.
    requestBodyMaxSize: '100MiB',
  },

  {
    // The platform's customer-facing sign-in surface. The hostname is a
    // ruling (portal.publicpress.co.uk), not a choice made here.
    name: 'tenant-portal',
    hostnames: ['portal.publicpress.co.uk'],
    // Upstream port is the tenant portal's `PORT` on ops1; its compose file
    // must publish this value on ops1's private address, and the two move
    // together. The application defaults to 8080, which both portal apps
    // would share, so each is given its own number there.
    privateUpstream: { host: 'ops1', port: 8301 },
    // Form posts at sign-in and sign-out only; no upload surface exists.
    requestBodyMaxSize: '1MiB',
  },

  {
    // Staff-only, but reachable like any other site: the sign-in gate is the
    // application's, not a network ACL. Hostname is a ruling.
    name: 'owner-console',
    hostnames: ['console.branchleft.co.uk'],
    // The owner console's `PORT` on ops1; see the tenant-portal entry.
    privateUpstream: { host: 'ops1', port: 8302 },
    requestBodyMaxSize: '1MiB',
    // The reviewer GitHub App's webhook target: GitHub requires an active
    // URL before the App may subscribe to the deployment-protection event,
    // and nothing is read from it (the approval script polls). The suffix
    // keeps the path out of drive-by scans; it is not a secret.
    discardRoute: '/_github/reviewer-app-webhook-a91f3c07',
  },

  {
    // The sign-in service (Zitadel). Both applications fetch the issuer's keys
    // from this hostname, so it must stay reachable from outside. Hostname is
    // a ruling. Upstream is the sign-in service's private listener on ops1;
    // its compose file must publish this port, and the two move together.
    name: 'identity',
    hostnames: ['id.publicpress.co.uk'],
    privateUpstream: { host: 'ops1', port: 8300 },
    // Login form posts and token requests only; no upload surface exists.
    requestBodyMaxSize: '1MiB',
  },

  {
    // The owner's pager. Subscribers reach it here over TLS; publishers
    // inside the estate use the monitoring stack's own network instead. Auth
    // is on and anonymous access is denied by the instance itself, so this
    // entry exposes a login wall, not a topic.
    name: 'ntfy',
    hostnames: ['ntfy.branchleft.co.uk'],
    privateUpstream: { host: 'edge1', port: 2586 },
    // A page and a subscription request are a few hundred bytes.
    requestBodyMaxSize: '64KiB',
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
  // Temporary, for the book -> cloud cutover: anyone holding an old link
  // gets redirected rather than a hard break. Remove once book's DNS record
  // is retired (see the nextcloud1 entry above).
  { from: 'book.branchleft.co.uk', to: 'cloud.branchleft.co.uk' },
];

/**
 * Hostnames the edge answers directly with a fixed page instead of proxying.
 * `hetzner/edge/render.ts` looks up each entry's actual page content by
 * `name` from its own `hetzner/edge/publicpressHolding.ts` (or the
 * equivalent file for a future entry) -- this registry stays hostname and
 * addressing only, same rule as the rest of this file.
 */
export const staticSites: StaticSite[] = [
  {
    // No `www`, no `sites.*`, no wildcard: publicpress.co.uk's own eventual
    // platform, and its subdomains, are a separate onboarding when they
    // exist. This entry is a temporary holding page for the apex alone.
    name: 'publicpress-holding',
    hostname: 'publicpress.co.uk',
  },
];
