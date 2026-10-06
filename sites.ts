import type { EdgeSite, HostRedirect, StaticSite } from './siteTypes';

/**
 * The site registry -- everything this load balancer serves. Hostnames and
 * service addressing only: nothing else about a site belongs in this file.
 * What reads it, and how to onboard a site, is in `sites.md`.
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
    // Port and ceiling belong to the tenant's own stack; where each is read
    // from, and why they can drift, is in `sites.md`.
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
