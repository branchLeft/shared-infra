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
 * ## One edge reads this file now
 *
 * `hetzner/edge/render.ts` derives the Caddy and CrowdSec configuration for
 * the Hetzner edge VM from these entries; `hetzner/monitoring/render.ts`
 * derives blackbox probe targets from them too. A second edge used to read
 * it — `edge.ts` declared a GCP load balancer from the same registry — until
 * the GCP estate was destroyed and that program was deleted once it
 * described infrastructure that no longer existed.
 *
 * `cloudRunService` and `region` below are what `edge.ts` used to read; no
 * code reads them any more. They are left on existing entries rather than
 * stripped as part of that deletion — pruning them, and the GCP-specific
 * onboarding steps that used to follow this comment, is its own pass, not a
 * side effect of removing the program that read them.
 *
 * ## Onboarding a site to the Hetzner edge
 *
 * One entry with a `privateUpstream` — see that type's own doc comment in
 * `siteTypes.ts` for what it needs, and `hetzner/edge/render.ts` for how the
 * renderer turns it into a Caddy site block. There is no GCP-side step any
 * more.
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
    //
    // Both values below belong to the tenant's own stack and neither is chosen
    // here. They are read differently, which matters when copying them:
    //
    //   port    -- `blog-infra:hostPort` in that repo's Pulumi.<slug>.yaml.
    //              It is NOT a stack output; `pulumi stack output hostPort`
    //              returns nothing. Read the config.
    //   ceiling -- `pulumi stack output edgeRequestBodyMaxSize`, derived in
    //              the tenant component as half the container's tmpfs ceiling.
    //
    // The copy into this file is an unchecked transcription, so the two can
    // drift: if this tenant ever sets `uploadCeilingMib`, the output moves and
    // this line does not, and the edge then admits more than the container can
    // hold. Nothing compares them -- re-read both on any change to either.
    privateUpstream: { host: 'app1', port: 8101 },
    requestBodyMaxSize: '64MiB',
    // Ghost-backed: its admin API carries author-written HTML and code, which
    // trips the injection signatures. Every Ghost tenant added here needs this
    // until there is enough admin-API traffic to prove otherwise.
    injectionWafPreviewOnly: true,
  },

  {
    name: 'nextcloud1',
    // Renamed from book.branchleft.co.uk: the site outgrew the booking-page
    // name it launched with -- Calendar, Talk/video and Files are all in use
    // now -- and cloud.<domain> is this estate's convention for a
    // self-hosted Nextcloud instance. The old hostname's DNS record stays
    // live until the new one is confirmed working, then is removed manually
    // at the registrar; nothing in this repo declares DNS.
    hostnames: ['cloud.branchleft.co.uk'],
    // No cloudRunService: this site was born on Hetzner and never had a GCP
    // backend, per this field's own doc in siteTypes.ts.
    //
    // Plain Nextcloud (official image over ordinary Compose), not AIO --
    // see estate.ts's nextcloud1 comment for why AIO is ruled out on this
    // host. 11000 is an arbitrary host-side port chosen for this deploy,
    // bound to nextcloud1's private IP in its compose file, not a value
    // Nextcloud itself picks -- the two must move together, same convention
    // as the blog entry above.
    privateUpstream: { host: 'nextcloud1', port: 11000 },
    // Calendar/Talk attachments and avatars, not general file sync. Raise
    // deliberately if a real bulk-upload use case shows up.
    requestBodyMaxSize: '100MiB',
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
