# The site registry

**Hostnames and service addressing only.** Nothing else about a site belongs
in this file: no member counts, no commercial terms, no contact details, no
personal data. A site appears here only if whoever it belongs to is content
to be served from a hostname anyone can read, and the entry says nothing
about them beyond the hostname itself.

## One edge reads this file now

`hetzner/edge/render.ts` derives the Caddy and CrowdSec configuration for
the Hetzner edge VM from these entries; `hetzner/monitoring/render.ts`
derives blackbox probe targets from them too, and `hetzner/status/render.ts` derives
the status page's probes from the same list. No other edge reads this file.

`cloudRunService` and `region` on some entries are vestigial: no code reads
them any more. Pruning them is its own pass.

## Onboarding a site to the Hetzner edge

One entry with a `privateUpstream` — see that type's own doc comment in
`siteTypes.ts` for what it needs, and `hetzner/edge/render.ts` for how the
renderer turns it into a Caddy site block.

A hostname with nowhere to proxy to -- a fixed page the edge answers
itself -- is a `StaticSite` in `staticSites` below instead, never an
`EdgeSite` with `privateUpstream` left out: that combination already means
"not rendered at all" here.

## Inbound webhook sites

An entry with `inboundWebhookPath` is a site that only receives signed callbacks; what
the edge lets through for it is in `hetzner/edge/render.md`, "`siteBlock`: inbound
webhook". Its hostname and port are owner decisions, so the entry names them through
two constants at the top of this file that read `undefined` until the owner supplies
them. While either is unset the entry claims no hostname and has no `privateUpstream`,
so it is skipped like any site with nowhere to proxy to: no block, no certificate
request, no probe target. This is the one case where an `EdgeSite` without a
`privateUpstream` is expected, and the registry test allows it only because the entry
also claims no hostname.

Setting both is a deliberate step: the upstream host is `edge1`, which the renderer
refuses except on the ports in `EDGE_HOST_ALLOWED_PORTS`, so the port must be added
there in the same change.

## Signed object gateway sites

An entry with `signedObjectGateway` is the tenant-state gateway: an S3-compatible service
whose clients sign their own requests. What the edge lets through for it is in
`hetzner/edge/render.md`, "`siteBlock`: signed object gateway". Its hostname is ruled
(`state.branchleft.co.uk`, in the zone file under `hetzner/dns/`), but the private address
of the gateway host is not in this repository, so the entry names its upstream through two
constants at the top of `sites.ts` that read `undefined` until the host exists. While
either is unset the entry claims no hostname and has no `privateUpstream`, so it is skipped
like any site with nowhere to proxy to: no block, no certificate request, no probe target.

Setting both is one deliberate change with three parts: the gateway host's name and address
in the estate address plan (`hetzner-host/addressPlan.ts`); the two constants; and, if the
host is `edge1`, a port in `EDGE_HOST_ALLOWED_PORTS`. The `A` record for the hostname is
already in the zone, and it must be applied before the entry is: Caddy requests a certificate as
soon as the block renders, and a failed HTTP-01 validation costs the account's failure
budget. Once set, the monitoring and status probes read `/healthz`, not the root, which the
gateway answers 404 by design.

## Copying a tenant's port and ceiling

Both values on a tenant's entry belong to that tenant's own stack and neither
is chosen in `sites.ts`. They are read differently, which matters when copying
them:

- **port**: `blog-infra:hostPort` in that repository's `Pulumi.<slug>.yaml`.
  It is not a stack output; `pulumi stack output hostPort` returns nothing.
  Read the config.
- **ceiling**: `pulumi stack output edgeRequestBodyMaxSize`, derived in the
  tenant component as half the container's tmpfs ceiling.

The copy into `sites.ts` is an unchecked transcription, so the two can drift:
if the tenant ever sets `uploadCeilingMib`, the output moves and the entry does
not, and the edge then admits more than the container can hold. Nothing
compares them. Re-read both on any change to either.

## The request body ceiling

`requestBodyMaxSize` is the maximum request body this edge will accept for a
site, as a Caddy size string. For a Ghost tenant it is the tenant stack's
`edgeRequestBodyMaxSize` output, copied verbatim. `RUNBOOK-tenant-onboarding.md`
section 9 in `branchLeft/ghost-platform` is where it comes from: it is derived
there from the same input as the container's `/tmp` ceiling so the two cannot
disagree, and setting a different number here by hand defeats that.

**Binary units only: `MiB`, never `MB`.** Caddy reads `MB` as a power of ten
while every other number in that derivation is a power of two, and a ~4.4%
disagreement in a set of values whose whole purpose is that they cannot
disagree is still a disagreement. The renderer rejects `MB`.

**Required for every site this edge serves**, and the renderer refuses to emit
a site block without it. For a Ghost tenant it is the only bound that exists on
the image, media, file and content-import paths: Ghost's generic upload
middleware sets none, and the tmpfs `size=` is a backstop that fails one upload
with `ENOSPC` rather than a control. For a non-tenant site it is a bound chosen
from that site's own request shapes.

Optional in the type because a site with no `privateUpstream` is not rendered
by this edge at all and needs none.

## The authoring exemption

`injectionWafPreviewOnly` keeps the injection WAF rules (sqli/xss/rce) in
preview for a site's hostnames instead of enforcing them. Set it for any site
with an authenticated authoring surface: a Ghost admin API request body carries
author-written HTML, code samples and SQL, which is indistinguishable from an
injection payload at sensitivity 1. A false positive there locks the owner out
of publishing rather than degrading a page.

The Hetzner edge honours this as one path prefix rather than a whole hostname,
and on that prefix it removes _every_ AppSec rule, `lfi` included: the handler
is per-request, so a rule family cannot be kept back individually.

## Static sites

A `StaticSite` is distinct from an `EdgeSite` with an absent `privateUpstream`,
because that combination already means something else here: `privateUpstream`
absent is how a site is _skipped_ by the renderer. A static site is the
opposite: always rendered, never proxied.

Hostname and addressing only, same rule as the rest of this registry: the page
content itself lives in a file under `hetzner/edge/`, keyed by `name`, so that
changing the words on the page never touches this file.

## Shared tenant domain files

The `sites-tenant-signals` entry serves `sites.publicpress.co.uk`, the apex of the
shared tenant domain (customer sites are `*.sites.publicpress.co.uk`, ruled as D10 in
`ghost-platform-docs/19-try-it-now-design/00-high-level-design.html`). Its two files
say that PublicPress hosts those sites and does not publish, author or endorse them.
Their text is in `hetzner/edge/sharedTenantFiles.ts`, and every wording there is an
ALL_CAPS placeholder until the owner supplies the prose.

Only the files that carry that meaning to a reader that reads them:

- `/robots.txt`, RFC 9309. Read by crawlers. It governs only the host it is served on,
  so this apex file does not reach a tenant subdomain. The file is comment-only, so it
  sets no crawl rule and states no crawl policy; the AI-crawler default stays open.
- `/.well-known/security.txt`, RFC 9116. Read by security researchers and their tooling.
  `Contact` and `Expires` are required by the RFC. The contact is
  `SHARED_TENANT_ABUSE_CONTACT`, the abuse role mailbox, defined in that same file
  because it is its only user. `Expires` is 2027-11-07; renew it before it passes.

No convention for a generic "we host this, we do not publish it" file was found, so none
is built. The sources are the RFC texts above, cited from the RFC numbers and not
re-fetched in the build that added these files.

The apex serves these files and nothing else. A tenant's own hostname is not covered:
the registry has no wildcard, and each tenant that needs a file is its own deliberate
entry.

## What the site runs

`backend` is `ghost` for a Ghost tenant and `other` for everything else, and
every entry with a `privateUpstream` must declare one: a registry test fails
for an entry that does not, so a new Ghost tenant cannot silently miss the
rules below.

Ghost accepts `.js`, `.html` and `.css` as uploads, and also `.txt`, `.md`,
`.json`, `.pdf`, `.zip` and `.py`, and serves them all from the tenant's own
origin under `/content/files/`, `/content/images/` and `/content/media/`. So an
uploaded script satisfies `script-src 'self'`. For `ghost` the edge therefore
does two things:

- answers 403 to any request under those prefixes for a file of an active type
  (script, HTML, XML, stylesheet, SVG), whatever the method;
- sets `X-Content-Type-Options: nosniff` on every response, error responses
  included, because the extension list cannot name every type: a browser runs
  a same-origin `<script src>` of a response typed `text/plain` or
  `application/json` unless `nosniff` is set.

Theme assets, the admin and `/content/public/` are untouched. An `other` site
changes in no way.

A `ghost` entry may also carry `media`, its object-storage host and bucket
(`branchleft-media-<slug>`, copied from the tenant stack like the port). The
edge then answers those three upload paths itself by reading the bucket, so a
reader's browser need not contact the storage host: `hetzner/edge/render.md`,
"Tenant media". The renderer refuses a bucket that is not a tenant media
bucket name, so an entry cannot point the edge at a state or backup bucket.
