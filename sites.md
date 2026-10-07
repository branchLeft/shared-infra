# The site registry

**Hostnames and service addressing only.** Nothing else about a site belongs
in this file: no member counts, no commercial terms, no contact details, no
personal data. A site appears here only if whoever it belongs to is content
to be served from a hostname anyone can read, and the entry says nothing
about them beyond the hostname itself.

## One edge reads this file now

`hetzner/edge/render.ts` derives the Caddy and CrowdSec configuration for
the Hetzner edge VM from these entries; `hetzner/monitoring/render.ts`
derives blackbox probe targets from them too. A second edge used to read
it — `edge.ts` declared a GCP load balancer from the same registry — until
the GCP estate was destroyed and that program was deleted once it
described infrastructure that no longer existed.

`cloudRunService` and `region` below are what `edge.ts` used to read; no
code reads them any more. They are left on existing entries rather than
stripped as part of that deletion — pruning them, and the GCP-specific
onboarding steps that used to follow this comment, is its own pass, not a
side effect of removing the program that read them.

## Onboarding a site to the Hetzner edge

One entry with a `privateUpstream` — see that type's own doc comment in
`siteTypes.ts` for what it needs, and `hetzner/edge/render.ts` for how the
renderer turns it into a Caddy site block. There is no GCP-side step any
more.

A hostname with nowhere to proxy to -- a fixed page the edge answers
itself -- is a `StaticSite` in `staticSites` below instead, never an
`EdgeSite` with `privateUpstream` left out: that combination already means
"not rendered at all" here.

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
