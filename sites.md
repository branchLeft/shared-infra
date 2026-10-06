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
