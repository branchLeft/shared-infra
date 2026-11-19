# `render.ts` notes (the tenant edge)

CMT-3 pointer target for `hetzner/edge-t/render.ts`. Update this doc, not a long comment
block, when any of the following changes.

## The tenant profile

edge-t is the tenants project's web edge. It runs the same Compose stack shape as the
estate's edge (Caddy and CrowdSec, one unit `branchleft-compose@edge`, one pin) and is
delivered by the same role, `ansible/roles/edge_stack`, selected by
`edge_stack_profile: tenant`. This directory is that profile's source of truth, as
`hetzner/edge/stack/` is the estate's. The two differ in four ways, each on purpose:

1. **No hostname is written into any file.** The estate's files name the registry's
   hostnames. A tenant's name is data (ISSUE branchLeft/workspace#1802), so this
   profile's renderer takes no registry and no hostname. The three Ghost-specific
   CrowdSec files are rendered with the `EVERY_HOST` scope
   (`hetzner/edge/render.md`, "Host scope of the Ghost files"). `render.test.ts` scans every
   rendered and every committed file for every name the estate registry serves or
   redirects, and for the estate's domain, and fails on one.
2. **One catch-all and no site.** The Caddyfile has the same global options and probe
   listeners as the estate's, a metrics listener, and one block on `:80` that answers
   every request no tenant block claims with 503 (the throttle and the bouncer in front,
   no AppSec, which has nothing to inspect on a refused request). With no tenant block
   the edge therefore answers 503 for every name and serves nothing. Tenant blocks and
   on-demand certificates are #1802 and #3823; the catch-all is what an unregistered
   name keeps getting after they land. No `:443` block is rendered, so a TLS handshake for
   a name with no certificate fails and nothing is issued for it.
3. **Fewer CrowdSec files.** The Nextcloud profile and the verified-session whitelist are
   the estate's and have no tenant counterpart yet: nothing on this edge is Nextcloud, and
   no site here verifies sessions with the edge. Compose does not mount a `parsers`
   directory for the same reason.
4. **This host's address and name.** The metrics ports are published on
   `TENANTS_HOST_IPS.edgeT`, and CrowdSec's hostname is `edge-t`.

The posture is spelled out in `TENANT_POSTURE`, with the estate's values today, so a
posture change on one edge does not move the other.

## What is held equal to the estate's, and how

- The CrowdSec image line of `stack/compose.yml` equals the estate's, so a bump of one
  that is not made to the other fails here. That is why the tenant stack has no
  Dependabot entry or hub-pin check of its own.
- The meaningful lines of `stack/crowdsec/config.yaml.local` equal the estate's.
- The bytes the estate renderer makes without a hostname (the acquisition files, the
  ban ladder, the watch-only list) are reused, under this profile's banner. The banner
  swap refuses a file that does not begin with the estate's banner.
