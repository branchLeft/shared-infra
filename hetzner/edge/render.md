# `render.ts` notes

CMT-3 pointer target: the narrative moved out of that file's comments lives
here. Update this doc, not a long comment block, when any of the following
changes.

## `MEMBERS_MAGIC_LINK_PATHS`

Ghost's members send-magic-link route (`ghost/core/core/server/web/members/app.js`,
mounted at `/members` by `ghost/core/core/server/web/parent/frontend.js`):
`POST /members/api/send-magic-link`. The one unauthenticated route that turns
a request into an email send from `mx1` -- see `posture.ts` for why it gets
its own, far tighter, throttle.

Both forms are listed because Express's default router (`strict: false`)
routes a trailing slash identically, and Caddy's `path` matcher does not
normalise one away -- an unmatched `/members/api/send-magic-link/` would
fall through to the general per-site zone instead, forty times looser.
Deliberately two exact patterns rather than a `*` suffix: a wildcard here
would also match any _longer_ path sharing this prefix, which is wider than
the one route this throttle exists for.

No case variants listed: confirmed against the exact `2.11.4` tag this
edge's image pins (`Dockerfile`'s `CADDY_VERSION`) that Caddy's `path`
matcher lowercases both the request path and every pattern before comparing
(`modules/caddyhttp/matchers.go`) -- its own stated rationale is that RFC
9110's case-sensitive path matching is a security footgun it deliberately
does not reproduce -- so `/Members/API/Send-Magic-Link` already matches
without listing it. Not assumed from a general Caddy version claim: checked
against this pin specifically.

Assumes one Ghost instance per hostname, rooted at `/` -- true of every site
in `sites.ts` today. A tenant served from a subdirectory rather than its own
hostname would need `/<prefix>` folded into both patterns below; nothing
here derives that prefix automatically.

## `AUTHORING_API_PATHS`

Paths exempted from AppSec evaluation on a site flagged `injectionWafPreviewOnly`.
Ghost's admin API is where author-written HTML, code samples and SQL arrive in a
request body; the admin UI around it is a static bundle carrying none, so the
prefix is the API and not `/ghost`.

The exemption removes **all** AppSec evaluation on these paths, not only the
injection rulesets -- the Caddy handler is per-request, so there is no way to
exempt three rule families and keep a fourth. That was a widening relative to the
GCP Cloud Armor policy this edge replaced, disclosed in that policy's baseline
document before it and the program that declared it (`edge.ts`) were deleted once
the GCP estate they described was destroyed.

## `MEMBERS_MAGIC_LINK_ZONE`

The same zone name is declared again in every site's own `rate_limit` block, not
shared by reference -- Caddy's directive syntax has no "reference elsewhere" form,
so each site block carries its own full zone declaration. What still makes it one
shared counter across every tenant hostname, rather than a per-site one like
`rateLimitDirective`: the module's zone state is a process-wide registry keyed by
name (`mholt/caddy-ratelimit`'s `LoadOrStore` on the zone map), so re-declaring
the identical name attaches to the same counter instead of creating a new one. See
`posture.ts` for why that sharing is the property Ghost's own per-instance limiter
lacks.

## `PROBE_HOSTNAME`

A second probe address on the same port, differing only in carrying a host.

The bare-port probe proves the handler chain runs; it cannot prove a request reaches
that chain _through a site block_, because a bare `:port` address matches every Host
and so exercises no host routing at all. A control that has only ever been tripped on
the bare port is one whose real delivery path -- Caddy selecting a site by Host, then
running its route -- has never executed.

`.invalid` is reserved by RFC 2606 and is guaranteed never to resolve, so this can
never collide with a tenant hostname or be reached from off-host, and the `http://`
scheme keeps Caddy from attempting ACME for a name no CA could ever validate. The
firewall does not open this port and Compose publishes it on `127.0.0.1` only, exactly
as for the bare-port probe.

It also makes the one property this control adds over Ghost's own limiter testable:
the magic-link zone is global across hostnames, so a budget spent on the bare-port
probe must already be spent when the same client arrives on this host. Ghost's
`membersAuthEnumeration` counts per instance and would not be. `RUNBOOK-edge.md` §8b(4)
is that test.

## `PROBE_MARKER_*` constants

Response header naming which probe block answered, and its two values.

The bare-port probe is a catch-all: it matches every Host, so it answers a request
carrying `Host: edge-probe.invalid` exactly as the host-qualified block would, whenever
that block is absent. Status code alone therefore cannot tell a delivered config from an
undelivered one -- a skipped `rsync` would produce the documented success signal with no
host routing exercised at all. The marker is the only thing that distinguishes them, and
so is what the verification actually reads.

## Module: Caddy configuration rendering

Renders the edge VM's Caddy and CrowdSec configuration from the hostname registry
in `sites.ts` and the enforcement posture in `posture.ts`.

Pure string building, deliberately: the output is committed under `stack/` and copied
onto the host by hand, so the only thing that can differ between what a reviewer reads
and what the edge runs is the copy step. `render.test.ts` is what keeps the committed
files and this file from drifting apart.

The registry is the only hostname list: a hostname written here rather than derived
from `sites.ts` is a hostname the GCP edge does not know about, which is precisely the
class of stray record the cutover has to find and fix. Everything below is derived.

## `hstsDirective`

`max-age=31536000` (365 days) with `includeSubDomains` is the standard baseline every
browser vendor documents for this header. `preload` is deliberately absent -- submitting
to a browser's preload list is a separate, slow-to-reverse decision (removal takes months
to propagate), not a rendering default this file should choose unilaterally.

Emitted for every real hostname this edge serves -- this is what closed the gap an admin
panel on `book.branchleft.co.uk` surfaced as a missing `Strict-Transport-Security` header
finding. The gap was edge-wide, not specific to that tenant: before this, nothing in this
file emitted any response header on any site.

Called first in each route, ahead of `request_body` and the protection chain, deliberately
-- `header` populates the response header map before calling the next handler, so whatever
runs afterwards (a proxied response, a 429 from the throttle, a block from AppSec or
CrowdSec) still carries it when it writes the response. Placed after `reverse_proxy` it
would cover only the proxied 200s and miss exactly the responses where keeping a browser
on HTTPS matters as much as it does on a success.

## `staticSiteCsp`

Every fetch directive `'none'` bar `script-src` and `style-src`, for a static site that
fetches no font and no image. Those two admit exactly the page's own inline `<script>`
and `<style>` elements by SHA-256 and nothing else, so nothing can be injected and a
`style` or event-handler attribute is refused; a page with no such element gets `'none'`.
The hash is taken from the page served, so the two cannot drift. `img-src` admits `data:`
only when the page carries an inline `data:` favicon, and `font-src` admits `data:` only
when the stylesheet carries an inline `data:` font -- either way a `data:` URI makes no
request. `connect-src` stays `'none'`, so the script can never send anything anywhere.
`form-action` and `frame-ancestors` are refused too: the page takes no input and is not
meant to be framed. CSP does not govern anchor navigation, so this does not affect the
page's own `mailto:` links.

## `BINARY_SIZE` regex

Caddy size strings this renderer will emit, restricted to powers of two.

`MB`/`GB` are deliberately absent rather than merely unused. Caddy reads them as powers
of ten -- measured against the pinned binary, `64MiB` is 67,108,864 and `64MB` is
64,000,000, so `MB` is ~4.6% _smaller_. It is the restrictive direction, not the
permissive one, and rejecting it is unit hygiene rather than a safety control: the
value's source derives it in MiB, and a registry that silently accepts a different base
makes the two incommensurable for anyone reasoning about them together.

Do not restate this as "MB would be dangerously large". It would not, and a maintainer
who believes it will draw the wrong conclusion under pressure.

## `requestBodyDirective`

Required of every site this edge serves, not only Ghost-backed ones.

Keying this on `injectionWafPreviewOnly` was tried and is unsound: that flag is a
WAF-preview switch whose own docstring in sites.ts records the condition for removing it
("until there is enough admin-API traffic to prove otherwise"). Meeting that condition
and dropping the flag would have silently dropped the body ceiling with it -- no error,
no failing test -- and for a Ghost tenant this directive is the only bound that exists:
verified in Ghost's core/server/web/api/middleware/upload.js, where the generic multer
instance carries no `limits` and only `themeUpload` sets `fileSize`. A control must not
hang off a flag documented as temporary.

Requiring it of everything also removes the "which sites are Ghost?" question entirely,
and bounds the marketing site, which had no ceiling at all and would stream an arbitrarily
large POST to app1.

## `siteBlock`: members magic-link matcher and rate-limit

Defined for every site, not only Ghost tenants: the matcher only ever matches Ghost's
own path, so a non-Ghost site (e.g. the marketing site) carries an inert matcher rather
than needing a flag to opt in. That is what makes this apply to a future tenant by
construction, with no entry in `sites.ts` needed beyond `privateUpstream`.

Gated on the magic-link field, not the general one: the matcher exists only to be
referenced by `rate_limit @members_magic_link`, so emitting it under the wrong condition
either leaves a dangling reference or an orphan matcher.

## `siteBlock`: Ghost first-run setup refusal

A freshly started Ghost has no owner, and its setup route (`POST
/ghost/api/admin/authentication/setup/`) creates the owner account for whoever reaches it
first. For a paying tenant that is an account takeover before the real owner has done
anything. The edge therefore answers a POST or PUT to that route with 403 on every site
block and on the probe listeners. The owner account is created on the app host, not
through this edge, so nothing legitimate needs the write here.

`GET` is deliberately not refused. Ghost's admin (v6.55.0, `unauthenticated.js` in the
Ember admin) reads the setup status before it shows sign-in, reset, signup or
signin-verify, so refusing the read breaks every tenant's admin login. The read only
reports whether setup is done and claims nothing.

Defined for every site, unconditionally, for the same reason as the magic-link matcher
above: it is inert on a non-Ghost site and applies to a future tenant by construction.
Unlike the throttle it is not keyed on posture, because a refusal is not a posture; no
setting in `posture.ts` can switch it off.

Four path patterns, not one. Measured against Caddy v2.11.4: the matcher lowercases,
cleans `.` and `..` segments, collapses a double slash and decodes percent-escapes before
matching, so `/GHOST/...`, `//ghost/...`, `/%73etup/` and `setup/../setup/` all match.
What it does not do is let `*` cross a slash: a trailing `/` and any deeper path need
the `setup/*` form, and Ghost's versioned API (`/ghost/api/<version>/admin/...`) needs
the `*` version segment.

After the protection chain, before `reverse_proxy`: a client probing for an open setup is
throttled and seen by CrowdSec rather than answered for free.

## `siteBlock`: discard route

`EdgeSite.discardRoute` is one literal path the edge answers itself: `POST` gets an empty
204, any other method gets 405 with `Allow: POST`, and nothing reaches the upstream. It
exists because GitHub requires an active webhook URL before an App may subscribe to the
deployment-protection event, while our approval script polls and reads nothing from it.
The path carries a short suffix to stay out of drive-by scans; it is not a secret, and the
webhook secret the owner sets is what authenticates a real delivery should one ever be read.

Placement inside the route: after HSTS, the 1 MiB body ceiling and whatever throttle and
CrowdSec the posture renders for the site, and immediately before `appsec`. The path
therefore inherits exactly what the console route has: under the enforcing posture a flood
is shed and a banned address refused; the shipped posture renders neither, and the path
has neither then. The answers are `respond`s, which end the route, so a discard request
never reaches AppSec or the upstream, while every other path still reaches the unchanged
`appsec` line. Nothing is parsed or stored here, so AppSec has nothing to protect on this
path, and GitHub's JSON payloads are not exposed to rules built for form posts. Emitting the
answers ahead of the `appsec` line, rather than editing that line, keeps the rendered change
additions-only. The renderer accepts only a plain literal path.

## `siteBlock`: `request_body` ordering

Ahead of everything else, including request_body -- see hstsDirective's own comment for
why its position is load-bearing rather than tidiness. Measured against Caddy v2.11.4:
`request_body` wraps the body in a MaxBytesReader and returns 413 once the limit is
passed, which does bound what is ingested -- but it does NOT terminate the handler chain.
The rate-limit token, the AppSec inspection and the upstream connection are all still
spent, and up to `max_size` bytes still reach the origin. Ordering it first therefore
buys tidiness and nothing else; AppSec in particular already caps its own inspection at
`appsec_max_body_bytes` (64 KiB, global block), so it was never reading the whole body
anyway.

## `staticBlock`

A hostname the edge answers directly with a fixed page, never proxying anywhere -- see
`StaticSite`'s own doc comment in `siteTypes.ts` for what belongs in an entry, and
`publicpressHolding.ts` for where this one's actual page text lives.

Carries the same TLS and throttle posture as a proxied site block (`siteBlock` above): a
browser or a scanner cannot tell this has a simpler backend and must not be given a
weaker one. It differs in three ways -- there is no upstream to proxy to, so `respond`
answers directly; every path gets the same response, so there is no per-path routing to
speak of; and it carries its own strict Content-Security-Policy, appropriate here because
the page ships no external resource of any kind, only its own inline stylesheet and script,
which is not true of every site this edge serves.

No members-magic-link matcher: that route is Ghost's, and nothing here is Ghost.

## `probeBlock`

A listener on loopback only, carrying the same handler chain as the public sites and
answering 204.

It is what makes the posture observable before any hostname resolves to this host: the
throttle and the CrowdSec handlers can be exercised with `curl` against a running edge
that serves no public traffic yet. The Hetzner firewall does not open this port and
Compose publishes it on `127.0.0.1` only.

Rendered twice, at the same port, with and without a host. See `PROBE_HOSTNAME` for why
the second one exists.

## `assertUpstreamsAreDistinct`

No two sites may proxy to the same private address.

Caddy accepts it happily -- two site blocks reverse-proxying one backend is valid
configuration -- and a snapshot test cannot see it either, because the rendered file is
exactly what the registry asked for. What it means on the wire is that one tenant's
hostname serves another tenant's Ghost: their content, and their members' sessions.

`resolvePrivateAddress` already rejects an unknown host name and an out-of-range port,
so a typo in either is caught. A port that is merely _another site's_ is not: it is
well-formed, in range, and wrong. The near miss is on the record -- `blog2` was almost
registered on 8081, read off `ss -ltnp` on app1, before its own stack config was
consulted and gave 8100. 8081 was free; had it been the website's 8080, nothing here
or in CI would have said so.

## `rateLimitDirective`: client IP key

The edge is the first hop -- no proxy in front of it -- so the direct peer is the
client. `{http.request.client_ip}` would take a forwarded header into account, which
here is a header an attacker sets.

This key and the no-CDN assumption are one decision and must move together. Put any CDN
or scrubbing service in front of this edge and every request arrives from a handful of
its addresses: a per-IP throttle then counts the whole internet as a few clients and
throttles everyone within seconds of the change. Both zones share this key, so that
failure would take the magic-link path down with the general one. Whoever evaluates a
CDN owns changing this line to a trusted-proxy configuration in the same change, never
afterwards.

## `protectionChain`: handler evaluation order

The handler chain, in evaluation order: throttle runs **before** the WAF, which is the
one place this edge deliberately reorders the Cloud Armor baseline (whose WAF rules sat
at priority 1000–1003, ahead of the throttle at 2000). Cloud Armor evaluated on Google's
edge fleet; this evaluates on two vCPUs, so a flood that reached the WAF first would
spend exactly the capacity the throttle exists to protect. The observable difference is
confined to a client that is both flooding and attacking: it is answered 429 rather than 403.
