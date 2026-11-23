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
exempt three rule families and keep a fourth.

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
from `sites.ts` is a hostname this renderer does not know about, which is precisely the
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

## `siteBlock`: uploaded-file refusal and `nosniff`

Ghost accepts `.js`, `.html` and `.css` as uploads, and also `.txt`, `.md`, `.json`, `.pdf`,
`.zip` and `.py`, and serves everything a tenant uploads from the tenant's own origin, under
`/content/files/`, `/content/images/` and `/content/media/`. An uploaded `x.js` therefore
satisfies `script-src 'self'`, and an uploaded `.html` or `.svg` is a document a browser
runs. The shared-domain limit is that no tenant script runs there, so for a site with
`backend: 'ghost'` the edge does two things. Both are copied from the demo edge.

- **Refusal.** 403 to any request below those prefixes for a file of an active type
  (`ACTIVE_CONTENT_EXTENSIONS`: script, HTML, XML, stylesheet and SVG families), any method.
  A refusal, not a download: a forced download would still put the bytes on the tenant's
  origin, and a `<script src>` ignores `Content-Disposition`.
- **`nosniff` on every response.** The list above cannot name every type Ghost accepts, and a
  browser runs a same-origin `<script src>` of a response typed anything but image, audio,
  video or `text/csv` unless `X-Content-Type-Options: nosniff` is set, so an uploaded `x.txt`
  or `x.json` would still run. The header is deferred (`>`) so it replaces Ghost's own copy
  rather than doubling it, and it sits in the route after HSTS. An error Caddy writes itself
  (a 502 with no healthy upstream) never reaches the route's `header`, so the site also has a
  `handle_errors` block with the same header; it is at the site level because Caddy refuses it
  inside a `route`.

`/content/public/` (Ghost's own shipped scripts), theme assets and the admin are outside the
prefixes and are untouched, and `nosniff` does not stop them: they are served typed as
script. A site with `backend: 'other'` has none of this, so its block does not change.

The refusal is two matchers, because Caddy's `path` lowercases, cleans dot segments and
decodes escapes but a regexp over the path as received also catches a run of slashes. The
glob matcher needs a nested `route`: two `path` lines in one matcher are an OR, so the prefix
and the extension are an AND only across the two matchers. After the protection chain, before
`reverse_proxy`, for the same reason as the setup refusal.

## `siteBlock`: Widget assets

Ghost loads Portal, search, comments, the announcement bar, the signup form and the admin
toolbar from jsDelivr unless its configuration names other addresses. A tenant rendered with
`render-core`'s `widgets: 'own-origin'` names `<siteUrl>/bl-assets/<file>`, so every `backend:
'ghost'` site answers that path itself and a reader's browser contacts no CDN.

- **Where the files come from.** The seven files of `branchLeft/ghost-platform`'s
  `widgets/pins.json`, copied into the edge image at `/srv/bl-assets/` by
  `hetzner/edge/Dockerfile` (`ADD --checksum`, one commit, one sha256 per file), so the build
  fails on a changed byte. No new delivery class: the image is the one the edge already pins and
  `branchleft-deploy` already rolls. `widgetAssets.test.ts` binds the Dockerfile's list to this
  route's root.
- **The route.** `GET` and `HEAD` of `/bl-assets/*`, compressed (`encode`: the bundle is 2.5 MB
  and Ghost's own responses are compressed upstream), `Cache-Control: public, max-age=3600`,
  served by `file_server` rooted at `/srv`. A name the image does not hold is a 404 from the
  edge, never passed to Ghost. An hour and not a year: the names are not content-addressed, and a
  re-pin replaces the bytes under them. After the protection chain and the upload refusal,
  before `reverse_proxy`, so a probe is throttled and seen by CrowdSec.
- **Order of rollout.** The image carrying the files, then this route (a Caddyfile delivery),
  then a tenant rendered `own-origin`. The route without the image answers 404 on a path nobody
  requests yet, so either of the first two may land first; a tenant rendered before both would
  lose Portal and search.
- **Not here.** The demo edge (`ghost-platform`'s `demo-host`, vendored under
  `ansible/roles/demo1_build`) refuses a `file_server` outright and is a separate change.

## `logDirective`: retention and rotation

Every edge log keeps its entries for 30 days (`LOG_RETENTION = '720h'`, the owner's ruling of
2026-08-24, inside the 90-day ceiling the website privacy notice states). The directive is
`roll_keep_for 720h`, which Caddy turns into 30 days.

`roll_keep_for` only prunes files that have already been rolled, so a file must also roll on
a clock. `roll_at 00:00` rolls every log daily at midnight UTC, even with no writes. Caddy
v2.11.9 accepts it (`roll_at`, parsed in `modules/logging/filewriter.go`, rotated by
`github.com/DeRuina/timberjack` v1.4.8 on a background timer). `roll_interval` exists in the
same module but rolls only on the next write, so it would not bound a quiet edge, and it is
not used.

`roll_keep 31` keeps 31 rolled files. Caddy's default of 10 would cap the daily roll at 10
days and shorten the retention silently. The worst-case age of an entry is about 31 days (30
days plus the one day its file spans), not exactly 30. A tighter 30-day bound would need
`roll_keep_for 696h`; that is a change to the owner's value and is not made here.

`render.test.ts` pins all three directives on every log and bounds the retention at or below
2160h, so a later value above 90 days fails.

A change to a log output option (retention, roll, or format) takes effect only when the caddy
container is recreated, not on `caddy reload`. See `hetzner/RUNBOOK-edge.md` "Log retention".

## `logDirective`: break-glass token redaction and strip

The break-glass sign-in (how support opens a customer's Ghost admin) carries a single-use
token in the query parameter `bl_break_glass` on a `/ghost/` request. Left alone, Caddy's
JSON access log writes it to disk in clear. Measured against Caddy v2.11.4 with the old
bare `format json`, the token appears in exactly three fields of a log line:
`request.uri`, `request.headers.Referer` (a refused token leaves the sign-in page at its
original URL, and its same-origin sub-requests send that URL) and `resp_headers.Location`
(Ghost's 302 to `/ghost/#/?bl_break_glass=...`). Nowhere else; `breakGlassToken.test.ts`
reads the real log back to keep it that way.

**Redaction.** Every `log` block, of every kind (site, redirect, static, probe), is written
by `logDirective`, which wraps the same JSON encoder in `format filter` and runs a
`regexp` filter over those three fields. The value of the parameter becomes `REDACTED`, so
a reader of the log can still see that a token was presented. A line with no token is
written byte for byte as before and has the same JSON key set, so CrowdSec's parser and
the rate-limit derivation in the runbook read it unchanged; the test compares the parsed
key sets of the old and new formats.

The log pattern is deliberately wider than what Ghost reads. It is case-insensitive and
redacts any parameter whose name starts with the token's, so `BL_BREAK_GLASS=`,
`bl_break_glass[]=` and a bare `?bl_break_glass` leave nothing. The `[?&]` boundary also
covers the `#/?bl_break_glass=` fragment in Ghost's `Location`. It does not hide the name
when it sits inside another parameter's value, which is not a token to anyone. The pattern
uses no backslash, brace or quote, so Caddyfile quoting cannot corrupt it. The `query`
filter is not used: it re-encodes every URI it touches, which would change token-free
lines.

**Strip.** The token is read only on `/ghost/` (Ghost's adapter reads exactly
`bl_break_glass`, case-sensitive, as a string). On any other path the adapter never sees,
refuses or consumes it, so it would sit valid in Ghost's request log until it expires. The
edge therefore removes it with `uri ... query -bl_break_glass` before any other handler,
and forwards the rest. It is a strip, not a refusal, so a stray parameter on an ordinary
page is not turned into an error. On `/ghost/` the request is forwarded byte for byte.

The gate (`@break_glass_strip`) is a CEL `expression` over the raw request target
`{http.request.orig_uri}`, not Caddy's `path` matcher. The `path` matcher lowercases,
decodes and cleans before matching, but Ghost's router (Express) routes on the raw path, so
`/%67host/`, `/ghost%2Fx` and `/%67host/x` would look like `/ghost/` to Caddy while Ghost
sends them to its front end, where the adapter never sees the token. Reading the raw target
removes the disagreement. It fires when both hold:

- the query has a parameter whose name is the token's, at the start of a parameter (so
  `a=?bl_break_glass=T` is one parameter named `a` and does not fire). Each character of
  the name is accepted as itself or as its percent form, with either hex case, because
  `%5f` and `%5F` decode to the same byte. The letters stay case-sensitive. One
  function, `paramNamePattern`, spells the name for both this gate and the log filter.
- the raw path is not `/ghost` followed by `/`, `?` or the end (lowercase only), or it
  contains two dot-spellings in a row (`.` or `%2e`).

The keep-test is lowercase on purpose. Express also routes `/GHOST/`, so a capitalised
break-glass URL is stripped and fails; the minter only builds lowercase `/ghost/` URLs.
`/ghost/../` is stripped although Express would route it into the admin app, to keep the
rule simple and to err toward stripping. Every form where Caddy and Express could disagree
about "under `/ghost/`" is therefore stripped, which is the safe direction.

`uri query` re-encodes the query it rewrites: keys come out sorted and values re-escaped.
Measured, the other parameters keep their decoded names and values; a token-only query
leaves no `?` at all; a pair with an invalid escape (`c=%ZZ`) is dropped by Go's query
parser along with the token. The rule fires only when the parameter is present, so no
other query string is ever re-encoded.

The strip is first in the route after the HSTS header, ahead of `request_body`, the
protection chain, the setup refusal and `reverse_proxy`, so neither the AppSec hop nor the
upstream carries a token that is off `/ghost/`. It is unconditional (no posture field
switches it off), is on every served site block and on both probe listeners so a loopback
`curl` can prove it, and is absent from redirect, static and metrics blocks, whose logs are
still filtered.

Not covered, by decision:

- Ghost's own request log on the application host. The token is on `/ghost/` by design,
  and the adapter's README names that as accepted.
- CrowdSec's records (alerts, AppSec event metadata).
- Forms the adapter does not read: `BL_BREAK_GLASS`, `bl_break_glass[]` (an array, refused
  as malformed) and a name hidden inside another parameter's value. They are forwarded
  as sent, and the first two are redacted in the log.

## `defaultLogDirective`: the error and no-site lines

The site `log` blocks above cover the access log only. Caddy's default logger is a second
path, and it writes to stderr, so to the edge container's log. Measured against Caddy
v2.11.4 with no default logger configured, two lines reach it with the token in clear:

- the `http.log.error` line written when a handler fails (a 502 from a refused upstream).
  It carries the whole request, `request.uri` and `request.headers.Referer` included;
- the line for a request whose Host matches no site block, which carries the same request.

The token stays valid for its full 600 s, and for as long as a hung upstream keeps the
request open, so a reader of the container log could use it.

**Fix.** `globalOptions` carries a `log { output stderr; format filter { wrap json ... } }`
block, written by `defaultLogDirective`. It uses the same `redactingFormat` as every site
log, so the encoder, the three fields and the pattern have one source. The block names no
logger, which in Caddy is the default one. Caddy's own default is JSON on stderr when no
terminal is attached, so a line with no token is unchanged.

`breakGlassToken.test.ts` starts a real Caddy in front of a dead upstream, sends the token
in every spelling the access-log rows use to a served site and to a host with no site,
and reads `docker logs`. With the global block removed from the renderer both paths leak
and the rows fail; with it, nothing matches `FAKE_`. `render.test.ts` pins the block, its
filter lines and their equality with the site logs.

Not covered: request headers other than `Referer` are written as sent in the error line
(for example `Cookie`). They carry no break-glass token, and redacting them is a separate
decision.

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

## `siteBlock`: inbound webhook

`EdgeSite.inboundWebhookPath` marks a site that exists only to receive signed callbacks
from one outside sender, and renders through `webhookSiteBlock` instead of the Ghost-shaped
`siteBlock` body. The sender authenticates each delivery with a signature the receiver
checks; the edge's job is to bound what can reach the receiver at all.

What the block lets through, and nothing else:

- `POST` on the one literal path, with a body of at most the site's `requestBodyMaxSize`
  (16 KiB for the shipped entry), from a client under the dedicated throttle, the general
  throttle, CrowdSec and AppSec, to the one upstream the entry names.
- Every other method on that path gets 405 with `Allow: POST`, from the edge.
- Every other request on the hostname gets 404, from the edge. The final `respond 404` is
  matcher-less and last, so a case the lines above forgot fails closed.
- The receiver's private drain listener is a different port and is never named here: the
  block contains exactly one upstream address.

Why a separate block rather than a path matcher added to the Ghost one: the Ghost block
defines the members magic-link matcher and its shared zone on every site, inertly. A
webhook block that carried them would name a zone and a matcher of the login-mail route.
It carries none of the Ghost matchers, so it shares no zone, matcher, upstream or process
with that route; the test file asserts each.

The dedicated zone (`<site>_inbound_per_ip`, keyed on the direct peer like the others)
applies to the matched `POST` only and sits after the general throttle, which is the
unchanged one every site has. It is not keyed on posture: a posture setting that could
switch it off would leave a public route with only the general budget. The budget is
`WEBHOOK_RATE_LIMIT_EVENTS` per `WEBHOOK_RATE_LIMIT_WINDOW_SECONDS` (`posture.md`).

Path matching is Caddy's: case-insensitive, dot segments cleaned, escapes decoded, `*` not
used. A request for `/Webhook` is proxied as sent and the receiver, which compares the path
exactly, answers its own 404.

Not proven here: Caddy's behaviour against a real sender (the 413 a sender sees for an
oversize body, the 429 it sees past the budget, the 404 and 405) was not run; the rendered
file is only parsed by `caddy validate` in CI. Whether AppSec's rules flag a real callback
payload is unknown, and a 403 would be retried by the sender. Caddy's read timeouts are
server-wide in the global block, so slow-sender protection for this route is whatever the
global block says, and changing it affects every site.

`edge1` as the upstream host: `resolvePrivateAddress` refuses `edge1` on every port but
those in `EDGE_HOST_ALLOWED_PORTS`, so the entry cannot render once its port is named
until that set gains the receiver's port. That is one deliberate line in this file, made
when the port is known and reviewed as a widening of what the edge proxies to.

### Naming the hostname

Naming the hostname is one change with three parts, and `webhookDns.test.ts` goes red
until all three are there: the `WEBHOOK_HOSTNAME` constant in `sites.ts`; one `A` record
for it in the matching zone file under `hetzner/dns/`, at the address the edge's other
hostnames use, with its owner name added to that file's `probe_names`; and the port in
`EDGE_HOST_ALLOWED_PORTS`. The record is not committed ahead of the name: a placeholder
in a zone file would be applied to production DNS, and a name the registry does not claim
would answer for a host that serves nothing. The same test refuses a hostname that is
not a real lowercase DNS name, so an ALL_CAPS placeholder cannot reach a rendered
configuration. The record's apply, like every DNS apply, is the owner's.

## `siteBlock`: signed object gateway

`EdgeSite.signedObjectGateway` marks a site that is an S3-compatible gateway whose clients
sign their own requests (the tenant-state gateway, which tenant CI on GitHub-hosted runners
reaches over the public internet). It renders through `gatewaySiteBlock`. The edge's job is
to terminate TLS, bound what can reach the gateway, and change nothing the client's
signature covers; the gateway verifies the signature and decides what each credential may do.

What the block lets through, and nothing else:

- A path-style request: one non-empty first segment (`/<bucket>` or `/<bucket>/<key>`), by
  `GET`, `HEAD`, `PUT`, `POST` or `DELETE`, with a body of at most the site's
  `requestBodyMaxSize` (8 MiB for the shipped entry, an order of magnitude above a Pulumi
  checkpoint), from a client under the general throttle, CrowdSec and AppSec, to the one
  upstream the entry names.
- `/healthz` and `/readyz` by `GET` and `HEAD`. `PUT`, `POST` and `DELETE` on them get 405
  with `Allow: GET, HEAD` from the edge, because they would otherwise match as a bucket
  of that name.
- Any other method gets 405 with `Allow` listing the five, from the edge. `/` (a bucket
  listing) and anything else with no first segment gets 404, from the edge. The final
  `respond 404` is matcher-less and last, so a case the lines above forgot fails closed.
- A `.` or `..` segment in the raw path, literal or percent-encoded, gets 400 from the edge.
  This is an expression on `{http.request.orig_uri}` and not `path_regexp`: Caddy matches
  `path` and `path_regexp` on the path with dot segments resolved, and proxies the path as
  sent, so `/bucket/..` is matched as `/` and forwarded unchanged. Measured against Caddy
  2.11.9 with a stand-in upstream, not assumed. The expression has no brace, because Caddy
  reads one as a placeholder.

What it does not do, on purpose: it sets no `header_up`, strips no query parameter, rewrites
no path, and adds no `encode`. The client's `Authorization` and `x-amz-*` headers, the
`Host` it signed, the path and the query all reach the gateway as sent. Caddy adds
`X-Forwarded-*` headers, which a signature does not cover unless the client lists them in
`SignedHeaders`. The break-glass query strip and the Ghost and Nextcloud matchers are not in
this block. It cannot be combined with a webhook path, `discardRoute`,
`injectionWafPreviewOnly`, `trustedSession` or a `backend` other than `other`.

Caching: no cache module exists on this edge. `header >Cache-Control "no-store"` is
deferred, so it replaces a `Cache-Control` the gateway sends instead of adding a second
value, and it also reaches the edge's own 404, 405 and 400. A 413 from the body cap does
not carry it (measured), which is no loss: 413 is not cacheable by default.

Timeouts: `dial_timeout 5s` and `response_header_timeout 30s` on the upstream transport. A
slow client sending a body is bounded only by the server-wide read timeouts in the global
block, as for the webhook route: Caddy 2.11.9 has no per-route `request_body` read timeout
(its parser refuses `read_timeout`, measured), and changing the global value affects every
site.

The upstream address is not in this repository yet: the gateway host is not in the address
plan, so `sites.ts` holds two `undefined` constants and the entry claims no hostname and no
upstream until both are set (`sites.md`, "Signed object gateway sites"). Until then the
committed `stack/caddy/Caddyfile` is unchanged, and `validation/Caddyfile.state-gateway`
is the same block rendered with a stand-in upstream so CI loads it through Caddy.

Not proven here: AppSec's behaviour against a real Pulumi checkpoint body (the state is
JSON with arbitrary plaintext config, and a rule firing on it would fail an apply with a
403; AppSec reads only the first 64 KiB); the general throttle's 200 requests per minute per
address against several tenants applying at once from one GitHub runner address; and
CrowdSec's 404 scenarios against the `HEAD` and `GET` of keys that do not exist yet, which
an S3 client sends as normal traffic. Each is for the first live inspection, and the
remedy for the first two is a deliberate change in this file and `posture.ts`, not a
setting.

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
`STATIC_SITE_CONTENT` in `render.ts` for where an entry's page text is registered.
No fixed-page site is registered today: `publicpress.co.uk`, the only one, is now a
proxied site (`publicpress-website` in `sites.ts`), and the page renderer in this block
is kept, unexercised, for the next fixed page. The one registered static site,
`sites.publicpress.co.uk`, answers with fixed text files, and `staticBlock` dispatches it
to `staticFilesBlock` below before it looks for a page. The paragraph below describes the
block as it was rendered for the holding page.

Carries the same TLS and throttle posture as a proxied site block (`siteBlock` above): a
browser or a scanner cannot tell this has a simpler backend and must not be given a
weaker one. It differs in three ways -- there is no upstream to proxy to, so `respond`
answers directly; every path gets the same response, so there is no per-path routing to
speak of; and it carries its own strict Content-Security-Policy, appropriate here because
the page ships no external resource of any kind, only its own inline stylesheet and script,
which is not true of every site this edge serves.

No members-magic-link matcher: that route is Ghost's, and nothing here is Ghost.

## `staticFilesBlock`

The same posture as `staticBlock`, for a hostname that answers with a small set of fixed
text files instead of a page: `sites.publicpress.co.uk`, whose files are in
`hetzner/edge/sharedTenantFiles.ts`. The files are picked by the entry's `name`, and
`staticBlock` dispatches to this block before it looks for a page.

Each file is one literal path with a `@file_N path` matcher, its own `Content-Type`, and a
`respond` with its body as a Caddy heredoc (`<<SHARED_TENANT_FILE_EOF`). The heredoc is
used because a `security.txt` has several fields on separate lines, and a quoted one-line
body cannot carry them. Heredoc bodies are not indented, so the renderer writes each body
line at column 0, and only the `respond` line carries the block's indentation. The
renderer refuses a path that is not a plain literal, a body without a trailing newline,
and a body with a line equal to the marker. Every other path gets `respond 404`.

The heredoc is not checked by a local Caddy binary: this repository's CI `caddy validate`
over `stack/caddy/Caddyfile` is the check that the syntax is accepted.

The CSP is `staticSiteCsp('')`, the strictest form, since a text file runs nothing.

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

## `assertHostnamesAreDistinct`

No hostname may be claimed by two served sites.

Two sites that list one hostname render it in two Caddy site blocks, and Caddy does not
refuse that: one block silently shadows the other, so the hostname answers with whichever
tenant Caddy happened to pick. The check runs on the servable sites only. An entry with no
private upstream is dropped before rendering, so it claims nothing and may list a hostname
a served site also lists.

A snapshot test cannot see this either. The snapshot is whatever the registry asked for,
so a mistaken duplicate is simply committed as the new expected output.

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

The same key can also fail without a CDN: if the edge's container networking presents
real clients as a Docker bridge address (for example `172.18.0.1` behind the docker-proxy),
every collapsed client shares one budget per zone. This module cannot see that; the
owner-run percentile and bridge-address check in `RUNBOOK-edge.md` §10a is what looks
for it before the general throttle is applied live.

## `protectionChain`: handler evaluation order

The handler chain, in evaluation order: throttle runs **before** the WAF, which is the
one place this edge deliberately reorders the rules the retired edge ran (its WAF sat
at priority 1000–1003, ahead of the throttle at 2000). The retired edge evaluated on a
shared fleet; this one evaluates on two vCPUs, so a flood that reached the WAF first would
spend exactly the capacity the throttle exists to protect. The observable difference is
confined to a client that is both flooding and attacking: it is answered 429 rather than 403.

### What the general throttle covers

`protectionChain` is called by four block builders, so the one `rateLimit` posture
field throttles all four: `siteBlock` (zone `<site>_per_ip`), `redirectBlock` (zone
`<site>_redirect_per_ip`), `staticBlock` (zone `<site>_per_ip`, its file-serving
form included) and `probeBlock` (zones `probe_host_per_ip` and `probe_per_ip`, the two
loopback probes). Only the `:9091` metrics listener is exempt: `metricsBlock` never calls
`protectionChain`. Under the committed posture that is one general `rate_limit` directive
per throttled block, each in its own zone, and `render.test.ts` counts them per kind
from the registries.

## Ghost admin preview exclusion

`renderGhostAdminAppsecConfig` writes `stack/crowdsec/appsec-configs/ghost-admin-previews.yaml`,
the AppSec configuration `branchleft/ghost-admin-previews`. It holds one
`pre_eval` hook and no rules.

What it is for. On 14 November 2026 the owner was banned from every site on the
edge for saving Settings > Design in the blog's Ghost admin. The admin API itself
never reaches AppSec on a Ghost site (`AUTHORING_API_PATHS`); the design and
announcement-bar previews do. Ghost admin fetches each preview by POSTing to the
site root, `/?admin_toolbar=0`, with no body, `Content-Type: text/html;charset=utf-8`
and the unsaved settings in an `X-Ghost-Preview` header, once per change. Two
Core Rule Set rules match that request: 920420 (the content type is not one the
rule set allows, 5 points) and 920180 (a POST with no Content-Length, 3 points;
the bouncer forwards a bodiless request without one). That is the "anomaly: 8"
in the owner's alerts. The out-of-band bucket bans an address at its sixth
match inside its leak window, so a few design tweaks are a ban.

What it narrows. The two rules, removed for one request, only when every
condition holds: out-of-band evaluation; the host is a Ghost hostname from the
registry (`backend: 'ghost'`); a POST to `/`; no body; exactly the preview's
content type; the `X-Ghost-Preview` header present. Every other rule still
evaluates that request, and both rules still evaluate everything else, including
the same request with a body, on another path, on a non-Ghost host, or without
the header. Sending the header is all a client needs to skip those two protocol
checks on that one bodiless request, which reaches a Ghost front page that
reads no body.

Why it is named first in the AppSec acquisition. CrowdSec merges the named
configurations in order: hooks and rules are appended, but options such as
`default_remediation` are taken from the last one loaded. With ours first, the
hub's configurations load after it exactly as before.

The replay in `test_crowdsec_replay.py` (CI's `edge-config-validate`) is what
found the rules and what proves the narrowing: it fails if the previews raise
any WAF alert, and if the same shape stops banning off a Ghost host or without
the header.

## Ghost admin API and admin-interface probing

Two files: `renderAdminProbingScenario` writes
`stack/crowdsec/scenarios/http-admin-interface-probing.yaml`, the scenario
`branchleft/http-admin-interface-probing`, and `renderHubAdminProbingPostoverflow`
writes `stack/crowdsec/postoverflows/ghost-admin-api-postoverflow.yaml`, a
post-overflow whitelist that silences the hub's scenario of the same kind. (The
post-overflow file keeps the name it had when it did something narrower: the
edge stack's file lists, and the stack directory on the host, carry that path.)

What it is for. The hub scenario `crowdsecurity/http-admin-interface-probing`
reads a 403 or 404 on any path containing one of its entries as a probe, and
bans at the third distinct such path in quick succession (capacity 2, leaking one every 10 seconds). One of its
entries is `/admin`, which every Ghost admin API path contains
(`/ghost/api/admin/...`). Ghost answers its own admin API 403 for an expired
session or a device check and 404 for a missing resource, and the bouncer
answers 403 to an address already banned, which is how the owner's second ban
followed the first at 00:50:54Z.

What it narrows. Our scenario has the hub's filter, thresholds, data file,
grouping and one-minute blackhole, with one more condition: a request is not
counted when it is to `/ghost/api/admin/` on a Ghost hostname with no dot
segment, literal or percent-encoded. Such a request does not enter the bucket
at all. A probe for `/wp-admin`, `/phpmyadmin`, `/admin` or any other entry
still bans on a Ghost host (three of them are needed: admin API paths mixed in
neither count nor reset them), and admin API paths on any other host still ban.
A path that leaves the prefix by a dot segment is counted, so
`/ghost/api/admin/../../phpmyadmin/` is a probe. Every other scenario still
reads every one of these requests.

Why a scenario and not a post-overflow. The first version dropped, after the
fact, an overflow made only of admin API requests on a Ghost host. CrowdSec
applies a scenario's blackhole when the bucket overflows, before any
post-overflow runs, and keeps it per address across every host. So three admin
API answers on the Ghost host began a one-minute blackhole that muted the whole
scenario for that address everywhere, and an attacker could keep it muted by
repeating them while probing another site. Not pouring those requests into the
bucket arms nothing. The replay's "admin interfaces on another host right after
Ghost admin API answers" case is that attack: it was not banned before this
change, and is now.

Why the hub's scenario is silenced and not replaced. The hub's scenario stays
installed and untouched, so the `crowdsecurity/caddy` collection is not tainted
and its hub upgrades continue. Its overflows are all dropped by the
post-overflow, by name, so it never bans; if one got through, an address would
be banned twice and counted twice on the ban ladder. The replay fails if the hub's
scenario raises any alert. Other scenarios (`http-probing`, the CVE ones, the Core
Rule Set) are not affected by either file.

What the copy costs. Our filter is a copy of the hub's: if the hub changes its
scenario's filter, ours does not follow. The list of entries does follow, because
ours reads the same data file (`admin_interfaces.txt`, downloaded from the same
address when CrowdSec starts). The hub's scenario is pinned by neither the image
nor this repository (`hub_branch: master`), so compare the two filters when the
CrowdSec image pin is bumped. A bucket that sees fewer requests than before can
only ban less: the exempt requests no longer count toward the third distinct
path, so two probes and any number of admin API answers do not ban.

Proved by `test_crowdsec_replay.py`, which names the scenario each probe must
reach and not only that the address was banned. The dot-segment case needs this:
the Apache path traversal scenario (`http-cve-2021-41773`) bans the same three
requests, so a test that only asks whether an address was banned stays green with
the dot-segment condition removed. Asking for `branchleft/http-admin-interface-probing`
among the address's alerts does not.

## Host scope of the Ghost files

The three Ghost files (the admin preview exclusion, the admin-interface probing
scenario and the brute-force scenario) each narrow to "our Ghost hostnames". The
estate's edge also serves Nextcloud, the portal and static pages, so there the
narrowing is real: each file carries the registry's Ghost hostnames.

`EVERY_HOST` is the other scope. It leaves the hostname condition out of the file.
It is for an edge on which every site is a tenant's Ghost and the names are data the
repository does not hold: the tenant edge, `hetzner/edge-t/`. A file rendered that way
names no hostname, so no name of the estate can be written into it. The estate's own
call sites pass the registry and never `EVERY_HOST`, and the committed estate files
are unchanged by the existence of the second scope (the snapshot test in
`render.test.ts` is what shows it).

What `EVERY_HOST` widens: on the tenant edge the preview exclusion applies to a
matching request on any name that edge answers, not to a list of names. The exclusion
is out-of-band only, a bodiless `POST` to `/` with the preview's exact content type
and header, and it removes two rules by id, so the widening gives a request nothing
that the narrow conditions did not already allow on a Ghost site.

## Verified sessions

`EdgeSite.trustedSession`, `sessionVerification`, `sessionVerificationMatchers`
and `renderTrustedSessionWhitelist`. A request whose signed-in session the site
itself confirms is never refused by a CrowdSec IP decision or an AppSec verdict,
and adds nothing to a CrowdSec bucket. A request with no session, or one the
site refuses, is handled exactly as on a site without the field. Only `ghost-staff`
exists: the Ghost staff cookie `ghost-admin-api-session` on `/ghost/*`, on a Ghost
site. Ghost members are never trusted. The portal and console need an endpoint in
the shell that answers 204 or 401 for a session, which does not exist yet.

**The check.** The edge asks the site's own Ghost `GET /ghost/api/admin/users/me/`
with the browser's cookie, Origin and Referer, the query emptied and any
`Authorization` header dropped (an Admin API key would also authenticate). Ghost
answers 2xx JSON only for a signed-in, origin-matching, verified (2FA) staff
session. Only that answer sets the Caddy variable `edge_trusted` to `1`; any other
status, a 2xx that is not JSON, a timeout or an error does not. It is written as
`reverse_proxy` with two `handle_response` blocks, not `forward_auth`:
`forward_auth` sends a non-2xx answer to the browser, which would break Ghost's
own sign-in page for an expired cookie. `method GET` drops the body from the
check only, so an upload reaches Ghost whole. There is no cache, so signing out,
a password change or suspending the user takes effect on the next request.

**Handler order.** HSTS, the break-glass strip and the body cap, then both
throttles (still applied to everyone, and they cap how many checks one address
can cause), then `vars edge_trusted 0`, `log_append` and the check, then
`crowdsec @edge_untrusted` and AppSec on unverified requests only (on an
authoring site `@inspected` gains `not vars edge_trusted 1`), then the setup
refusal, the upload refusals and the upstream proxy, for everyone.

**Keeping verified traffic out of every bucket.** A request that skips AppSec
raises no AppSec event, but the log scenarios read every access-log line. Caddy
writes the variable as a top-level `edge_trusted` field of the JSON log line,
and the `s02-enrich` whitelist `branchleft/edge-trusted-session` drops a Caddy
line whose top-level field is `1` before any scenario reads it. A client cannot
forge it: everything a client sends (headers, path, query, cookies) is escaped
into the line under `request`, never at the top level, and only the check's 2xx
JSON answer sets the variable.

**What still protects a stolen session.** Revocation, on the next request. The
pass covers one site's `/ghost/*` and only that site's session: a tenant's staff
session gives nothing on another tenant, the public pages or the portal. The
per-address throttle, the body cap, the setup refusal and the upload refusals
still apply. Ghost's staff history records what was done, and the access log
marks every verified request. Ghost's own brute-force limits protect sign-in and
password reset. What is left: while the session is valid, its holder cannot be
banned by address and AppSec does not inspect their admin requests. An
Administrator already controls the site; the answer is to revoke the session.
Ghost staff sessions last months.

**Cost.** A request without the staff cookie on `/ghost/*` costs a header match.
A staff request costs one bodiless request to its own Ghost over the private
network: a session and user lookup in MySQL, a few milliseconds, roughly doubling
Ghost's load from admin use. A forged cookie costs one failed lookup, inside the
throttle.

**Failure.** Any answer other than 2xx JSON is the normal path, so the edge never
fails open. If Ghost cannot be reached the check's error ends the request with a
502 or 504; that request could not have been served by that Ghost anyway. The
dial timeout is 3 seconds and the answer timeout 10 seconds.

**Limits.** A request with neither Origin nor Referer is not verified, because
Ghost refuses a session from no origin. The one such request in normal use is
opening the admin app from a typed URL or a bookmark: on a banned address that
page load is still refused. Every request the admin app then makes carries its
origin and is verified. Supplying the site's own origin when the browser sends
none would close this, at the cost of the edge vouching for an origin Ghost's
CSRF check did not see; that is not done.
`test_trusted_session_replay.py` proves each claim above against the real Caddy
image and CrowdSec, and `render.test.ts` pins the rendered lines.

## Ghost admin brute force

`renderGhostBruteForceScenario` writes
`stack/crowdsec/scenarios/ghost-admin-login-bruteforce.yaml`, the scenario
`branchleft/ghost-admin-login-bruteforce`. No hub scenario counts failed Ghost
sign-ins, and the admin-probing scenario above does not count Ghost admin API
paths, so nothing at the edge banned an address for guessing a password or an
Admin API key until this one.

What Ghost already does, read from its source (v6.55): `POST
/ghost/api/admin/session/` runs `brute.globalBlock` (per route per address,
99 free retries, one-hour lock) and `brute.userLogin` (key `user_login`, per
address, 4 free retries, so five tries, then a 10 minute lock that grows to a
week; a good sign-in resets it). Both key on `req.ip`; Ghost enables `trust
proxy` (`usingLoopbackReverseProxy` defaults false) and Caddy sets
`X-Forwarded-For` to the client address without trusting a client-supplied one,
so Ghost sees the real client and a client cannot choose it. That limiter is
per tenant, because each tenant has its own database, and it does not cover
the Admin API key: a bad or unknown key is answered 401 with no limit at all.
The scenario covers those two gaps and holds one address across every Ghost
hostname.

What it counts, on a Ghost hostname only, from Caddy's access log:

- `POST` to the session path (`/ghost/api/admin/session/`, with or without a
  version segment) answered 422 (wrong password), 404 (unknown email), 401 (no
  credentials, or a locked account) or 429 (Ghost's own lockout, so a client
  that keeps going after Ghost says stop keeps counting).
- Any request to `/ghost/api/admin/` answered 401: a bad, expired or unknown
  Admin API key, a malformed `Authorization` header, and a wrong sign-in
  verification code (`PUT /session/verify`, which Ghost answers 401).

What it does not count. 403: a correct password from a new device is answered
403 (`2FA_NEW_DEVICE_DETECTED`), and so is every admin call with no session,
which is what the owner's expired session and the bouncer's answer to a banned
address look like. 404 on any path but the session. Successes.

The numbers. A leaky bucket per source address, `capacity: 9`, `leakspeed:
30s`: the tenth failure inside the bucket bans, and one failure drains every 30
seconds. Ghost's own limiter locks a sign-in after five tries, so a person who
mistypes a password a few times, or one who tries a few more times against the
lock, stays under ten; a script's burst does not, and a script that keeps
sending 429s is banned though Ghost is already refusing it. Sustained guessing
slower than two failures a minute is not banned by this scenario; Ghost's
lock covers the sign-in and nothing covers the key, which is the limit it
carries. The ban follows the ladder in "Ban length and watch-only scenarios"
below: ten minutes first, longer on repeats.

Why it is a separate scenario: the post-overflow above matches the hub's
admin-probing scenario by name, so this one is never dropped by it, and our
admin-probing scenario excludes these paths from its own count. The replay in
`test_crowdsec_replay.py` proves a burst of sign-in failures and of key
failures is banned, and that the owner's mistyped passwords, new-device
sign-in and admin use are not.

## Ban length and watch-only scenarios

Two files CrowdSec reads instead of the image's own, rendered into
`stack/crowdsec/remediation/` and mounted read-only at
`/etc/crowdsec-remediation`; `config.yaml.local` points `profiles_path` and
`simulation_path` at them. The image's own copies stay in the config volume,
unread.

`profiles.yaml` (`renderProfiles`). Every ban, by IP or by range, lasts
`BAN_LADDER_MINUTES[n]` minutes, where `n` is the number of decisions the same
value already had in the last `BAN_LADDER_WINDOW` (CrowdSec's
`GetDecisionsSinceCount`), capped at the last rung: 10, 30, 120, 240. The
image's profile was a flat four hours, so one false alarm cost the owner every
site for four hours. `posture.md`, "Ban length", has the reasoning and the one
cost (simulated decisions count towards `n`).

`simulation.yaml` (`renderSimulation`). `simulation: false`, with the scenarios
in `WATCH_ONLY_SCENARIOS` as exclusions: CrowdSec runs those in simulation and
every other scenario for real. The one entry is the out-of-band Core Rule Set
scenario. Its alerts and would-be bans are still stored and listed (`cscli
decisions list` marks them simulated), so the false-alarm review keeps its
data, but no bouncer receives them. The in-band rules still refuse a known
exploit with a 403, and their scenario still bans. The renderer refuses any
other entry, so widening watch-only is a reviewed change to it.

Proved against a running CrowdSec by `test_crowdsec_replay.py`: the Core Rule
Set probes are recorded and ban nobody, two known exploits are refused in-band
and ban, a first ban lasts ten minutes and a ban after an earlier one thirty.

## Our own hosts are never banned

Nothing of ours renders this; the image already does it. The CrowdSec image
installs the hub's `crowdsecurity/whitelists` parser, which drops every event
from a private address (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
loopback) at `s02-enrich`, access-log and AppSec alike. Our hosts' fixed
addresses on the private network (`10.20.1.0/24`, in the estate address plan)
are inside it, so no scenario can ban one. A private host that calls a site by
its public name reaches Caddy over the private network, so Caddy sees that
private address.

The owner ruled that only fixed dedicated addresses go on a never-ban list,
never a person's address, which can change. Nothing here lists a person's
address, and our hosts' public addresses are not listed: nothing of ours is
known to call the edge from one.

The replay in `test_crowdsec_replay.py` sends Core Rule Set probes, known
exploits and admin probes from ops1's address and requires no alert and no
ban, so a change that drops the hub's whitelist fails CI.

Two consequences to know:

- The same whitelist covers every Docker bridge address (`172.16.0.0/12`).
  edge1's own probes, and any check run on edge1, come from one and are never
  banned. A real visitor whose address the docker-proxy collapses to a bridge
  address ("client IP key" above) is never banned either.
- A whitelist stops bans, not an in-band AppSec refusal of a single request:
  the in-band rules still answer 403 to a known exploit from a private
  address.

## Nextcloud profile

A site whose `backend` is `nextcloud` gets two things.

The throttle. Its general zone allows `NEXTCLOUD_RATE_LIMIT_EVENTS` a minute
instead of `RATE_LIMIT_EVENTS` (`posture.md`, "Nextcloud throttle").

The log whitelist. `stack/crowdsec/parsers/nextcloud-profile.yaml`
(`renderNextcloudWhitelist`) drops, on the Nextcloud hostnames only, the
access-log lines of Nextcloud's own normal traffic before any scenario reads
them. Each entry is a path family and the statuses Nextcloud answers a
signed-in client there:

- WebDAV (`/remote.php/dav`, `/remote.php/webdav`, `/public.php/...`). The
  desktop client asks for each new file before uploading it and is answered
  404, so a sync of ten new files looked like `http-probing`. An
  unauthenticated request there is answered 401, which is never in the list.
- Talk's API (`/ocs/v2.php/apps/spreed/`). Mid-call it answers 404 for an
  expired signalling session, 412 for a call already left, 409 and 400 for
  races between participants.
- Previews, avatars and thumbnails. A file with no preview yet, or a guest
  with no avatar, is a 404 at a new path each time.

The patterns follow the hub's own Nextcloud whitelist, narrowed to our
hostnames, to the path families we serve, and to no 401. A path with a dot
segment, encoded or not, is never dropped. The hub's admin-interface,
sensitive-file and exploit scenarios still read everything else on the
hostname.

What it does not do: the Core Rule Set still inspects Nextcloud traffic, and
WebDAV verbs such as `PROPFIND` trip it. While that scenario is watch-only this
only records. The OWASP Nextcloud rule exclusions belong to the false-alarm
review that ends watch-only, not to this profile.

The replay in `test_crowdsec_replay.py` plays a signed-in Talk video call and a
desktop sync with the Files app, to AppSec and to the access log, and requires
no ban; it plays admin probes, dot segments under the WebDAV prefix and two
known exploits on the same hostname, and requires each to ban.

## Being told about a ban

A ban pages the owner only when the banned address is owned. An address is
owned when it made a verified Ghost staff request through the edge in the last
30 days (the access log's `edge_trusted` is `1`), or when it sits inside a
banned range that contains such an address. "Owned" covers every tenant's
Ghost staff addresses (admins and editors who signed in through the edge), not
only the owner's. `EdgeBanIssued` in `hetzner/monitoring/render.ts` pages for
owned bans, through ntfy (page register entry `edge-ban`). Any other ban raises
`EdgeBanUnowned`, a warning that goes to email only and never to ntfy.

A systemd timer on edge1 (role `edge_ban_owner`) classifies every ban every 5
minutes. It reads only the edge's own access log, through the Caddy container,
and keeps the addresses only in the root-only state file
`/var/lib/branchleft/edge-ban-owner/trusted.json` (mode 0600), for at most 30
days, the edge's log retention. The metric and the alerts carry no address: each
owned ban is its own alert, labelled with CrowdSec's integer decision id. So an
owned ban pages up to about 5 minutes after it fires, plus the scrape interval.
A repeat ban of the same scenario is a new decision id, so it also pages within
about 5 minutes. Unowned bans are counted per scenario and go to email only.

If the classifier is stale (no run for over 15 minutes), every ban pages at
once. If it has reported and then goes missing (a lost scrape, or the node
exporter restarting), every ban pages once its absence has lasted 10 minutes, so
one lost scrape does not page. If it has never reported, every ban pages at once.
A stale classifier also raises `EdgeBanOwnerStale`, a page of its own, once the
staleness has lasted 5 minutes.

The role ships disabled: `edge_ban_owner_enabled: false` in
`ansible/roles/edge_ban_owner/defaults/main.yml`, with the matching constant
`EDGE_BAN_OWNER_ENABLED` in `hetzner/monitoring/render.ts`. While it is off the
role installs nothing on edge1, so no classifier ever reports: every ban pages at
once through the fallback, as before this change, and `EdgeBanOwnerStale` goes to
the `discard` receiver rather than the phone.
Turning it on is one commit that sets both to `true` and re-renders. The simulated
decisions of a watch-only scenario are not classified, so they never page; the
replay asserts that the gauge leaves them out.
