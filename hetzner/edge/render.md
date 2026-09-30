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
