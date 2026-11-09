# `render.test.ts` notes

CMT-3 pointer target: the narrative moved out of that file's comments lives
here. Update this doc, not a long comment block, when any of the following
changes.

## Redirect blocks never carry the magic-link directive

The highest-consequence regression this split could produce, named
explicitly rather than left to the committed-Caddyfile snapshot.

`redirectBlock()` gets its chain from `protectionChain()` without
`membersMagicLink: true`, so the directive cannot render there -- but that is
a property of one argument at one call site, and a redirect block has no
matcher to reference. If it ever gained the directive, the rendered
Caddyfile would carry `rate_limit @members_magic_link` against an undefined
matcher, Caddy would refuse to load the file, and the restart that deployed
it would take every hostname on this edge down rather than throttling one
path.

## The committed posture's general throttle

The `the committed posture's general throttle` describe renders the committed
`POSTURE` and splits it into top-level blocks. It then asserts, per kind
(servable site, redirect, static and probe blocks), that each carries exactly one
matcher-less `rate_limit`, with expected counts derived from `sites`,
`hostRedirects` and `staticSites` rather than a hard-coded total. A builder that
stops calling `protectionChain` therefore fails on its own kind. It also asserts
that the `:9091` metrics listener carries none, that every general zone is
distinct, that each uses the direct-peer key at `RATE_LIMIT_EVENTS` per
`RATE_LIMIT_WINDOW_SECONDS`, and that the general directive precedes the
magic-link directive and `reverse_proxy`.

It asserts the shape of the directive, not that the key or the threshold is safe
for real traffic. That is the owner-run pre-apply check in `RUNBOOK-edge.md`
§10a.
