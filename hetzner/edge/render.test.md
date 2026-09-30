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
