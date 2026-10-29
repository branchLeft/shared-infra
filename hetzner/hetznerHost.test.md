# hetznerHost.test

`@branchleft/hetzner-host` is a `link:` dependency, not a workspace member, so
it resolves its _own_ `@pulumi/pulumi` and `@pulumi/hcloud` from its own
`node_modules` rather than being hoisted into this project's. `pnpm ls`
confirms two physically separate copies of each package (both at the
identical pinned version). Pulumi's SDK is built to tolerate that — `Output`
uses a marker property rather than `instanceof` specifically so consumers
of third-party component packages work across copies — but nothing else
here exercises the boundary: `host.test.ts` moved to `hetzner-host/` with
the code it tests, and it constructs `Host` using _its own_ copy of
`@pulumi/pulumi` throughout.

This test sets mocks with _this_ project's copy and constructs a `Host`
from the dependency, so it is the one thing in this repository that would
fail if the two copies stopped interoperating -- whether from a future
version drift, a resolution change, or the package boundary being wired up
wrong (as it briefly was: this test is what a broken `hetzner/` install
looks like from Vitest's side, one layer before Pulumi ever sees it).
