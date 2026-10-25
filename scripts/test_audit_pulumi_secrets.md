# test_audit_pulumi_secrets: shipped-inventory test

`test_shipped_inventory_marks_exactly_the_fixed_sites_retired` runs the audit
with `root=None` on purpose. That matches this repo's own CI, which runs the
audit with no `--root`, so the test checks what the gate the shipped repo
actually runs sees. It is not a stand-in for a fuller check.

With no root, `retired` claims can only read back as `retired-unverified` or
`live`, never `retired`. The test therefore asserts on the claim each site
carries, not on file content. It fails if a site's `retired` claim regresses
either way: a fixed site silently un-flipped, or an unfixed site flipped.

A prior version asserted `all(status != "retired")`. Under `root=None` that
held for every possible inventory content and could never fail, so it
protected nothing.

## WorkspaceStackDiscoveryTests

This is the regression guard for the failure the inventory's own `$comment`
names: a stack that exists but was never entered in the inventory. The other
checks audit sites the inventory already knows about, so none of them can
notice a stack nobody wrote down. This test walks the stack-owning repos for
every `Pulumi.yaml` and fails if one has no matching entry.

It runs only where those repos sit next to this one on disk. This repo's own
CI checks out `shared-infra` alone, so there the sibling repos are absent and
the test skips. That avoids a false pass or fail for a tree it cannot see.

## Tenant provisioning sites

`infra/provisioning/index.ts` is deliberately not one of the enumerated sites.
It creates a new per-tenant state bucket, never a secrets-provider selection.
The earlier inventory that listed it was a miscategorisation. It is tracked as
its own item rather than folded into this gate.
