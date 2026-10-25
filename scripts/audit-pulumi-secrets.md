# audit-pulumi-secrets

Read-only. It reads committed files and never contacts a backend, a cloud API
or the Pulumi CLI, so it is safe to run from CI, from a pre-commit hook and
from a workstation with no credentials at all.

It exists because the constraint it guards has no other enforcement. Every
stack's secrets are wrapped by one KMS key; the key is destroyed during the
GCP wind-down; and once it is gone, the ciphertext committed in every
`Pulumi.<stack>.yaml` is undecryptable with no recovery path. The ordering
that prevents that is prose in a migration doc, which nothing checks. This
turns it into an exit code:

    --require-migrated   fail unless every stack has reached the terminal
                         state the inventory gives it, and every path that
                         can mint a new KMS-wrapped stack is retired. This
                         is the precondition the wind-down checks before it
                         destroys anything.

What it can and cannot see, stated plainly because a gate that overclaims is
worse than no gate:

- **It reads committed configuration, not checkpoints.** The KMS dependency
  lives in two places -- `secretsprovider`/`encryptedkey` in the committed
  `Pulumi.<stack>.yaml`, and `secrets_providers` inside the stack's
  checkpoint in its state bucket. Only the first is a committed file.
  A _half-finished_ re-wrap is precisely the case where the two disagree,
  and this script cannot detect it. `pulumi stack export --show-secrets`
  against the stack is the only proof of the checkpoint side; the runbook
  requires it per stack and requires the result recorded.
- **Two stacks have no committed configuration at all**, so nothing about
  them is machine-checkable from this repo. They are satisfied by an
  `attestation` recorded in the inventory instead -- an operator statement
  under review in git, reported as attested rather than verified.
- **A migrated stack's own file cannot prove it either.** PUL-12 forbids
  committing `encryptionsalt` even for a passphrase stack, so the mandated
  end state is salt-injected-at-deploy: nothing about the provider survives
  in the tree. That file reads identically to a stack that was never
  created -- both classify as `absent` -- so these stacks are satisfied by
  an `attestation` too, the same as the two with no file at all.
- **Other repos' files are only visible with `--root`.** Without it their
  stacks are `unresolved`, which is never silently treated as a pass.

Two further failure modes it does catch, both of which present as success:

- **A backend reference nobody enumerated.** The `gs://` state backend is
  configured in each CI workflow's `pulumi login` step rather than anywhere
  central, so a new workflow adds a site silently, and the site is only
  discovered when it applies against the state everyone else has left.
- **A provider-selection site left live.** Separately from where state is
  read, some workflows select the shared KMS key via `--secrets-provider`
  when they _create_ a stack. A sweep that re-wraps every existing stack
  while one of those survives is not finished: the next stack it mints is
  KMS-wrapped again, in a bucket that did not exist when this inventory was
  written.
- **A provider-selection site nobody enumerated.** The same shape as the
  backend-reference gap above: `provider_selection_sites` only verifies sites
  it already names, so a scan across the tree catches a new one.

Usage:

    audit-pulumi-secrets.py [--inventory PATH] [--root DIR]
                            [--require-migrated] [--json]

`--root` is the multi-repo workspace directory containing `shared-infra`,
`website`, `ghost-platform` and the tenant repos.

## Attestations versus files

Which file-derived provider an attested state is allowed to sit next to. An
attestation is an operator's word; a committed file is a fact, and where both
exist the file decides. Without this a `"state": "migrated"` typed onto a
stack whose `Pulumi.<stack>.yaml` still reads `gcpkms://` would turn the gate
green over the one stack in the set that could actually be checked.

`"absent"` belongs here alongside `"passphrase"`, not as a looser check but
as the _correct_ one: PUL-12 forbids a migrated stack from ever committing
its `encryptionsalt` again, so the salt is injected at deploy and never
lands in the tree. A fully migrated stack's config file is therefore
indistinguishable, by content, from one whose stack was never created --
both classify as `absent`. That ambiguity is exactly why an attestation is
required for these stacks rather than inferred from the file; the file can
only fail to contradict it. The rollback guarantee this table exists for
survives that: a rolled-back checkpoint restores an explicit
`secretsprovider: gcpkms://...` line, which is still outside this set and
still turns the gate red.

## Terminal states

What each terminal state accepts as reaching it. `attested-*` is an operator
statement recorded in the inventory rather than a fact read from a file, and
is kept as a separate status so a report never presents the two as equal.

`never-kms` is for a stack born on the passphrase provider that has no KMS
dependency to migrate away from -- listed to be enumerated (a `pulumi stack
ls --all` sweep still has to be able to find it and confirm that), not to
be swept. Demanding an attestation from it would repeat the exact failure
these comments warn against elsewhere: a gate red in its own success state
gets routed around by an operator typing "migrated" for a migration that
never happened. `needs-attestation` -- no committed evidence either way --
is that success state here, so it satisfies this terminal state on its own.
`pending` and `drift` still do not: if such a stack's file ever did show
`gcpkms`, or an attestation contradicted it, that is a real anomaly this
terminal state must not paper over.

## Provider-selection sites

Sites that pass a secrets provider when _creating_ a stack.

Re-wrapping every stack that exists is only half the sweep. While one of
these is live, the next stack minted is KMS-wrapped again -- and it lands
in a bucket that did not exist when the inventory was written, so nothing
downstream lists it.

`retired` is a claim in a JSON file that one hand edit can flip, on the
single gate the whole irreversible wind-down hangs on. So the flag is
never sufficient: where `--root` makes the file reachable, the file is
read and the claim checked against it. Unreachable is treated as not
retired rather than as retired, because the failure this guards is
unrecoverable and the other direction merely inconvenient.

## Undeclared provider-selection sites

The regression assertion `hetzner/RUNBOOK-existing-stack-migration.md`
describes: re-wrapping every stack that _exists_ is not the whole sweep while
something can still _mint_ a new KMS-wrapped one in a bucket no earlier
enumeration could list. `audit_provider_selection_sites` verifies the sites
this inventory already knows about; `audit_provider_selection_scan` instead
looks for one it does not.

Its reach is the same as the backend-reference scan: this repo's own tree
unconditionally (`REPO_ROOT`, via `main`), every sibling repo only with
`--root` -- because that is what CI can reach without one, and the two
provisioning sites this inventory does know about live in `ghost-platform`,
not here.
