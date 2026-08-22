# Runbook — migrating an existing stack off GCP KMS and off `gs://` state

For stacks that already exist. Creating a new one is
[`RUNBOOK-new-stack.md`](RUNBOOK-new-stack.md), which starts on the passphrase
provider and the Object Storage backend and never touches any of this.

Two independent migrations, deliberately written as two parts:

|            | What moves                                                     | When it has to happen                                                                   | What blocks it                                                                                                                                      |
| ---------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Part A** | Secrets: the shared GCP KMS key → Pulumi's passphrase provider | **Before the GCP wind-down destroys the key.** Nothing else gates it — it can run today | Nothing. Every input exists                                                                                                                         |
| **Part B** | State: `gs://` → Hetzner Object Storage                        | Any time before the state buckets are retired, which is after cutover                   | Object Storage's own backend behaviour, which is unverified. Its destination bucket exists; its rehearsal needs a separate lab bucket that does not |

**Do not wait for Part B to run Part A.** They share a stack but not a
deadline, and Part A's deadline is the one that cannot be missed. Part A
leaves every stack fully working on the `gs://` backend it is on today.

**Part C is not a third migration.** It moves nothing. It is the check that
the passphrases Part A minted still open the archives Part A produced, run
immediately before the GCP wind-down destroys the KMS key version — the point
after which a wrong passphrase is unrecoverable.

---

## The gate, stated once

Every stack in the estate has its secrets wrapped by one key:

```text
gcpkms://projects/branchleft-prod/locations/europe-west1/keyRings/pulumi/cryptoKeys/pulumi-secrets
```

One key ring (`pulumi`), one key (`pulumi-secrets`), one enabled key version
(`1`), software protection level, in `europe-west1` in project
`branchleft-prod`.

That key does not encrypt the secrets themselves. It wraps each stack's own
data key — the `encryptedkey:` line in every `Pulumi.<stack>.yaml`, and the
same value inside each checkpoint's `secrets_providers` block. The data keys
are what encrypt the ciphertext. So:

- **Destroy key version 1 and every stack loses its data key at once.** Not
  one stack, not the ones with secret config values — all of them, including
  stacks whose config file declares no secrets, because their checkpoints
  still hold encrypted resource outputs.
- **There is no recovery.** A destroyed KMS key version cannot be restored
  after its destruction-scheduled window elapses — **30 days** on this key
  (`destroyScheduledDuration: 2592000s`), not the 24-hour default — and the
  plaintext
  data keys exist nowhere else. The committed ciphertext stays in git
  forever, permanently meaningless.
- **A stranded stack cannot be destroyed either.** `pulumi destroy` reads
  the checkpoint, and reading a checkpoint that holds encrypted outputs needs
  the data key. So missing the gate does not merely lose secrets; it leaves
  live GCP resources that Pulumi can no longer tear down, which then have to
  be deleted by hand and reconciled.

The wind-down's own precondition is "no stack decrypts via KMS", and that has
to be checkable rather than assertable. The check reads a committed
enumeration of every stack, the terminal state each one owes, and every path
that could mint a new KMS-wrapped stack, and exits non-zero unless all of them
are satisfied. Treat a non-zero exit as a hard stop on the wind-down, not as a
warning.

Terminal state is per stack, not one rule for all of them: a stack whose end
state is **gone** is satisfied by being gone, not by being re-wrapped, and
demanding a migration of it would leave the gate red in its own success
state.

**Two stacks have no committed configuration**, so no file in any repo can
report their provider. They are closed by an `attestation` in the inventory
instead — `state`, `date` and a line saying what was actually run:

```json
"attestation": {
  "state": "removed",
  "date": "2026-08-16",
  "evidence": "pulumi stack ls --all on gs://branchleft-pulumi-state: absent"
}
```

The report labels these `attested-*` rather than `migrated`, and never
presents an operator statement as a machine-verified fact. An attestation
missing its date or its evidence line is rejected as drift — the difference
between an attestation and a checkbox is that one says what was run, and a
checkbox on this gate is what the gate exists to replace.

### What may be destroyed, and when

The key ring cannot be deleted at all — GCP key rings are permanent — so the
end state is an empty tombstone ring either way. The only destructive action
is on the key version, and it is the **last** step of the whole programme, not
part of the resource teardown:

1. Every stack reaches a terminal state (below).
2. `--require-migrated` exits 0.
3. Only then, the one destructive command:

```bash
gcloud kms keys versions destroy 1 \
  --key=pulumi-secrets --keyring=pulumi \
  --location=europe-west1 --project=branchleft-prod
```

Six identities hold `roles/cloudkms.cryptoKeyEncrypterDecrypter` on that key —
five deployer service accounts and the platform owner. Revoking any of those
bindings before the sweep has the same effect as destroying the key, for
whichever pipeline held it. **Revoke nothing on this key until the audit
passes.**

A seventh binding matters more than any of them: `ghost-tenant-provisioner`
holds `roles/cloudkms.admin`. That is the only identity besides the platform
owner that can execute `keys versions destroy`, and it is reachable from a CI
workflow rather than from a person. Nothing in the wind-down needs that
service account to be able to destroy the key, and the sweep is the natural
moment to narrow it to the encrypt/decrypt role it actually uses.

---

## The stacks

Six stacks exist today across two state backends, and no single command lists
them. Plain `pulumi stack ls` lists only the _current project's_ stacks, so it
shows one; `pulumi stack ls --all` shows every stack in the backend you are
logged into, which is five; and the sixth lives in a different bucket and
appears in neither.

`scripts/pulumi-stack-inventory.json` also carries two Hetzner stacks that do
not exist yet, in a third backend that neither of the commands above will ever
reach until something is created there — listed ahead of their own creation
precisely so provisioning them later cannot mint one KMS-wrapped by accident.
`scripts/audit-pulumi-secrets.py --root <workspace>` is what actually walks
every stack in the inventory, across every backend and every sibling repo;
run it before trusting `pulumi stack ls` for anything this runbook depends on.

**That is the finding, and it generalises past this estate.** A sweep that has
to cover every stack cannot discover its own subject, so the subject has to be
written down first, in a file, and the sweep has to fail on a stack that file
does not list. A stack absent from the enumeration is a stack nobody re-wraps,
and after the key is destroyed its committed ciphertext is meaningless
permanently.

Terminal state is per stack, not one rule for all of them: a stack whose end
state is **gone** is satisfied by being gone, not by being re-wrapped, and
demanding a migration of it would leave the gate red in its own success state.

### Re-wrapping what exists is not the whole sweep

An enumeration covers every stack that exists **today**. Anything that can
_mint_ a new stack — a provisioning workflow passing
`--secrets-provider="gcpkms://…"`, or code that creates a new state bucket per
tenant — will mint it wrapped by the same key, in a location that did not exist
when the enumeration was written.

The failure mode is concrete: sweep completes, audit goes green, a new tenant is
provisioned, it is minted wrapped by the doomed key in a brand-new bucket, the
key is destroyed, and that stack is stranded on day one — unable to decrypt and
unable to `pulumi destroy` either, because destroy reads the checkpoint.

**So the sweep is not complete while any provider-selection site is live**, and
those sites have to be enumerated and flagged retired separately from the
stacks. The precondition check fails while any of them is still live, which is
the intended coupling: the audit cannot go green until the workflow change
lands.

### Two shapes that are not straightforward re-wraps

**A stack whose program is committed nowhere.** `pulumi stack rm` resolves the
project from the working directory, and there is no committed directory to
resolve. Give it a throwaway workspace naming the project it must match:

```bash
mkdir /tmp/stack-removal && cd /tmp/stack-removal
printf 'name: <the project name>\nruntime: nodejs\n' > Pulumi.yaml
pulumi login <the backend>
pulumi stack ls --all                                  # confirm it is the stack you think
pulumi stack rm <the stack> --yes --remove-backups
```

`--force` is deliberately absent: it would remove a stack that still manages
resources. A stack managing none succeeds without it — and if the unforced
command refuses, that refusal is information, not an obstacle to override.

**A stack that is going away anyway.** The temptation is to skip it, and that
is exactly the stranded-stack failure above: `pulumi destroy` is the command
that stops working once the key is gone. Either migrate it like the others, or
destroy it and archive its export, and record which. "It's going away" is not a
terminal state.

---

# Part A — re-wrap secrets onto the passphrase provider

## A.0 Before you start

Generate **one passphrase per stack**, fresh, high entropy. Store each one in
the password manager **and** as a `PULUMI_CONFIG_PASSPHRASE` GitHub Actions
secret on the repo that applies that stack, before running anything.

Losing a passphrase strands that stack exactly as losing the KMS key would.
There is no escrow and no re-wrap without it. This is a strictly worse failure
mode than the key it replaces and it is accepted, for the reason
`RUNBOOK-new-stack.md` gives: the alternative is a dependency on the cloud
account this programme exists to leave.

Three repos hold a `PULUMI_CONFIG_PASSPHRASE` secret, and all three are set:
`branchLeft/shared-infra`, `branchLeft/website` and `branchLeft/ghost-platform`.

| Repo                        | Stack it applies                                                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `branchLeft/shared-infra`   | `branchleft-shared-infra/production` (`branchleft-mail/production` shares the repo but has its own secret, `PULUMI_PASSPHRASE_MAIL`) |
| `branchLeft/website`        | `branchleft-website-infra/production`                                                                                                |
| `branchLeft/ghost-platform` | `branchleft-ghost-platform/platform`, `branchleft-ghost-provisioning/blog` and, during provisioning, the tenant's own stack          |

**`branchLeft/ghost-tenant-blog` is not a fourth row.** `blog-infra/blog` is a
tenant stack, and unlike the three repos above, its secret was never set at
onboarding: its stack has been KMS-wrapped since it was created, so nothing
has needed a passphrase secret until now. **This is a fact about that
repo's history, not a promise about its current state — check before relying
on it:** `gh secret list --repo branchLeft/ghost-tenant-blog`. If
`PULUMI_CONFIG_PASSPHRASE` is already there, this stack has already been
through the mint-escrow-set sequence below (`branchLeft/workspace#128` is
where that re-wrap is tracked) — do not repeat it. If it is not there, that
sequence is what to run when this stack's turn comes; see "The hazard that
decision creates" below for the exact steps.

### One passphrase per repo, not per stack — decided

Per-stack passphrases collide with a fixed environment-variable name.
`PULUMI_CONFIG_PASSPHRASE` is what Pulumi reads, so two values in one repo are
only reachable by naming the secrets differently and mapping each into that
variable at the step that needs it. `ghost-platform` is where that bites:
`provision-tenant.yml` handles **three** stacks in a single run.

**`ghost-platform` uses one passphrase for the whole repo, covering all three
of its stacks, as a single repo-level `PULUMI_CONFIG_PASSPHRASE`.** The
per-stack blast-radius property is knowingly traded for a workable single
environment-variable name; that repo's workflows can already reach every one
of its stacks, so the isolation being given up is smaller than it first looks.
This is settled — do not re-open it per stack while working through A.2.

`shared-infra` reached the same collision when `branchleft-mail` gained its CI
apply path, and resolved it the other way: **per-stack passphrases with
per-stack secret names**, each mapped into `PULUMI_CONFIG_PASSPHRASE` at the
job that needs it (`PULUMI_CONFIG_PASSPHRASE` itself stays the edge stack's
secret for continuity; mail's is `PULUMI_PASSPHRASE_MAIL`, and the estate
stacks follow that naming as they join). The repos differ deliberately:
`ghost-platform`'s workflows already reach all three of its stacks in one run,
so a shared passphrase gave up little; `shared-infra`'s stacks are separate
pipelines for separate blast radii — mx1 above all — and keeping their
passphrases separate is the point of the project split.

### The hazard that decision creates: one checkpoint, two repos

**This blocks `blog-infra/blog`, and it is a precondition rather than a
future-tenant concern.**

A tenant's stack is written by two different pipelines holding two different
secrets:

- `provision-tenant.yml`, in `ghost-platform`, acts on the **tenant's own
  stack** in the tenant's own bucket, using `ghost-platform`'s passphrase.
- The **tenant repo's** own CI reads and applies that same stack, using the
  tenant repo's `PULUMI_CONFIG_PASSPHRASE`.

Two different values cannot both decrypt one checkpoint. Re-wrapping
`blog-infra/blog` without first making `ghost-tenant-blog`'s own secret match
whatever value the checkpoint ends up wrapped with breaks whichever of those
two pipelines is not holding that passphrase — and it breaks it silently
until something needs a secret. Unlike a stack that has already been
re-wrapped once, `ghost-tenant-blog` has no prior passphrase secret to
mismatch against the first time (below) — but a freshly minted one, wrapped
into the checkpoint and never propagated to that repo's secret, creates the
exact same mismatch from the other direction.

**The resolution is decided and landed: provisioning mints the tenant's
passphrase and sets the tenant repo's Actions secret from it**, so one value
exists per tenant stack and both pipelines hold that same one. Tenant repos
sharing `ghost-platform`'s passphrase, and provisioning ceasing to touch
tenant stacks after creation, are both closed — implemented in the
provisioning rewrite, `branchLeft/ghost-platform#81`.

**Each tenant's stack must have its own distinct passphrase.** The
`encryptionsalt` value is an offline passphrase verifier, not a harmless
scalar — it encodes a known-plaintext ciphertext that anyone holding it can
use to brute-force the passphrase offline without touching a state bucket.
A tenant repo must never receive a verifier for `ghost-platform`'s passphrase,
because it grants the ability to attempt offline brute-force against a
passphrase the tenant repo should not be able to attack. This constraint
is why each tenant's stack must reach CI with the tenant repo's own secret,
not `ghost-platform`'s — the two secrets are never interchangeable.

Two things follow that change what you do here.

**`blog-infra/blog`'s gate is narrower now, and it is a manual call made at
re-wrap time, not something the rewrite's code decides.** The rewrite never
touches an already-onboarded tenant's stack: `provision-tenant.yml` refuses
outright when the tenant repo already exists (onboarding is create-only), so
`blog-infra/blog` is structurally never reached by the mint-and-set path —
that path only runs the one time a tenant is first onboarded.
Unlike the three repos in the table above, `ghost-tenant-blog`'s secret was
never set at onboarding — its stack has been KMS-wrapped since it was
created and has never needed one (confirm this is still true before acting
on it, per the note above the table). Absent that secret, there is no
existing value to adopt at step 0. The call made by whoever runs A.2 against
`blog-infra/blog` is **mint, escrow by hand, and set the tenant repo's
secret**, in this order, before starting that stack's A.2 run:

1. Generate a fresh, high-entropy passphrase for `blog-infra/blog` alone —
   never `ghost-platform`'s. A tenant repo must never hold an offline
   verifier for another repo's passphrase (above); reusing `ghost-platform`'s
   here would hand `ghost-tenant-blog` exactly that.
2. Store it in the password manager, the same as every other stack's
   passphrase under this section.
3. Set it as `branchLeft/ghost-tenant-blog`'s `PULUMI_CONFIG_PASSPHRASE`
   repository secret.

**Do all three before A.2 step 5 runs against this stack, not after.** Step 5
is what wraps the checkpoint with the value now sitting in the password
manager; setting the tenant repo's secret only after that step leaves the
checkpoint decryptable by a value nothing else holds for however long the
secret takes to set — the same stranding this whole runbook exists to
prevent, reached from the other direction. Once the secret is set, use that
same minted value as this stack's passphrase for the rest of A.2: it now
lives in the password manager, the tenant repo's CI secret, and (once step 5
runs) the checkpoint, which is the end state this section wants.

**A minted passphrase still has no human copy, and that gap is accepted for
now rather than closed.** `ghost-platform` is a public repo, so there is no
safe channel inside `provision-tenant.yml` to print a freshly minted
passphrase anywhere a human could read it back — any Actions log or job
summary in a public repo is visible to anyone, not just this org. The
workflow instead surfaces the gap loudly, every run, in its job summary,
rather than solving it: it names the tenant, states plainly that no escrow
copy exists, and gives the exact command to overwrite the tenant's secret
with a human-chosen, password-manager-escrowed value for any tenant where
durable recoverability matters before that becomes acceptable long-term. A
lost secret with no escrow leaves that stack undecryptable and undestroyable,
exactly as a lost KMS key would — closing this properly needs a retrieval
channel that never touches the public repo's own Actions output, which is
follow-up work.

## A.1 Confirm you can decrypt, before you change anything

The passphrase is **not** supplied here. It is supplied inside the per-stack
block in A.2, once per stack, and torn down at the end of that same block.

That placement is the whole point. A passphrase file created once and left in
place is still pointing at stack 1's passphrase when stack 2 runs, and every
verification step in A.2 passes anyway — the stack re-wraps cleanly, decrypts
cleanly and previews clean, because one valid passphrase is as good as
another to Pulumi. The result is six stacks sharing one secret, silently,
which is exactly the property A.0 exists to prevent. **Never carry a
passphrase file across two stacks.**

The old provider needs no secret from you — it is KMS, and your own
`gcloud` credentials authorise the unwrap. Confirm they do, before touching a
stack:

```bash
gcloud kms keys versions list --key=pulumi-secrets --keyring=pulumi \
  --location=europe-west1 --project=branchleft-prod
```

Key version `1` must report `ENABLED`. If this errors with a reauth message,
run `gcloud auth login` and `gcloud auth application-default login` and start
again — Pulumi's GCS backend and its KMS unwrap both use application-default
credentials, and a stale token surfaces as an opaque state-read failure.

## A.2 Per-stack sequence

Run this whole block once per stack, in the order the table below gives, **in
a fresh shell each time**. Each step's `<...>` is filled from the stacks
table. Step 0 and step 7 are the bookends that keep one stack's passphrase
out of the next stack's run — do not hoist step 0 out of the loop.

```bash
# 0. This stack's own passphrase, freshly generated for this stack alone.
#    Never on a command line, never echoed, never exported as a value.
#    Entered twice: what you type here becomes the only thing that can ever
#    decrypt this stack, and nothing downstream compares it to the copy in
#    the password manager. A typo here is silent and permanent.
#    `read -rs "VAR?prompt"`, not `read -rs -p 'prompt' VAR` -- the platform
#    owner's shell is zsh, where `-p` means "read from a coprocess", not
#    "print a prompt". It fails with `no coprocess`, leaves VAR empty, and
#    the confirm check below then compares "" to "" and passes.
umask 077
install -m 600 /dev/null ~/.pulumi-passphrase-tmp
read -rs "PASSPHRASE?New passphrase for THIS stack: "; echo
read -rs "CONFIRM?Again, to confirm:            "; echo
[ "$PASSPHRASE" = "$CONFIRM" ] || { echo 'MISMATCH -- start this stack again'; return 1 2>/dev/null || exit 1; }
printf '%s' "$PASSPHRASE" > ~/.pulumi-passphrase-tmp; unset PASSPHRASE CONFIRM
[ -s ~/.pulumi-passphrase-tmp ] || { echo 'EMPTY PASSPHRASE FILE -- do not continue'; return 1 2>/dev/null || exit 1; }
export PULUMI_CONFIG_PASSPHRASE_FILE=~/.pulumi-passphrase-tmp
unset PULUMI_CONFIG_PASSPHRASE
[ -z "${PULUMI_CONFIG_PASSPHRASE:-}" ] || { echo 'PULUMI_CONFIG_PASSPHRASE is set and would override the _FILE -- unset it'; return 1 2>/dev/null || exit 1; }

# 1. The checkout that owns this stack's Pulumi.<stack>.yaml, on a branch --
#    not on main, and not a worktree checked out for other work. The command
#    below rewrites that file in place, and the rewrite must land in a commit.
cd <repo>/<project-dir>
git switch -c chore/passphrase-secrets-<stack>
nvm use && npm ci

# 2. Address the right state. `pulumi login` is global: it rewrites
#    ~/.pulumi/credentials.json for every project on the machine.
pulumi login <backend-url>
pulumi whoami --verbose        # Backend URL must be <backend-url>

# 3. Pre-re-wrap archive. This is the ROLLBACK, and it is KMS-wrapped, so it
#    is restorable only while the key lives. See step 6b for the durable one.
#    Pre-created 0600: the default mode would leave the stack's encrypted
#    state world-readable, and step 0 already set umask 077 for this shell.
install -m 600 /dev/null ~/pulumi-archive-<project>-<stack>.json
pulumi stack export --stack <stack> --file ~/pulumi-archive-<project>-<stack>.json

# 4. Prove the current provider can decrypt, before replacing it. A stack that
#    cannot decrypt now will fail mid-rewrite, and mid-rewrite is the one place
#    this procedure has no clean recovery. `pulumi preview` is the probe
#    because it fails closed on a wrong passphrase; `stack export
#    --show-secrets` does not (it exits 0 regardless, observed v3.255.0 --
#    INC-4 in ghost-platform-docs/INCIDENTS.md), so it proves nothing here.
pulumi preview --stack <stack> > /dev/null && echo 'decrypt OK'

# 5. Re-wrap. Reads through the old provider, writes through the new one,
#    rewrites every encrypted value in the checkpoint and in
#    Pulumi.<stack>.yaml. This is the irreversible step.
pulumi stack change-secrets-provider passphrase --stack <stack>

# 6. Verify before moving on. All three, in this order.
git diff --stat Pulumi.<stack>.yaml          # secretsprovider: gcpkms -> passphrase (also
                                              # gains an encryptionsalt line -- not committed, see below)
pulumi preview --stack <stack>               # expect: no changes -- and reaching
                                              # the plan at all IS the decrypt
                                              # proof (fails closed on a wrong
                                              # passphrase; `stack export
                                              # --show-secrets` does not)

# 6b. Post-re-wrap archive. This is the DURABLE BACKUP, wrapped by the new
#     passphrase, and it is the only archive of this stack that still opens
#     after the KMS key is destroyed. Keep it; it is what the wind-down's
#     "state exports archived" step actually means.
install -m 600 /dev/null ~/pulumi-postwrap-<project>-<stack>.json
pulumi stack export --stack <stack> --file ~/pulumi-postwrap-<project>-<stack>.json

# 7. Prove the STORED copy works, before deleting the only other one.
#    Re-type the passphrase from the password manager -- do not copy the
#    temp file, which would prove nothing except that the file matches
#    itself. If this fails, the temp file is still the only working copy:
#    fix the password manager entry now, before step 8.
install -m 600 /dev/null ~/.pulumi-passphrase-check
read -rs "STORED?Passphrase AS STORED in the password manager: "; echo
printf '%s' "$STORED" > ~/.pulumi-passphrase-check; unset STORED
[ -s ~/.pulumi-passphrase-check ] || { echo 'EMPTY PASSPHRASE FILE -- do not continue'; return 1 2>/dev/null || exit 1; }
PULUMI_CONFIG_PASSPHRASE_FILE=~/.pulumi-passphrase-check \
  pulumi preview --stack <stack> > /dev/null \
  && echo 'STORED COPY OK' || echo 'STORED COPY FAILED -- do not run step 8'
# `pulumi preview`, not `stack export --show-secrets`: export exits 0 under a
# wrong passphrase (v3.255.0), and this is the gate that authorises deleting
# the only other copy -- the one check in this file that must be able to fail.
# A wrong value stored at creation is not hypothetical: it is how the estate
# stack's state was lost on 2026-08-21 (INC-3).

# 8. Only once step 7 printed OK.
rm -f ~/.pulumi-passphrase-tmp ~/.pulumi-passphrase-check
unset PULUMI_CONFIG_PASSPHRASE_FILE
```

Then close the shell and open a new one for the next stack.

Step 7 is not belt and braces. Step 0 takes the passphrase from your fingers,
not from the password manager, and every check in step 6 decrypts using that
same temp file — so a stack re-wrapped under a mistyped passphrase verifies
perfectly and then dies at step 8, when the only copy that worked is deleted.

It mattered most for **`branchleft-mail/production`**, and step 7 was not
optional there under any circumstances. Every other stack had a CI apply path
that would fail loudly on its next run, while the KMS archive was still
restorable — a second chance that costs a broken pipeline and nothing worse.
`mail` had no CI apply path when its Part A ran (it has since gained one —
the `mail-plan`/`mail-apply` jobs in `.github/workflows/ci.yml`, which now
exercise its passphrase on every merge), and it is the one stack that
outlives the GCP estate, so at the time nothing would have exercised its
passphrase until somebody genuinely needed it. It stayed early in the order
because it was the gentlest stack to learn on, not because it was the most
forgiving to get wrong.

Step 4 is the one that turns a silent failure into a loud one, and its probe
is `pulumi preview`, which refuses to proceed at `getting stack
configuration` when the provider cannot decrypt. It was originally written
around `stack export --show-secrets` on the theory that emitting plaintext
forces the decryption; **observed reality disagrees** — with the passphrase
provider on v3.255.0 that command exits 0 under a wrong passphrase (INC-4 in
`ghost-platform-docs/INCIDENTS.md`). Whether the KMS provider behaves
differently is moot: preview fails closed for both, and emits no secrets.

**Record step 6's result in the stack's PR description** — the three commands
and their output, minus the export itself. This is not ceremony: the audit
script reads committed configuration only, and the KMS dependency also lives
in the checkpoint, in its `secrets_providers` block. A half-finished re-wrap
is exactly the case where the two disagree, and no committed file shows it.
step 6's clean preview is the proof the
checkpoint side moved, and if it is not written down it did not happen.

`change-secrets-provider` rewrites `Pulumi.<stack>.yaml` mechanically and
**strips every YAML comment** in it. If a comment in that file is load-bearing
for anything — this repo's own inventory listed the root
`Pulumi.production.yaml` as a backend-reference site on the strength of one —
the dependent check will flag the loss after the re-wrap. Update the checker's
inventory in the same session; do not re-add the comment to a file the tool
rewrites.

Step 6's `pulumi preview` expecting **no changes** is the real acceptance
test. Re-wrapping is a state-representation change and must be invisible to
the program. Any diff means something else moved, and it is worth
understanding before the next stack rather than after the whole sweep.

**One stack has a known, expected diff: `branchleft-website-infra/production`.**
Its committed `imageTag` is a stale bootstrap value that CI overrides
out-of-band on every deploy, so a preview from a checkout always reports an
image change — documented in `website/infra/KNOWN_ISSUES.md`. For that stack
the acceptance test is "no changes **other than** the Cloud Run image", and
nothing else. Two things follow, and both matter more than the wording:

- **Do not stop the sweep on it.** It is not evidence of anything the re-wrap
  did, and treating it as a surprise stalls a deadline-bound procedure on a
  red herring.
- **Do not reconcile it.** Running `pulumi up` to make the preview clean rolls
  production back to the bootstrap image. The diff is meant to be there.

`change-secrets-provider` wrote a real `encryptionsalt` value into
`Pulumi.<stack>.yaml` in step 5 — Pulumi has no other way to leave the file
usable locally. **That line must never be staged or committed.** Every stack
in this estate is salt-injected-at-deploy: the salt lives only as a
repository secret, appended to the working copy at apply time — by CI for a
stack CI applies, by the operator's own copy for one that has no CI apply
path (`hetzner/`'s two stacks, until they join CI applies) — and it is never
committed. This repo's own
`Restore the stack's encryption salt` step in `.github/workflows/ci.yml` is
the pattern to match. Committing it publishes an offline verifier for the
stack's passphrase in a public repo, which is exactly what A.0 exists to
prevent.

Before staging anything, pull the salt back out and turn it into a secret
instead of a committed line:

```bash
SALT=$(awk -F': ' '/^encryptionsalt:/ {print $2}' Pulumi.<stack>.yaml)
sed -i '' '/^encryptionsalt:/d' Pulumi.<stack>.yaml
```

Set `$SALT` as a repository secret on the repo that applies this stack —
named consistently with any stack that repo's CI already salts (this repo's
edge stack uses `PULUMI_SALT_EDGE`) — then `unset SALT`. Only then commit and
open a PR **for that stack's repo**:

```bash
git add Pulumi.<stack>.yaml
git commit -m 'chore(infra): re-wrap <stack> secrets onto the passphrase provider'
```

**Do not merge that PR until the repo holds both the
`PULUMI_CONFIG_PASSPHRASE` secret and the new salt secret**, or the next CI
run fails closed on whichever one is missing.

### The window between step 5 and that merge

Step 5 rewrites the **remote checkpoint immediately**. The matching config
change lands only when the PR merges. Until it does, `main` carries a
`secretsprovider: gcpkms://` line and a stale `encryptedkey` against a
checkpoint that is now passphrase-wrapped — and `shared-infra`'s CI runs
`Deploy (pulumi up)` on **every push to `main`**. So the risk in this window
is merging too _late_, or letting anything else merge first, not merging too
early.

Three rules for it:

- **Do one stack per session, start to merged.** Do not re-wrap on a Friday
  and merge on a Monday.
- **Freeze merges to that repo for the duration**, including tool-generated
  PRs. A graph-update PR merging into that window is a push to `main` like
  any other.
- **Neutralise the automatic merge before step 5, not by intending to.**
  A freeze that depends on people choosing not to merge does not hold here,
  because nothing in this workspace waits to be asked: the workspace-root
  hook `.claude/hooks/graphify-session.py` squash-merges open
  `chore(graphify)` PRs **at every session start, with no human in the
  loop**, and this repo's CI runs `Deploy (pulumi up)` on every push to
  `main`. So anyone — or any agent — opening a session in the workspace
  during the window pushes to `main` and triggers a deploy against a
  checkpoint that no longer matches `main`'s config. Before step 5 either
  merge or close every open `chore(graphify)` PR on this repo so the hook has
  nothing to act on, or disable the hook for the duration. Confirm with
  `gh pr list --repo branchLeft/shared-infra --author app/github-actions`
  returning nothing before you start.
- **If a sweep is abandoned mid-stack** — you re-wrapped and cannot finish —
  do not leave it. Either restore the A.2 step 3 archive with `pulumi stack
import` (which puts the checkpoint back on KMS, valid while the key lives)
  or land the config PR. Leaving the checkpoint and `main` disagreeing is the
  one state this procedure has no safe resting point in.

What Pulumi does on that mismatch is not documented and has not been tested
here, so none of the above rests on a prediction about it. The window is the
finding; its exact symptom is not worth guessing.

### Order

Least blast radius first, so a surprise is found on a stack whose failure
costs least. Concretely:

1. **Anything being removed rather than migrated** — nothing depends on it, and
   it takes a stack out of every future `pulumi stack ls --all`.
2. **The smallest real stack with no CI apply path.** A stack with a handful of
   resources and no encrypted values in state exercises the whole procedure
   without a deploy pipeline participating. If any stack in the sweep outlives
   the estate being wound down, do this one here — its `step 7` proof is the
   one that matters most later.
3. **Stacks whose config file is committed and whose CI applies them**, in
   ascending order of what an outage costs.
4. **Any stack in a separate state bucket**, which needs its own `pulumi login`
   and is the easiest to forget entirely.
5. **Last: any stack whose config file is committed nowhere**, or whose CI path
   actively rejects the new provider. These need a code change elsewhere before
   the sweep can touch them.

Name the blocked ones up front rather than leaving them to be discovered at the
last stack of the set: a gate found at step 6 of 6 is a gate found after the
irreversible steps.

The order itself does not change because of those gates — both blocked stacks
were already last, for unrelated reasons. What changes is that reaching them
is not a matter of working down the list: if either gate is still open when
you get there, stop at four and come back. **Four of six re-wrapped is a
perfectly good resting state**; a tenant stack re-wrapped under the wrong
passphrase is not.

## A.3 The special case: the provisioning stack

`branchleft-ghost-provisioning/blog` has no `Pulumi.blog.yaml` in any repo. The
tenant-provisioning workflow rebuilds it on the runner from
`pulumi stack export` on every run, via
`ghost-platform/infra/provisioning/scripts/restore-stack-secrets-config.py`,
and that script raises outright on any provider that is not `cloud`:

> stack … records a … secrets provider. Restoring its configuration would not
> reproduce the key its state was encrypted with.

So re-wrapping this stack breaks tenant provisioning until that script and the
workflow are changed to handle a passphrase-managed stack — restoring
`encryptionsalt` from the deployment's `secrets_providers.state.salt` and
sourcing the passphrase from a GitHub Actions secret. **That change lands
first, in `ghost-platform`; the re-wrap follows it.** Doing it the other way
round leaves the provisioning pipeline broken for as long as the fix takes,
and the pipeline is how a tenant gets onboarded.

The re-wrap itself works the same way — Pulumi writes `Pulumi.blog.yaml` into
the working directory, and that file must never be committed. Instead,
**`encryptionsalt` is reconstructed from the deployment on every run**, via
`restore-stack-secrets-config.py` reading `deployment.secrets_providers.state.salt`.
This is deliberate and not an oversight: `pulumi stack export` needs only bucket
read access and no secret, so the salt is genuinely reproducible. The salt is an
offline passphrase verifier (see A.0), safe to reconstruct this way, and
committing the file would add no security benefit while requiring a commit-back
step the workflow does not have. Reconstructing on every run has the same
exposure as the current process for `cloud` provider stacks already accepts.

## A.4 Rollback, and the point of no return

| Step                                     | Reversible?                             | How                          |
| ---------------------------------------- | --------------------------------------- | ---------------------------- |
| A.1 supply passphrase                    | yes                                     | Delete the temp file         |
| A.2 step 2 `pulumi login`                | yes                                     | `pulumi login <old-backend>` |
| A.2 step 3 export                        | yes                                     | Read-only                    |
| A.2 step 4 decrypt check                 | yes                                     | Read-only                    |
| **A.2 step 5 `change-secrets-provider`** | **no — this is the point of no return** | See below                    |
| A.2 step 6 verify                        | yes                                     | Read-only                    |
| commit/PR                                | yes                                     | Close the PR                 |

`change-secrets-provider` rewrites the checkpoint in place. There is no
inverse command. What exists instead is the step 3 archive: `pulumi stack
import --file ~/pulumi-archive-<project>-<stack>.json` restores the previous
checkpoint, including its KMS-wrapped values, and works for exactly as long as
the KMS key still exists. Restore also needs the `Pulumi.<stack>.yaml` from
before the rewrite — `git checkout -- Pulumi.<stack>.yaml`, which is why step
1 insists on a clean branch rather than a dirty tree.

That archive is the whole rollback. Keep every one of them until the last
stack has verified, and delete them only after — **each archive holds that
stack's encrypted state, so store them as you would the state bucket, and do
not put them in a repo.**

The point of no return for the _programme_, as opposed to for one stack, is
destroying KMS key version 1. Before that, a botched migration is recoverable
from an archive. After it, nothing is.

---

# Part B — move state to Hetzner Object Storage

**Not urgent.** The destination this part migrates _to_ exists: the production
Object Storage bucket `branchleft-pulumi-state`. What is still open is the
backend's own behaviour — login string, path-style addressing, locking
behaviour, credential sourcing — which the rehearsal below closes, and the
rehearsal needs a **lab** bucket that does not exist yet. The state buckets
are not retired until after cutover, so nothing here races the KMS gate.

Two buckets are involved and they are never interchangeable: the **production**
bucket is where real state lands, and a **lab** bucket in the lab hcloud
project is where the procedure is proved first. Do not rehearse against
production.

Run Part A first regardless. A stack that is already on the passphrase
provider moves between backends cleanly, because its secrets no longer depend
on anything the source project holds.

## B.1 Per-stack sequence

> **Confirm the bucket's location before running any of this.** The
> `AWS_REGION`, the endpoint host and the `region` query parameter all name it,
> all three inherit from the pinned `backend.url` in `hetzner/Pulumi.yaml`, and
> one wrong assumption makes all three wrong together. **The expected answer is
> `hel1`** — the bucket's location is not the servers', which are in `nbg1`.
> Check rather than trust this sentence: a bucket answers `403` on its own
> location and `404` on every other, so one unauthenticated request against
> `https://branchleft-pulumi-state.<location>.your-objectstorage.com/` settles
> it. A mismatch surfaces as an opaque `403` that reads as a credential
> problem, sending you to the one thing that is fine.

```bash
export AWS_REGION=hel1
read -rs "AWS_ACCESS_KEY_ID?Object Storage access key: "; echo; export AWS_ACCESS_KEY_ID
read -rs "AWS_SECRET_ACCESS_KEY?Object Storage secret:     "; echo; export AWS_SECRET_ACCESS_KEY
# This stack's passphrase, re-supplied from the password manager. A.2 step 8
# deleted the temp file deliberately, and there is no other copy on this
# machine -- so this is a fresh entry, not a leftover. Never reuse a file left
# behind by a crashed Part A run: it holds a *different* stack's passphrase,
# and every command below would silently address this stack with it.
# `read -rs "VAR?prompt"`, not `read -rs -p` -- see A.2 step 0 for why.
umask 077
install -m 600 /dev/null ~/.pulumi-passphrase-tmp
read -rs "PASSPHRASE?Passphrase for THIS stack, from the password manager: "; echo
printf '%s' "$PASSPHRASE" > ~/.pulumi-passphrase-tmp; unset PASSPHRASE
[ -s ~/.pulumi-passphrase-tmp ] || { echo 'EMPTY PASSPHRASE FILE -- do not continue'; return 1 2>/dev/null || exit 1; }
export PULUMI_CONFIG_PASSPHRASE_FILE=~/.pulumi-passphrase-tmp
unset PULUMI_CONFIG_PASSPHRASE
[ -z "${PULUMI_CONFIG_PASSPHRASE:-}" ] || { echo 'PULUMI_CONFIG_PASSPHRASE is set and would override the _FILE -- unset it'; return 1 2>/dev/null || exit 1; }

cd <repo>/<project-dir>

# 1. Export from the old backend.
pulumi login <old-backend-url>
pulumi stack export --stack <stack> --file ~/pulumi-move-<project>-<stack>.json

# 2. Pin the new backend in Pulumi.yaml rather than logging into it, matching
#    the pattern hetzner/Pulumi.yaml already uses. Add:
#      backend:
#        url: 's3://branchleft-pulumi-state?endpoint=hel1.your-objectstorage.com&s3ForcePathStyle=true&region=hel1'

# 3. Preserve the salt. `stack init` generates a NEW encryptionsalt and
#    overwrites the file -- and a different salt derives a different key from
#    the same passphrase, so every committed ciphertext stops decrypting.
cp Pulumi.<stack>.yaml /tmp/salt-keep.yaml
pulumi stack init <stack>
cp /tmp/salt-keep.yaml Pulumi.<stack>.yaml && rm /tmp/salt-keep.yaml

# 4. Import the deployment. It carries its own secrets_providers block, so the
#    state side and the config side agree only if step 3 was done.
pulumi stack import --stack <stack> --file ~/pulumi-move-<project>-<stack>.json

# 5. Prove it.
pulumi whoami --verbose
pulumi preview --stack <stack>          # expect: no changes -- reaching the plan
                                        # is also the decrypt proof; `stack
                                        # export --show-secrets` exits 0 under
                                        # a wrong passphrase and proves nothing
```

Step 3 is the trap in this half. Everything up to step 5 succeeds without it,
and the damage only appears the next time something reads a secret.

**`branchleft-ghost-provisioning/blog` cannot follow step 3 at all**, because
there is no `Pulumi.blog.yaml` to copy — the same gap A.3 covers for Part A,
and it is worse here. `stack init` mints a fresh salt, the import succeeds,
the preview is clean, and the stack is broken the next time provisioning reads
a secret, with nothing anywhere recording the salt that would have worked.

So Part B for that stack is **blocked on the same fix A.3 names**: either its
configuration becomes a committed artifact, or the reconstruction path learns
to restore `encryptionsalt` from the deployment's
`secrets_providers.state.salt`. Until one of those is true, do not move this
stack's state. Moving it is not urgent — nothing in Part B is — and the
alternative is a silent, unrecorded loss.

Step 5's zero-diff preview proves the imported checkpoint matches the program.
It proves nothing about whether the live infrastructure matches either of
them — `pulumi preview` compares the program to state, never to reality. That
gap is covered by `pulumi refresh --preview-only`, not by this.

## B.2 Rollback

Until the old bucket's state object is deleted, rollback is `pulumi login
<old-backend-url>` and reverting the `backend:` key in `Pulumi.yaml`. The old
checkpoint is still there and still current, because export does not remove
it. Retire the source objects only after every stack has moved and verified —
which happens after cutover anyway.

## B.3 Every place a backend is chosen or created

There is no central backend configuration. Each site selects one
independently, so each is a place a later run can silently address the old
state — and some of them _create_ backends rather than referring to one, which
is why an enumeration of `pulumi login` calls alone is not enough. Enumerate,
by category:

- **CI workflows that `pulumi login`.** One per repository at least, sometimes
  twice in one file (a preview job and a deploy job both need it).
- **Workflows that select a backend from a repository variable at runtime.**
  These are the dangerous ones: the stack is applied against whichever backend
  a variable happens to name, decided outside the file you are reading.
  `RUNBOOK-new-stack.md` pins the backend in `Pulumi.yaml` for exactly this
  reason, and the migration is when to stop doing it the other way.
- **Code that creates a backend.** A provisioning program that creates a state
  bucket per tenant is a _source_ of backends, not a reference to one, which is
  why an inventory can never be complete by enumeration alone.
- **Guards that encode a bucket-naming convention.** A delete guard matching a
  `-pulumi-state` suffix silently protects nothing the day the convention is
  renamed.
- **Runbooks and docs naming a backend.** Each needs its supersession note when
  its stack moves.

Two things no enumeration reaches:

**Untracked vendor snapshots.** A stale local copy of another repository can
carry its own `Pulumi.<stack>.yaml` with that stack's `secretsprovider` and
`encryptedkey`. It is committed nowhere, so it is not a site — but after the
sweep those are stale values naming a key that is going away. Never read a
provider from a vendor snapshot; read it from the owning repository.

**Workstations.** `pulumi login` writes `~/.pulumi/credentials.json` and
persists across projects and sessions until the next login. There is no
inventory of which machines hold which backend and no way to build one, so the
control is the pinned `backend.url` in `Pulumi.yaml` — that is what makes a
workstation's ambient login irrelevant. Until every project pins it,
`pulumi whoami --verbose` before any command is the only check available.

Finally, the repository variables that pointed at the old backend have to be
removed once no workflow logs into it any more. A variable outliving its
backend is a loaded gun for the next person who adds a workflow.

---

# Part C — prove an escrowed passphrase still opens its archive

Parts A and B leave every stack passphrase-wrapped, and A.2 step 6b's
post-re-wrap export of each one is archived offsite. Those archives are the
only copies that survive the destruction of the GCP KMS key version, and every
one of them is opened by a passphrase rather than by the key. The whole risk
has therefore moved from the key to the escrow: a passphrase that was
mis-transcribed, truncated on paste, or filed under the wrong entry looks
identical in a password manager to one that works, and the difference only
shows up after the key is gone, when there is nothing left to fall back to.

**"It is in the password manager" and "it opens the archive" are different
claims.** Part C checks the second one.

It is a **precondition of the wind-down, not a follow-up to it**, and it is
checked immediately before the key version is destroyed rather than weeks
earlier — an escrow entry can be edited, and the only run that means anything
is the most recent one.

- **Every archive PASSes** — that is the evidence the wind-down's "each
  archive's passphrase proven, from escrow, to still open it" precondition
  asks for. Record the run and its date with the other precondition results.
- **Anything other than a PASS** — **the key version is not destroyed.** A
  `FAIL`, an `ARCHIVE` and an `INCONCLUSIVE` block it equally: none of them is
  the evidence the precondition wants, and the distinction between them is
  about what to fix, not about whether to proceed.

## C.1 What the tool proves, and what it does not

[`scripts/verify-archive-passphrase.py`](../scripts/verify-archive-passphrase.py)
takes one or more archives and a passphrase, and reports whether that
passphrase actually opens them.

It does not re-implement Pulumi's decryption. It drives the real `pulumi`
binary against a throwaway `file://` backend inside a temporary directory,
seeds a scratch stack with the archive's own salt, and imports the archive
into it. Two stages, both of which must pass:

1. `pulumi stack init` over the archive's salt. A passphrase salt carries a
   known plaintext encrypted under the key it derives, so Pulumi validates the
   passphrase against the salt alone.
2. `pulumi stack import` of the archive. Deserialising a deployment decrypts
   every encrypted value in it, so this is the stage that proves the archive's
   own secrets open — not merely that the passphrase matches its salt.

`pulumi stack export --show-secrets` is deliberately not used — for two
reasons now. Its output is every secret the stack holds in plaintext, and it
is not a decryption proof at all: with the passphrase provider on v3.255.0
it exits 0 under a wrong passphrase (INC-4). An import forces real
decryption while emitting nothing, which is why stage 2 is trustworthy.

Three properties worth knowing before relying on it:

- **It prints nothing that was decrypted.** Pulumi's own output is captured
  and classified, never echoed — with the _correct_ passphrase over a corrupt
  archive, Pulumi reports a JSON parse error that quotes a character of the
  decrypted plaintext.
- **It cannot reach live state.** `pulumi login` is never run, because it
  rewrites `~/.pulumi/credentials.json` for every project on the machine. The
  backend is passed per invocation and pinned to the temporary directory, the
  run refuses to continue unless `pulumi whoami` agrees that is where it
  landed, and the directory is removed on every exit path.
- **It reads the archive and changes nothing.** Nothing is written outside the
  temporary directory, and no bucket, cloud API or network call is involved.

Exit codes, deliberately distinct so that "the passphrase does not work" can
never be read as "the check did not run":

| Code | Outcome        | Means                                                                                                          |
| ---- | -------------- | -------------------------------------------------------------------------------------------------------------- |
| `0`  | `PASS`         | every archive given opened with the supplied passphrase                                                        |
| `1`  | `FAIL`         | Pulumi reported an incorrect passphrase, or values that do not authenticate under it. **Blocks the wind-down** |
| `2`  | usage          | the invocation or the environment is wrong — no passphrase, an empty one, no `pulumi` binary. Nothing ran      |
| `3`  | `ARCHIVE`      | an archive is unusable as evidence: unreadable, not a stack export, not passphrase-wrapped, or unwrapped       |
| `4`  | `INCONCLUSIVE` | no verdict was reached — an archive with nothing encrypted in it, or a Pulumi failure of neither kind          |

With several archives the worst outcome wins, in the order
`FAIL` > `ARCHIVE` > `INCONCLUSIVE` > `PASS`.

A pre-re-wrap archive reports `ARCHIVE`, naming its provider. That is correct
rather than a defect: those exports are KMS-wrapped, no passphrase opens one,
and they are not a fallback for this precondition — see "What this runbook
deliberately does not cover" below.

## C.2 Four passphrases, six archives

A.0 decided one passphrase per repository rather than one per stack, so two
repositories cover two archives each:

| Passphrase held by             | Archives it must open                                                      |
| ------------------------------ | -------------------------------------------------------------------------- |
| `branchLeft/shared-infra`      | `branchleft-shared-infra/production`, `branchleft-mail/production`         |
| `branchLeft/website`           | `branchleft-website-infra/production`                                      |
| `branchLeft/ghost-platform`    | `branchleft-ghost-platform/platform`, `branchleft-ghost-provisioning/blog` |
| `branchLeft/ghost-tenant-blog` | `blog-infra/blog`                                                          |

**Give one repository's archives to a single invocation**, and run the tool
four times in all. Passing all six at once would need one passphrase to open
all of them, which is exactly the state A.0 exists to prevent; passing them in
pairs proves the pairing as well as the passphrase.

The object keys are not derivable from the stack names — one of them is
shortened — so take them from the wind-down programme's archive record rather
than constructing them. That record also holds the storage endpoint and the
container name, which are deliberately not committed to this public repository.

## C.3 Running it, once per passphrase

The archives live in OVHcloud Object Storage and are fetched with an
S3-compatible client. Fill `<endpoint-url>`, `<container>`, `<prefix>` and each
`<object-key>` from the archive record named above.

```bash
# 0. Credentials and workspace. `read -rs "VAR?prompt"`, not
#    `read -rs -p 'prompt' VAR` -- the platform owner's shell is zsh, where
#    `-p` means "read from a coprocess", not "print a prompt". It fails with
#    `no coprocess` and leaves the variable empty, which is a failure this
#    procedure must not carry forward silently. Same reasoning as A.2 step 0.
umask 077
workdir=$(mktemp -d)
read -rs "AWS_ACCESS_KEY_ID?Object Storage access key: "; echo; export AWS_ACCESS_KEY_ID
read -rs "AWS_SECRET_ACCESS_KEY?Object Storage secret:     "; echo; export AWS_SECRET_ACCESS_KEY
[ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ] || { echo 'EMPTY CREDENTIAL -- do not continue'; return 1 2>/dev/null || exit 1; }

# 1. Confirm the archive set is where it is expected to be, before fetching.
aws s3 --endpoint-url <endpoint-url> ls s3://<container>/<prefix>

# 2. Fetch this repository's archives. Pre-created 0600: an archive is
#    encrypted, but its salt and every ciphertext it holds are still not
#    world-readable material.
install -m 600 /dev/null "$workdir/<object-key>"
aws s3 --endpoint-url <endpoint-url> \
  cp s3://<container>/<prefix><object-key> "$workdir/<object-key>"

# 3. Supply the passphrase AS STORED in the password manager -- re-typed, not
#    pasted from anywhere this procedure produced. Verifying against a copy
#    this machine already had would prove only that the copy matches itself,
#    which is the same trap A.2 step 7 exists for.
install -m 600 /dev/null "$workdir/passphrase"
read -rs "STORED?Escrowed passphrase for THIS repository: "; echo
printf '%s' "$STORED" > "$workdir/passphrase"; unset STORED
[ -s "$workdir/passphrase" ] || { echo 'EMPTY PASSPHRASE -- do not continue'; return 1 2>/dev/null || exit 1; }

# 4. Verify. Both of this repository's archives in one invocation.
#    PULUMI_CONFIG_PASSPHRASE outranks the file form, so the tool strips it
#    from the environment it hands Pulumi and asserts it is gone -- but unset
#    it here too, so the shell this runs in cannot be the reason it passed.
unset PULUMI_CONFIG_PASSPHRASE
python3 scripts/verify-archive-passphrase.py \
  --passphrase-file "$workdir/passphrase" \
  "$workdir/<object-key>" "$workdir/<second-object-key>"
echo "exit: $?"

# 5. Tear down. The archives are plain files holding this estate's state; do
#    not leave them on a workstation.
rm -rf "$workdir"
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```

Then close the shell and open a new one for the next repository's passphrase,
for the same reason A.2 does: a passphrase file left in place is still the
previous repository's, and every check against the next set would address it
with the wrong secret.

**Record all four runs together**, each with its exit code and the archives it
covered. Four separate PASSes are the precondition; three PASSes and one run
nobody kept the result of is not.

---

## Lab rehearsal

This must be rehearsed before it is run for real, and it has **not been
rehearsed**. What follows is the procedure, and its two
halves have different prerequisites.

**Part A's rehearsal is unblocked and needs no Hetzner resource at all.**
Part A is entirely GCP-side, and a scratch stack in the existing shared bucket
exercises all of it. This is the half worth doing first regardless, because
Part A is the deadline-bound one.

**Part B's rehearsal is blocked on one specific thing.** The lab hcloud
project exists. What does not exist is a **lab** Object Storage bucket inside
it, and an S3 credential pair for that bucket — both console-only,
platform-owner work, and both small. The production bucket is not a substitute:
rehearsing against it would exercise the procedure on live state, which is the
one thing a rehearsal exists to avoid.

**Rehearsing Part A** — no dependency, runnable now:

1. In a scratch directory, `pulumi new` a trivial TypeScript project — one
   `random.RandomPassword`, which produces a genuinely secret output, plus one
   secret config value. It must have both: config secrets and state secrets
   are re-wrapped by different code paths, and a stack with only one proves
   only half.
2. `pulumi login gs://branchleft-pulumi-state`, then `pulumi stack init
rehearsal --secrets-provider=gcpkms://projects/branchleft-prod/locations/europe-west1/keyRings/pulumi/cryptoKeys/pulumi-secrets`.
   No `pulumi up` is needed — the checkpoint holds the encrypted config
   without one, and applying would create a resource for nothing.
3. Run A.2 verbatim against it.
4. **Then rehearse the failure**, which is the part worth the time: restore the
   step 3 archive with `pulumi stack import`, confirm the stack is back on
   `gcpkms`, and confirm it decrypts. A rollback nobody has executed is a
   rollback nobody has.
5. `pulumi stack rm rehearsal --yes`.

**Rehearsing Part B** — once the lab bucket and its credential pair exist,
runs in the lab hcloud project against that lab bucket, never against
production. Same scratch stack, run B.1 against the lab bucket, and check
specifically for what is still unverified about the backend:
whether path-style addressing works with the real bucket name, and whether two
concurrent clients take and release the state lock. Record what is observed,
with a date, and correct `RUNBOOK-new-stack.md`'s unverified banner from the
same observation.

## What this runbook deliberately does not cover

**Historical checkpoints.** `change-secrets-provider` re-wraps the current
checkpoint. Every `.bak` and every earlier version retained in both state
buckets keeps its original KMS-wrapped ciphertext, and none of them is
re-wrapped by anything here. Once the key version is destroyed, the whole
history becomes permanently unreadable and only the current checkpoint of each
stack survives. That is accepted — the current checkpoint is what a restore
needs — but it is worth stating against the wind-down's assumption that
per-stack archives are restorable: **any archive taken before a stack's
re-wrap is KMS-wrapped and stops being restorable at the same moment
everything else does.** The archive the wind-down should hold is A.2 step
6b's, not step 3's — A.4's table is the authority on which is which.

Retiring the GCS buckets, revoking the deployer bindings on the KMS key,
narrowing `ghost-tenant-provisioner`'s `cloudkms.admin`, and destroying the key
version. Those are the wind-down's, and they are gated on
`--require-migrated` exiting 0 — not on this runbook having been read.
