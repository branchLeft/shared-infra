# Pulumi state-backend inventory

This is the enumeration `branchLeft/workspace#130` step 4 asked for: every
Pulumi stack in the estate, every place its state backend is named or a
`pulumi login` is performed, and every place a GCS bucket name appears. The
previous copy of this enumeration was dropped in `shared-infra`'s fresh-repo
republish and only partially reinstated — see `branchLeft/workspace#126` and
`scripts/pulumi-stack-inventory.json`, whose `backend_reference_sites` and
`external_backend_reference_sites` arrays are a **related but narrower**
artifact: they list sites for the KMS secrets-provider audit, not a
verified backend/login map, and this document finds real drift against
them (§7).

This document is **audit output**. It changes no state, moves no Pulumi
stack, and touches no bucket. Where a claim below needed a live API call or
a credential this session does not hold, it says so instead of guessing
(§8).

Placement: at the repo root, alongside `README.md`, matching this repo's
existing top-level reference-document convention (`CLOUD-ARMOR-BASELINE.md`
is the precedent — a standing captured-state document, not a runbook to
execute). It supports `hetzner/RUNBOOK-existing-stack-migration.md` without
sitting beside it on disk — that runbook lives under `hetzner/`.

## 1. Every Pulumi stack in the estate

Nine stacks, not the eight `RUNBOOK-existing-stack-migration.md`'s own count
implies ("Six stacks exist today across two state backends", plus "two
Hetzner stacks that do not exist yet" in a third) or the eight
`scripts/pulumi-stack-inventory.json` currently lists. The ninth —
`branchleft-ghost-platform-hosts` — is real, committed, and CI-applied; it
is simply missing from the inventory JSON (§7), and post-dates the
runbook's "not yet created" wording for the third backend.

| Project / stack                                                      | Repo                | Definition path                                           | Committed backend today                                | Born there or moved? |
| -------------------------------------------------------------------- | ------------------- | --------------------------------------------------------- | ------------------------------------------------------ | -------------------- |
| `branchleft-shared-infra/production`                                 | `shared-infra`      | `Pulumi.yaml` / `Pulumi.production.yaml`                  | `gs://branchleft-pulumi-state`                         | still on `gs://`     |
| `branchleft-mail/production`                                         | `shared-infra`      | `mail/Pulumi.yaml` / `mail/Pulumi.production.yaml`        | `s3://branchleft-pulumi-state?endpoint=hel1…` (pinned) | **moved** 2026-08-22 |
| `branchleft-website-infra/production`                                | `website`           | `infra/Pulumi.yaml` / `infra/Pulumi.production.yaml`      | `gs://branchleft-pulumi-state`                         | still on `gs://`     |
| `branchleft-ghost-platform/platform`                                 | `ghost-platform`    | `infra/platform/Pulumi.yaml` / `Pulumi.platform.yaml`     | `gs://branchleft-pulumi-state`                         | still on `gs://`     |
| `branchleft-ghost-provisioning/blog`                                 | `ghost-platform`    | `infra/provisioning/Pulumi.yaml` (config never committed) | `gs://branchleft-pulumi-state`                         | still on `gs://`     |
| `blog-infra/blog`                                                    | `ghost-tenant-blog` | `Pulumi.yaml` / `Pulumi.blog.yaml`                        | `gs://branchleft-blog-pulumi-state`                    | still on `gs://`     |
| `branchleft-hetzner-network/production`                              | `shared-infra`      | `hetzner/Pulumi.yaml` / `Pulumi.production.yaml`          | `s3://branchleft-pulumi-state?endpoint=hel1…` (pinned) | born there           |
| `branchleft-hetzner-estate/production`                               | `shared-infra`      | `hetzner/estate/Pulumi.yaml` / `Pulumi.production.yaml`   | `s3://branchleft-pulumi-state?endpoint=hel1…` (pinned) | born there           |
| `branchleft-ghost-platform-hosts` (project name; stack `production`) | `ghost-platform`    | `infra/hosts/Pulumi.yaml` / `Pulumi.production.yaml`      | `s3://branchleft-pulumi-state?endpoint=hel1…` (pinned) | born there           |

**Five stacks remain on `gs://`**, matching the count in the issue: the
shared-infra edge stack, website-infra, ghost-platform/platform,
ghost-provisioning/blog, and blog-infra/blog. Four stacks are already on
Hetzner Object Storage — one moved (`mail`), three born there (the two
Hetzner-native stacks plus the previously-unlisted hosts stack).

**Verified two ways:**

1. Read each stack's committed `Pulumi.yaml` directly (`backend.url` present
   or absent) — done for all nine, quoted inline above.
2. Cross-checked against `scripts/pulumi-stack-inventory.json`'s
   `state_backends` map and per-stack `state_backend` field, and against
   `graphify query` traversals in `shared-infra` and `ghost-platform`
   surfacing the same project nodes independently. The cross-check is what
   surfaced the missing ninth stack and the stale template entry in §7 —
   the two methods disagreed, and reading the file settled it.

## 2. Backend and login enumeration

No central list exists (the runbook says so explicitly, §B.3, and it is
right) — this is built by category, each verified by reading the file
rather than assuming a role from its name.

### 2.1 Executable `pulumi login` steps in CI (the ones a workflow run actually executes)

| Repo                             | Workflow                                  | Job(s)                                    | Backend logged into                                                                   |
| -------------------------------- | ----------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------- |
| `shared-infra`                   | `.github/workflows/ci.yml`                | `deploy-plan`, `deploy-apply`             | `gs://branchleft-pulumi-state`                                                        |
| `website`                        | `.github/workflows/ci.yml`                | `pulumi-preview`, `deploy`                | `gs://branchleft-pulumi-state`                                                        |
| `ghost-platform`                 | `.github/workflows/infra-platform-ci.yml` | `Deploy (pulumi up)`                      | `gs://branchleft-pulumi-state`                                                        |
| `ghost-platform`                 | `.github/workflows/provision-tenant.yml`  | `provision` (new tenant's own stack init) | `$HETZNER_PULUMI_BACKEND_URL` (repo variable, `s3://…`)                               |
| `ghost-platform-tenant-template` | `.github/workflows/infra-ci.yml`          | preview/deploy jobs                       | `$PULUMI_BACKEND_URL` (repo variable, `s3://…`, generated into every new tenant repo) |
| `ghost-tenant-blog`              | `.github/workflows/infra-ci.yml`          | preview/deploy jobs                       | `gs://$PULUMI_STATE_BUCKET` = `gs://branchleft-blog-pulumi-state`                     |

`mail-plan`/`mail-apply`, `hetzner-network-plan`/`-apply`,
`hetzner-estate-plan`/`-apply` and the `hosts` plan/apply jobs run **no**
`pulumi login` step — see §2.2.

### 2.2 Pinned `backend.url` in a committed `Pulumi.yaml` (no login step needed)

| Repo             | Path                         | Backend                                                                                               |
| ---------------- | ---------------------------- | ----------------------------------------------------------------------------------------------------- |
| `shared-infra`   | `hetzner/Pulumi.yaml`        | `s3://branchleft-pulumi-state?endpoint=hel1.your-objectstorage.com&s3ForcePathStyle=true&region=hel1` |
| `shared-infra`   | `hetzner/estate/Pulumi.yaml` | same                                                                                                  |
| `shared-infra`   | `mail/Pulumi.yaml`           | same                                                                                                  |
| `ghost-platform` | `infra/hosts/Pulumi.yaml`    | same                                                                                                  |

### 2.3 Hand-run commands in runbooks and READMEs (documented, not automatic)

| Repo                             | Path                                          | Backend named                                                                                                                                                                         |
| -------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `shared-infra`                   | `README.md`                                   | `gs://branchleft-pulumi-state`                                                                                                                                                        |
| `shared-infra`                   | `RUNBOOK-ci-bootstrap.md`                     | `gs://branchleft-pulumi-state`                                                                                                                                                        |
| `shared-infra`                   | `RUNBOOK-edge-state-move.md`                  | `gs://branchleft-pulumi-state`                                                                                                                                                        |
| `shared-infra`                   | `mail/RUNBOOK-import-mail-host.md`            | `gs://branchleft-pulumi-state` — **stale, see §7.1**                                                                                                                                  |
| `shared-infra`                   | `hetzner/RUNBOOK-existing-stack-migration.md` | generic `<backend>`/`<old-backend-url>` placeholders throughout Parts A/B; the one literal is the Part-B rehearsal snippet's `gs://branchleft-pulumi-state` login before `stack init` |
| `ghost-platform`                 | `infra/platform/RUNBOOK-bootstrap.md`         | `gs://branchleft-pulumi-state` (bootstrap) and `gs://<state-bucket>` / `gs://branchleft-pulumi-state` (provisioning-stack recovery and teardown, §4 below)                            |
| `ghost-platform`                 | `RUNBOOK-tenant-onboarding.md`                | `"$(gh variable get PULUMI_BACKEND_URL --repo branchLeft/<generated-repo>)"` — Hetzner-native, current pattern                                                                        |
| `ghost-platform-tenant-template` | `RUNBOOK-bootstrap.md`                        | same pattern, Hetzner-native                                                                                                                                                          |
| `website`                        | `infra/KNOWN_ISSUES.md`                       | documents a `pulumi login gs://branchleft-pulumi-state` failure symptom, not a live procedure                                                                                         |

### 2.4 The template has already moved; the one generated repo from it has not

`ghost-platform-tenant-template`'s `Pulumi.yaml` and `.github/workflows/infra-ci.yml`
require an `s3://` `PULUMI_BACKEND_URL` and **actively refuse** a `gs://`
value (`"PULUMI_BACKEND_URL must be an s3:// backend. A gs:// backend would
give this tenant a GCP dependency, which the Hetzner migration exists to
remove."`). Any tenant generated from the template today is born on
Hetzner Object Storage with no GCP state dependency at all.

`ghost-tenant-blog` — the one repo already generated from an earlier
version of the template — still carries the pre-rewrite
`PULUMI_STATE_BUCKET` / `gs://` pattern, because it diverged at generation
time and a template change does not reach an already-generated repo. This
is expected and is called out in the existing inventory JSON's note on that
site; it is confirmed still true by reading `ghost-tenant-blog`'s own
workflow file directly.

## 3. GCS bucket name occurrences

Both searches below used the same method (`grep -rl`, five target repos,
common extensions) with a control case run first to prove the search tool
returns results at all (a known hit, `shared-infra/.github/workflows/ci.yml`,
returned 6 matches for `pulumi login` — the tool is not silently empty).
The second method was `git grep -l` from each repo's own root against
tracked files only, which additionally rules out a stale/untracked local
copy inflating a count. `graphify-out/`'s two committed files that also
match (`GRAPH_REPORT.md`, `graph.html` in both `shared-infra` and
`ghost-platform`) are excluded from every count below on purpose: CI
regenerates them from source on every push, so they mirror a real site
rather than being one themselves, and counting them would double-count the
file they mirror.

**`branchleft-pulumi-state`** — **22 files** across the estate (excluding
worktree/vendor duplicates, the `graphify-out/` mirrors above, and this
document itself):

- **14 in `shared-infra`**: three `Pulumi.yaml`s (`hetzner/Pulumi.yaml`,
  `hetzner/estate/Pulumi.yaml`, `mail/Pulumi.yaml`), `README.md`, **five**
  `RUNBOOK-*.md` (`RUNBOOK-ci-bootstrap.md`, `RUNBOOK-edge-state-move.md`,
  `hetzner/RUNBOOK-existing-stack-migration.md`, `hetzner/RUNBOOK-new-stack.md`
  — this is where the "two backends share this bucket name" passage §3
  itself discusses lives — `mail/RUNBOOK-import-mail-host.md`),
  `hetzner/scripts/test_probe_object_storage.py`,
  `scripts/pulumi-stack-inventory.json`, `scripts/audit-pulumi-secrets.py`,
  `scripts/test_audit_pulumi_secrets.py`, `.github/workflows/ci.yml`.
- **6 in `ghost-platform`**: `RUNBOOK-tenant-onboarding.md`,
  `infra/platform/RUNBOOK-bootstrap.md`, `infra/provisioning/index.ts` — the
  guard comment, not a live reference, `infra/hosts/Pulumi.yaml` — the
  Hetzner bucket of the same name, `.github/workflows/provision-tenant.yml`,
  `.github/workflows/infra-platform-ci.yml`.
- **2 in `website`**: `.github/workflows/ci.yml` — the live
  `pulumi login gs://branchleft-pulumi-state` step, already named in §2.1's
  table — and `infra/KNOWN_ISSUES.md`, already named in §2.3's table.

Zero in `ghost-platform-tenant-template` or `ghost-tenant-blog`, confirmed
by both `grep` and `git grep` and by their absence from every
`backend_reference_sites`/`external_backend_reference_sites` entry in
`scripts/pulumi-stack-inventory.json`.

**Correction, and how the count diverged.** An earlier pass of this tally
summed the per-repo file lists by hand into "14 + 6 = 20" and stopped
without re-adding `website`, even though both `website` files were already
named correctly in §2.1 and §2.3 above and both already appear in
`scripts/pulumi-stack-inventory.json`'s `external_backend_reference_sites`
under `repo: website`. The source data was right in three places and wrong
in exactly the one place doing arithmetic on it by hand instead of
re-reading it — this section now states the itemized list first and the
total as its sum, rather than the other way round, so a future re-check
can re-add the column instead of re-deriving the list. The same manual-sum
error dropped a fifth `RUNBOOK-*.md` from `shared-infra`'s named list
(`hetzner/RUNBOOK-new-stack.md`) while still counting it in the "14" —
fixed above by naming all five.

Separately, note this name is now **overloaded**: `branchleft-pulumi-state`
is both the legacy GCS bucket (europe-west2, doc 14 §15 step 4 deletes it)
and the current-generation Hetzner Object Storage bucket (`hel1`) that
`mail`, both Hetzner-native stacks and the new `hosts` stack are pinned to.
They are different buckets in different clouds that happen to share a
name; every reference above was read in context to tell which one it
means, not matched by string alone.

**`branchleft-blog-pulumi-state`** — 2 files, both in `shared-infra`
(`scripts/pulumi-stack-inventory.json`, `scripts/test_audit_pulumi_secrets.py`).
Zero occurrences in `ghost-tenant-blog` itself or in `ghost-platform` —
that stack's own repo names it only through `$PULUMI_STATE_BUCKET`, a
repository variable, never as a literal string in committed source.

**`branchleft-lab-pulumi-state`** — 1 file
(`shared-infra/hetzner/scripts/test_probe_object_storage.py`), and that one
occurrence is a **unit test asserting the probe script refuses to run
against it** (a guard, not evidence the bucket exists or is reachable
today — see §8).

No credential, key, passphrase or bucket access key was found committed
anywhere searched. The `secure:` ciphertext values in
`website/infra/Pulumi.production.yaml` and the salt/passphrase-recovery
prose throughout the runbooks are the documented, intentional PUL-12
pattern (offline-unrecoverable ciphertext, no salt alongside it) — not a
finding.

## 4. CI apply-path audit

| Stack                                   | Has a CI apply path today?                           | Evidence                                                                                                                                                                                                                                                                                                                  |
| --------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `branchleft-shared-infra/production`    | Yes                                                  | `deploy-plan`/`deploy-apply`, `.github/workflows/ci.yml`                                                                                                                                                                                                                                                                  |
| `branchleft-mail/production`            | **Yes — this is a material correction to the issue** | `mail-plan`/`mail-apply`, same file. Added by `branchLeft/shared-infra#29` (merged 2026-08-22), which explicitly retires "no CI apply path" as mail's steady state. The issue's framing — "nothing exercises \[mail\] until someone genuinely needs it" — was accurate when filed (2026-08-17) and is no longer accurate. |
| `branchleft-website-infra/production`   | Yes                                                  | `pulumi-preview`/`deploy`, `website/.github/workflows/ci.yml`                                                                                                                                                                                                                                                             |
| `branchleft-ghost-platform/platform`    | Yes                                                  | `Deploy (pulumi up)`, `ghost-platform/.github/workflows/infra-platform-ci.yml`                                                                                                                                                                                                                                            |
| `branchleft-ghost-provisioning/blog`    | **No**                                               | See §4.1                                                                                                                                                                                                                                                                                                                  |
| `blog-infra/blog`                       | Yes                                                  | `Deploy (pulumi up)`, `ghost-tenant-blog/.github/workflows/infra-ci.yml`                                                                                                                                                                                                                                                  |
| `branchleft-hetzner-network/production` | Yes                                                  | `hetzner-network-plan`/`-apply`, `shared-infra/.github/workflows/ci.yml`                                                                                                                                                                                                                                                  |
| `branchleft-hetzner-estate/production`  | Yes                                                  | `hetzner-estate-plan`/`-apply`, same file                                                                                                                                                                                                                                                                                 |
| `branchleft-ghost-platform-hosts`       | Yes                                                  | `Apply (hosts, pulumi up)`, `ghost-platform/.github/workflows/infra-hosts-ci.yml`                                                                                                                                                                                                                                         |

### 4.1 The stack that now carries mail's old risk: `branchleft-ghost-provisioning/blog`

This is the headline finding of the CI-apply audit. `branchleft-ghost-provisioning/blog`
creates tenant zero's GCP deploy identity (service account + Workload
Identity Federation pool) for blog's still-GCP-based CI/CD pipeline. It is:

- Still on `gs://branchleft-pulumi-state` (one of the five remaining stacks).
- **Config-path `null`** — no `Pulumi.blog.yaml` is ever committed for it;
  its config is reconstructed from the live deployment only when a human
  runs `restore-stack-secrets-config.py` by hand.
- Applied **only by hand**, per `ghost-platform/infra/platform/RUNBOOK-bootstrap.md`'s
  onboarding and recovery/teardown sections. `restore-stack-secrets-config.py`
  and its test are the only two files that reference each other anywhere in
  the committed tree — no workflow YAML in `ghost-platform` calls the
  script. `infra-platform-ci.yml`'s `infra/provisioning` step is a
  typecheck, not an apply; `provision-tenant.yml` only initialises a
  **new** tenant's own Hetzner-native stack, never this one.

So the exact reasoning the issue used to justify moving `mail` first —
"the one with no CI to catch a mistake" — now applies to this stack
instead. It has the added complication that its config file does not
exist to pin a backend into without first reconstructing it by hand. Any
Part B sequencing for this stack should treat it with at least the care
`mail` got, not less, precisely because nothing exercises it.

## 5. What breaks if the GCS buckets were deleted today

Reading straight from §1 and §4: deleting `gs://branchleft-pulumi-state`
today strands four live stacks with no way to `pulumi preview`, `up` or
`destroy` — `branchleft-shared-infra/production` (the production edge,
CI-applied on every merge to `main`), `branchleft-website-infra/production`
(CI-applied), `branchleft-ghost-platform/platform` (CI-applied), and
`branchleft-ghost-provisioning/blog` (hand-applied only, tenant zero's GCP
deploy identity). Deleting `gs://branchleft-blog-pulumi-state` strands
`blog-infra/blog`, the tenant Ghost site itself, CI-applied on every merge
to `ghost-tenant-blog`. In every case this is not "loses convenience" —
per `RUNBOOK-existing-stack-migration.md`'s own gate section, a stack that
cannot read its checkpoint cannot be destroyed either, so the resources
become permanently unmanageable by Pulumi, not merely un-previewable.

## 6. Blockers: verified vs inherited

**The lab Object Storage bucket and credential pair (Part B rehearsal).**
The issue's premise — that these do not exist — was true when filed
(2026-08-17) and **is contradicted by later evidence I read, not
reproduced live**: `branchLeft/ghost-platform-docs` doc 14 §16 item 1
records that `branchleft-lab-pulumi-state` (`hel1`) was created and used
for a rehearsal on 2026-08-22, immediately before the real mail move. This
session did not confirm the bucket or its credentials still exist
**today** — that needs a live, credentialed check (§8). The repo's own
committed runbook, `hetzner/RUNBOOK-existing-stack-migration.md`, is
**stale** on this point: its "Lab rehearsal" section still reads "this must
be rehearsed before it is run for real, and it has **not** been rehearsed"
and "What does not exist is a lab Object Storage bucket" — both contradicted
by the 2026-08-22 record. Filed as discovered work (§7.1); not fixed here.

**Doc 14 §16 item 1 (Pulumi's S3-compatible backend behaviour).** The
issue's summary — "locking behaviour and credential sourcing in CI are
still open" — is also stale. Reading doc 14 directly: CI credential
sourcing is now **closed** ("exercised" against production by the mail
apply jobs). Locking is **narrower than open**, not closed: two concurrent
`pulumi preview` runs completed with no contention (consistent with an
advisory per-operation lock), but two clients contending for one lock
during a concurrent **update**, and what happens to a lock left behind by
an interrupted apply, remain genuinely unverified. Read directly from the
doc, not reproduced.

**Doc 14 §15 step 4 (retiring the GCS buckets).** Read directly: the step's
own precondition is "per-stack archives verified restorable" plus (per
§15.1, added since) each archive's escrowed passphrase proven, from
escrow, to still open it — a live roundtrip against a lab copy, not a
listing of the escrow entry. §15.1 records that check as done for the six
post-wrap archives on 2026-08-18. Whether it has been re-run for any stack
that moved since (mail, 2026-08-22) is not stated in the doc and is not
something this session can check without escrow access (§8).

## 7. Discovered discrepancies

Filed as issues rather than fixed here, per the instruction not to widen
this branch.

### 7.1 `RUNBOOK-existing-stack-migration.md` and `mail/RUNBOOK-import-mail-host.md` describe a state the mail move already superseded — [branchLeft/shared-infra#172](https://github.com/branchLeft/shared-infra/issues/172)

The Part B "Lab rehearsal" section (§6 above) reads as unrehearsed and
lab-bucket-blocked; `mail/RUNBOOK-import-mail-host.md:76` still instructs
`pulumi login gs://branchleft-pulumi-state` for a stack whose backend is
now pinned in `mail/Pulumi.yaml` (no login step applies, and the command as
written would operate on the wrong backend entirely). Both are stale
against the 2026-08-22 move recorded in the issue thread and in doc 14
§16 item 1.

### 7.2 `scripts/pulumi-stack-inventory.json` is incomplete and one entry is stale — [branchLeft/shared-infra#173](https://github.com/branchLeft/shared-infra/issues/173)

Missing `branchleft-ghost-platform-hosts` entirely — a real, CI-applied,
`never-kms` stack that the audit's own stated guarantee ("a stack absent
from this file is a stack nobody re-wraps") should cover. The
`ghost-platform-tenant-template` entry in `external_backend_reference_sites`
still describes the pre-rewrite `PULUMI_STATE_BUCKET` / `gs://` pattern;
the template itself now requires and enforces `PULUMI_BACKEND_URL` /
`s3://` (§2.4).

Filed as [branchLeft/shared-infra#172](https://github.com/branchLeft/shared-infra/issues/172)
(the runbook staleness) and
[branchLeft/shared-infra#173](https://github.com/branchLeft/shared-infra/issues/173)
(the inventory JSON gaps).

## 8. What could not be verified without credentials or a live call

- Whether `branchleft-lab-pulumi-state` and `branchleft-lab-probe` (the two
  lab buckets doc 14 §16 item 1 names) and their S3 credential pair still
  exist today, three-plus weeks after the 2026-08-22 rehearsal. No
  committed file states a teardown, but absence of a teardown record is
  not evidence of persistence either.
- Whether `gs://branchleft-pulumi-state` and `gs://branchleft-blog-pulumi-state`
  currently hold live, decryptable checkpoints for the five stacks §1
  lists as still on `gs://` — this document reads committed config, not
  bucket contents.
- Whether the six escrowed post-wrap archive passphrases (doc 14 §15.1)
  have been re-verified against ProtonPass since 2026-08-18, and whether
  that verification has been extended to any stack moved after that date.
- Whether the `production` and `tenant-provisioning` environments'
  required-reviewer rules are actually configured live in each repo's
  GitHub settings. Every CI apply job asserts this via the API at runtime
  and fails closed if it is not (`ci.yml`'s "Refuse to apply through an
  ungated environment" steps) — so a real gap would surface as a failed
  run, not a silent one — but this session did not query the GitHub API
  for repo environment protection rules directly.
- Whether `branchleft-ghost-provisioning/blog`'s live checkpoint matches
  what `scripts/pulumi-stack-inventory.json`'s attestation records
  (passphrase, 12 resources) — the attestation itself notes "re-verify by
  hand before relying on it" because this stack's `config_path` is `null`.

Each of these needs either a Hetzner/GCP-credentialed session or the
platform owner's own access (ProtonPass, GitHub repo settings) — none of
them were attempted here.

## 9. Sequencing, read from the existing runbook, not re-derived

`RUNBOOK-existing-stack-migration.md` §B.1 already specifies Part A before
Part B for any stack; that ordering is unchanged and this document adds
nothing to it beyond what §4.1 says about `branchleft-ghost-provisioning/blog`
deserving the same caution `mail` got. The two Hetzner-native stacks and
the newly-identified `hosts` stack need no Part B at all — they were never
on `gs://`. Of the five remaining:

1. `branchleft-shared-infra/production`, `branchleft-website-infra/production`,
   `branchleft-ghost-platform/platform` — CI-applied, so a Part B mistake
   surfaces on the next merge.
2. `blog-infra/blog` — CI-applied, own bucket, own credential.
3. `branchleft-ghost-provisioning/blog` — **no CI**, `config_path: null`.
   §4.1's reasoning applies: treat this one with at least mail's level of
   care, and confirm the lab bucket (§8) is live before rehearsing against
   it, since production is not a substitute for rehearsal per the
   runbook's own rule.

This is a reading of existing sequencing guidance, not a new plan, and
executing any of it is explicitly out of scope for this document.
