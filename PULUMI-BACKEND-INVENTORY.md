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
top-level reference-document convention — a standing captured-state
document, not a runbook to execute. It supports
`hetzner/RUNBOOK-existing-stack-migration.md` without sitting beside it on
disk — that runbook lives under `hetzner/`.

## 1. Every Pulumi stack in the estate

**Eight stacks today, not nine.** `branchleft-shared-infra/production` — the
GCP edge stack that used to be the first row of this table — was deleted
2026-09-17 in the GCP wind-down (branchLeft/workspace#1000): the GCP estate
was destroyed 2026-09-13, and the program (`edge.ts` and friends) went with
it, not merely migrated, so it carries no migration state to attest and
`scripts/pulumi-stack-inventory.json` no longer has an entry for it.
`branchleft-ghost-platform-hosts`, previously missing from the inventory
JSON, was added there since (branchLeft/shared-infra#173, closed) and is
included below.

| Project / stack                                                      | Repo                | Definition path                                           | Committed backend today                                | Born there or moved? |
| -------------------------------------------------------------------- | ------------------- | --------------------------------------------------------- | ------------------------------------------------------ | -------------------- |
| `branchleft-mail/production`                                         | `shared-infra`      | `mail/Pulumi.yaml` / `mail/Pulumi.production.yaml`        | `s3://branchleft-pulumi-state?endpoint=hel1…` (pinned) | **moved** 2026-08-22 |
| `branchleft-website-infra/production`                                | `website`           | `infra/Pulumi.yaml` / `infra/Pulumi.production.yaml`      | `gs://branchleft-pulumi-state`                         | still on `gs://`     |
| `branchleft-ghost-platform/platform`                                 | `ghost-platform`    | `infra/platform/Pulumi.yaml` / `Pulumi.platform.yaml`     | `gs://branchleft-pulumi-state`                         | still on `gs://`     |
| `branchleft-ghost-provisioning/blog`                                 | `ghost-platform`    | `infra/provisioning/Pulumi.yaml` (config never committed) | `gs://branchleft-pulumi-state`                         | still on `gs://`     |
| `blog-infra/blog`                                                    | `ghost-tenant-blog` | `Pulumi.yaml` / `Pulumi.blog.yaml`                        | `gs://branchleft-blog-pulumi-state`                    | still on `gs://`     |
| `branchleft-hetzner-network/production`                              | `shared-infra`      | `hetzner/Pulumi.yaml` / `Pulumi.production.yaml`          | `s3://branchleft-pulumi-state?endpoint=hel1…` (pinned) | born there           |
| `branchleft-hetzner-estate/production`                               | `shared-infra`      | `hetzner/estate/Pulumi.yaml` / `Pulumi.production.yaml`   | `s3://branchleft-pulumi-state?endpoint=hel1…` (pinned) | born there           |
| `branchleft-ghost-platform-hosts` (project name; stack `production`) | `ghost-platform`    | `infra/hosts/Pulumi.yaml` / `Pulumi.production.yaml`      | `s3://branchleft-pulumi-state?endpoint=hel1…` (pinned) | born there           |

**Four stacks remain on `gs://`**: website-infra, ghost-platform/platform,
ghost-provisioning/blog, and blog-infra/blog — each in `website` or
`ghost-platform`/`ghost-tenant-blog`, outside this repo. Four stacks are
already on Hetzner Object Storage — one moved (`mail`), three born there
(the two Hetzner-native stacks plus the hosts stack).

**Verified two ways:**

1. Read each stack's committed `Pulumi.yaml` directly (`backend.url` present
   or absent) — done for all eight, quoted inline above.
2. Cross-checked against `scripts/pulumi-stack-inventory.json`'s
   `state_backends` map and per-stack `state_backend` field, and against
   `graphify query` traversals in `shared-infra` and `ghost-platform`
   surfacing the same project nodes independently. The cross-check is what
   originally surfaced the then-missing `branchleft-ghost-platform-hosts`
   stack and the stale template entry §7 records as resolved.

## 2. Backend and login enumeration

No central list exists (the runbook says so explicitly, §B.3, and it is
right) — this is built by category, each verified by reading the file
rather than assuming a role from its name.

### 2.1 Executable `pulumi login` steps in CI (the ones a workflow run actually executes)

| Repo                             | Workflow                                                   | Job(s)                                    | Backend logged into                                                                   |
| -------------------------------- | ---------------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------- |
| `website`                        | none -- deleted; deploys are a GHCR digest pinned over SSH | --                                        | none (removed, `branchLeft/workspace#1000`)                                           |
| `ghost-platform`                 | `.github/workflows/infra-platform-ci.yml`                  | `Deploy (pulumi up)`                      | `gs://branchleft-pulumi-state`                                                        |
| `ghost-platform`                 | `.github/workflows/provision-tenant.yml`                   | `provision` (new tenant's own stack init) | `$HETZNER_PULUMI_BACKEND_URL` (repo variable, `s3://…`)                               |
| `ghost-platform-tenant-template` | `.github/workflows/infra-ci.yml`                           | preview/deploy jobs                       | `$PULUMI_BACKEND_URL` (repo variable, `s3://…`, generated into every new tenant repo) |
| `ghost-tenant-blog`              | `.github/workflows/infra-ci.yml`                           | preview/deploy jobs                       | `gs://$PULUMI_STATE_BUCKET` = `gs://branchleft-blog-pulumi-state`                     |

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
| `shared-infra`                   | `RUNBOOK-edge-state-move.md`                  | `gs://branchleft-pulumi-state` — history only, the program it documents is deleted                                                                                                    |
| `shared-infra`                   | `mail/RUNBOOK-import-mail-host.md`            | `gs://branchleft-pulumi-state` — inside a "historical record only" block; fixed per §7.1 (branchLeft/shared-infra#172, closed)                                                        |
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

**`branchleft-pulumi-state`** — was 22 files across the estate as of the
original pass below; **re-counted for `shared-infra` only** while fixing
this document for the GCP wind-down (branchLeft/workspace#1000) — the
`ghost-platform` and `website` sub-counts are unchanged from that original
pass and not re-verified here, since both repos' own GCP wind-downs are
separate PRs:

- **11 in `shared-infra`, down from 14**: three `Pulumi.yaml`s
  (`hetzner/Pulumi.yaml`, `hetzner/estate/Pulumi.yaml`, `mail/Pulumi.yaml`
  — all naming the _Hetzner_ bucket of the same overloaded name, see below),
  **four** `RUNBOOK-*.md` (`RUNBOOK-edge-state-move.md`,
  `hetzner/RUNBOOK-existing-stack-migration.md`, `hetzner/RUNBOOK-new-stack.md`
  — this is where the "two backends share this bucket name" passage §3
  itself discusses lives — `mail/RUNBOOK-import-mail-host.md`),
  `hetzner/scripts/test_probe_object_storage.py`,
  `scripts/pulumi-stack-inventory.json`, `scripts/audit-pulumi-secrets.py`,
  `scripts/test_audit_pulumi_secrets.py`. `README.md`, `RUNBOOK-ci-bootstrap.md`
  and `.github/workflows/ci.yml` are the three that dropped out: the first
  two no longer mention a `gs://` backend (`RUNBOOK-ci-bootstrap.md` is
  deleted outright) and `ci.yml` lost its only two `pulumi login
gs://branchleft-pulumi-state` lines with the `deploy-plan`/`deploy-apply`
  jobs.
- **6 in `ghost-platform`** (as of the original pass, not re-verified):
  `RUNBOOK-tenant-onboarding.md`, `infra/platform/RUNBOOK-bootstrap.md`,
  `infra/provisioning/index.ts` — the guard comment, not a live reference,
  `infra/hosts/Pulumi.yaml` — the Hetzner bucket of the same name,
  `.github/workflows/provision-tenant.yml`, `.github/workflows/infra-platform-ci.yml`.
- **2 in `website`** (as of the original pass, not re-verified — and per
  branchLeft/workspace#1000, `website`'s own CI now has no Pulumi job at
  all, which this document's original §2.1 pass had not yet caught; see the
  corrected §2.1/§4 rows above): `.github/workflows/ci.yml` and
  `infra/KNOWN_ISSUES.md`, already named in §2.3's table.

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

| Stack                                   | Has a CI apply path today? | Evidence                                                                                      |
| --------------------------------------- | -------------------------- | --------------------------------------------------------------------------------------------- |
| `branchleft-mail/production`            | Yes                        | `mail-plan`/`mail-apply`, same file.                                                          |
| `branchleft-website-infra/production`   | **No**                     | Removed; deploys are a GHCR digest pinned over SSH to app1 (own wind-down, outside this repo) |
| `branchleft-ghost-platform/platform`    | Yes                        | `Deploy (pulumi up)`, `ghost-platform/.github/workflows/infra-platform-ci.yml`                |
| `branchleft-ghost-provisioning/blog`    | **No**                     | See §4.1                                                                                      |
| `blog-infra/blog`                       | Yes                        | `Deploy (pulumi up)`, `ghost-tenant-blog/.github/workflows/infra-ci.yml`                      |
| `branchleft-hetzner-network/production` | Yes                        | `hetzner-network-plan`/`-apply`, `shared-infra/.github/workflows/ci.yml`                      |
| `branchleft-hetzner-estate/production`  | Yes                        | `hetzner-estate-plan`/`-apply`, same file                                                     |
| `branchleft-ghost-platform-hosts`       | Yes                        | `Apply (hosts, pulumi up)`, `ghost-platform/.github/workflows/infra-hosts-ci.yml`             |

### 4.1 The one stack with no CI apply path anywhere: `branchleft-ghost-provisioning/blog`

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

This is the one stack in §4's table whose Part B move would happen with no
CI to catch a mistake. It has the added complication that its config file
does not exist to pin a backend into without first reconstructing it by
hand. Any Part B sequencing should treat it with at least as much care as
a CI-applied stack gets, not less, precisely because nothing exercises it.

## 5. What the GCS buckets being deleted actually broke, 2026-09-13

This section used to ask what _would_ strand each remaining `gs://` stack if
the bucket were deleted. It has happened: the GCP estate, both state
buckets included, was destroyed 2026-09-13 (branchLeft/workspace#15).

`branchleft-shared-infra/production` is no longer one of the stranded
stacks — its whole program was deleted rather than left stranded, in this
same wave (branchLeft/workspace#1000, §1 above). The other three named
here were not: `branchleft-website-infra/production`,
`branchleft-ghost-platform/platform` and `branchleft-ghost-provisioning/blog`
still declare a `gs://branchleft-pulumi-state` backend as of this writing,
now unreachable, in `website` and `ghost-platform` respectively — those
repos' own wind-downs are outside this PR. `blog-infra/blog` similarly
still names `gs://branchleft-blog-pulumi-state` in `ghost-tenant-blog`. Per
`RUNBOOK-existing-stack-migration.md`'s own gate section, a stack that
cannot read its checkpoint cannot be destroyed either, so those resources
are permanently unmanageable by Pulumi, not merely un-previewable, until
each is either migrated or its program removed the same way this one was.

## 6. Blockers: verified vs inherited

**The lab Object Storage bucket and credential pair (Part B rehearsal).**
`branchLeft/ghost-platform-docs` doc 14 §16 item 1 records that
`branchleft-lab-pulumi-state` (`hel1`) was created and used for a
rehearsal immediately before the production mail move. This session did
not confirm the bucket or its credentials still exist today — that needs
a live, credentialed check (§8). The repo's own committed runbook,
`hetzner/RUNBOOK-existing-stack-migration.md`, does not reflect this: its
"Lab rehearsal" section still describes the rehearsal as not yet run and
the lab bucket as not yet created. Tracked at
[branchLeft/shared-infra#172](https://github.com/branchLeft/shared-infra/issues/172).

**Doc 14 §16 item 1 (Pulumi's S3-compatible backend behaviour).** CI
credential sourcing is closed — exercised against production by the mail
apply jobs. Locking is narrower-but-not-fully-open: two concurrent
`pulumi preview` runs completed with no contention (consistent with an
advisory per-operation lock), but two clients contending for one lock
during a concurrent update, and what happens to a lock left behind by an
interrupted apply, remain unverified. Read directly from doc 14, not
reproduced.

**Doc 14 §15 step 4 (retiring the GCS buckets).** The step's own
precondition is "per-stack archives verified restorable" plus (per §15.1)
each archive's escrowed passphrase proven, from escrow, to still open it —
a live roundtrip against a lab copy, not a listing of the escrow entry.
§15.1 records that check as done for the six post-wrap archives, dated
2026-08-18. Whether it has been re-run for `branchleft-mail/production`,
which moved to Hetzner after that check ran, is not stated in the doc and
is not something this session can check without escrow access (§8).

## 7. Discovered discrepancies

Both filed as issues and since resolved — verified against current state
while fixing this document for the GCP wind-down (branchLeft/workspace#1000).

### 7.1 Two runbooks were stale against mail's current backend — [branchLeft/shared-infra#172](https://github.com/branchLeft/shared-infra/issues/172), closed

`hetzner/RUNBOOK-existing-stack-migration.md`'s Part B rehearsal guidance
(§6 above) and `mail/RUNBOOK-import-mail-host.md:76`'s login instructions
did not reflect `mail`'s current Hetzner-pinned backend. Verified fixed:
the latter's `pulumi login gs://…` line now sits inside a block marked
"Historical record only — do not run this against the live stack" (§2.3).

### 7.2 `scripts/pulumi-stack-inventory.json` was incomplete and one entry was stale — [branchLeft/shared-infra#173](https://github.com/branchLeft/shared-infra/issues/173), closed

Was missing `branchleft-ghost-platform-hosts` entirely — a real,
CI-applied, `never-kms` stack the audit's own stated guarantee ("a stack
absent from this file is a stack nobody re-wraps") should cover. The
`ghost-platform-tenant-template` entry in `external_backend_reference_sites`
described the pre-rewrite `PULUMI_STATE_BUCKET` / `gs://` pattern, while the
template itself requires and enforces `PULUMI_BACKEND_URL` / `s3://` (§2.4).
Verified fixed: the inventory JSON now carries a `branchleft-ghost-platform-hosts`
entry (`terminal_state: never-kms`, §1 above) and the tenant-template
`external_backend_reference_sites` entry already names the `s3://` /
`PULUMI_BACKEND_URL` pattern.

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
the `hosts` stack need no Part B at all — they were never on `gs://`.
`branchleft-shared-infra/production` needs no Part B either now, for a
different reason: its program was deleted rather than moved (§1, §5). Of
the four remaining:

1. `branchleft-website-infra/production`, `branchleft-ghost-platform/platform`
   — CI-applied (in their own repos), so a Part B mistake surfaces on the
   next merge, once each repo can log in to plan again.
2. `blog-infra/blog` — CI-applied, own bucket, own credential.
3. `branchleft-ghost-provisioning/blog` — **no CI**, `config_path: null`.
   §4.1's reasoning applies: treat this one with at least mail's level of
   care, and confirm the lab bucket (§8) is live before rehearsing against
   it, since production is not a substitute for rehearsal per the
   runbook's own rule.

This is a reading of existing sequencing guidance, not a new plan, and
executing any of it is explicitly out of scope for this document.
