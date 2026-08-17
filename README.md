# shared-infra

The shared branchLeft edge: one Global External Application Load Balancer, one
Cloud Armor policy, one Certificate Manager map, and the per-site backends that
hang off them. Every hostname branchLeft serves on the public internet is
served through the resources defined in this repo.

GCP project `branchleft-prod`. Pulumi project `branchleft-shared-infra`, stack
`production`, state in `gs://branchleft-pulumi-state`.

**This GCP edge is being wound down**, in favour of a Hetzner VM running Caddy
and CrowdSec. `hetzner/` holds the network and host modules that land first,
and `CLOUD-ARMOR-BASELINE.md` is the artifact the cutover checks edge parity
against. Everything below describes the configuration that is retiring.

> **What this repo will not carry.** `sites.ts` lists hostnames and the Cloud
> Run service behind each — nothing more. No member counts, no commercial
> terms, no personal data, and nothing identifying a tenant who has not agreed
> to appear. No secrets, no key material, no credentials, and no stack
> `encryptionsalt`: an operator supplies each of those out of band. A tenant
> who prefers not to be named is served from a hostname that does not name
> them, in their own infrastructure repository, and never appears here.

## What lives here, and what does not

The placement rule: **anything not specific to the website moves here;
anything specific to the Ghost platform goes in the Ghost repos.**

| Repo                          | Owns                                                                                                                                                                                                                                                   |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`shared-infra`** (here)     | The load balancer: global IP, Cloud Armor policy, URL maps, target proxies, forwarding rules, certificate map, DNS authorizations, managed certificates. Also the per-site serverless NEGs and backend services (see below). Cloud DNS, when it lands. |
| **`website`** (public)        | The marketing site and its own infrastructure — Cloud Run service, Artifact Registry, Secret Manager, monitoring, CI/CD identity federation. Also the **shared Cloud KMS key** (see below).                                                            |
| **`ghost-platform`** (public) | The shared Ghost platform — Cloud SQL instance, media bucket, tenant image registry, CI identity — plus the reusable `GhostTenant` component. Names no tenant.                                                                                         |
| **one repo per tenant**       | One tenant's stack invocation: its name, hostname and config. Generated from `ghost-platform-tenant-template`, and private unless that tenant chooses otherwise.                                                                                       |

### Resources no single repo cleanly owns

Three things every stack here depends on are worth knowing about before
changing anything, because none of them is owned where you would look:

| Thing                                                  | Actually owned by                                                 | Why it matters                                                                                                                                                                                                                         |
| ------------------------------------------------------ | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Cloud KMS key** `pulumi-secrets`                     | `website/infra/kms.ts` — the _public_ marketing-site repo         | Every stack in the project, including this one and every tenant's, names it as `secretsprovider` by hardcoded URI. A stack file must name its provider before config resolves, so there is no indirection available and no opting out. |
| **Pulumi state bucket** `gs://branchleft-pulumi-state` | **No Pulumi program.** Created by hand; IAM managed with `gcloud` | Appears as a literal string in every stack's CI and runbook. Its access bindings are a bootstrap prerequisite — Pulumi cannot grant itself access to the bucket it must log in to first.                                               |
| **DNS**                                                | **No Pulumi program.** `branchleft.co.uk` is manual at IONOS      | Several documents have claimed this repo owns DNS. It does not — no `gcp.dns.*` resource exists anywhere in the workspace. This repo is where Cloud DNS _would_ land.                                                                  |

### Identifiers that must be unique in `branchleft-prod`

Workload Identity Pool IDs, service-account IDs and Pulumi project names are
unique per project, and a collision only surfaces on the first apply. There
is no automated check, so allocate from here:

| Pool ID                                 | Allocated to                                                                                |
| --------------------------------------- | ------------------------------------------------------------------------------------------- |
| `github-actions`                        | `website/infra` — the first one created, which is why nothing else can use the obvious name |
| `ghost-platform-gha`                    | `ghost-platform/infra/platform`                                                             |
| `shared-infra-gha`                      | this repo (`workloadIdentity.ts`)                                                           |
| per-tenant, from a template placeholder | each generated tenant repo                                                                  |

A deleted pool ID is unavailable for reuse for 30 days, so a rename here is not
reversible within a working day.

### Why the per-site NEGs and backend services are here rather than in each product's repo

They look product-specific, and they are not placed here for tidiness. A
backend service needs the shared Cloud Armor policy's ID; the shared URL map
needs the backend service's ID. Split across two stacks that is a circular
`StackReference` — each stack would need an output of the other — which Pulumi
cannot resolve. So the whole path from NEG to forwarding rule lives in one
stack.

### Why this repo exists at all

The edge was originally written in `website/infra/edge.ts`. The URL map,
certificate map and Cloud Armor policy are singletons that must enumerate every
hostname they serve, so whoever owned that stack owned the full list of hosted
sites — and, more importantly, could deploy it: `website`'s CI runs `pulumi up`
on merge to `main`, which meant a marketing-site change could apply a change to
every tenant's edge.

Extracted 2026-08-04/05 via a Pulumi state move, not a rebuild — the live edge
has served production traffic continuously since 2026-08-03 and was never
recreated. History and rationale: [`RUNBOOK-edge-state-move.md`](RUNBOOK-edge-state-move.md).

## No dependency on any product stack

This stack holds **no `StackReference`** to `website` or anything else, and
imports no code from another repo. A serverless NEG needs only the _name_ of a
Cloud Run service and its region, both plain strings, so `sites.ts` carries
them as literals.

The trade is explicit: nothing here validates that the named service exists. A
typo applies cleanly and 404s in production. `sites.ts` documents the `gcloud`
check to run before adding an entry.

## Adding a site

One entry in the `sites` array in [`sites.ts`](sites.ts). Everything else — NEG,
backend service, certificate, certificate-map entry, URL-map host rule — is
derived from it. That file also carries the pre- and post-apply checklist: ingress lock, DNS
authorization, issuance timings, TTL wait.

## TLS floor

Every hostname behind this LB negotiates through one `SSLPolicy`
(`branchleft-edge-tls`): the **MODERN** profile at a **TLS 1.2** minimum.

A target proxy with no policy attached inherits GCP's default, which is the
COMPATIBLE profile at TLS 1.0 — so before this existed the edge's TLS floor was
set by omission. That is the thing worth stating: not that TLS 1.0 was
catastrophic, but that nobody had chosen.

MODERN keeps the TLS 1.2 CBC suites. RESTRICTED drops them for AEAD-with-PFS
only, and is the next step up; it costs clients predating roughly 2015, which
is a decision to take deliberately rather than a default to drift into.

The values are constants in `edge.ts`, not stack config. A TLS minimum that
`pulumi config set` can lower without a code review is not a minimum.

```bash
gcloud compute ssl-policies describe branchleft-edge-tls \
  --format='value(profile,minTlsVersion,enabledFeatures)'
```

## Cloud Armor policy (superseded)

**This describes the retiring GCP edge.** The rules and thresholds below are
what `edge.ts` declares, and they are the reference the Hetzner edge's
CrowdSec configuration is built to reproduce — not a description of a policy
anyone should still be tuning. `CLOUD-ARMOR-BASELINE.md` records the captured
state of the live policy and the recorded divergences between it and this
code; read it, and never assume that what `edge.ts` declares is what the
retiring policy is doing.

What the policy declares: four OWASP-class rulesets at sensitivity 1 (`sqli`,
`xss`, `rce`, `lfi`), a per-IP throttle, and a default allow.

```bash
# What is being blocked now
gcloud logging read \
  'jsonPayload.enforcedSecurityPolicy.name="branchleft-edge-armor"
   AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"' \
  --project=branchleft-prod --limit=50

# What the still-previewing rules would block
gcloud logging read \
  'jsonPayload.previewSecurityPolicy.outcome="DENY"' \
  --project=branchleft-prod --limit=50
```

**What a 7.5-day preview window showed**, and what calibrated the thresholds
below. ~20k requests produced 555 preview denies from 15 source addresses,
every one attributable to scanning, and **no false positive against legitimate
traffic**. 522 were `lfi` — a credential
sweep for `.env` (~40 filename variants), `.aws/credentials`, `.ssh/id_rsa`,
`.git/config`, `.kube/config`, `terraform.tfstate` — plus Vite `@fs/`
double-encoded traversal and `?cmd=`-style command-injection probes. Several
scanners rotated AI-crawler user agents (ClaudeBot, GPTBot, PerplexityBot,
Amazonbot) from a single IP while sending those payloads, so **never allowlist
by crawler user agent here**; it is actively being impersonated.

**Rate-limit threshold: 200 requests/IP/60s, not the original 100.** Peak
observed requests per address per minute: scanners at 394, 379, 243 and 146;
the highest legitimate sources were operator `curl` testing at 106 and
Googlebot at 92. 200 sits in the gap with roughly double headroom over the
worst legitimate burst and below every scan burst — which is the number worth
carrying to the replacement edge, rather than the round one it replaced.

**The injection rules do not enforce for Ghost-backed hosts.** `sqli`, `xss`
and `rce` at sensitivity 1 match author-written HTML, code samples and SQL,
which is exactly what a Ghost admin API request body contains — and a false
positive there locks the owner out of publishing rather than degrading a page.
Sites set `injectionWafPreviewOnly` in `sites.ts` to opt in; they get
preview-mode copies of those three rules at priorities 1100+, so the exemption
keeps producing the evidence needed to end it rather than simply hiding the
question. `lfi` enforces everywhere regardless — nothing legitimate requests
`.env`.

A host still carrying `injectionWafPreviewOnly` at the Hetzner cutover needs
its exemption re-decided on the new stack rather than carried across silently.
To end it, check its preview rules have stayed clean across real authoring
traffic (not just reads), then drop the flag:

```bash
gcloud logging read \
  'jsonPayload.previewSecurityPolicy.outcome="DENY"
   AND httpRequest.requestUrl:"blog.branchleft.co.uk"' \
  --project=branchleft-prod --limit=50
```

**Rule ordering in `edge.ts`'s `OWASP_RULESETS`/rate-limit array is an
invariant, not a style choice: append only, never insert.** Priorities are
assigned by array index, so inserting mid-array renumbers every rule after
it as separate per-priority API calls — a partial failure there previously
left the live policy holding a mix of old and new rules (see
`RUNBOOK-edge-state-move.md`, appendix A). Also keep the rate-limit rule
after the WAF rules: its match condition (`srcIpRanges: ['*']`) is
unconditionally true, so ahead of the WAF rules it wins every match first
and makes them permanently unreachable regardless of preview/enforce mode —
confirmed by 23h of real traffic logs showing zero hits against any WAF
rule while the order was wrong.

The same first-match rule is why the preview-only copies sit at 1100+, after
`lfi` at 1003 and not interleaved with the rules they mirror: a request to an
exempt host that trips both `lfi` and an injection signature is denied by
`lfi`, which is the intended outcome.

## Operating this stack

**CI applies this stack on merge to `main`. Do not hand-apply it** — general
rule and rationale: `standards/docs/infrastructure.md` IAC-1. This stack's own
guardrails (Workload Identity Federation with a `refs/heads/main` condition, a
deployer that cannot grant itself a role or delete a certificate, a
`pulumi preview --json` delete guard, an `environment`, a concurrency group),
the one-time bootstrap behind them, and the three kinds of change CI is
deliberately unable to apply (project IAM, federation, taking a site off the
edge) are in [`RUNBOOK-ci-bootstrap.md`](RUNBOOK-ci-bootstrap.md).

```bash
npm ci
npx tsc --noEmit                              # what CI type-checks with
python3 scripts/assert-no-edge-deletes.py --self-test
python3 scripts/assert-no-edge-deletes.py --verify-coverage .

pulumi login gs://branchleft-pulumi-state
pulumi stack select production
pulumi preview                                # read this, then open a PR
```

### One thing this stack does not own, and needs

**API enablement.** `compute.googleapis.com` and
`certificatemanager.googleapis.com` are declared in `website/infra/apis.ts` and
stay owned there. Declaring them here too would put two stacks in charge of one
real resource. This stack's deployer holds no
`roles/serviceusage.serviceUsageAdmin` as a result, so it cannot turn an API on
— if this program ever needs one that is not already enabled, enabling it is a
prerequisite step, not something a merge can do.

`website/infra/serviceAccounts.ts` separately grants
`roles/compute.loadBalancerAdmin`, `roles/compute.securityAdmin` and
`roles/certificatemanager.owner` to `github-actions-deployer`, a leftover from
when the edge lived in that repo. Nothing here uses that identity —
`serviceAccounts.ts` declares its own, deliberately narrower — and those three
grants are candidates for removal from `website` once someone confirms its
program no longer touches an edge resource.

## Mail delivery host (`mail/`)

A second, separate Pulumi project lives at [`mail/`](mail/) —
`branchleft-mail`, its own `Pulumi.yaml`, own `package.json`, own stack.
It declares the Hetzner delivery host (`mx1`) and its firewall — the reason it
is not on GCP is that GCP blocks outbound port 25 unconditionally. It is a
separate project rather than a second stack of this one, or resources added
to this file's own program, for three reasons: a different cloud (Hetzner,
not GCP) with a different credential and no shared dependency on
`@pulumi/gcp`; a stack whose only two resources must never be perturbed by
an edge-stack change to this project, or vice versa; and both resources are
hand-created and imported rather than created by Pulumi, so keeping them
isolated keeps a mistake here from ever being able to propose replacing
them.

See [`mail/RUNBOOK-import-mail-host.md`](mail/RUNBOOK-import-mail-host.md)
for the import procedure, gated on the platform owner. Unlike the edge
project above — CI-applied on merge to `main` — this project has no CI apply
path: Hetzner's API is a plain bearer token with no Workload Identity
Federation equivalent, so CI type-checks `mail/` only (no credentials), and
its `pulumi up` is run by the platform owner from a workstation.

## Related documents

- [`CLOUD-ARMOR-BASELINE.md`](CLOUD-ARMOR-BASELINE.md) — the parity artifact
  for the Hetzner cutover: a captured snapshot of the Cloud Armor policy, kept
  diffable against future re-captures.
- [`RUNBOOK-edge-state-move.md`](RUNBOOK-edge-state-move.md) — the migration
  procedure. Appendix A records a live-vs-checkpoint drift on the Cloud Armor
  policy that predates this repo, is invisible to `pulumi preview`, and is
  **not** fixed by the move — with a gated remediation to run afterwards. If
  you touch this repo's Cloud Armor rules, read A.5 first: a clean `pulumi up`
  is evidence about the checkpoint, not about the policy.
- [`hetzner/RUNBOOK-existing-stack-migration.md`](hetzner/RUNBOOK-existing-stack-migration.md)
  — moving every stack in the estate off the shared GCP KMS secrets provider
  and off `gs://` state. The secrets half has a deadline that cannot be
  missed: the key it re-wraps away from is destroyed in the GCP wind-down, and
  a stack left behind can no longer be decrypted or even destroyed.
- [`RUNBOOK-ci-bootstrap.md`](RUNBOOK-ci-bootstrap.md) — the one-time apply that
  gives CI an identity, the two IAM grants that can never come from the program,
  and what CI is deliberately unable to apply afterwards.
- `website/infra/KNOWN_ISSUES.md` — GCP/Pulumi bootstrap failure modes for this
  project. Load-bearing; read it before adding a resource type this program has
  never created before.
