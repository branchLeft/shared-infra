# shared-infra

Two live pieces of shared branchLeft infrastructure, plus the hostname
registry they share:

- **`mail/`** — the self-hosted mail delivery host (`mx1`), its own Pulumi
  project.
- **`hetzner/`** — the estate's network and host modules, and the edge VM
  (`edge1`) running Caddy and CrowdSec, replacing what used to be a GCP
  load balancer. See [`hetzner/README.md`](hetzner/README.md).
- **`sites.ts`** / **`siteTypes.ts`** at the repository root — the hostname
  registry `hetzner/edge/render.ts` and `hetzner/monitoring/render.ts` read.
  Adding a site is one entry here; see that file's own docstring.

> **What this repo does not carry.** `sites.ts` lists hostnames and where
> each is served from — nothing more. No member counts, no commercial terms,
> no personal data, and nothing identifying a tenant who has not agreed to
> appear. No secrets, no key material, no credentials, and no stack
> `encryptionsalt`: an operator supplies each of those out of band. A tenant
> who prefers not to be named is served from a hostname that does not name
> them, in their own infrastructure repository, and never appears here.

## History: the GCP edge

A GCP global load balancer, Cloud Armor policy and certificate map used to
front every branchLeft hostname from this repo's root (`edge.ts` and its
`deploy-plan`/`deploy-apply` CI jobs). Extracted from `website/infra/edge.ts`
2026-08-04/05 via a Pulumi state move — [`RUNBOOK-edge-state-move.md`](RUNBOOK-edge-state-move.md)
is the record of that move, including appendix A's live-vs-checkpoint Cloud
Armor drift incident.

It was wound down in favour of the Hetzner edge above over August–September
2026, the GCP estate was destroyed 2026-09-13, and the program itself —
`edge.ts`, `serviceAccounts.ts`, `workloadIdentity.ts`, `config.ts`,
`index.ts`, its CI jobs, `CLOUD-ARMOR-BASELINE.md` and `RUNBOOK-ci-bootstrap.md`
— was deleted 2026-09-17 in the GCP wind-down (branchLeft/workspace#1000).
`sites.ts`/`siteTypes.ts` outlived it: they were never GCP-specific, and the
Hetzner edge reads them still. A `cloudRunService`/`region` pair on an
existing site entry is what `edge.ts` used to read and is now vestigial —
nothing reads it — kept rather than stripped as a side effect of that
deletion.

## Mail delivery host (`mail/`)

A second, separate Pulumi project lives at [`mail/`](mail/) —
`branchleft-mail`, its own `Pulumi.yaml`, own `package.json`, own stack. It
declares the Hetzner delivery host (`mx1`) and its firewall — the reason it
is not on GCP is that GCP blocks outbound port 25 unconditionally. It is a
separate project rather than a stack of the Hetzner network/estate program,
or resources added there, for three reasons: a different credential shape
(Hetzner API bearer token, scoped to its own hcloud project) with nothing
shared; a stack whose only two resources must never be perturbed by an
unrelated change; and both resources are hand-created and imported rather
than created by Pulumi, so keeping them isolated keeps a mistake here from
ever being able to propose replacing them.

See [`mail/RUNBOOK-import-mail-host.md`](mail/RUNBOOK-import-mail-host.md)
for the first-time import procedure, gated on the platform owner. Steady-state
applies happen in CI on merge to `main` — the `mail-plan`/`mail-apply` jobs
in `.github/workflows/ci.yml` preview, gate on the Hetzner delete guard,
pause for a human to read the plan, and apply. Hetzner's API is a plain
bearer token with no Workload Identity Federation equivalent, so the jobs
hold a long-lived token scoped to the mail hcloud project alone
(`HCLOUD_TOKEN_MAIL`) rather than a federated credential — the trade doc 14
§3.5 records.

## Operating the stacks in this repo

**CI applies each stack on merge to `main` that touches that stack's own
inputs. Do not hand-apply any of them** — general rule and rationale:
`standards/docs/infrastructure.md` IAC-1. A `changes` job in
`.github/workflows/ci.yml` traces each program's actual import graph to a
per-stack `paths:` filter, so an unrelated merge plans and applies nothing.
Each apply is a plan job whose `pulumi preview` output lands in the job
summary, then an apply job paused by the `production` environment's
required-reviewer rule until a human has read that plan —
`scripts/assert-no-hetzner-deletes.py` catches the destruction class
mechanically, the reviewer catches the plan that is green and still wrong.

```bash
npm ci
npx tsc --noEmit                              # what CI type-checks with
```

## Related documents

- [`RUNBOOK-edge-state-move.md`](RUNBOOK-edge-state-move.md) — history: the
  now-deleted GCP edge's one state move and its Cloud Armor drift incident
  (appendix A). Nothing in it is actionable any more.
- [`hetzner/RUNBOOK-existing-stack-migration.md`](hetzner/RUNBOOK-existing-stack-migration.md)
  — moving every stack in the estate off the shared GCP KMS secrets provider
  and off `gs://` state.
- `PULUMI-BACKEND-INVENTORY.md` — the state-backend enumeration across the
  repos that still have Pulumi programs.
- `website/infra/KNOWN_ISSUES.md` — GCP/Pulumi bootstrap failure modes; that
  repo's own infra program is a separate, later removal.

## License

Source-available under the PolyForm Shield License 1.0.0. See [LICENSE](LICENSE).
