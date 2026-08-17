# CLAUDE.md — branchLeft Shared Infra

The shared edge for all branchLeft-hosted sites: global ALB, Cloud Armor policy, cert map, per-site serverless NEGs/backends, and the hostname registry (`sites.ts`). Also `mail/`, the self-hosted mail delivery host, and `hetzner/`, the network and host modules the estate is moving onto.

**Not DNS.** No program in this repo declares a `gcp.dns.*` resource; `branchleft.co.uk`'s zone is manual at the registrar. Moving it to a provider with an API is the prerequisite for onboarding a bundled subdomain without a manual DNS touch, and this repo is where it would land — but it has not landed.

**Migration in flight.** The GCP edge this repo describes is being wound down in favour of a Hetzner edge VM running Caddy and CrowdSec. `hetzner/` holds the foundations that land first, and `CLOUD-ARMOR-BASELINE.md` is the parity artifact the cutover checks against.

## Hard operational rules

- **CI applies the edge stack on merge to `main`** (`.github/workflows/ci.yml`). Do not hand-apply it. This stack's guardrails, its three CI-cannot-apply classes (project IAM, its own federation, deleting a certificate) and their targeted-apply recipe: `RUNBOOK-ci-bootstrap.md`.
- **`mail/` and `hetzner/` have no CI apply path at all.** Hetzner's API is a plain bearer token with no workload-identity equivalent, so CI type-checks and tests them and holds no credential. Their `pulumi up` is run by hand.
- **No stack config file in this repo carries an `encryptionsalt`.** It is an offline verifier for the stack passphrase, so a public tree must not hold one. CI appends the edge stack's salt from a repository secret at deploy; an operator appends the others from their own copy before running `pulumi`, and does not commit the result.
- **A clean `pulumi preview` is evidence about Pulumi state, not about the edge.** For Cloud Armor especially — the provider writes rules as independent per-priority API calls — verify against the live policy with `gcloud compute security-policies describe` after any apply that touched it. `RUNBOOK-edge-state-move.md` appendix A is the incident.
- `sites.ts` ordering matters: the **first** entry's backend service becomes the URL map's `defaultService` (the fallback for unmatched Host headers) — keep the marketing site first.

## graphify

`graphify-out/` holds a knowledge graph of this repo, rebuilt and committed by CI on every push to `main`.

- Answer codebase and architecture questions with `graphify query "<question>"` first — `graphify path "<A>" "<B>"` for a relationship, `graphify explain "<concept>"` for a concept. Each returns a scoped subgraph, far smaller than the equivalent grep.
- `graphify-out/GRAPH_REPORT.md` is the broad-navigation entry point. The payload files behind it are read-blocked in `.claude/settings.json` — go through the query commands instead.
- After changing code, `graphify update .` refreshes the graph locally. AST-only, no API cost. Never commit the result: `graphify-out/` is written by CI alone, and a local rebuild regresses it.
- `graphify-out/.graphify_root` and `.graphify_python` are never committed: they record absolute paths on the machine that built the graph, and a foreign value in either one is worse than its absence.
