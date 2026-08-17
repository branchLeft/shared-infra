# Graph Report - lint-sweep  (2026-08-10)

## Corpus Check
- 10 files · ~12,330 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 90 nodes · 83 edges · 17 communities (9 shown, 8 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 1 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `230fe293`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- index.ts
- compilerOptions
- package.json
- A.2: Cloud Armor drift remediation procedure (targeted refresh + up)
- devDependencies
- README.md
- Rationale: CI never applies to shared-infra (single shared LB is blast-radius-wide)
- Pulumi Stack: production (branchleft-shared-infra)
- CLAUDE.md
- Certificate Manager Map
- Cloud Armor Policy
- Global External Application Load Balancer
- Pulumi Project: branchleft-shared-infra
- Pulumi Stack: production
- Gate 11b: website-infra preview shows zero deletions
- Gate 11c: production is still serving

## God Nodes (most connected - your core abstractions)
1. `compilerOptions` - 12 edges
2. `Mechanism: pulumi state move (chosen)` - 4 edges
3. `A.2: Cloud Armor drift remediation procedure (targeted refresh + up)` - 4 edges
4. `Pulumi Stack: production (branchleft-shared-infra)` - 3 edges
5. `Appendix A: live-vs-state drift on branchleft-edge-armor (duplicate sqli, missing lfi)` - 3 edges
6. `region` - 2 edges
7. `EdgeSite` - 2 edges
8. `HostRedirect` - 2 edges
9. `createEdge()` - 2 edges
10. `scripts` - 2 edges

## Surprising Connections (you probably didn't know these)
- `Rationale: CI never applies to shared-infra (single shared LB is blast-radius-wide)` --references--> `website CI deploy job (pulumi up --yes on merge to main)`  [EXTRACTED]
  .github/workflows/ci.yml → RUNBOOK-edge-state-move.md
- `Runbook: Moving the Edge from website-infra to shared-infra` --references--> `Pulumi Stack: production (branchleft-shared-infra)`  [EXTRACTED]
  RUNBOOK-edge-state-move.md → Pulumi.production.yaml
- `Runbook: Moving the Edge from website-infra to shared-infra` --references--> `Shared Cloud KMS Secrets Provider (pulumi-secrets keyring)`  [EXTRACTED]
  RUNBOOK-edge-state-move.md → Pulumi.production.yaml

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Cross-Repo Dependencies** — website_repo, ghost_platform_repo, readme_md [INFERRED 0.90]
- **Runbook §11 Safety Gates (11a/11b/11c)** — runbook_edge_state_move_gate_11a, runbook_edge_state_move_gate_11b, runbook_edge_state_move_gate_11c [EXTRACTED 1.00]

## Communities (17 total, 8 thin omitted)

### Community 0 - "index.ts"
Cohesion: 0.12
Nodes (18): config, gcpConfig, projectId, region, ALL_SOURCE_IPS, createEdge(), DnsAuthorizationRecord, Edge (+10 more)

### Community 1 - "compilerOptions"
Cohesion: 0.12
Nodes (15): ES2022, *.ts, compilerOptions, experimentalDecorators, lib, module, moduleResolution, noFallthroughCasesInSwitch (+7 more)

### Community 2 - "package.json"
Cohesion: 0.17
Nodes (11): comment, dependencies, @pulumi/gcp, @pulumi/pulumi, main, name, private, scripts (+3 more)

### Community 3 - "A.2: Cloud Armor drift remediation procedure (targeted refresh + up)"
Cohesion: 0.18
Nodes (12): A.1: pulumi up / refresh --preview-only do not fix checkpoint-vs-live drift, A.2: Cloud Armor drift remediation procedure (targeted refresh + up), A.3: Sequencing rationale — remediation runs after migration, not before, A.4: What gate 11a can and cannot prove, A.5: Generalisable lesson — SecurityPolicy rules array is not applied atomically, Appendix A: live-vs-state drift on branchleft-edge-armor (duplicate sqli, missing lfi), Backup procedure: pulumi stack export + raw gcloud storage copy before any change, Gate 11a: shared-infra preview shows zero changes (+4 more)

### Community 4 - "devDependencies"
Cohesion: 0.40
Nodes (5): devDependencies, @types/node, typescript, @types/node, typescript

### Community 5 - "README.md"
Cohesion: 0.50
Nodes (3): GCP Project: branchleft-prod, ghost-platform repo, website repo

### Community 6 - "Rationale: CI never applies to shared-infra (single shared LB is blast-radius-wide)"
Cohesion: 0.50
Nodes (4): Rationale: CI never applies to shared-infra (single shared LB is blast-radius-wide), CI Type-check Job, Ordering hazard: state-move-first vs code-removal-first, website CI deploy job (pulumi up --yes on merge to main)

### Community 7 - "Pulumi Stack: production (branchleft-shared-infra)"
Cohesion: 0.67
Nodes (4): Shared GCS State Backend (gs://branchleft-pulumi-state), Shared Cloud KMS Secrets Provider (pulumi-secrets keyring), Pulumi Stack: production (branchleft-shared-infra), Runbook: Moving the Edge from website-infra to shared-infra

## Knowledge Gaps
- **50 isolated node(s):** `config`, `gcpConfig`, `projectId`, `DnsAuthorizationRecord`, `Edge` (+45 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **8 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `devDependencies` connect `devDependencies` to `package.json`?**
  _High betweenness centrality (0.013) - this node is a cross-community bridge._
- **What connects `config`, `gcpConfig`, `projectId` to the rest of the system?**
  _50 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `index.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.12121212121212122 - nodes in this community are weakly interconnected._
- **Should `compilerOptions` be split into smaller, more focused modules?**
  _Cohesion score 0.125 - nodes in this community are weakly interconnected._