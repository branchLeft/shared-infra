# Runbook — moving the edge from `branchleft-website-infra` to `branchleft-shared-infra`

This runbook documents a one-time state migration, run by hand against the
live stack and the live GCP project while the site stayed up. Nothing in it
runs from CI. It is kept as the historical record and as the reference for
A.5's generalisable lesson — not a template for future onboarding (see
`sites.ts` for that).

**What it does:** transfers 17 Pulumi resources — the entire edge load
balancer — from the `branchleft-website-infra/production` stack to the
`branchleft-shared-infra/production` stack, **without recreating a single GCP
resource**. `branchleft.co.uk` stays up throughout. No DNS changes, no
certificate reissue, no new IP.

**What it does not do:** steps 1–12 make **no GCP API call at all**. `pulumi
state move`, `stack export` and `stack import` are pure state operations — no
sequence of mistakes inside the migration window can alter a live resource.
That property is deliberate and is the reason the mechanism in §7 was chosen
over the alternative. Preserve it: do not add a cloud write to steps 1–12.

It also does not fix the pre-existing Cloud Armor drift described in
[appendix A](#appendix-a--live-vs-state-drift-on-branchleft-edge-armor). **Read
that appendix before you start.** It is a live-vs-checkpoint divergence that
`pulumi preview` structurally cannot see, so it changes how much gate 11a
proves (see A.4), and its remediation — which is a real production write — is
sequenced deliberately _after_ step 12 (see A.3).

---

## 0. Read this first — the hazard that makes ordering non-negotiable

`website`'s CI runs `pulumi up --yes` on every merge to `main`
(`.github/workflows/ci.yml`, job `deploy`).

That gives two possible orderings and they are not symmetric:

| Ordering                                                  | What happens                                                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Code removed from `website` first**, state moved second | The merge to `main` triggers `pulumi up`. Pulumi sees 17 resources in state with no corresponding declarations and **deletes them**. That deletes the forwarding rules, the URL map, the certificate map and the reserved anycast IP. `branchleft.co.uk` and `www.branchleft.co.uk` go down. The IP is not recoverable — a new one gets a new address, so recovery also needs a DNS change and a full TTL. **Catastrophic.** |
| **State moved first**, code removed second                | Between the two, `website`'s state no longer has the resources but its code still declares them. A merge to `main` in that window makes `pulumi up` try to **create** `branchleft-edge-ip`, `branchleft-edge-armor` et al., which already exist. GCP returns 409 `alreadyExists`, the resource fails, the update aborts. The deploy goes red; the site keeps serving. **Noisy, non-destructive, recoverable.**               |

**Therefore: state move first, website code removal second.** The window between
them is safe but must still be kept short and quiet — see step 11.

There is no ordering that makes the window disappear, because the two halves
live in different repositories. There is only an ordering whose failure mode is
a red build instead of an outage.

### The gate on the website-side PR

The follow-up PR that deletes `website/infra/edge.ts` and its wiring **must not
be mergeable until the move is confirmed.** Before starting:

- Open it as a **draft**, or apply a `do-not-merge` label, or both.
- Put the reason in the PR body, not just the title: a reviewer who does not
  know about this document will read a file deletion as low-risk.
- Have it written and approved _before_ step 10, so it can be merged within
  minutes of the move rather than hours.

---

## 1. Preconditions

- [ ] You are `rob@branchleft.co.uk` with `roles/owner` on `branchleft-prod`,
      and hold `roles/cloudkms.cryptoKeyEncrypterDecrypter` on
      `projects/branchleft-prod/locations/europe-west1/keyRings/pulumi/cryptoKeys/pulumi-secrets`.
- [ ] Pulumi CLI **v3.255.0 or later** (`pulumi state move` exists from 3.129;
      the flags used here were read from 3.255.0's `--help`).
- [ ] This PR is merged to `shared-infra`'s `main` and checked out locally.
- [ ] `npm ci && npx tsc --noEmit` passes in `shared-infra`.
- [ ] The website-side removal PR exists, is approved, and is blocked from
      merging (§0).
- [ ] `website`'s `main` is green _right now_. Do not start on top of a broken
      deploy — you will not be able to tell your failure from the existing one.
- [ ] Announce a merge freeze on `website` for the duration. It should be
      30–60 minutes.

```bash
pulumi login gs://branchleft-pulumi-state
pulumi whoami -v          # expect: Backend URL: gs://branchleft-pulumi-state
pulumi version            # expect: v3.255.0 or later
```

---

## 2. Back up both stacks — before anything else

The `.bak` file the DIY backend keeps is one revision deep and is overwritten
by the next write. It is not a backup. Take your own.

```bash
mkdir -p ~/edge-move-backups && cd ~/edge-move-backups
export TS=$(date -u +%Y%m%dT%H%M%SZ)

pulumi stack export \
  --cwd ~/branchLeft/website/infra \
  --stack organization/branchleft-website-infra/production \
  > website-infra-production.$TS.json

# Record the raw state objects too — belt and braces, and readable without
# Pulumi if the CLI is the thing that has gone wrong.
gcloud storage cp \
  gs://branchleft-pulumi-state/.pulumi/stacks/branchleft-website-infra/production.json \
  ./raw-website-infra-production.$TS.json

ls -l ./*.$TS.json
```

Verify the export is real before continuing — an empty or truncated file here
is the difference between a recoverable mistake and an unrecoverable one:

`jq` is not installed on this workstation, so these use `python3`, which is.
(`brew install jq` if you would rather; the equivalents are
`jq '.deployment.resources | length'` and `jq -r '.deployment.resources[].urn'`.)

```bash
python3 - "$PWD/website-infra-production.$TS.json" <<'PY'
import json, re, sys
urns = [r['urn'] for r in json.load(open(sys.argv[1]))['deployment']['resources']]
print('total resources:', len(urns), '(expect 62)')
edge = [u for u in urns
        if re.search(r'edge|cert-|dns-auth|website-neg|website-backend', u)]
print('edge resources: ', len(edge), '(expect 17)')
for u in sorted(edge):
    print('  ', u)
PY
```

Both numbers must match. A count of 0, or a `json.decoder.JSONDecodeError`,
means the export did not work — go no further.

**Restore command** (used by every rollback below). It replaces the stack's
entire state with the file:

```bash
pulumi stack import \
  --cwd ~/branchLeft/website/infra \
  --stack organization/branchleft-website-infra/production \
  --file ~/edge-move-backups/website-infra-production.$TS.json
```

`pulumi stack import` is a state-only operation. It does not call GCP and
cannot create, change or delete a cloud resource. Note it will complain about
the snapshot's `version`/integrity if you have edited the file by hand — do
not edit it by hand.

> Keep these files off any repo. `shared-infra/.gitignore` excludes
> `stack-backup-*.json` and `*.checkpoint.json` as a safety net, but the
> intended location is outside both working trees. A state export contains
> every resource's inputs and outputs.

---

## 3. Create the destination stack

The destination must exist before anything can be moved into it.

```bash
cd ~/branchLeft/shared-infra

pulumi stack init production \
  --secrets-provider="gcpkms://projects/branchleft-prod/locations/europe-west1/keyRings/pulumi/cryptoKeys/pulumi-secrets"
```

This is _expected_ to write an `encryptedkey:` line into
`Pulumi.production.yaml`. That line is a KMS-wrapped per-stack data key, not key
material — it is safe to commit, and `website/infra/Pulumi.production.yaml`
already commits its equivalent.

### Gate 3a — `encryptedkey:` actually landed

**Unverified assumption, so check it rather than assume it.** The committed
`Pulumi.production.yaml` already declares `secretsprovider:` but deliberately
carries no `encryptedkey:`. Whether `pulumi stack init --secrets-provider=...`
fills in the missing key on a file that already names the provider was **not
confirmed before writing this runbook** — doing so would have required running
`stack init`, which was out of scope. Treat the following as a branch, not a
formality.

```bash
grep -c '^encryptedkey:' Pulumi.production.yaml     # want: 1
grep '^secretsprovider:' Pulumi.production.yaml     # want: the gcpkms:// URL, unchanged
```

**If the count is 1** — proceed. Commit the file in its own small PR, so a later
`pulumi stack init` on another machine does not mint a second data key.

**If the count is 0** — `stack init` did not populate it. Recover like this:

```bash
# 1. Discard the half-initialised stack. It is empty; nothing is lost.
pulumi stack rm production --force --preserve-config

# 2. Remove the pre-written provider line so --secrets-provider owns both lines.
#    (Delete the `secretsprovider:` line; leave the `config:` block alone.)
$EDITOR Pulumi.production.yaml

# 3. Re-init.
pulumi stack init production \
  --secrets-provider="gcpkms://projects/branchleft-prod/locations/europe-west1/keyRings/pulumi/cryptoKeys/pulumi-secrets"

# 4. Re-check — both lines must now be present.
grep -E '^(secretsprovider|encryptedkey):' Pulumi.production.yaml   # want: 2 lines
```

If it _still_ does not appear after step 4, stop and treat it as a real
problem rather than working around it — but note the blast radius is small:
this stack holds no secret config values at all (`Pulumi.production.yaml` has
only `gcp:project` and `region`), so nothing is encrypted, nothing can fail to
decrypt, and the state move itself does not touch secrets. The consequence of
getting this wrong is that the _first_ `pulumi config set --secret` later on
fails or mints a key nobody committed — an inconvenience, not corruption. Do
not let it block the migration if you are mid-window; note it and fix it after.

### Gate 3b — the new stack is empty and its config matches

```bash
pulumi stack ls --all -Q
# expect both:
#   organization/branchleft-website-infra/production
#   organization/branchleft-shared-infra/production

pulumi config --stack organization/branchleft-shared-infra/production
# expect: gcp:project = branchleft-prod
#         branchleft-shared-infra:region = europe-west1
```

### Gate 3c — provider parity

The moved resources reference the default GCP provider
`pulumi:providers:gcp::default_9_32_1`, whose inputs are
`{project: branchleft-prod, version: 9.32.1}`. If `shared-infra` resolves a
different provider version or a different `gcp:project`, every moved resource
shows a provider change on preview and the zero-diff gate fails.

```bash
cd ~/branchLeft/shared-infra
node -p "require('./node_modules/@pulumi/gcp/package.json').version"   # expect exactly: 9.32.1
```

`@pulumi/gcp` is pinned exactly in `package.json` for this reason. If it is not
`9.32.1`, stop and fix that before going further.

**Rollback for step 3:** `pulumi stack rm production --force` in `shared-infra`
(it is empty; nothing is lost) and `git checkout -- Pulumi.production.yaml`.

---

## 4. Freeze `website` and confirm the baseline

```bash
# Nothing in flight
gh run list --repo branchLeft/website --branch main --limit 3

# The site is up, from the edge, over both schemes
curl -sSI https://branchleft.co.uk        | head -1   # expect: HTTP/2 200
curl -sSI http://branchleft.co.uk         | head -1   # expect: HTTP/2 301
curl -sSI https://www.branchleft.co.uk    | head -1   # expect: HTTP/2 301
dig +short branchleft.co.uk A                          # expect: the edge's global IP
```

Record what you see. You are going to compare against it at step 12, and
"it looked fine before" is not a baseline.

---

## 5. Gate — `website` has no pending diff

Run a preview on the _source_ stack before touching it. If it is not clean, you
are moving state out from under an unapplied change and you will not be able to
attribute the result.

```bash
cd ~/branchLeft/website/infra
pulumi preview --stack organization/branchleft-website-infra/production
```

**Expected:** no changes, _except_ a `~ image` diff on
`gcp:cloudrunv2/service:Service::website`. That one is normal and documented in
`website/infra/KNOWN_ISSUES.md` — the local `Pulumi.production.yaml` pins
`imageTag: bootstrap-amd64-v2` while CI has deployed a git SHA.

**Do not** try to make that diff go away with `pulumi preview --config`. It
writes to `Pulumi.production.yaml` as a side effect and changes what the next
deploy rolls out. Read past it.

**Anything else — especially any delete — stop.** Investigate before
continuing.

---

## 6. The resource mapping

17 resources. The URNs below were **read from `pulumi stack export`**, not
derived from the source file — the type tokens in particular are not guessable
(`gcp:compute/uRLMap:URLMap`, lower-case `u`, is the real token).

Only the project segment of the URN changes. The stack name (`production`),
type token and logical name are all identical on both sides — which is exactly
what makes the destination program match the moved state with no diff.

| #   | GCP `name` (verified live)        | Type token                                                          | Old URN                                                                                                                                            | New URN                                                                                                                                           |
| --- | --------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `branchleft-edge-ip`              | `gcp:compute/globalAddress:GlobalAddress`                           | `urn:pulumi:production::branchleft-website-infra::gcp:compute/globalAddress:GlobalAddress::edge-ip`                                                | `urn:pulumi:production::branchleft-shared-infra::gcp:compute/globalAddress:GlobalAddress::edge-ip`                                                |
| 2   | `branchleft-edge-armor`           | `gcp:compute/securityPolicy:SecurityPolicy`                         | `urn:pulumi:production::branchleft-website-infra::gcp:compute/securityPolicy:SecurityPolicy::edge-armor`                                           | `urn:pulumi:production::branchleft-shared-infra::gcp:compute/securityPolicy:SecurityPolicy::edge-armor`                                           |
| 3   | `branchleft-edge-certs`           | `gcp:certificatemanager/certificateMap:CertificateMap`              | `urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/certificateMap:CertificateMap::edge-cert-map`                             | `urn:pulumi:production::branchleft-shared-infra::gcp:certificatemanager/certificateMap:CertificateMap::edge-cert-map`                             |
| 4   | `dns-auth-branchleft-co-uk`       | `gcp:certificatemanager/dnsAuthorization:DnsAuthorization`          | `urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/dnsAuthorization:DnsAuthorization::dns-auth-branchleft-co-uk`             | `urn:pulumi:production::branchleft-shared-infra::gcp:certificatemanager/dnsAuthorization:DnsAuthorization::dns-auth-branchleft-co-uk`             |
| 5   | `dns-auth-www-branchleft-co-uk`   | `gcp:certificatemanager/dnsAuthorization:DnsAuthorization`          | `urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/dnsAuthorization:DnsAuthorization::dns-auth-www-branchleft-co-uk`         | `urn:pulumi:production::branchleft-shared-infra::gcp:certificatemanager/dnsAuthorization:DnsAuthorization::dns-auth-www-branchleft-co-uk`         |
| 6   | `cert-branchleft-co-uk`           | `gcp:certificatemanager/certificate:Certificate`                    | `urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/certificate:Certificate::cert-branchleft-co-uk`                           | `urn:pulumi:production::branchleft-shared-infra::gcp:certificatemanager/certificate:Certificate::cert-branchleft-co-uk`                           |
| 7   | `cert-www-branchleft-co-uk`       | `gcp:certificatemanager/certificate:Certificate`                    | `urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/certificate:Certificate::cert-www-branchleft-co-uk`                       | `urn:pulumi:production::branchleft-shared-infra::gcp:certificatemanager/certificate:Certificate::cert-www-branchleft-co-uk`                       |
| 8   | `cert-entry-branchleft-co-uk`     | `gcp:certificatemanager/certificateMapEntry:CertificateMapEntry`    | `urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/certificateMapEntry:CertificateMapEntry::cert-entry-branchleft-co-uk`     | `urn:pulumi:production::branchleft-shared-infra::gcp:certificatemanager/certificateMapEntry:CertificateMapEntry::cert-entry-branchleft-co-uk`     |
| 9   | `cert-entry-www-branchleft-co-uk` | `gcp:certificatemanager/certificateMapEntry:CertificateMapEntry`    | `urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/certificateMapEntry:CertificateMapEntry::cert-entry-www-branchleft-co-uk` | `urn:pulumi:production::branchleft-shared-infra::gcp:certificatemanager/certificateMapEntry:CertificateMapEntry::cert-entry-www-branchleft-co-uk` |
| 10  | `website-neg`                     | `gcp:compute/regionNetworkEndpointGroup:RegionNetworkEndpointGroup` | `urn:pulumi:production::branchleft-website-infra::gcp:compute/regionNetworkEndpointGroup:RegionNetworkEndpointGroup::website-neg`                  | `urn:pulumi:production::branchleft-shared-infra::gcp:compute/regionNetworkEndpointGroup:RegionNetworkEndpointGroup::website-neg`                  |
| 11  | `website-backend`                 | `gcp:compute/backendService:BackendService`                         | `urn:pulumi:production::branchleft-website-infra::gcp:compute/backendService:BackendService::website-backend`                                      | `urn:pulumi:production::branchleft-shared-infra::gcp:compute/backendService:BackendService::website-backend`                                      |
| 12  | `branchleft-edge`                 | `gcp:compute/uRLMap:URLMap`                                         | `urn:pulumi:production::branchleft-website-infra::gcp:compute/uRLMap:URLMap::edge-url-map`                                                         | `urn:pulumi:production::branchleft-shared-infra::gcp:compute/uRLMap:URLMap::edge-url-map`                                                         |
| 13  | `branchleft-edge-https`           | `gcp:compute/targetHttpsProxy:TargetHttpsProxy`                     | `urn:pulumi:production::branchleft-website-infra::gcp:compute/targetHttpsProxy:TargetHttpsProxy::edge-https-proxy`                                 | `urn:pulumi:production::branchleft-shared-infra::gcp:compute/targetHttpsProxy:TargetHttpsProxy::edge-https-proxy`                                 |
| 14  | `branchleft-edge-https`           | `gcp:compute/globalForwardingRule:GlobalForwardingRule`             | `urn:pulumi:production::branchleft-website-infra::gcp:compute/globalForwardingRule:GlobalForwardingRule::edge-https-rule`                          | `urn:pulumi:production::branchleft-shared-infra::gcp:compute/globalForwardingRule:GlobalForwardingRule::edge-https-rule`                          |
| 15  | `branchleft-edge-http-redirect`   | `gcp:compute/uRLMap:URLMap`                                         | `urn:pulumi:production::branchleft-website-infra::gcp:compute/uRLMap:URLMap::edge-http-redirect`                                                   | `urn:pulumi:production::branchleft-shared-infra::gcp:compute/uRLMap:URLMap::edge-http-redirect`                                                   |
| 16  | `branchleft-edge-http`            | `gcp:compute/targetHttpProxy:TargetHttpProxy`                       | `urn:pulumi:production::branchleft-website-infra::gcp:compute/targetHttpProxy:TargetHttpProxy::edge-http-proxy`                                    | `urn:pulumi:production::branchleft-shared-infra::gcp:compute/targetHttpProxy:TargetHttpProxy::edge-http-proxy`                                    |
| 17  | `branchleft-edge-http`            | `gcp:compute/globalForwardingRule:GlobalForwardingRule`             | `urn:pulumi:production::branchleft-website-infra::gcp:compute/globalForwardingRule:GlobalForwardingRule::edge-http-rule`                           | `urn:pulumi:production::branchleft-shared-infra::gcp:compute/globalForwardingRule:GlobalForwardingRule::edge-http-rule`                           |

Rows 13/14 and 16/17 share a GCP `name` (`branchleft-edge-https`,
`branchleft-edge-http`). That is not a mistake: a target proxy and a forwarding
rule are different resource collections in the Compute API and names only have
to be unique within a collection.

### What is deliberately _not_ moved

- `gcp:cloudrunv2/service:Service::website` (`branchleft-website`) — the
  marketing site's own Cloud Run service. Stays in `website`. `website-neg`
  currently records a dependency on it; the move severs that (see step 8) and
  the new program replaces it with the plain string `'branchleft-website'`.
- The 12 `gcp:projects/service:Service::api-*` resources. They stay owned by
  `website/infra/apis.ts`. `shared-infra` deliberately does not declare them —
  declaring them would put two stacks in charge of one real resource _and_
  would make step 9's preview show 12 creates instead of zero changes.
- `gcp:projects/iAMMember::deployer-load-balancer-admin`,
  `deployer-compute-security-admin`, `deployer-certificate-manager-owner`.
  These grant `github-actions-deployer` the roles the edge needs. `shared-infra`
  has no CI deploy, so nothing here needs them today. Leaving them where they
  are is a deliberate deferral, not an oversight — moving project-level IAM for
  the deploy identity has its own bootstrap trap
  (`website/infra/KNOWN_ISSUES.md`).

---

## 7. Mechanism — `pulumi state move`, and why not `pulumi import`

**Recommendation: `pulumi state move`.** Not a preference; the two options fail
differently and only one of them can fail into an outage.

### Option A — `pulumi state move` (recommended)

One command. Pulumi lifts the resources' state records out of the source
snapshot and writes them into the destination snapshot, rewriting the project
segment of each URN and carrying the provider reference across.

- **It never calls the GCP API.** Not to read, not to write. No GCP resource can
  be created, modified or deleted by this command, whatever happens.
- **Worst realistic failure:** the process dies between writing the destination
  snapshot and rewriting the source, leaving the resources recorded in _both_
  stacks. That is inert — the source stack's `pulumi up` is frozen (§0) and no
  apply happens until you run one. Fixed by restoring both stacks from the
  step-2 exports.
- **Recovery is state-only**, which means recovery is also incapable of touching
  the live edge.
- It preserves the recorded _inputs_, so the destination stack's preview
  compares the new program against the same values `website` last applied.

### Option B — `pulumi import` into the new stack, then `retainOnDelete: true` in the old one

The mechanics: import all 17 resources into `shared-infra` by GCP ID; add
`retainOnDelete: true` to every one of them in `website/infra/edge.ts`; run
`pulumi up` on `website` to record that flag in state; then delete the code and
run `pulumi up` again, which drops them from state without deleting them.

Rejected, for three reasons in increasing order of seriousness:

1. **It needs 17 hand-written import IDs**, each in a provider-specific format
   (`projects/.../global/urlMaps/...` vs `.../regions/.../networkEndpointGroups/...`
   vs Certificate Manager's own paths). A wrong ID either errors or silently
   imports a different resource.
2. **It imports from live, not from state.** Whatever has drifted comes across
   as truth — see [appendix A](#appendix-a--live-vs-state-drift-on-branchleft-edge-armor);
   there _is_ drift on this edge. That is arguably a feature, but it means the
   post-import preview shows a real diff and you lose the zero-diff signal that
   the whole procedure is verified by.
3. **It requires two `pulumi up` runs against the production edge**, and the
   safety of the second one rests entirely on `retainOnDelete: true` being
   present and correct on all 17 resources. Miss one — or typo it, or let a
   rebase drop it — and that resource is **deleted**. If it is
   `branchleft-edge-ip`, the anycast address is gone for good and recovery
   needs a DNS change plus a full TTL. Option B's failure mode is the same
   catastrophe §0 exists to prevent, just reached through a different door.

**Summary:** Option A cannot delete a production resource because it cannot
reach the GCP API. Option B's correctness depends on a boolean being right
seventeen times on a program that CI applies automatically. Take Option A.

_Option B remains the right tool for a different job_ — adopting a resource
that Pulumi has never managed. That is not this.

---

## 8. Expect these warnings, and know which one is a problem

`pulumi state move` drops dependency edges that point at resources staying
behind, and prints a warning for each.

**Exactly four of the seventeen carry such edges — not all of them.** Only the
four `createEdge` call sites that passed `{ dependsOn: enabledApis }` recorded
them; the other thirteen resources have no outward edges at all. Counted from
`pulumi stack export`:

| Resource        | → `api-*` (12 each) | → `cloudrunv2 Service::website` |
| --------------- | ------------------- | ------------------------------- |
| `edge-ip`       | 12                  | —                               |
| `edge-armor`    | 12                  | —                               |
| `edge-cert-map` | 12                  | —                               |
| `website-neg`   | 12                  | 1                               |
| _the other 13_  | **0**               | —                               |

**Total severed: 49 edges — 48 to the API services, 1 to the Cloud Run
service.** All are expected and correct: the destination program declares no
`dependsOn` on API resources (§6, "what is deliberately not moved") and takes
the Cloud Run service as a plain string, precisely so that the state after the
move and the program agree.

The 16 edges _within_ the moved set are preserved, and are still generated by
the new program from data flow:

| Resource                                                                                    | Preserved dependencies                       |
| ------------------------------------------------------------------------------------------- | -------------------------------------------- |
| `website-backend`                                                                           | `edge-armor`, `website-neg`                  |
| `edge-url-map`                                                                              | `website-backend`                            |
| `edge-https-proxy`                                                                          | `edge-cert-map`, `edge-url-map`              |
| `edge-https-rule`                                                                           | `edge-ip`, `edge-https-proxy`                |
| `edge-http-proxy`                                                                           | `edge-http-redirect`                         |
| `edge-http-rule`                                                                            | `edge-ip`, `edge-http-proxy`                 |
| `cert-branchleft-co-uk`                                                                     | `dns-auth-branchleft-co-uk`                  |
| `cert-www-branchleft-co-uk`                                                                 | `dns-auth-www-branchleft-co-uk`              |
| `cert-entry-branchleft-co-uk`                                                               | `cert-branchleft-co-uk`, `edge-cert-map`     |
| `cert-entry-www-branchleft-co-uk`                                                           | `cert-www-branchleft-co-uk`, `edge-cert-map` |
| `edge-ip`, `edge-armor`, `edge-cert-map`, `website-neg`, `edge-http-redirect`, `dns-auth-*` | none                                         |

**How to read the warning output:** every severed edge named must have
`api-<something>.googleapis.com` or `cloudrunv2/service:Service::website` on
the _far_ side, and one of `edge-ip`, `edge-armor`, `edge-cert-map`,
`website-neg` on the near side. A warning naming any other pair — in
particular any near-side resource outside those four — means the mapping is
wrong. Answer `no` at the confirmation prompt and stop.

---

## 9. Dry run — the move, without `--yes`

`pulumi state move` prints the full plan and prompts before writing anything.
Run it interactively. **Read the plan. Do not pass `-y`.**

```bash
cd ~/branchLeft/shared-infra

pulumi state move \
  --source organization/branchleft-website-infra/production \
  --dest   organization/branchleft-shared-infra/production \
  'urn:pulumi:production::branchleft-website-infra::gcp:compute/globalAddress:GlobalAddress::edge-ip' \
  'urn:pulumi:production::branchleft-website-infra::gcp:compute/securityPolicy:SecurityPolicy::edge-armor' \
  'urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/certificateMap:CertificateMap::edge-cert-map' \
  'urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/dnsAuthorization:DnsAuthorization::dns-auth-branchleft-co-uk' \
  'urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/dnsAuthorization:DnsAuthorization::dns-auth-www-branchleft-co-uk' \
  'urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/certificate:Certificate::cert-branchleft-co-uk' \
  'urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/certificate:Certificate::cert-www-branchleft-co-uk' \
  'urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/certificateMapEntry:CertificateMapEntry::cert-entry-branchleft-co-uk' \
  'urn:pulumi:production::branchleft-website-infra::gcp:certificatemanager/certificateMapEntry:CertificateMapEntry::cert-entry-www-branchleft-co-uk' \
  'urn:pulumi:production::branchleft-website-infra::gcp:compute/regionNetworkEndpointGroup:RegionNetworkEndpointGroup::website-neg' \
  'urn:pulumi:production::branchleft-website-infra::gcp:compute/backendService:BackendService::website-backend' \
  'urn:pulumi:production::branchleft-website-infra::gcp:compute/uRLMap:URLMap::edge-url-map' \
  'urn:pulumi:production::branchleft-website-infra::gcp:compute/targetHttpsProxy:TargetHttpsProxy::edge-https-proxy' \
  'urn:pulumi:production::branchleft-website-infra::gcp:compute/globalForwardingRule:GlobalForwardingRule::edge-https-rule' \
  'urn:pulumi:production::branchleft-website-infra::gcp:compute/uRLMap:URLMap::edge-http-redirect' \
  'urn:pulumi:production::branchleft-website-infra::gcp:compute/targetHttpProxy:TargetHttpProxy::edge-http-proxy' \
  'urn:pulumi:production::branchleft-website-infra::gcp:compute/globalForwardingRule:GlobalForwardingRule::edge-http-rule'
```

Notes on the invocation, from `pulumi state move --help` on v3.255.0:

- The only flags are `--source`, `--dest`, `--include-parents` and `-y/--yes`.
  There is **no** `--dry-run`; the interactive prompt is the dry run.
- **Do not pass `--include-parents`.** Every one of these 17 resources has the
  stack resource itself as its parent (confirmed from `pulumi stack export`),
  so there is nothing useful to include, and the flag would pull the source
  stack's root resource across.
- Both stack names are **fully qualified** (`organization/<project>/<stack>`).
  Both stacks are named `production`; a bare `production` would be resolved
  against whichever project the current directory's `Pulumi.yaml` names, which
  is a coin-flip you should not take with production state.
- Single quotes around every URN. They contain `:` and `/`; leaving them
  unquoted invites shell surprises.

**Answer `no` at the prompt.** Confirm against §8 that the plan is 17 resources
and that the severed-dependency warnings match. Then run it again and answer
`yes`.

---

## 10. Execute the move

Re-run the exact command from step 9 and answer `yes`.

Immediately confirm the counts:

```bash
pulumi stack ls --all -Q
# The source must drop by exactly 17: 62 -> 45.
# The destination must hold those 17 plus the copied default GCP provider.
```

The exact destination number depends on whether the copied
`pulumi:providers:gcp::default_9_32_1` resource is counted in that column — do
not treat 17-vs-18 as a failure on its own. **The count that must be exact is
the source's: 62 → 45.** The authoritative check on the destination is gate
11a, not a number.

The source keeps its own copy of the provider for the 45 resources still there;
providers are copied, not moved.

For a precise list of what landed where:

```bash
pulumi stack export --cwd ~/branchLeft/shared-infra \
  --stack organization/branchleft-shared-infra/production \
  | python3 -c 'import json,sys; [print(r["urn"]) for r in json.load(sys.stdin)["deployment"]["resources"]]'
```

### Rollback for step 10

```bash
# Source stack back to 62 resources
pulumi stack import --cwd ~/branchLeft/website/infra \
  --stack organization/branchleft-website-infra/production \
  --file ~/edge-move-backups/website-infra-production.$TS.json

# Destination stack discarded. `--force` here means "remove the stack record,
# leave the cloud resources alone" — which is exactly right: the GCP resources
# are real, in use, and about to be back under the source stack's state.
# `--preserve-config` keeps the committed Pulumi.production.yaml on disk.
pulumi stack rm organization/branchleft-shared-infra/production \
  --force --preserve-config
```

Both are state-only. Neither touches GCP. The live edge is unaffected by the
move _and_ by its rollback — that is the property this mechanism was chosen
for.

---

## 11. Gates — before the website code removal merges

Both must pass. This is the point of no easy return: once the website PR
merges, its `pulumi up` runs.

### Gate 11a — `shared-infra` preview shows **zero changes**

```bash
cd ~/branchLeft/shared-infra
pulumi preview --stack organization/branchleft-shared-infra/production
```

**Required: no create, update, delete or replace of any kind. Everything
unchanged.**

This is the single most informative check in the runbook. Zero changes means
the new program's resource names, logical names, types, provider and every
input match the state that was just moved — i.e. the extraction reproduced the
edge exactly rather than approximately.

If it is not zero:

- **Creates** → a logical name or type does not match the moved URN. Compare
  against the table in §6.
- **Updates** → an input differs. Read the diff; it names the field.
- **Provider changes on everything** → `@pulumi/gcp` is not 9.32.1 (gate 3c).
- **Deletes** → something moved that the program does not declare. Stop.

Do not "fix" a non-zero preview by running `pulumi up`. Roll back (§10), fix
the code, and repeat.

### Gate 11b — `website-infra` preview shows **zero deletions**

```bash
cd ~/branchLeft/website/infra
pulumi preview --stack organization/branchleft-website-infra/production
```

At this point `website`'s code still declares the edge but its state no longer
holds it, so this preview will show **17 creates** and the familiar `~ image`
diff. That is expected and is exactly why the website removal PR must merge
next and nothing else may merge in between.

**The requirement is `- delete: 0`.** A delete here means the state move took
something it should not have. Roll back immediately.

> If you need to hold at this point for any length of time, roll back (§10)
> rather than sitting in the window. The window is safe against automation
> failing loudly; it is not safe against a person deciding to "just merge this
> small thing".

### Gate 11c — production is still serving

Re-run the step-4 curls. Nothing should have changed — no GCP API call has been
made by anything in this runbook so far.

```bash
curl -sSI https://branchleft.co.uk | head -1        # HTTP/2 200
curl -sSI https://www.branchleft.co.uk | head -1    # HTTP/2 301
```

---

## 12. Hand over to the website-side removal

Unblock the website PR (undraft / remove the label) and merge it. Watch the
deploy:

```bash
gh run watch --repo branchLeft/website
```

**Expected:** `pulumi up` shows 17 deletes _from state only_ — Pulumi deletes
nothing in GCP because the resources are no longer in this stack's state; it
simply stops declaring them. Resource count drops to 45 and stays there.

**If the deploy tries to delete GCP resources**, the state move did not take
effect on the source stack. Cancel the run immediately
(`gh run cancel --repo branchLeft/website <id>`) and restore the source stack
from the step-2 export before anything else.

Then verify the edge end to end, from GCP rather than from Pulumi:

```bash
gcloud compute forwarding-rules list --global --project=branchleft-prod \
  --format="table(name,IPAddress,portRange)"
gcloud compute url-maps list --project=branchleft-prod
gcloud certificate-manager maps entries list --map=branchleft-edge-certs \
  --project=branchleft-prod --format="table(name,hostname,state)"

curl -sSI https://branchleft.co.uk | head -1
dig +short branchleft.co.uk A       # still the edge's global IP
```

Lift the merge freeze. **The migration is complete here.**

One follow-up, on a separate day and as its own change: the pre-existing Cloud
Armor drift in [appendix A](#appendix-a--live-vs-state-drift-on-branchleft-edge-armor).
Do not start it in the same session — it is the first live production write
this repo makes, it needs its own change window, and there is no urgency (every
affected rule is in preview mode). A.3 sets out why it is sequenced here rather
than earlier.

### Rollback for step 12

Once the website deploy has completed, rollback is no longer state-only, and it
is genuinely harder than everything before it. Prefer forward fixes.

1. Revert the website removal commit on `main` and let CI redeploy. That
   restores the _code_, but its `pulumi up` will now try to **create** the edge
   resources, which already exist → 409 `alreadyExists`, red build, site up.
2. To actually put the resources back under `website`'s stack, run the step-9
   command with `--source` and `--dest` swapped and the URNs rewritten to the
   `branchleft-shared-infra` project segment (column 5 of the §6 table).
3. Then `pulumi stack rm organization/branchleft-shared-infra/production --force
--preserve-config`.

At no point in that sequence is the live edge deleted, which is the only
guarantee that matters.

---

## Appendix A — live-vs-state drift on `branchleft-edge-armor`

**Found 2026-08-04 while verifying resource names for this migration. It
predates this work, is not caused by it, and is not fixed by it.**

The deployed Cloud Armor policy does not match either the source code or the
Pulumi state.

`edge.ts` declares, and `website-infra/production` state records, four WAF
rules:

| Priority | Declared / in state |
| -------- | ------------------- |
| 1000     | `sqli-v33-stable`   |
| 1001     | `xss-v33-stable`    |
| 1002     | `rce-v33-stable`    |
| 1003     | `lfi-v33-stable`    |

`gcloud compute security-policies describe branchleft-edge-armor` returns:

| Priority | Actually deployed                       |
| -------- | --------------------------------------- |
| 1000     | `sqli-v33-stable`                       |
| 1001     | `sqli-v33-stable` ← duplicate           |
| 1002     | `xss-v33-stable`                        |
| 1003     | `rce-v33-stable`                        |
| —        | **`lfi-v33-stable` is absent entirely** |

The rate limit (200 req/60s, `enforceOnKey: IP`), the priority-2000 placement
and the default-allow rule are all correct and match. Every rule is
`preview: true` on both sides.

**Probable cause.** The rate-limit rule used to sit at priority 1000, with the
WAF rules at 1001–1004. Reordering them (the change whose reasoning is recorded
in the big comment in `edge.ts`) rewrote every priority. The provider applies
security-policy rule changes as independent per-priority API calls, and the
observable result is exactly what you would get if the patch at 1000 and the
delete at 1004 succeeded while the patches at 1001–1003 did not: each of those
priorities still holds its _old_ content, shifted one place, and the rule that
used to live at 1004 (`lfi`) is gone. This is consistent with a partial apply,
not with anyone editing the policy by hand.

**Impact.** Low but not nil. Every rule is in preview mode, so nothing is being
blocked or throttled either way and no visitor is affected. What is affected is
the _logging_: LFI attempts have never been evaluated, and the "23h of traffic
showed zero WAF hits" observation that informed the rate-limit tuning was made
against a policy that was missing a quarter of its WAF coverage and
double-counting SQLi. Treat that observation as weaker evidence than it reads.

**Why it does not block this migration.** `pulumi preview` compares the program
against _state_, and program and state agree. So gate 11a will show zero
changes — correctly, on its own terms — while the live policy still differs.
The gate proves the extraction is faithful; it does not prove the edge matches
the code, and it was never capable of proving that.

### A.1 Why a plain `pulumi up` will _not_ fix this

This is the trap, and an earlier draft of this runbook fell into it. Written
out so nobody repeats it:

**`pulumi up` does not refresh by default.** It diffs the program against the
last recorded _checkpoint_, not against live infrastructure. The checkpoint for
`edge-armor` already records the four correct rules — sqli/xss/rce/lfi at
1000–1003 — byte-identical to what the program declares. So a plain
`pulumi up` computes **zero changes and does nothing**, reports success, and
leaves the duplicate `sqli` and the missing `lfi` live indefinitely. No error,
no warning.

**`pulumi refresh --preview-only` does not fix it either.** From
`pulumi refresh --help` on v3.255.0:

```text
--preview-only    Only show a preview of the refresh, but don't perform the
                  refresh itself
```

It shows you the drift and writes nothing. Useful as a _look_; useless as a
_fix_. Running it and then a bare `pulumi up` — which is what an earlier draft
of this document told you to do — is two no-ops in a row that read as a
successful remediation.

The relevant flag on `up` and `preview`, from their `--help`:

```text
-r, --refresh string[="true"]   Refresh the state of the stack's resources
                                before this update
```

So the fix requires the checkpoint to be brought in line with live _first_, by
a refresh that actually performs the refresh.

### A.2 The remediation, with a gate on every step

Run this **after** the migration (see A.3), as its own change, in its own
window. It is the first thing this repo ever applies to production, and unlike
everything else in this runbook it **does** call the GCP API and **does** write
to a live Cloud Armor policy. Take a fresh `pulumi stack export` of
`shared-infra/production` first, per step 2.

```bash
cd ~/branchLeft/shared-infra
export ARMOR='urn:pulumi:production::branchleft-shared-infra::gcp:compute/securityPolicy:SecurityPolicy::edge-armor'
export S=organization/branchleft-shared-infra/production
```

**Step 0 — save the assertion.** The same check is used before and after, so
write it to a file once. It exits non-zero on any problem.

```bash
cat > /tmp/assert-armor.py <<'PY'
import json, sys
doc = json.load(sys.stdin)
if isinstance(doc, list):        # `describe --format=json` wraps in a list
    doc = doc[0]
rules = doc["rules"]
want = {1000: "sqli-v33-stable", 1001: "xss-v33-stable",
        1002: "rce-v33-stable", 1003: "lfi-v33-stable"}
got = {r["priority"]: r for r in rules}
fail = []
for p, ruleset in want.items():
    r = got.get(p)
    desc = (r or {}).get("description", "")
    if r is None:
        fail.append("priority %d: MISSING (want %s)" % (p, ruleset))
    elif ruleset not in desc:
        fail.append("priority %d: is %r, want %s" % (p, desc, ruleset))
    elif r.get("preview") is not True:
        fail.append("priority %d: preview=%r, MUST be true" % (p, r.get("preview")))
rl = got.get(2000)
if rl is None or rl.get("preview") is not True:
    fail.append("priority 2000 rate limit: missing, or not preview:true")
dflt = got.get(2147483647)
if dflt is None or dflt.get("action") != "allow":
    fail.append("default-allow rule at 2147483647: missing or wrong action")
if len(rules) != 6:
    fail.append("expected exactly 6 rules, found %d" % len(rules))
if fail:
    print("FAIL:")
    for f in fail:
        print("  - " + f)
    sys.exit(1)
print("PASS: sqli/xss/rce/lfi at 1000-1003, each once, all preview:true; "
      "rate limit at 2000 preview:true; default allow at 2147483647.")
PY
```

**Step 1 — record live truth, from GCP, not from Pulumi.**

```bash
gcloud compute security-policies describe branchleft-edge-armor \
  --project=branchleft-prod --format=json | python3 /tmp/assert-armor.py
```

**Expect it to FAIL**, with exactly this — it is the output this check produced
against the live policy on 2026-08-04:

```text
FAIL:
  - priority 1001: is 'OWASP preconfigured: sqli-v33-stable (sensitivity 1)', want xss-v33-stable
  - priority 1002: is 'OWASP preconfigured: xss-v33-stable (sensitivity 1)', want rce-v33-stable
  - priority 1003: is 'OWASP preconfigured: rce-v33-stable (sensitivity 1)', want lfi-v33-stable
```

If it **passes**, someone has already fixed the drift — stop here and re-derive
before changing anything. If it fails _differently_, the policy has moved again
since this was written; investigate before proceeding.

Note the rule _count_ is 6 either way — the duplicate `sqli` masks the missing
`lfi`. A count check alone would have passed. That is why the assertion is
per-priority.

**Step 2 — see what a refresh would adopt, writing nothing.**

```bash
pulumi refresh --stack "$S" --target "$ARMOR" --diff --preview-only
```

Expect exactly one resource, `edge-armor`, with the rules array changing from
the correct four to the deployed broken five. **Zero here means the drift is
not what this appendix describes — stop and re-investigate.** Note `--target`
scopes this to the one resource, so a surprise elsewhere in the stack cannot
be silently swept in.

**Step 3 — perform the refresh.** State now records reality, which is the
whole point.

```bash
pulumi refresh --stack "$S" --target "$ARMOR" --diff
# answer: yes
```

This is a state write, not a cloud write. Nothing in GCP changes.

**Step 4 — gate: the drift is now visible to `preview`.**

```bash
pulumi preview --stack "$S" --target "$ARMOR" --diff
```

**Required: exactly one update, to `edge-armor`, restoring `lfi-v33-stable` at
1003 and removing the duplicate `sqli` at 1001.** If this shows zero changes,
step 3 did not take — do not proceed to step 5, and do not "fix" it with an
untargeted `pulumi up`.

**Step 5 — apply.** This is the live production write.

```bash
pulumi up --stack "$S" --target "$ARMOR"
```

**Step 6 — gate: assert the fix landed, from GCP.** A remediation with no
assertion is exactly how the original defect survived a clean `pulumi up`. This
is the same command as step 1; it must now report `PASS`.

```bash
gcloud compute security-policies describe branchleft-edge-armor \
  --project=branchleft-prod --format=json | python3 /tmp/assert-armor.py
echo "exit=$?"      # must be 0
```

The assertion covers all four failure modes that matter: `lfi-v33-stable`
present at 1003, no duplicate ruleset, exactly six rules, and — the one worth
being loudest about — **`preview: true` on every WAF rule and on the rate
limiter.** If any comes back `preview: false`, that is an enforcing rule on
live traffic: revert immediately (restore state from the export taken before
step 1, then re-apply).

For a human-readable view alongside the assertion:

```bash
gcloud compute security-policies describe branchleft-edge-armor \
  --project=branchleft-prod --format=yaml \
  | grep -E '^  (priority|preview|description):'
```

Note the separator in `--format="value(rules[].description)"` is a **semicolon**,
not a comma, if you would rather split that output by hand
(`| tr ';' '\n' | sort`).

**Step 7 — spot-check the site still serves.** The rules are all preview-mode,
so this should be a formality — but it is a live Cloud Armor change and the
formality is cheap.

```bash
curl -sSI https://branchleft.co.uk | head -1    # HTTP/2 200
```

**Rollback:** `pulumi stack import` the pre-remediation export, then re-run
step 5's `pulumi up --target "$ARMOR"` to push the intended rules again. The
policy is preview-mode throughout, so no rollback path here can affect a
visitor.

### A.3 Sequencing — re-derived: still _after_ the move

The original recommendation was made on the assumption that the fix was two
clean commands. That assumption was wrong (A.1), so the sequencing has been
re-derived from scratch. **The conclusion is unchanged, and the new information
strengthens it rather than weakening it.**

Fixing _before_ the move would mean applying it in the
`branchleft-website-infra` stack. Three reasons not to:

1. **It would destroy this runbook's single best property.** As written, steps
   1–12 make no GCP API call at all: `state move`, `stack export` and
   `stack import` are pure state operations, so no sequence of mistakes inside
   the migration window can alter a live resource. Inserting a live production
   write into that window trades that guarantee away for something with no
   urgency attached to it.
2. **It would mean running `pulumi up` locally in `website/infra`**, which is
   independently forbidden: that stack pins `imageTag: bootstrap-amd64-v2`
   locally, so a local apply rolls production back to the bootstrap image. A
   `--target`ed up would technically dodge it, but "one flag stands between you
   and rolling production back" is precisely the situation that prohibition
   exists to prevent — and it would be run mid-migration, under time pressure.
3. **The remediation is bigger than it looked, not smaller.** It is now seven
   steps with six gates, a state write and a cloud write. Discovering that a
   remediation is more involved than assumed is an argument for giving it its
   own window, not for bolting it onto a migration.

Against that, the only argument for going first is that the drift is
pre-existing and it feels untidy to migrate a known-wrong resource. That is an
aesthetic preference, and it costs a hard safety property. **Every rule is
`preview: true`: nothing is blocked or throttled either way, and no visitor is
affected by this drift for as long as it persists.** There is no urgency to
trade anything for.

**Recommendation: complete the migration first, lift the merge freeze, confirm
the site is healthy, then run A.2 as a separate change on a separate day.**
The platform owner decides.

### A.4 What gate 11a can and cannot tell you

Worth stating plainly, because this drift is the counter-example. Gate 11a's
zero-diff preview proves **the extraction is faithful to the state that was
moved**. It does not prove the live edge matches the code, and it never could —
`preview` compares program to checkpoint, and here the checkpoint and the
program agree with each other while both differ from reality.

A zero-diff preview is therefore necessary and not sufficient. The independent
check is `gcloud`, which is why step 12 verifies the edge from GCP rather than
from Pulumi. If you want a drift audit across the whole stack after the
migration, this is read-only and writes nothing:

```bash
pulumi refresh --stack organization/branchleft-shared-infra/production \
  --diff --preview-only
```

Expect `edge-armor` and nothing else. Anything further is new information and
wants investigating before it is reconciled.

### A.5 The generalisable lesson

Alongside the existing entries in `website/infra/KNOWN_ISSUES.md`:

- A `gcp.compute.SecurityPolicy`'s `rules` array **is not applied atomically**,
  and a change that renumbers priorities is a change to _every_ rule at or
  after the renumber point. Prefer appending rules to inserting them.
- **A clean `pulumi up` is not evidence that the resulting policy is what the
  code says** — it is evidence that the checkpoint says what the code says.
  Those are different claims, and this incident is the gap between them.
- Verify Cloud Armor rule changes with
  `gcloud compute security-policies describe`, every time. State is not a
  substitute for looking.

### Outcome

Steps 1–12 ran clean: zero-diff gates passed both sides, no GCP resource was
created, modified or deleted by the move itself. Two things worth recording
for whoever next writes a runbook like this:

- **`pulumi stack init` overwrites `Pulumi.<stack>.yaml` wholesale, not
  merges.** Running it against the pre-committed file (which already declared
  `config:` and `secretsprovider:`) discarded both. Recovered with
  `pulumi config set`, which writes back through the CLI's own serializer
  rather than by hand. Worth a line in step 3 for the next person.
- **A.2's `pulumi refresh --diff --preview-only` did not detect the
  documented drift at all** (reported `1 unchanged`) — a real limitation of
  the provider's refresh for `gcp.compute.SecurityPolicy.rules`, not a
  procedural mistake. `pulumi refresh` proper had the same blind spot: it ran,
  reported no change, and left state exactly as it was — the drift stayed
  invisible to every Pulumi-side check. The remediation that actually worked
  went around Pulumi entirely: three `gcloud compute security-policies rules
update` calls to bring live GCP into line with what Pulumi's state and
  program already (correctly) declared, verified with A.2 step 0's assertion
  script against live `gcloud` output, not against a Pulumi diff. No `pulumi
up` was needed or run for the remediation.
