# RUNBOOK: importing mx1 and its firewall into Pulumi

Everything in this file is gated on the platform owner: `pulumi import` and
the firewall `pulumi up` are privileged operations run by hand, from a
workstation, by the platform owner. Nothing here is executed by an agent.

Both resources were hand-provisioned in the Hetzner Cloud console, in the
production project. Read their ids from the API before starting — they are
what `pulumi import` addresses, and they are not in this repository:

```bash
hcloud server list -o 'columns=id,name'
hcloud firewall list -o 'columns=id,name'
```

**The firewall's real name is not the descriptive one the design assumed.**
Whatever the console assigned is what `firewall.ts`'s `name` must say, or the
import is not zero-diff. Renaming it afterwards is a normal, non-replacing
property update; it is deliberately not bundled into the import.

## Why this is a two-step apply, not one

`mail/firewall.ts` **as it stands on this branch** already declares the full
target rule set (22/tcp + ICMP, plus 25/443/465/587/993 tcp for mail —
443 was added after this runbook was first written, for ACME certificate
issuance; see `mail/RUNBOOK-mx1-provision.md`). Importing
against that file directly would not produce a zero-diff import, because the
firewall's live state is still 22/tcp + ICMP only — target state and current
reality are two different rule sets, and the import's whole point is to
prove the program matches reality _before_ anything changes.

So: import against the commit that matches reality, confirm zero diff, then
move to the tip of the branch and apply the rule-addition as its own
reviewed `pulumi up`.

- Baseline commit (22/tcp + ICMP only, matches `hcloud firewall describe
<the firewall> -o json` exactly)
- Rule-addition commit: the tip of `main` — adds 25/443/465/587/993 tcp on
  top of the imported baseline.

## 0. Prerequisites

```bash
cd shared-infra/mail   # or the equivalent path in your checkout
nvm use
npm ci
```

You need:

- A Hetzner Cloud API token for the production project, scoped
  read+write (import needs to _read_ the resources; the later `pulumi up`
  for the mail rules needs write). Generate one from the Hetzner Cloud
  Console → Security → API Tokens if you don't already have one for this
  project. **Never commit this token, paste it into a PR, or put it in a
  shell history file that gets synced anywhere.**
- The same GCP credentials you already use for `shared-infra`'s root stack
  (`gcloud auth application-default login`, or whatever you have configured
  today) — the secrets provider below is the same GCP KMS key ring the root
  stack uses, just a different per-stack wrapped data key.

## 1. Create the stack

> **Do not run the commands below against the live stack.** They are the
> original bootstrap record only. The live stack uses the passphrase secrets
> provider (Part A of `hetzner/RUNBOOK-existing-stack-migration.md`) and the
> Hetzner Object Storage backend pinned in `mail/Pulumi.yaml` (Part B) — not
> the GCS bucket or the KMS key ring named here.

This is a brand-new Pulumi project (`branchleft-mail`), so it has no stack
yet. Initialize one against the same state bucket and KMS key ring the root
`shared-infra` stack uses — one bucket, one key ring, to grant/revoke/audit
once rather than per-stack:

```bash
pulumi login gs://branchleft-pulumi-state
pulumi stack init production \
  --secrets-provider gcpkms://projects/branchleft-prod/locations/europe-west1/keyRings/pulumi/cryptoKeys/pulumi-secrets
```

This writes `mail/Pulumi.production.yaml` with a freshly KMS-wrapped data
key for this stack — commit it (it is ciphertext, safe in a private repo
engineered to public hygiene, same as the root stack's file).

## 2. Set the Hetzner token

Two supported ways — pick one, do not do both:

```bash
# Option A: Pulumi config, encrypted at rest via the same gcpkms provider
# as every other secret in this stack's config file.
pulumi config set --secret hcloud:token
# (prompts; paste the token, it is not echoed and not stored in shell history)

# Option B: environment variable, for this shell session only. The provider
# reads HCLOUD_TOKEN directly if no `hcloud:token` config is set.
export HCLOUD_TOKEN=...
```

Option A is the one to use if you want the token available every time you
`pulumi up` this stack without re-exporting it. Either way, the token value
never appears in this repo, in a commit, or in a PR — only its ciphertext
(Option A) or your own shell environment (Option B).

**The token also lives in CI, as the `HCLOUD_TOKEN_MAIL` repository secret.**
Doc 14 §3.5 decided that this stack applies from CI on merge to `main` —
Hetzner's API is a plain bearer token with no OIDC equivalent, and that trade
is accepted with per-project, per-pipeline token scoping as the compensating
control. The secret is scoped to the mail hcloud project alone and exposed
only to the `mail-plan`/`mail-apply` jobs in `.github/workflows/ci.yml`,
which preview, gate on `scripts/assert-no-hetzner-deletes.py`, pause for a
human to read the plan, and apply. **Steady-state applies happen on merge;
this runbook is the first-time import procedure only.** Option A/B above is
how an operator supplies the token for a hand-gated stack operation — the
value never appears in this repo, a commit, or a PR.

## 3. Import mx1 first

Order matters: `mail/firewall.ts`'s `applyTos` references `mx1.id`, so mx1
must already exist in this stack's state before the firewall import runs,
or the firewall import will try to _create_ mx1 rather than finding it
already there.

```bash
pulumi import 'hcloud:index/server:Server' mx1 <the server id>
```

`pulumi import` protects imported resources from deletion by default
(`--protect` defaults to `true`) — consistent with `server.ts` already
setting `protect: true` in code, so this isn't relied on as the only guard.

Expect this to complete with **no code changes required** — `server.ts` was
authored directly from `hcloud server describe mx1 -o json` and hasn't
changed since. If the import reports a mismatch (Pulumi will print the
actual vs. declared value for whatever differs), stop and diff the live
`hcloud server describe mx1 -o json` against `server.ts` again before
proceeding — something about mx1 changed since this runbook was written.

One field needs a specific expectation: live state shows the firewall already
attached (`public_net.firewalls` in the describe output), but `server.ts`
never sets `firewallIds` and lists it in `ignoreChanges`. A **clean** import
here shows no diff on `firewallIds` at all — Pulumi is told not to look. If
you ever see a proposed _update_ naming `firewallIds` on mx1 (here or on a
later `pulumi preview`), that means the `ignoreChanges` entry in `server.ts`
has regressed — stop, because the underlying change it would apply is
clearing mx1's only firewall attachment to `[]`.

## 4. Import the firewall — against the baseline rule set

An import is only meaningful against a program that already matches live
state, so temporarily reduce `mail/firewall.ts` to the rules the firewall
actually has right now. For a firewall created by hand in the console with
nothing but management access, that is 22/tcp and ICMP:

```bash
git stash   # or commit your work-in-progress -- whichever you'd normally do
# then edit mail/firewall.ts down to the live rule set
hcloud firewall describe <the firewall> -o json   # the authority for what that is
```

Confirm `mail/firewall.ts` now declares exactly the live rules and nothing
else, and that `git diff --stat` shows `firewall.ts` as the only file touched.
The target rules go back in at step 6, as a diff Pulumi applies rather than a
diff it imports.

```bash
pulumi import 'hcloud:index/firewall:Firewall' mail-firewall <the firewall id>
```

## 5. The zero-diff gate

```bash
pulumi preview
```

**This must report zero changes.** If it reports _any_ proposed change —
even a metadata-only one — stop. Do not proceed to step 6 with a preview
that isn't clean; find and fix the mismatch first.

**What this does and doesn't prove.** A clean `pulumi preview` here proves
the _program_ agrees with Pulumi's recorded _state_ — nothing more. It is
not itself a check against live Hetzner reality at this exact moment: state
and reality can already disagree by the time you run this, e.g. from a
console hand-edit made between the `hcloud describe` snapshot this program
was authored against and this import running. Two compensating checks, use
at least one before treating this gate as done:

- `hcloud server describe mx1 -o json` / `hcloud firewall describe
<the firewall> -o json` (already step 7, below) — reads live reality
  directly, independent of Pulumi's state.
- `pulumi refresh --preview-only` — reads live reality _through_ the
  provider and reports what a real refresh would change in state, without
  writing anything (verified against `pulumi refresh --help`: "Only show a
  preview of the refresh, but don't perform the refresh itself"). A clean
  result here means state and live reality agree too, not just program and
  state.

## 6. Move to the branch tip and apply the mail rules

```bash
git checkout feat/mail-delivery-host -- mail/firewall.ts
# or: git checkout main -- mail/firewall.ts, once this PR has merged
```

```bash
pulumi preview
```

Expect exactly five rule additions (25, 443, 465, 587, 993/tcp) and nothing
else — no change to the server, no change to the existing 22/tcp or ICMP
rules, no replace or delete of anything. (443 was added after this runbook
was first written — see `mail/RUNBOOK-mx1-provision.md`'s "The ACME
decision" for why: Stalwart's certificate issuance needs a reachable ACME
challenge, and TLS-ALPN-01 is the only challenge type that fits this host's
inbound set without a DNS-provider API IONOS doesn't have.) Read the plan.
If it matches that description:

```bash
pulumi up
```

If you ran `git stash` back in step 4, this is the point to restore it:

```bash
git stash pop
```

## 7. Confirm

```bash
pulumi preview   # zero changes again, now against the full target state
hcloud firewall describe <the firewall> -o json   # cross-check against reality directly
```

Both resources are now under Pulumi, `protect: true` on both, matching live
reality exactly.
