# Cloud Armor parity baseline (superseded configuration)

**The GCP edge this describes is being wound down**, in favour of a Hetzner VM
running Caddy and CrowdSec. This file is the parity artifact for that cutover:
a captured snapshot of the `branchleft-edge-armor` Cloud Armor policy, kept
alongside the code so a re-capture diffs cleanly against it, and so the
replacement edge's rule families can be checked against something concrete
rather than against a memory of what GCP was doing.

Parity is checked against a capture rather than against `edge.ts` or Pulumi
state deliberately. `pulumi preview` compares the program to the last recorded
checkpoint, and this repository already has one documented incident
(`RUNBOOK-edge-state-move.md` appendix A) where the checkpoint, the code and
the deployed policy all disagreed while every Pulumi-side check reported
clean. A snapshot taken from the API is the only artifact that answers "what
was this thing actually configured to do".

Nothing here should be read as a description of what any policy is doing
today. It is a dated capture of a configuration on its way out.

## Status of this capture

**Captured 2026-08-16**, project `branchleft-prod`, via the four commands in
"Reproducing this capture" below. `export` and `describe` were both read and
agree byte-for-byte once the volatile per-read fields are stripped — the
independent-second-read check this doc calls for turned up no discrepancy
between the two GCP code paths.

One practical note for anyone re-running it: an automated session can hit a
`gcloud` OAuth reauth wall, where every read fails with "Reauthentication
failed: cannot prompt during non-interactive execution". The fix is a
browser-interactive `gcloud auth login` from a human session first.

## What it covers

- **Project:** `branchleft-prod`
- **Policy:** `branchleft-edge-armor` (global `compute.SecurityPolicy`,
  declared in `edge.ts` as `edge-armor`) — the single shared Cloud Armor
  policy in front of every site behind the branchLeft edge load balancer.
- **Scope:** this is the only Cloud Armor policy in the project. There is no
  per-region or per-site policy to separately capture (`edge.ts`'s own
  comment: per-site policies were rejected as $5/mo each and host-scoped
  rules within one policy were chosen instead).

## Reproducing this capture

Read-only throughout — `list`, `describe` and `export` only, no mutating
verb.

```bash
# 0. A scratch directory outside the repo tree for the two intermediates
#    the normalizer needs as input. They hold an unguarded raw read -- if
#    the live policy ever does carry a person/tenant-identifying address,
#    these are where it appears before the normalizer's guard has had a
#    chance to refuse it, so they must never be somewhere `git add` can
#    reach them by accident. `cloud-armor-baseline/*.raw.json` and
#    `*.list.json` are also gitignored as a second layer, but a scratch dir
#    outside the tree is the actual control, not the advisory one.
scratch=$(mktemp -d)

# 1. Confirm there is exactly one policy in the project, and its name.
gcloud compute security-policies list \
  --project=branchleft-prod --format=json \
  > "$scratch/branchleft-edge-armor.list.json"

# 2. Canonical export — the format this artifact is committed in.
gcloud compute security-policies export branchleft-edge-armor \
  --project=branchleft-prod --global \
  --file-name="$scratch/branchleft-edge-armor.raw.json" \
  --file-format=json

# 3. describe as a second, independently-shaped read of the same policy —
#    export and describe have different GCP code paths, and this repo's
#    own incident history (RUNBOOK-edge-state-move.md appendix A) is a case
#    where trusting one read method alone would have been reasonable and
#    wrong. Keep both raw responses if they disagree; that disagreement is
#    itself a finding. This one *is* committed as-is (see below), because it
#    is read-only cross-check evidence, not an unguarded intermediate.
gcloud compute security-policies describe branchleft-edge-armor \
  --project=branchleft-prod --global --format=json \
  > cloud-armor-baseline/branchleft-edge-armor.describe.json

# 4. Normalize the export into the committed, diffable form. Strips fields
#    GCP rewrites on every read (id, fingerprint, creationTimestamp,
#    selfLink, kind, labelFingerprint), sorts rules by priority, and refuses
#    to write anything (exit 1) if any string field anywhere in the policy
#    or a rule -- not a fixed list of "the fields an IP usually lives in" --
#    contains an IP/CIDR other than the wildcard `*`, in any notation
#    (dotted-quad, compressed or IPv4-mapped IPv6, CIDR of either). See
#    "Redaction" below. Also exits non-zero (not a warning) if it cannot run
#    prettier on its own output -- an unformatted file would diff against
#    the committed baseline as if the policy had drifted, when nothing
#    actually changed.
python3 scripts/normalize-cloud-armor-baseline.py \
  "$scratch/branchleft-edge-armor.raw.json" \
  cloud-armor-baseline/branchleft-edge-armor.normalized.json

rm -rf "$scratch"
```

A freshly normalized file diffs byte-identical against the committed
`branchleft-edge-armor.normalized.json` on an unchanged policy -- verified by
running this exact sequence against live during this capture, and the
normalizer now refuses to exit 0 if that claim would be false (see step 4).

Commit `branchleft-edge-armor.normalized.json` (the diffable artifact) and
`branchleft-edge-armor.describe.json` (the independent second read, kept
as-is for cross-checking, not normalized). The `.list.json` and `.raw.json`
intermediates are scratch inputs to step 4, not part of the artifact --
`.gitignore` also blocks them under `cloud-armor-baseline/` if a future
re-capture writes them there instead of to a scratch directory.

## What "parity" means at the cutover

The cutover gate requires edge parity against this file's baseline, and
requires the replacement edge's detect-only period to have been reviewed with
remediation enabled. Concretely:

1. Re-run the four commands above against the retiring GCP policy, or against
   whatever its state was at the moment of cutover if captured earlier in the
   soak.
2. Diff the freshly normalized export against the committed
   `branchleft-edge-armor.normalized.json`. A clean diff means the live
   policy did not drift again between this capture and cutover.
3. Confirm CrowdSec's detect-only-then-remediate configuration on the new
   edge VM covers the same rule families this baseline records: the four
   OWASP-class injection rulesets (sqli/xss/rce/lfi, sensitivity 1), the
   per-IP throttle (200 req/60s, keyed on IP, 429 on exceed), and the TLS 1.2
   floor (`edge.ts`'s `TLS_PROFILE`/`TLS_MIN_VERSION` constants — Cloud
   Armor does not itself enforce a TLS minimum; that floor lives on the
   target proxy's SSL policy, a separate resource this baseline does not
   capture and CrowdSec parity does not need to reproduce, since the new
   edge sets its own TLS floor directly in Caddy).
4. Any host still carrying `injectionWafPreviewOnly` in `sites.ts` at
   cutover time needs its preview-mode exemption re-decided on the new
   stack, not silently carried over — see README.md's "Cloud Armor policy"
   section for why the exemption exists and what ends it.

### Named differences on the replacement edge

Point 3 above cannot be satisfied exactly, and the differences are recorded
here rather than glossed as "CrowdSec covers OWASP". `hetzner/edge/` is the
implementation and `hetzner/RUNBOOK-edge.md` the operation; each difference
below is a decision, not a gap left open.

**Every match ends in an IP ban, which no rule in this capture does.** This is
the difference that matters most and it is not the one the split is usually
described by. Whatever the replacement edge blocks, it also remediates: an
in-band AppSec block feeds `crowdsecurity/appsec-vpatch`, a leaky bucket at
`capacity: 1` with `remediation: true`, so a second _distinct_ in-band rule
match from one address inside its 60-second window becomes a ban for the
profile's duration. An out-of-band match feeds
`crowdsecurity/crowdsec-appsec-outofband`, `capacity: 5`, to the same end. The
rules in this capture answer `deny(403)` on the offending request and have no
IP-level consequence at all. So a visitor who trips two rules in a minute — one
`generic-*` false positive on a comment body and one on a subsequent request —
is refused every hostname on the edge for hours, where here they would have
been refused one request. Reading "in band" as "equivalent to `deny(403)`" is
the specific wrong conclusion this paragraph exists to prevent.

**The OWASP rule families are split across two evaluation modes.** CrowdSec
evaluates its virtual-patching rules in band — before the request proceeds —
and the OWASP Core Rule Set out of band, after the request has been answered.
The replacement edge takes that split rather than forcing CRS in band. So a
first CRS-class injection attempt reaches the origin with a normal response and
remediation arrives afterwards.

**Why the split, stated on the reasons that actually hold.** An in-band CRS
configuration exists on the CrowdSec hub, so this is a choice rather than a
limitation. It is not chosen for two reasons, and a third argument that reads
persuasively is false and is recorded here so it is not made again:

- **False-positive surface on an authoring surface.** CRS is a large generic
  ruleset whose injection signatures match author-written HTML, code samples
  and SQL — which is the whole reason `injectionWafPreviewOnly` exists on this
  policy. The in-band set that is used instead is `base-config` plus
  `vpatch-*` (known-CVE exploit shapes, `confidence: 3`, `spoofable: 0`) plus
  `generic-*`; none of those inspects a request body for injection shapes, so
  an in-band false positive on a Ghost admin request is implausible where a CRS
  one is expected. Combined with the ban semantics above, that is the whole
  argument.
- **Unmeasured cost.** CRS is large and the edge is a two-vCPU `cx23`. The
  verification register is explicit that this must be measured rather than
  assumed, and it cannot be measured before the edge carries traffic.
- **Not a reason: "in-band CRS bans rather than 403s".** True of
  `crowdsecurity/crs-inband`, and equally true of `crowdsecurity/appsec-default`,
  `crowdsecurity/virtual-patching` and `crowdsecurity/generic-rules` — every
  in-band AppSec configuration on the hub carries `default_remediation: ban`.
  It distinguishes nothing. **Neither option reproduces `deny(403)` with no IP
  consequence**, so the choice is not which one achieves parity; it is which
  false-positive profile is acceptable on the traffic this edge will carry.

One thing bounds how much the split gives up: every rule in this capture is
live in `preview: true`, the throttle included, so the deployed policy this
baseline records blocks nothing at all. Detect-then-ban is stronger than what is
serving traffic today and weaker than what `edge.ts` declares.

**The exemption for an authoring host narrows on three rule families and
widens on the fourth.** On this policy, `injectionWafPreviewOnly` exempts every
request to the flagged hostname from the three injection rulesets — and `lfi`
keeps enforcing across the whole host, `/ghost` included, because nothing
legitimate requests `.env`.

On the replacement edge the flag exempts one path prefix, `/ghost/api/`, which
is narrower than a whole hostname; the admin UI bundle and every other path
stay inspected. But on that prefix it removes **all** AppSec evaluation, the
`lfi` analogues (`vpatch-env-access`, the `.git` rules) included. Caddy's
AppSec handler is per-request, so there is no construction that exempts three
rule families and keeps a fourth.

The residual exposure is a filesystem-probe path that begins `/ghost/api/`,
which is not where that class of request goes — but it is a widening and it is
recorded rather than left to be found. Ending it means either a CrowdSec-side
rule exclusion scoped to the prefix, or evidence from the detect-only period
that the exemption is not needed at all.

**The throttle is evaluated before the WAF, not after.** Here the injection
rules sit at priorities 1000–1003 and the throttle at 2000. The replacement
edge reverses that: Cloud Armor evaluated on Google's edge fleet, the
replacement evaluates on two vCPUs, and a flood reaching the WAF first would
spend exactly the capacity the throttle exists to protect. The observable
difference is confined to a client that is both flooding and attacking, which
is answered 429 rather than 403.

**The TLS floor cannot be checked against this artifact at all**, as point 3
already says. On the replacement edge it is a `tls` directive in the rendered
Caddy configuration, asserted by that renderer's unit tests. Checking it
against the retiring edge means reading `edge.ts`'s constants, not diffing this
capture.

## What the capture recorded

### 1. The appendix A remediation held

`RUNBOOK-edge-state-move.md` appendix A documents a code-vs-deployed drift
found 2026-08-04: a partial Cloud Armor apply left the deployed policy holding
a duplicate `sqli` rule and missing `lfi` entirely, while Pulumi state and
`edge.ts` both correctly recorded all four. That runbook's "Outcome" section
records the remediation as executed and verified directly against `gcloud`
output — three `gcloud compute security-policies rules update` calls, not a
Pulumi apply.

**This capture confirms it held.** The captured policy carries exactly the four
WAF rules `edge.ts` declares — `sqli-v33-stable` (1000), `xss-v33-stable`
(1001), `rce-v33-stable` (1002), `lfi-v33-stable` (1003) — no duplicate, none
missing. Rule count, priorities and actions for all nine rules match the shape
`edge.ts` declares: the four base rules, three `injectionWafPreviewOnly` copies
at 1100–1102, the rate-limit rule at 2000 and the default-allow catch-all.

### 2. The capture and the code diverge on eight fields

Match expressions and `preview` flags do **not** all agree between the capture
and `edge.ts`. Eight specific field values differ, and each one is enumerated —
priority, field name, exact observed value — in
`cloud-armor-baseline/accepted-parity-failures.json`, with the reason it is
recorded and what closes it.

They fall into two groups:

- Three rules carry a match expression predating the preview-only-host
  carve-out `edge.ts` now declares, so their expressions are the pre-change
  ones. The fourth base rule takes no carve-out and matches.
- Five rules differ on `preview`, the flag that decides whether a match is
  acted on or only logged.

Both groups are consequences of the same mechanism appendix A already
documents: Cloud Armor's provider writes rules as independent per-priority API
calls, so a partial failure leaves some rules at their old values while the
checkpoint and the code both record the new ones. `pulumi preview` reports zero
changes throughout, because it compares the program to the checkpoint and never
reads the policy.

**The lesson, not the specific values, is what carries forward.** For any edge
where the control plane writes rules one at a time, a clean apply is evidence
about the checkpoint alone. Something has to read the deployed configuration
back, and this repository's answer to that is the capture-plus-parity-check
below. The replacement edge needs its own answer to the same question.

**Nothing here was remediated by the capture.** Changing a deployed security
policy is a write, outside a read-only capture's bounds however small the
change looks.

## Machine-checked parity

Both records above were only caught by reading this file's own prose against
its own committed JSON, by hand, after the fact — the first version of this
document claimed a parity its own committed capture did not show.
`scripts/assert-cloud-armor-baseline-parity.py` now checks the committed
baseline against every rule `edge.ts` declares — the four base WAF rules, the
preview-only-host copies, the rate-limit rule including its actual
threshold/key/action parameters, and the default-allow rule — plus the
policy's own `name` and `type`, and that the baseline carries no rule at a
priority `edge.ts` does not declare at all (Cloud Armor evaluates rules by
ascending priority and stops at the first match, so an undeclared rule can
silently override every declared one). A rule it cannot parse — a non-object
entry, a missing or non-integer priority, a duplicate priority — fails the
check rather than being skipped: a rule dropped from the comparison is a rule
no part of it can see.

The two records above are specific instances of what it checks, not the whole
of it. It reads only committed files — no `gcloud` call — so it is
cheap enough to run in CI on every push regardless of what changed.

**It is not a whole-policy comparison.** `adaptiveProtectionConfig` and
`advancedOptionsConfig` both affect enforcement — layer-7 DDoS auto-defence,
and the JSON body parsing that decides what the WAF rules above can see — and
neither is compared, because `edge.ts` declares neither and there is no
committed shape to compare against. Rule and policy `description` text and
the Pulumi-managed `labels` are unchecked too, but those carry no enforcement
behaviour. The script's module docstring carries the same list.

### The eight divergences are recorded, not hidden

The capture diverges from `edge.ts` on eight fields, described above. The check
finds all eight every time it runs.

They are enumerated one by one in
`cloud-armor-baseline/accepted-parity-failures.json`, each with the reason it
is accepted and what closes it, and the check exits 0 when the set it finds
is exactly the set recorded. So the job is green today — and a _ninth_
divergence, appearing tomorrow for any reason, turns it red.

That differential signal is the whole point, and a permanently red job cannot
provide it. A red X looks identical whether the cause is the eight recorded
divergences or a regression landed this morning, so the only way to tell is to
read the job log every time — which is another way of saying nobody will.
Recording the eight makes "red" mean one thing: something nobody wrote down.

The recording is deliberately hard to abuse:

- An entry names one rule priority, one field, and the **exact observed
  value**, compared by value and by type. There is no wildcard, no priority
  range and no "ignore this field" form, so an entry cannot quietly widen. If
  a recorded field diverges some _other_ way, that is a different divergence
  and it fails.
- Policy identity (`name`/`type`) and a baseline this script cannot parse can
  never be accepted — a capture of a different policy, or one whose rules are
  unreadable, answers no question about this one.
- An entry whose divergence **stops happening** fails the check until the
  entry is deleted. A stale acceptance is how a fixed problem gets silently
  re-broken months later, so removing one is a deliberate edit, made in the
  same commit as the fresh capture that closed it. The list shrinks visibly
  as remediation lands.

Because both halves of closing a divergence — a fresh capture and the deleted
entries — are edits to committed files, this check never blocks its own
remedy. That is what lets it sit in `deploy`'s `needs` alongside this repo's
other audit jobs without stopping every unrelated `mail/` and `hetzner/`
change from deploying while the recorded divergences stay open.

### What actually enforces it

What the job gates is `deploy`: it is in that job's `needs`, so a push to
`main` that fails parity does not run `pulumi up`. Whether it also gates a
merge depends on the repository's branch-protection configuration, which is
set outside this tree — read `GET /repos/<owner>/<repo>/rulesets` rather than
assuming a check listed here is required.

Locally, pre-commit runs the checker's hermetic self-test whenever
`scripts/assert-cloud-armor-baseline-parity.py` changes, and the real check
whenever a `cloud-armor-baseline/*.json` file changes — the capture and the
accepted-failures file alike. Neither hook fires on an `edge.ts` or `sites.ts`
edit, so a code change that legitimately alters the declared policy stays
locally committable rather than forcing a same-commit live GCP change or a
hurried acceptance entry. CI runs the real check on every push and PR
regardless of what changed.

Re-run "Reproducing this capture" above only _after_ a deployed change has
landed, then re-run the script and delete the entries it reports as no longer
happening. A still-red result after a fresh capture means the change did not
fully land, not that the script needs adjusting.

## Redaction

Every rule this policy declares (`edge.ts`) matches on `srcIpRanges: ['*']`
— the wildcard, not a specific range — for both the WAF rules and the rate
limit, and the capture confirms this is also true of every rule actually
live: no field of any rule names an address at all.

`normalize-cloud-armor-baseline.py` enforces this on every future capture,
and does not trust a fixed list of "the fields an IP usually lives in" to
find one: it scans **every string field of the policy and every rule, at
any nesting depth** — `config.srcIpRanges` entries, IP/CIDR literals
embedded inside a `match.expr.expression` CEL string, and free text such as
a hand-written rule or policy `description`, which is exactly where an
operator adding a one-off allowlist rule is most likely to note who or what
it is for. Detection matches IP/CIDR-shaped substrings and validates each
with Python's `ipaddress` module, so it isn't tied to one notation: IPv4,
compressed or IPv4-mapped IPv6, and CIDR forms of any of those are all
caught. It refuses to normalize (and therefore refuses to let a capture
commit) anything it finds, because a specific address anywhere in the
export can identify a person or a tenant rather than a public range, and this
capture is published. If a live capture ever does turn one
up, redact it by hand, note the redaction and the reason in a dated entry
in this file, and only then re-run the normalizer with `--redact-ips`.

**No redaction was needed or applied in this capture** — confirmed by
inspecting the raw export directly, not just by the normalizer accepting it
without the flag.
