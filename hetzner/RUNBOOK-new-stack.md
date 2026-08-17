# Runbook — creating a new Hetzner Pulumi stack

For **new** stacks only. Moving an existing stack off `gs://` state and off
the shared GCP KMS secrets provider is a different, ordered, one-way
operation and is not this runbook.

Two things differ from every stack in this repo today, and they are
independent of each other:

- **State** lives in Hetzner Object Storage over Pulumi's S3-compatible
  backend, not in `gs://branchleft-pulumi-state`.
- **Secrets** are wrapped by Pulumi's passphrase provider, not by the shared
  GCP KMS key. The ciphertext still lives committed in
  `Pulumi.<stack>.yaml`, exactly as it does today.

> **Partly verified.** The endpoint form, and why path style is the safe
> setting, are confirmed against the live endpoint — step 1 states what was
> actually seen. Two things are still unverified because they need a bucket
> this account does not yet have: locking behaviour under contention, and CI
> credential sourcing. Neither is closed by `scripts/probe-object-storage.py`,
> which exercises storage semantics rather than Pulumi; the lock questions are
> closed by step 5's two-client check, and nothing has run it. Correct this
> file from whatever the first real run observes — do not assume it was
> right.

## Before you start

Three things must already exist, and all three are platform-owner work:

1. A bucket in Hetzner Object Storage. Its location is independent of where
   the stack's servers live and does not have to match them — but the
   endpoint host and the `region` parameter must both name **the bucket's**
   own location, and getting either wrong surfaces as an opaque 403. Two
   facts worth knowing before creating one, both from Hetzner's published
   limits. The account is capped at **100 buckets and 200 S3 credentials
   across all projects** — a scarce allowance rather than a free-form
   resource. And the **base price is per account**: "regardless of how many
   Buckets you have and how many different projects or locations they are
   in", charged "for every hour you have at least one active Bucket".

   So an additional bucket on an account that already has one adds no
   subscription line, **including a bucket in a different project** — the
   pricing page names projects explicitly. Two qualifications, because "free"
   is not quite the word. Storage and egress above the included quota (744
   TB-hour and ~1.116 TB in a 31-day month, pooled across every bucket in
   every project) bill pay-as-you-go, so a bucket holding real media or
   backups is a cost even though the bucket itself is not. And the base price
   attaches to having _any_ bucket, not to the first one: deleting the
   original while a later bucket survives keeps the charge alive.

2. An S3 credential pair for it (access key + secret), created in the Hetzner
   console. There is no CLI or API surface for this on a Cloud API token.
   Note that a key pair is "automatically valid for every Bucket within the
   same project" by default and cannot be scoped at creation; narrowing it
   means a bucket policy.
3. A passphrase for the stack — high entropy, generated fresh, stored in the
   platform owner's password manager **and** as a GitHub Actions secret for
   the repository that applies the stack.

**Losing the passphrase destroys the stack's secrets permanently.** There is
no escrow, no recovery and no re-wrap without it. This is a strictly worse
failure mode than the KMS key it replaces, and it is accepted because the
alternative is a dependency on the very cloud account this migration exists to
leave. Store it in two places before you use it once.

Work through the steps in order and run the teardown block at the end. Every
`export` below is live for the whole session, so do not stop halfway.

## 1. Supply the state-backend credentials

The backend URL itself is not set here. It is pinned in `Pulumi.yaml` as
`backend.url`, so every command in this project addresses the same state
whatever the workstation was last logged into, and `pulumi login` is not part
of this runbook at all. If the bucket name or location ever differs from what
that file says, `Pulumi.yaml` is the one place to change it.

What this step supplies is the credential to read it with:

```bash
export AWS_REGION=hel1              # matches the bucket's location
read -rs -p 'Object Storage access key: ' AWS_ACCESS_KEY_ID; echo; export AWS_ACCESS_KEY_ID
read -rs -p 'Object Storage secret:     ' AWS_SECRET_ACCESS_KEY; echo; export AWS_SECRET_ACCESS_KEY
```

`read -rs` rather than an `export` with the value inline, for the same reason
step 4 refuses a command-line argument: an assignment typed at a prompt is
written to shell history, and a secret that has been in history is a secret
that has to be rotated. The values still reach every child process of this
shell once exported — close the shell when the runbook is done rather than
leaving it open.

`s3ForcePathStyle=true` because a bucket name containing a **dot** cannot be
addressed virtual-host style over TLS. The endpoint serves a wildcard
certificate — `CN=hel1.your-objectstorage.com`, SAN
`*.hel1.your-objectstorage.com` — and DNS is wildcard too, so a single-label
bucket name _does_ work virtual-host style. A wildcard matches exactly one
label, so `media.tenant-x.hel1.your-objectstorage.com` fails certificate
verification. Path style sidesteps the question entirely and costs nothing,
which is why it is set unconditionally rather than decided per bucket name.

The constraint is **not** DNS-label validity in general, which is what this
file previously claimed. The distinction matters wherever bucket names are
chosen rather than inherited.

`AWS_*` variable names are not a mistake: Pulumi's S3 backend is the AWS SDK,
and it reads the standard chain regardless of who is serving the API. That
also means an unrelated AWS profile on the workstation will be picked up if
these are unset — check `pulumi whoami --verbose` before trusting the result
of anything below.

## 2. Install the dependencies, and know which directory you are in

`hetzner/` is one npm package holding **two** Pulumi projects, and the rest of
this runbook is directory-sensitive as a result. Dependencies install once, at
the package root; every `pulumi` command runs in the project directory of the
stack being created.

```bash
cd hetzner
nvm use
npm ci
```

A clean checkout has no `node_modules`, and `pulumi preview` in step 5 fails
on the missing Pulumi SDK rather than on anything to do with the backend —
which reads as a backend problem and sends you back to step 1.

| Stack you are creating       | Run every `pulumi` command from | Config file it writes                   |
| ---------------------------- | ------------------------------- | --------------------------------------- |
| `branchleft-hetzner-network` | `hetzner/`                      | `hetzner/Pulumi.production.yaml`        |
| `branchleft-hetzner-estate`  | `hetzner/estate/`               | `hetzner/estate/Pulumi.production.yaml` |

**`cd` to the right one before step 3, and stay there.** `pulumi` resolves the
project from the working directory, so running the steps below from `hetzner/`
while intending to create the estate stack does not fail — it creates
`branchleft-hetzner-network/production` and writes its config file, and the
first sign of it is a stack that exists under a name nobody meant to make. The
two are separate stacks with separate passphrases; work through this file once
per stack rather than trying to interleave them.

Applies have an order: the estate stack reads the network stack's `networkId`
through a stack reference, so the network stack must be created **and applied**
first, or the estate preview fails on a stack it cannot read.

## 3. Create the stack with the passphrase provider

The passphrase is the one irrecoverable secret in this design, so it gets the
strictest handling in this file: it is never assigned on a command line,
never exported into the environment of every child process, and never typed
where a terminal will echo it. Write it to a file only readable by you, point
Pulumi at the file, and delete the file in the teardown block at the end —
**not here.** Steps 4 and 5 still need it.

```bash
umask 077
install -m 600 /dev/null ~/.pulumi-passphrase-tmp
read -rs -p 'Stack passphrase: ' PASSPHRASE; echo
printf '%s' "$PASSPHRASE" > ~/.pulumi-passphrase-tmp; unset PASSPHRASE
export PULUMI_CONFIG_PASSPHRASE_FILE=~/.pulumi-passphrase-tmp

pulumi stack init production --secrets-provider passphrase
```

`PULUMI_CONFIG_PASSPHRASE_FILE` is what makes this possible — Pulumi reads
the passphrase from the named file, so the value itself never appears in an
environment variable, a process listing or shell history.

`pulumi stack init` writes `encryptionsalt` into `Pulumi.production.yaml`.
**Commit that file.** It is not a secret; it is what makes the committed
ciphertext decryptable by anyone holding the passphrase, and a stack whose
salt is not committed cannot be applied from CI.

**A `Pulumi.<stack>.yaml` that is already committed is safe to init against.**
`stack init` merges rather than replaces: it keeps the existing `config:`
entries and appends the salt, and so does every later `config set`. This is how
a project's non-secret configuration gets reviewed in a pull request before the
stack that will use it exists.

Two qualifications, both observed against v3.255.0. Pulumi rewrites the file
each time, so its own layout wins over any hand formatting. And comments
survive that rewrite **only while the file carries at least one populated
config entry** — against a file that is all comments, or one whose only content
is an empty `config: {}`, the rewrite drops everything and leaves the salt
alone on the first line. A stack with no non-secret configuration therefore has
nothing to commit ahead of time and nowhere to write down why.

That is the case for `branchleft-hetzner-network`, whose only config value is
the secret token: its `Pulumi.production.yaml` is created entirely by this step
and must be committed afterwards.
`branchleft-hetzner-estate`'s file is already committed with its non-secret
entries, and this step adds the salt to it.

**One passphrase per stack, not one per project or per bucket.** Several stacks
share this backend; each is wrapped independently, and losing any one
passphrase loses that stack's secrets alone.

## 4. Set the Hetzner token as stack config

```bash
pulumi config set --secret hcloud:token
```

The command prompts. Pass no value on the command line: an argument lands in
shell history and in the process table, and a token that has been in either
is a token that has to be rotated.

The token is scoped to one hcloud project. A lab-project token must never be
set on a production stack and the reverse is worse — the project boundary is
the only isolation hcloud offers, since a token has full power over
everything in its project.

## 5. Prove the backend before you rely on it

```bash
pulumi stack ls                     # the new stack, on the new backend
pulumi preview --stack production   # expect a create plan, no errors
```

Then run the same preview a second time from a different machine or a clean
checkout. The point is not the plan; it is that two clients can read the same
state and that the lock is taken and released. Pulumi's S3 backend locks with
an object rather than a separate lock service, and object stores differ in
the consistency guarantees that makes safe — this is the check that catches
it before an interrupted apply does.

Pulumi's DIY backend puts state at `.pulumi/stacks/<project>/<stack>.json`
with a `.bak` alongside, and takes locks as objects under
`.pulumi/locks/organization/<project>/<stack>/`, written per operation and
removed on completion. **Nothing should be under that prefix at rest**, and an
object left there after a failed run is a stranded lock — which is what a
later "another update is currently in progress" is telling you about.

That layout was read from a `file://` backend on v3.255.0, not from S3. It is
the same `gocloud.dev/blob` code path, so the paths carry over; what does
**not** carry over is any conclusion about safety under contention. The lock
is advisory — a write followed by a list, with no compare-and-swap — so
whether it holds depends on the object store's read-after-write and
list-after-write consistency, which is exactly what the two-client check above
exists to find out. Do not delete a lock object on the strength of this
paragraph.

Storage semantics — versioning, the 30-day noncurrent lifecycle, and the
public-read-but-not-listable bucket policy — are a separate exercise, and
**not part of creating a stack.** They belong to the lab, they run once rather
than per stack, and they are here only because this is where the Object
Storage knowledge lives. `scripts/probe-object-storage.py` prints a dated
markdown block recording what it observed:

```bash
# In the LAB project, with that project's own Object Storage credentials --
# not the ones exported in step 1. A key pair is valid only within the project
# it was created in, so a production key against a lab bucket is the opaque
# 403 this file keeps warning about.
export AWS_REGION=hel1
read -rs -p 'LAB Object Storage access key: ' AWS_ACCESS_KEY_ID; echo; export AWS_ACCESS_KEY_ID
read -rs -p 'LAB Object Storage secret:     ' AWS_SECRET_ACCESS_KEY; echo; export AWS_SECRET_ACCESS_KEY

python3 scripts/probe-object-storage.py \
  --bucket branchleft-lab-probe \
  --endpoint hel1.your-objectstorage.com --region hel1
```

**The probe bucket is deliberately not a state bucket.** The script writes,
and one of the things it writes is a policy granting anonymous reads over its
own `_probe/` prefix. Pointing it at a bucket holding Pulumi state would
publish checkpoint JSON at a key path this very file documents, so it refuses
any bucket name ending `-pulumi-state`, refuses a bucket that is non-empty or
that already carries a policy or lifecycle configuration, and refuses to
proceed when any of those checks cannot be answered rather than assuming the
answer is no.

It undoes what it wrote — restoring the bucket's prior versioning state rather
than forcing one, never writing a state it failed to read, and reporting every
step it could not reverse.

## 6. Tear the session down

```bash
rm -f ~/.pulumi-passphrase-tmp
unset PULUMI_CONFIG_PASSPHRASE_FILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION
```

Plain `rm`, not `shred`: `shred` is GNU-only and absent on macOS, and its
overwrite guarantee does not survive a copy-on-write filesystem or an SSD's
wear levelling anyway, so reaching for it here would buy a false sense of
security rather than an erasure. What actually protects the passphrase is
that it is in the password manager and was never in shell history.

Then close the shell. Nothing needs a `pulumi login` to undo, because this
project never issued one — see step 1.

## 7. Wire CI

The applying workflow needs four secrets and no federated identity. There is
no Workload Identity Federation equivalent here: the Hetzner API authenticates
a bearer token and nothing else, so the short-lived-credential posture the GCP
stacks have does not carry over. That trade is accepted deliberately; what it
demands in return is that each token is scoped to one project and one
pipeline.

| Secret                         | Purpose                                                      |
| ------------------------------ | ------------------------------------------------------------ |
| `HCLOUD_TOKEN`                 | The Hetzner Cloud API token for this stack's project         |
| `PULUMI_CONFIG_PASSPHRASE`     | Decrypts this stack's committed secrets                      |
| `HETZNER_S3_ACCESS_KEY_ID`     | Object Storage state access, exported as `AWS_ACCESS_KEY_ID` |
| `HETZNER_S3_SECRET_ACCESS_KEY` | Its secret, exported as `AWS_SECRET_ACCESS_KEY`              |

The workflow needs no `pulumi login` step: `backend.url` in `Pulumi.yaml`
already fixes the backend, which is the point of pinning it there. Do not add
one, and in particular do not template a backend URL from a repository
variable another workflow also sets — a state backend chosen at runtime is a
stack that can be applied against the wrong state.

## What this runbook deliberately does not cover

Migrating an existing stack. Every stack that predates this pattern has its
secrets wrapped by one shared KMS key, and re-wrapping them requires that key
to still exist. That is a single ordered sweep across every surviving stack,
gated before any GCP teardown, with a lab rehearsal first. Running
`pulumi stack change-secrets-provider` on a live stack outside that sweep
rewrites every secret in place, and it is not an agent action.

The sweep itself, its stack-by-stack commands, its rollback and the point
after which there is none:
[`RUNBOOK-existing-stack-migration.md`](RUNBOOK-existing-stack-migration.md).
