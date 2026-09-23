# Runbook — seven Hetzner projects, a probe token each, isolation proven

Refs branchLeft/workspace#1165. The issue closes on this runbook's verify
output, not on the merge of the PR that adds it.

## What is wrong, and why now

A Hetzner Cloud project is the only credential boundary Hetzner offers: a
token reaches everything in the project that minted it. Today the estate has
two projects — mail (`mx1`) and the estate (`edge1`, `ops1`, `app1`, `db1`, the
network). The try-it-now build is about to create customer hosts, demo hosts,
an API-driven DNS zone for `branchleft.co.uk`, a separate zone for the demo
domain, and a Hetzner Object Storage backup bucket. If those land in the
estate project, one leaked estate token reaches customer data, strangers'
demo code, both DNS zones and every backup at once.

The design (try-it-now §02, the DNS decision in the mail-delivery design, and
the owner's rulings on branchLeft/workspace#1203 and #1260) fixes seven
projects:

| Project    | Console name          | Holds                                                      |
| ---------- | --------------------- | ---------------------------------------------------------- |
| `mail`     | as it is today        | `mx1`. Exists                                              |
| `org`      | as it is today        | the network, `edge1`, `ops1`, `app1`, `db1`. Exists        |
| `tenants`  | `branchLeft tenants`  | new, empty: `edge-t`, `app-t1`, `db-t1` later              |
| `demos`    | `branchLeft demos`    | new, empty: `demo1` later                                  |
| `dns`      | `branchLeft dns`      | new, empty: the branchleft.co.uk zone later, never a host  |
| `backup`   | `branchLeft backup`   | new, empty: the Hetzner backup bucket later, never a host  |
| `demo-dns` | `branchLeft demo dns` | new, empty: the demo domain's own zone later, never a host |

Splitting now costs a console session. Splitting later means moving live
resources.

## What moves: nothing

**No server, network, volume, IP or bucket moves in this runbook, and nothing
is deleted.** Hetzner does allow moving a server, or a snapshot, to another
project ([Hetzner docs: backups and snapshots
FAQ](https://docs.hetzner.com/cloud/servers/backups-snapshots/faq/)). The
design chooses not to. The tenant estate is built fresh in the tenants
project, the blog migrates into it by replication as tenant zero, and `db1`
retires in place once it is empty. `app1` stays in org because it serves
`branchleft.co.uk`. Each of those is its own later story. `ops1` and its data
are not touched by any step here. `backup` and `demo-dns` hold no host at any
point — they exist to bound a bucket and a DNS zone respectively, nothing
more.

## Blast radius

- **Creates:** five empty projects (`tenants`, `demos`, `dns`, `backup`,
  `demo-dns`), seven marker firewalls across all seven projects (no rules,
  attached to nothing, so they cost nothing and change no traffic) and seven
  Read-only API tokens. No token with write power is created.
- **Changes nothing that exists.** No server, network or firewall already in
  mail or org is edited. The mail and org projects each gain one unattached
  firewall and nothing else.
- **Irreversible:** nothing. Every step has a rollback below.
- **Spend:** none. Projects, firewalls and tokens are free.

## Before you start

1. The PR adding this runbook is merged, and your checkout of
   `branchLeft/shared-infra` is on `main` at or after it:

   ```bash
   cd ~/branchLeft/shared-infra && git checkout main && git pull --ff-only && test -f hetzner/scripts/probe-project-isolation.py && echo READY
   ```

   Expected: `READY`.

2. ProtonPass is open. Every token gets an entry at the moment it is shown.
   Hetzner never shows a token again.

### The ProtonPass naming convention (all seven projects, from now on)

One entry per token, titled `hcloud / <project> / <token name>`, where
`<project>` is one of `mail`, `org`, `tenants`, `demos`, `dns`, `backup`,
`demo-dns` and `<token name>` is the token's name in the Console, exactly.
The entry holds:

- **Password:** the token.
- **Note:** the Console project name and project ID, the permission (`Read`
  or `Read & Write`), the creation date, and where else the token is
  deployed (a CI secret name, or `local only`).

The console name and the entry title match, so revoking a token and finding
its entry are the same search. This runbook mints seven Read tokens, one
probe token per project:

| ProtonPass title                     | Console project       | Token name       | Permission | Used by                         |
| ------------------------------------ | --------------------- | ---------------- | ---------- | ------------------------------- |
| `hcloud / mail / probe-mail`         | the mail project      | `probe-mail`     | Read       | the isolation probe, local only |
| `hcloud / org / probe-org`           | the estate project    | `probe-org`      | Read       | the isolation probe, local only |
| `hcloud / tenants / probe-tenants`   | `branchLeft tenants`  | `probe-tenants`  | Read       | the isolation probe, local only |
| `hcloud / demos / probe-demos`       | `branchLeft demos`    | `probe-demos`    | Read       | the isolation probe, local only |
| `hcloud / dns / probe-dns`           | `branchLeft dns`      | `probe-dns`      | Read       | the isolation probe, local only |
| `hcloud / backup / probe-backup`     | `branchLeft backup`   | `probe-backup`   | Read       | the isolation probe, local only |
| `hcloud / demo-dns / probe-demo-dns` | `branchLeft demo dns` | `probe-demo-dns` | Read       | the isolation probe, local only |

**Only Read tokens now.** A Read token can issue GET requests and nothing
else, and the probe needs nothing more. The Cloud API scopes every token to
its project whatever its permission, so a Read token proves the same
boundary a Read & Write one would. A **Read & Write** token for tenants,
demos, dns, backup or demo-dns is minted only when the first stack in that
project needs one, by that stack's own story, under the same convention (for
example `hcloud / tenants / pulumi-tenants`). Until then nothing holds write
power over the five new projects. This matters for dns, backup and demo-dns
in particular: a stolen token there reaches no data outside that one zone or
bucket, but a Read & Write one can still create billable resources in that
project and use up the account-wide server cap.

The working mail and estate tokens live in the `HCLOUD_TOKEN_MAIL` and
`HCLOUD_TOKEN_ESTATE` repository secrets, which can't be read back. If you also
hold either in ProtonPass, bring it under the convention by renaming the entry
to `hcloud / mail / <its console name>` or `hcloud / org / <its console name>`.

## Steps

### 1. Create the five new projects

Hetzner Console → **Projects** → **+ New project**, five times:
`branchLeft tenants`, `branchLeft demos`, `branchLeft dns`,
`branchLeft backup`, `branchLeft demo dns`.

Expected: seven projects on the Projects page, plus any lab project.

### 2. Write down all seven project IDs

Open each project. Its ID is the number in the address bar,
`console.hetzner.com/projects/<ID>/...`. Keep the seven `name → ID` pairs for
step 7. Project IDs aren't secret.

Expected: seven distinct numbers. The mail project and the estate project are
two different IDs. If you only find two, stop: the estate is not where this
runbook thinks it is.

### 3. Create the seven marker firewalls

In **each** of the seven projects: **Firewalls** → **Create Firewall**.

- Name: `project-marker-mail`, `project-marker-org`,
  `project-marker-tenants`, `project-marker-demos`, `project-marker-dns`,
  `project-marker-backup`, `project-marker-demo-dns`, one per project,
  matching the table at the top.
- **Delete every rule the form pre-fills**, inbound and outbound. The marker
  has no rules.
- **Apply to:** nothing. Leave it empty.

Expected: each project's Firewalls page lists its own marker with `0` rules
and `0` resources. In the mail and estate projects it sits next to the
existing firewalls. Those are untouched.

The name is the identity, and the probe and the stack guards match it
exactly. `project-marker-tenant`, `project-marker-demodns` or a capital
letter is a different firewall.

### 4. Mint the seven probe tokens

For each row of the naming table: open that project → **Security** → **API
tokens** → **Generate API token**, name it exactly as the **Token name**
column says, choose the **Permission** column's value, and save it into
ProtonPass under the **ProtonPass title** column **before closing the dialog**.

Expected: seven ProtonPass entries matching the table, and each project's API
tokens page listing its new token by name.

### 5. Run the isolation probe

Load one token per project. Each `read` is its own block. Paste the token when
the cursor waits. Nothing is echoed. **The demo-dns variable is
`HCLOUD_PROBE_TOKEN_DEMO_DNS` — an underscore, not the project's own hyphen: a
shell variable name can't carry one.**

```bash
read -rs HCLOUD_PROBE_TOKEN_MAIL; export HCLOUD_PROBE_TOKEN_MAIL
```

```bash
read -rs HCLOUD_PROBE_TOKEN_ORG; export HCLOUD_PROBE_TOKEN_ORG
```

```bash
read -rs HCLOUD_PROBE_TOKEN_TENANTS; export HCLOUD_PROBE_TOKEN_TENANTS
```

```bash
read -rs HCLOUD_PROBE_TOKEN_DEMOS; export HCLOUD_PROBE_TOKEN_DEMOS
```

```bash
read -rs HCLOUD_PROBE_TOKEN_DNS; export HCLOUD_PROBE_TOKEN_DNS
```

```bash
read -rs HCLOUD_PROBE_TOKEN_BACKUP; export HCLOUD_PROBE_TOKEN_BACKUP
```

```bash
read -rs HCLOUD_PROBE_TOKEN_DEMO_DNS; export HCLOUD_PROBE_TOKEN_DEMO_DNS
```

Then, from the checkout in "Before you start":

```bash
cd ~/branchLeft/shared-infra && python3 hetzner/scripts/probe-project-isolation.py; echo "exit=$?"
```

Expected: a 7×7 matrix where every cell starts `ok`. The diagonal reads
`ok listed/200`: each token lists its own marker and fetches it by id, and the
mail and org tokens also list and fetch `mx1` and `edge1`. Every
other cell reads `ok absent/404`: the token lists none of that project's
servers or marker, and fetching that marker by id returns 404. The last lines
are `PASS` and `exit=0`.

- `exit=1` with `REACHES ACROSS` in a row: that token sees another project.
  Stop. Revoke that token (rollback step R2) and re-mint it inside the
  correct project.
- `exit=1` with `OWN PROJECT NOT SEEN: mx1` or `…: edge1`: the probe token
  for mail or org was minted in the wrong project. Revoke it (R2) and re-mint
  it in the project that holds that server.
- `exit=1` with `does not list project-marker-…`: that project's marker is
  missing or misnamed, or the token was minted in a different project. Check
  step 3's name first.
- `exit=2`: the probe could not observe. A token was refused, the network
  failed, or a response was malformed. **An `exit=2` is never evidence of
  isolation.** Fix the cause and re-run.

### 6. Run the control case, which must report FAIL

This evaluates the tenants row with the demos token. If the probe can't tell
that apart from a clean run, its `PASS` in step 5 proves nothing.

```bash
cd ~/branchLeft/shared-infra && python3 hetzner/scripts/probe-project-isolation.py --control-swap tenants=demos; echo "exit=$?"
```

Expected: the matrix's tenants row shows `XX`, the line
`tenants token vs demos project: REACHES ACROSS`, then `FAIL`, then
`CONTROL OK: the probe reported the tenants row reaching across into demos, as it must.`, then
`exit=0`.

If it prints `CONTROL BROKEN` and `exit=1`, step 5's `PASS` is void. Stop and
hand the output back.

Then clear the tokens from the shell:

```bash
unset HCLOUD_PROBE_TOKEN_MAIL HCLOUD_PROBE_TOKEN_ORG HCLOUD_PROBE_TOKEN_TENANTS HCLOUD_PROBE_TOKEN_DEMOS HCLOUD_PROBE_TOKEN_DNS HCLOUD_PROBE_TOKEN_BACKUP HCLOUD_PROBE_TOKEN_DEMO_DNS
```

### 7. Record the project-ID map

Paste the seven `name → ID` pairs from step 2, and the full output of steps 5
and 6, back into the session. The agent posts them on
branchLeft/workspace#1165. They contain no secret: the probe never prints a
token, and it names only markers and the servers in `hetzner/projects.ts`.

## Verify

Steps 5 and 6 are the verification: `PASS`/`exit=0`, then
`CONTROL OK`/`exit=0`. They prove that each project's probe token reaches its
own project and no other. Isolation is proven by the diagonal. Each token lists
and fetches its own marker. That shows the 404s off the diagonal come from a
project boundary, not a broken path.

## Rollback

Nothing that existed before this runbook is changed, so rollback only removes
what it added. Run any subset, in this order:

- **R1 — the markers.** In each project → Firewalls → the
  `project-marker-<name>` firewall → **Delete**. It is attached to nothing,
  so no traffic changes. The probe then reports that project's marker missing
  until it is re-created.
- **R2 — a token.** Project → Security → API tokens → the token → **Delete**,
  then delete its ProtonPass entry. Only the probe uses these seven.
- **R3 — a new project.** Only once it is empty (no marker, no token, no
  resources): Project → **Settings** → **Delete project**. Never do this to
  the mail or estate project. `tenants`, `demos`, `dns`, `backup` and
  `demo-dns` are all fair game while empty.

## After it succeeds

- The agent posts the ID map and the step 5/6 output on
  branchLeft/workspace#1165 and closes it, citing that comment.
- Later stories, not this one: register the owner SSH key
  (`rob@branchleft.co.uk`, `id_ed25519_hetzner`) in `branchLeft tenants` and
  `branchLeft demos` before their first server apply, because `sshKeys` is
  create-time-only. `backup` and `demo-dns` never hold a server, so they never
  need one. Add `HCLOUD_TOKEN_TENANTS`/`_DEMOS`/`_DNS`/`_BACKUP`/`_DEMO_DNS`
  as repository secrets when those stacks first get CI.
