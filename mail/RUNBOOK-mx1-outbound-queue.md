# Runbook — what is mx1's outbound queue holding, for whom, and how old

## What this answers

When a provider defers mx1's mail (a Gmail `421` tempfail is the usual case),
the monitoring alerts say _that_ it is happening and nothing about _who_ is
affected: Stalwart's `queue.count` and `queue_rescheduled` metrics carry no
destination label. This runbook reads the queue itself, read-only, and prints
one line per **destination domain and status**: how many recipients are queued
to that domain, in which status, how long the oldest has been waiting, and the
highest retry count among them. It is meant to be read in under a minute,
during the deferral.

It answers **what is stuck now**. A message that has been delivered or bounced
has left the queue, so this is not a history, and it does not say _why_ a
provider is deferring — that is the provider's own postmaster pages, see
"What to do next".

These commands were written from Stalwart's v0.16.17 source (the version
`mail/provision/docker-compose.yml` pins), because no documentation page for
the queue object could be found. They were **not run against mx1**. The same
request and the same `jq` filter were run against the official v0.16.17
release binary on a throwaway local server with synthetic data and no network;
what that did and did not cover is under "Verify".

## Read this first

- **Nothing here changes the queue.** Every command reads. None retries,
  reschedules, cancels, deletes, flushes or releases a message. Keep it that
  way: do not reach for the management API's write method on queued messages to
  "help" a stuck message along.
- **Do not resend, retry or flush into a deferral.** The queue's backoff is the
  correct pacing; resends are the unusual rate a provider objects to. See
  `hetzner/RUNBOOK-monitoring.md` ("MailDeliveryDeferred").
- **Cancelling a queued message drops real mail.** The message is never
  delivered, and nothing here can undo that.
- **Raw queue rows hold recipient addresses, which are personal data.** Step 2
  reduces them to domain, status and count on your Mac, in the same pipeline,
  so no raw row is written to a file. Never paste raw rows, or the admin
  credential, into an issue, a PR, a commit or a chat message. The reduced
  lines are safe to paste, except that a domain with a count of 1 can identify
  one person: write `OTHER_DOMAIN` for it.

## Before you start

1. `~/.ssh/id_ed25519_hetzner` present. Every `ssh` below needs `-i` with it.
2. `jq` on your Mac: `jq --version`. If it is missing, `brew install jq`.
3. **You do not type the admin credential and it is never printed.** It is read
   from `/root/.stalwart-admin-credentials` by the shell on mx1, inside the
   `curl` that mx1 runs against its own loopback. Port 8080 stays closed to the
   outside, and no tunnel is needed. This is the same read as the `x:Http/get`
   check in `mail/RUNBOOK-mx1-prometheus-metrics.md` (V2), with the same
   property: `curl -u` puts the credential on that one command line for as long
   as the `curl` runs, visible in mx1's process list, where only you can log in.
4. Run every step below **in one terminal session**: Step 1 defines a shell
   variable that Steps 2 and 3 use.

The SSH-tunnel route (`mail/RUNBOOK-mx1-provision.md`, "How to SSH-tunnel to
the admin interface") also works for this API, but it would need the credential
on your Mac, so it is not used here.

## Step 1 — define the summary filter (runs nothing)

This is the whole of the reduction. Read it before running anything: it takes
the reply from the management API, counts **recipients** (not messages) per
destination domain and status, and prints nothing but those counts, ages and
retry numbers.

```bash
QUEUE_SUMMARY_JQ='
  (.methodResponses[0][1].total // error("no total in the reply: the query call failed")) as $total
  | (.methodResponses[1][1].list // error("no list in the reply: the get call failed")) as $messages
  | "\($total) queued messages, \($messages | length) listed"
    + (if ($messages | length) < $total then " -- LISTING TRUNCATED, counts below are partial" else "" end),
    ( [ $messages[] | .createdAt as $queued | .recipients | to_entries[]
        | {domain: (.key | split("@") | last | ascii_downcase), status: .value.status["@type"], queued: $queued, retries: .value.retryCount} ]
      | group_by([.domain, .status])[]
      | "\(length) recipient(s) to \(.[0].domain), status \(.[0].status), oldest queued \((now - (map(.queued) | min | fromdate)) / 60 | floor) min ago, max retries \(map(.retries) | max)" )
'
```

## Step 2 — list the queue

```bash
printf '%s' '{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["x:QueuedMessage/query",{"calculateTotal":true,"limit":1},"total"],["x:QueuedMessage/get",{},"list"]]}' \
  | ssh -i ~/.ssh/id_ed25519_hetzner root@mx1.branchleft.co.uk \
    'curl -sS -u "$(cat /root/.stalwart-admin-credentials)" -H "Content-Type: application/json" -d @- http://127.0.0.1:8080/jmap' \
  | jq -r "$QUEUE_SUMMARY_JQ"
```

The request is two read-only calls in one round trip. `x:QueuedMessage/query`
with `calculateTotal` counts every queued message. `x:QueuedMessage/get` with no
`ids` lists them, up to the server's get limit. The summary's first line puts
the two side by side.

**Expect, on a healthy empty queue**, exactly one line:

```text
0 queued messages, 0 listed
```

**Expect, during a deferral**, the first line and then one line per destination
domain and status, sorted by domain:

```text
COUNT_MESSAGES queued messages, COUNT_MESSAGES listed
COUNT_RECIPIENTS recipient(s) to DOMAIN_A, status TemporaryFailure, oldest queued AGE_MINUTES min ago, max retries RETRIES
COUNT_RECIPIENTS recipient(s) to DOMAIN_B, status Scheduled, oldest queued AGE_MINUTES min ago, max retries RETRIES
```

The queue is empty, or nothing is deferred, when the only line is the first one.
**If nothing at all is printed**, the `ssh` or `curl` half failed and `jq` had
no input — the first line is printed for an empty queue too, so silence is
never "all clear". Run V1 under "Verify" below.

### Reading the lines

- **Counted per recipient, not per message.** The status lives on each
  recipient, and one message can address several domains. A message to two
  recipients at `DOMAIN_A` and one at `DOMAIN_B` is one queued message and three
  recipients, and shows as one line for each domain. So the counts of
  recipients add up to more than the number of messages whenever a message has
  more than one recipient.
- **`TemporaryFailure`**: the last attempt got a temporary refusal (a `4xx`,
  a connection or DNS failure) and the recipient is waiting for its retry. This
  is the deferral. **`Scheduled`**: not yet attempted, or held for a later time;
  nothing has failed. Together these two are "still being delivered".
- **`PermanentFailure`**: the destination refused for good and Stalwart sent the
  sender a bounce. The row stays only while other recipients of the same message
  are still pending, so it is a leftover, not a live problem. A message whose
  only recipient failed permanently left the queue within seconds in the
  local run.
- **`Completed`**: delivered. By the source it stays, like `PermanentFailure`,
  only while another recipient of the message is pending; this status was not
  seen in the local run.
- **`max retries`** is the highest `retryCount` in the group: how many retries
  have been scheduled for the most-retried recipient, which grows with each
  failed attempt. A count that keeps rising while the age rises is a provider
  that has not let up; a high age with a low count is a recipient scheduled far
  out. The per-recipient `retryDue` (when the next attempt is due) and
  `expires.expiresAt` (when Stalwart gives up and bounces) are in the raw reply
  and not printed here.
- **`oldest queued`** is the age of the oldest message in the group by
  `createdAt`, in minutes, computed on your Mac at the moment `jq` runs.

### If the first line says `LISTING TRUNCATED`

The first number counts every queued message; the second is how many the server
returned. They differ when the queue is longer than the server's get limit
(500 by default: a throwaway v0.16.17 server reported `maxObjectsInGet` as 500
and its `x:Jmap` settings object `getMaxResults` as 500 and `queryMaxResults`
as 5000). The counts below the first line are then **partial**: the listing is
the messages due soonest (the source iterates by due time, and the local run
with a lowered limit dropped the latest-due message). Do not treat them as
totals. Step 3 narrows to one
destination domain.

## Step 3 — only if truncated, or to look at one provider

`to` matches by substring on the full recipient address, so `@DOMAIN_A` is the
way to ask for one domain; it can also match a longer domain that contains it,
which the per-domain lines then show. The prompt asks for the domain, so
nothing illustrative is pasted:

```bash
printf 'domain to narrow to (for example the deferring provider): '; read -r PROVIDER_DOMAIN
jq -n --arg to "@$PROVIDER_DOMAIN" '{
    using: ["urn:ietf:params:jmap:core"],
    methodCalls: [
      ["x:QueuedMessage/query", {filter: {to: $to}, calculateTotal: true, limit: 500}, "total"],
      ["x:QueuedMessage/get", {"#ids": {resultOf: "total", name: "x:QueuedMessage/query", path: "/ids"}}, "list"]
    ]
  }' \
  | ssh -i ~/.ssh/id_ed25519_hetzner root@mx1.branchleft.co.uk \
    'curl -sS -u "$(cat /root/.stalwart-admin-credentials)" -H "Content-Type: application/json" -d @- http://127.0.0.1:8080/jmap' \
  | jq -r "$QUEUE_SUMMARY_JQ"
```

Expect the same shape as Step 2, for the messages that have at least one
recipient at that domain. A message that also addresses other domains shows
those recipients too, as their own lines. The first line's first number is the
messages matching the filter; if it still exceeds the second, the domain alone
holds more than 500 queued messages.

## Verify

Two checks; the first is the one to run whenever Step 2 prints nothing.

**V1 — the pipeline never fails quietly.** `jq` stops with an error (and exit
status 5) when the reply has no `total` or no `list`, which is what a refused
credential, an unknown method or a server error looks like. Empty input — the
`ssh` itself failing — prints nothing. Both mean the same thing: do not read
the absence of lines as an empty queue. To see why, run the `ssh` half alone
and look at the status code only, which prints no body:

```bash
printf '%s' '{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["x:QueuedMessage/query",{"limit":1},"probe"]]}' \
  | ssh -i ~/.ssh/id_ed25519_hetzner root@mx1.branchleft.co.uk \
    'curl -sS -o /dev/null -w "%{http_code}\n" -u "$(cat /root/.stalwart-admin-credentials)" -H "Content-Type: application/json" -d @- http://127.0.0.1:8080/jmap'
```

Expect `200`. `401` means the credentials file does not hold the credential
the running server has: report that rather than retrying. No output, or an
`ssh` error, is a connection or key problem, not a queue problem.

**V2 — what was and was not exercised.** The request and the filter were run
against the v0.16.17 release binary (the x86_64 Linux build), started with
throwaway storage inside an empty network namespace, with a handful of
synthetic messages to reserved `.invalid`, `.test` and `.net` names. There they
printed the lines in the shape above for `TemporaryFailure`,
`PermanentFailure` and `Scheduled` recipients, printed the single
`0 queued messages, 0 listed` line for an empty queue, flagged a deliberately
lowered get limit as `LISTING TRUNCATED`, and failed with a `jq` error on a
refused credential. **Not exercised:** the `Completed` status (read from the
source, not seen), a real provider's `4xx` reply, the pinned container image
(the release binary was used, not the image), a queue anywhere near 500, and
`ssh` itself (the remote command was run through a stand-in).

## What to do next

This runbook stops at "which domains, which status". For the deferral itself go
to `hetzner/RUNBOOK-monitoring.md` ("MailDeliveryDeferred" and
"MailDelayNotified"), and to the provider's own postmaster pages (for Gmail,
Google Postmaster Tools). Neither involves changing the queue.

## What this deliberately does not do

- **No change to the queue, in any form.** No retry, reschedule, cancel,
  delete, flush or release. The management API has one method that does those
  (it is the `set` method on the queued-message object); it is not used here
  and should not be added to this runbook.
- **No per-message view.** Counting is per recipient, and the addresses are
  dropped in the pipeline on purpose.
- **No remote reply code.** Each failing recipient's `status` also carries the
  remote server's `responseCode` and `responseEnhanced` (for example a `421`
  and `4.7.28`), and an `errorMessage`. They are not printed: the free text
  can echo an address, and adding the two codes to the group key in Step 1 is a
  separate change.
- **No `stalwart-cli`.** A separate `stalwart-cli` exists, which the
  `stalwartlabs/cli` README describes as listing objects with its `query`
  command. It is not in the pinned image, and it needs the credential in an
  environment variable on your Mac. It was not tried.
- **No alert and no automation.** The alert is `MailDeliveryDeferred`; this is
  the owner's look at what it is about.

## Sources

Stalwart's documentation site has no queue page that could be fetched; searches
returned only the project README. Everything the commands rely on is therefore
**source code at the pinned tag**, not documentation, with the exact names
copied from it.

**Source at tag `v0.16.17`**, each path under
`https://github.com/stalwartlabs/stalwart/blob/v0.16.17/`:

- Object name `QueuedMessage`:
  `crates/registry/src/schema/properties.rs#L216`.
- Method names `x:<Object>/get`, `x:<Object>/set`, `x:<Object>/query` — the
  only three forms:
  `crates/jmap-proto/src/request/method.rs#L357-L368`.
- A registry call needs no `using` entry of its own; the check is skipped for
  the Stalwart capability, whose name is `urn:stalwart:jmap`:
  `crates/jmap/src/api/request.rs#L108-L111` and
  `crates/jmap-proto/src/request/capability.rs#L334`. This is why the request
  carries only `urn:ietf:params:jmap:core`, as
  `mail/provision/configure_stalwart.py` does for its own `x:` calls.
- `x:QueuedMessage/get`, with and without `ids`, and the limit on a listing:
  `crates/jmap/src/registry/mapping/queued_message.rs#L269-L311` and
  `#L752-L783`.
- `x:QueuedMessage/query`: the only filters are `due`, `queueName`, `returnPath`,
  `to` and `text`; the only sort is `due`; `to` is a substring match:
  `crates/jmap/src/registry/mapping/queued_message.rs#L313-L398` and
  `#L445-L450`. There is no status filter, no domain filter and no way to
  group or count, which is why the grouping is done in `jq`.
- The reply shape. `QueuedMessage` holds `createdAt`, `recipients` and the rest;
  each `QueuedRecipient` holds `retryCount`, `retryDue`, `expires`, `status`;
  `status` is tagged by `@type`, one of `Scheduled`, `Completed`,
  `TemporaryFailure`, `PermanentFailure`; the failure variants carry a
  `DeliveryError`:
  `crates/registry/src/schema/structs.rs#L4296-L4347`, `#L4358-L4365` and
  `#L902-L919`.

**Project text, not source:**

- `https://github.com/stalwartlabs/stalwart/blob/main/UPGRADING/v0_16.md` — the
  v0.16 statement that management is JMAP objects (`main`, not the tag).
- `https://github.com/stalwartlabs/cli` — the README of `stalwart-cli`, for the
  one sentence above.

If the pinned version in `mail/provision/docker-compose.yml` is bumped, re-run
Step 2 and check the first line and the per-domain lines before relying on this
runbook: the `status` shape and the method names are the parts that could move.
