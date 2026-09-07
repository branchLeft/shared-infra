# Runbook — mx1 disaster recovery

> **UNREHEARSED.** No step below has been executed against a real host. This
> document was written by reading `mail/RUNBOOK-mx1-provision.md`,
> `mail/RUNBOOK-import-mail-host.md`, `mail/provision/`, the `mail/` Pulumi
> program and `mail/RUNBOOK-mx1-prometheus-metrics.md` — it has not been
> tested against a lab host or a real loss. The first time any step here runs
> for real **is** the rehearsal that [branchLeft/workspace#173](https://github.com/branchLeft/workspace/issues/173)
> also asks for, and that rehearsal has not happened. Treat every step marked
> **[inferred]** below as a best-effort reconstruction, not a proven
> procedure, until it has actually been run once and this file updated with
> what was true and what wasn't. Steps marked **[transcribed]** are lifted
> from a runbook that has been executed for real; treat those as materially
> more trustworthy, though still not exercised in a disaster context.

## Scope

Answers "mx1 is gone — what now?" mx1 is branchLeft's self-hosted mail
delivery host (Stalwart, on Hetzner). Unlike the database and media parity
drills in doc 14 §13, nothing has ever drilled losing this host. Three things
make it different from an ordinary host rebuild:

1. **mx1's Pulumi treatment is import-only** (`mail/index.ts`, `mail/server.ts`,
   `mail/firewall.ts`) and both resources carry `protect: true`. Pulumi did
   not create this host and cannot recreate it — a `pulumi up` after real loss
   does nothing useful until the state is deliberately repointed at whatever
   replaces it (see "Pulumi state after a rebuild" below).
2. **Stalwart has no config-as-code.** Its settings live in a database on the
   host, reconciled by `mail/provision/configure_stalwart.py` against
   Stalwart's JMAP-style management API — there is no file to restore from
   version control.
3. **Mail reputation is bound to the IP address**, and the primary IP is not
   a Pulumi-managed resource here (`server.ts`'s `ignoreChanges: ['publicNets']`
   says so explicitly) — its Hetzner-side `auto_delete` / delete-protection
   state is not recorded anywhere in this repository. This runbook could not
   check it: touching the Hetzner API is out of scope for the session that
   wrote this document (see "What this runbook could not verify" below).

This is a recovery runbook, not a provisioning tutorial — read
`mail/RUNBOOK-mx1-provision.md` for what each script actually does before
running the sequences below.

## What this runbook could not verify

Written under a hard constraint: no SSH to mx1, no Pulumi, no Hetzner API
call, of any kind, including read-only ones. Two consequences:

- **The primary IP's `auto_delete` and delete-protection state is unknown.**
  This is [branchLeft/workspace#173](https://github.com/branchLeft/workspace/issues/173)'s
  action item 1, and it is still open. The first live action for whoever
  rehearses this runbook should be `hcloud primary-ip describe mx1` (or the
  console equivalent) to find out, before trusting anything below that
  assumes the address survives a loss.
- **Whether a Hetzner server backup for mx1 actually exists, and how old it
  is, is unknown.** `mail/server.ts` sets `backups: true` on the `hcloud.Server`
  resource, which is Hetzner's automatic-backup feature — but this repo
  records nothing about retention or a verified restore point. **[inferred]**
  Hetzner's documented product behaviour is a rolling window of the most
  recent automatic snapshots (commonly seven), taken on its own schedule, not
  triggered by this platform — stated here from general knowledge of the
  product, not from anything this repo or an executed check confirms.

Both are read-only checks an operator with Hetzner API access can run in
under a minute; neither needs write access. Do them before deciding which
path below applies.

## Decision tree: what's actually gone

Two independent questions decide the path:

1. **Is the primary IP still allocated to the branchLeft Hetzner project?**
   (`hcloud primary-ip describe mx1` — read-only.) If it was released
   (`auto_delete` fired, or someone released it by hand), a replacement host
   gets a **new** address, unconditionally, regardless of anything else below.
2. **Does a usable Hetzner backup exist for mx1, and is its restore point
   recent enough to matter?** (`hcloud server list-backups mx1` or the
   console equivalent — read-only.) A backup restore recovers Stalwart's
   database wholesale — mailbox contents, DKIM keys, queue state, the admin
   credential — as of the snapshot; the alternative, `mail/provision/`'s
   scripts, reconstructs _configuration_ only and creates a mailbox layout
   with **no mail in it and new DKIM keys**.

|                 | Backup usable                                                                                                                                                                                           | No usable backup                                                                                                                                                                                   |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **IP retained** | **Path A** — restore from backup onto the retained address. Best case: reputation intact, mail data intact up to the backup's age.                                                                      | **Path B** — fresh Stalwart install on the retained address via `mail/provision/`. Reputation intact; all mailbox content and the old DKIM keypair are gone.                                       |
| **IP lost**     | **Path C** — restore from backup onto a _new_ address (Hetzner can attach a backup's disk to a new server). Mail data intact up to the backup's age; reputation resets regardless of the data recovery. | **Path D** — fresh install on a new address. Total loss: no mail data, new DKIM identity, reputation resets from zero. Worst case, and the only one with nothing recoverable beyond configuration. |

**What "reputation resets" costs, concretely:** DNSBL history and spam-filter
trust accumulated on the old IP do not transfer. `mail/RUNBOOK-mx1-provision.md`
and this platform's own mail-warmup practice treat a fresh IP as needing a
deliberate low-volume warm-up period before bulk sending resumes — sending at
normal volume from a cold IP is itself a strong signal to receiving providers'
spam filters. Do not re-enable the mailgun shim or resume newsletter sends
immediately after any IP-lost path; treat the new address the same way a
brand-new mail host would be treated.

## Ordering and gates — read before doing anything

These apply to every path below:

1. **Never point MX at a host that is not yet accepting mail.** Publishing
   the DNS change before Stalwart is confirmed listening on 25 and answering
   ESMTP means every inbound sender's mail bounces or queues for retry against
   a host that refuses the connection. Do the "Confirming the result" checks
   in `mail/RUNBOOK-mx1-provision.md` (or the abbreviated version under
   "Verify the rebuild" below) before touching DNS.
2. **Never resume outbound sending — transactional or bulk — before DKIM is
   published and resolving.** A message signed with a key whose TXT record
   isn't live yet fails DKIM at the receiving end, which on a host already
   fighting reputation (any IP-lost path) compounds the damage.
3. **Never restart the mailgun shim (bulk mail) before the transactional
   path has been confirmed end-to-end.** The shim is higher volume and a
   bigger reputation swing if something is still wrong.
4. **DNS changes are the slow path, and every one of them queues behind the
   previous record's TTL.** Start correcting the records that carry no
   ordering risk — the new host's A/AAAA (needed for ACME to issue against
   it) and PTR/rDNS — as early as the target state is known (i.e., as soon
   as Path A/B/C/D is decided and, for a new host, the new address is known)
   rather than waiting until the host is fully provisioned. **This does not
   extend to MX, SPF or DKIM** — those stay gated by items 1 and 2 above,
   regardless of how early the address is known.

## DNS records that matter, and what breaks while each is wrong

**All manual, at IONOS.** No program in this repo or elsewhere owns DNS
(`shared-infra/CLAUDE.md`: "Not DNS"). Every row below is a human editing the
zone by hand, with a human-speed TTL lag after each edit — there is no way to
make any of these instant.

| Record                                                          | Changes when                                                                                                                                                                                               | Breaks while wrong                                                                                                                                                                                                                                                                                    |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **MX** (`branchleft.co.uk.` → `mx1.branchleft.co.uk.`)          | Any path where the host is being replaced or the address changes                                                                                                                                           | Inbound mail bounces or misdelivers to whatever the stale MX target is (or nothing, if that target is also gone)                                                                                                                                                                                      |
| **A/AAAA for `mx1.branchleft.co.uk`**                           | Path C/D (new address), or Path A/B if the address is unchanged but the record needs re-confirming                                                                                                         | TLS SNI and every client/relay resolving the hostname reaches the wrong host or nothing                                                                                                                                                                                                               |
| **SPF** (`branchleft.co.uk` TXT)                                | Only if the _sending_ IP changes — i.e., any IP-lost path (C/D)                                                                                                                                            | Receiving providers see a sender IP not listed in SPF and either reject or heavily penalise the message — this is the single highest-impact record for an IP change, per `mail/RUNBOOK-mx1-provision.md`'s own note that SPF tracks the outbound path, not the receiving one                          |
| **DKIM selector TXT records** (`*._domainkey.branchleft.co.uk`) | Any path that generates new keys — B and D (fresh Stalwart install); **not** A/C (backup restore keeps the old keypair)                                                                                    | Messages fail DKIM alignment; combined with a cold IP (C/D) this is the difference between "suspicious" and "outright rejected" at a strict receiving provider                                                                                                                                        |
| **DMARC** (`_dmarc.branchleft.co.uk` TXT)                       | Not directly changed by any path here, but its policy interacts with whichever of SPF/DKIM above is broken                                                                                                 | A `p=reject`/`p=quarantine` policy amplifies an SPF or DKIM failure into an outright bounce rather than a soft score penalty — check the current policy before assuming a "minor" DKIM gap is tolerable                                                                                               |
| **MTA-STS / TLS-RPT**                                           | Only if this platform has published either (not confirmed by this runbook — `mail/RUNBOOK-mx1-provision.md`'s "DKIM records to publish" section lists both as explicitly out of scope of that runbook too) | If published: a stale MTA-STS policy can cause strict senders to refuse delivery to a host whose certificate/hostname no longer matches what the policy asserts                                                                                                                                       |
| **PTR / rDNS** (set at Hetzner, not IONOS)                      | Any path with a new address (C/D)                                                                                                                                                                          | Many receiving providers reject or heavily penalise inbound connections from an IP with no matching or mismatched reverse DNS — this is a Hetzner-side setting (`hcloud primary-ip` / rDNS API), not an IONOS zone edit, and is easy to forget precisely because it isn't in the IONOS console at all |

**[inferred]** The PTR/rDNS point is not documented anywhere in this repo —
it is general mail-deliverability practice, flagged here because it is the
record most likely to be missed in a rebuild since it lives outside the
zone editors otherwise reach for.

## Credentials and secrets: what's regenerated, escrowed, or gone

Per `mail/RUNBOOK-mx1-provision.md`'s "Secrets" section: **nothing secret is
in this repository**, and every secret is generated on the host itself.

| Secret                                                                | Path A/C (backup restore)                                                                                                       | Path B/D (fresh install)                                                                                                                                                                                                                                                                                                                                                                    |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stalwart admin credential                                             | Recovered as-is from the backup                                                                                                 | Regenerated by Stalwart on first boot; the _old_ value in whatever operator record held it (if any) is dead                                                                                                                                                                                                                                                                                 |
| Mailbox passwords (per account)                                       | Recovered as-is                                                                                                                 | Regenerated by `provision_mailboxes.py`; every mailbox user needs the new password communicated to them again                                                                                                                                                                                                                                                                               |
| DKIM keypair (Ed25519 + RSA)                                          | Recovered as-is — DNS does **not** need republishing                                                                            | Regenerated by Stalwart; DNS **must** be republished (see DNS table above)                                                                                                                                                                                                                                                                                                                  |
| ACME/Let's Encrypt account + certificate                              | Recovered as-is (account); certificate itself is short-lived either way and will re-issue on the new host once 443 is reachable | Fresh ACME account and issuance — no action needed beyond what `mail/RUNBOOK-mx1-provision.md`'s "The ACME decision" section already covers                                                                                                                                                                                                                                                 |
| Website/blog/shim/alerting submission credentials (`60`–`64` scripts) | Recovered as-is                                                                                                                 | Regenerated; **every dependent system needs its credential updated** — the website contact form, the blog's send path, the mailgun shim's own credential, and Alertmanager's submission credential. None of these are escrowed centrally per the provision runbook; each was generated and handed to its consumer directly, so "regenerate and redistribute" is real work, not a formality. |
| Historical mailbox content (received/sent mail)                       | Recovered up to the backup's timestamp; anything after that timestamp and before the loss is genuinely gone                     | **Entirely unrecoverable.** There is no other backup of mailbox content described anywhere in this repo. State this plainly rather than assuming a copy exists somewhere: if the backup restore path fails or no usable backup exists, mail history is gone.                                                                                                                                |

**Nothing above should ever be pasted into this runbook, a PR, or a chat
transcript** — the same rule `mail/RUNBOOK-mx1-provision.md`'s "Rotating the
admin credential" section states for the admin credential applies to every
row in this table.

## Path A / C — restore from a Hetzner backup

**[inferred] — this entire path is a reconstruction from Hetzner's general
product behaviour and this repo's Pulumi comments, not from any runbook that
has actually restored mx1.** No file in this repo documents a Hetzner backup
restore procedure for any host.

1. Confirm a usable backup exists and note its timestamp (read-only,
   operator-run): `hcloud server list-backups mx1` or the Hetzner console's
   backup list for the server.
2. Restore. Hetzner's restore either rebuilds the existing server in place
   from the backup image, or (Path C, address lost) creates a new server from
   the backup's image and a fresh primary IP. Both are console/API operations
   this runbook does not script — treat the exact command as something to
   confirm against Hetzner's own current documentation at rehearsal time
   rather than trusting a command frozen into this file, since Hetzner's CLI
   surface for backup restore has changed shape before.
3. Once the host is reachable by SSH, confirm the containers came back:

   ```bash
   MX1_IPV4=$(hcloud server describe mx1 -o json | python3 -c "import json, sys; print(json.load(sys.stdin)['public_net']['ipv4']['ip'])")
   ssh -i ~/.ssh/id_ed25519_hetzner -o StrictHostKeyChecking=accept-new root@"$MX1_IPV4" 'docker ps'
   ```

   Expect the `stalwart` container (and the mailgun-shim/Caddy containers if
   they were part of the restored image) `Up` and healthy. **[inferred]** —
   there is no documented case of a restore leaving containers in a
   half-started state, but nothing rules it out either; if `docker ps` shows
   anything other than a clean `Up`, treat it as closer to Path B/D (fresh
   install may be safer than debugging an unknown restored state) rather than
   pressing on blind.

4. If the restore also changed the primary IP (Path C), skip to "DNS" above
   for the SPF/PTR/A-record work, and to "Pulumi state after a rebuild" below
   — the Pulumi program's imported resource IDs are stale either way a new
   server object was created.
5. Run the "Confirming the result" checks from `mail/RUNBOOK-mx1-provision.md`
   (line-referenced in that file's own "Confirming the result" section) —
   **[transcribed]**, these are the exact checks that runbook proved worked
   the first time this host was provisioned, and they apply unchanged to a
   restored host: listener check, port 25 banner, TLS check, DKIM presence,
   admin-interface-unreachable check.
6. If the backup predates the loss by more than a few hours, expect gaps:
   any mailbox change, credential rotation, or DNSBL-ban clear made between
   the backup and the loss did not happen as far as the restored host is
   concerned. Re-run `mail/provision/list_and_clear_blocked_ips.py --list-only`
   and re-check DNSBL status (`check_dnsbl_blocklist.py --status`) rather than
   assuming the restored state matches what was true just before the loss.

## Path B / D — fresh install (no usable backup)

**Most steps here are [transcribed] from `mail/RUNBOOK-mx1-provision.md`**,
which is a runbook that has actually been run against this exact host once
already. What's genuinely different in a disaster context — as opposed to
first-time provisioning — is called out explicitly below.

1. **Provision the new server.** This repo's Pulumi program does not create
   mx1 — it only imports an already-existing one (`mail/RUNBOOK-import-mail-host.md`,
   "Why this is a two-step apply, not one"). **[inferred]** Creating the
   replacement host itself (an `hcloud server create` equivalent, OS image
   `debian-13`, type `cx23`, location `nbg1` — matching `mail/server.ts`'s
   declared values) is not something any runbook in this repo has actually
   executed as a _recovery_ action; `RUNBOOK-import-mail-host.md`'s
   prerequisite section assumes the host is "already provisioned" without
   saying how, because in the original build it was created once, out of
   band, before that runbook was ever written. Match `mail/server.ts`'s
   declared shape (server type, image, location) so the later Pulumi import
   is a clean diff rather than fighting a mismatch.
2. **Run the full provisioning sequence.** **[transcribed]** — this invokes
   `run-all.sh`, which runs the entire `00` through `70` sequence in one
   pass, not just `00`–`40`. `run-all.sh`'s own header documents a
   deliberate reordering within that sequence — `64` (the alerting
   credential) runs before `63` (the shim deploy), specifically so a
   rebuilt host has `alerts@` and a working Alertmanager credential even if
   the shim's own deploy step fails partway through. See step 5 below.

   ```bash
   MX1_IPV4=$(hcloud server describe mx1 -o json | python3 -c "import json, sys; print(json.load(sys.stdin)['public_net']['ipv4']['ip'])")
   scp -r -i ~/.ssh/id_ed25519_hetzner mail/provision/. root@"$MX1_IPV4":/root/mail-provision
   ssh -i ~/.ssh/id_ed25519_hetzner root@"$MX1_IPV4" 'chmod +x /root/mail-provision/*.sh /root/mail-provision/*.py && /root/mail-provision/run-all.sh'
   ```

   The trailing `/.` on the `scp` source is load-bearing exactly as
   `mail/RUNBOOK-mx1-provision.md` says — a fresh host has no
   `/root/mail-provision` yet, so this particular failure mode (nesting under
   a stale copy) cannot bite on a genuinely new host, but keep the form
   anyway since the same command is what a partial-recovery re-run would use.

3. **The firewall.** `mail/RUNBOOK-import-mail-host.md`'s two-step import
   (import against the pre-mail-rules baseline, then apply the real rule set)
   was the sequence used when this firewall was first attached — **[inferred]**
   whether a _new_ server object needs the same two-step dance, or can have
   the full rule set applied directly since there's no pre-existing live
   firewall state to diff against cleanly, is not settled by anything in this
   repo. Treat the two-step approach as the safer default until proven
   unnecessary.
4. **Mailboxes.** `50-provision-mailboxes.sh` creates the same
   `MAILBOXES`/`ROLE_ADDRESSES` set (`mail/provision/provision_mailboxes.py`)
   — **[transcribed]** idempotent, proven live per that runbook's "Live
   validation" table. **This creates empty mailboxes.** There is no mail in
   any of them until senders resend or forward — see "What is genuinely
   unrecoverable" below.
5. **Submission credentials** (`60`–`64`). **[transcribed]** — all five run;
   each is independently revocable and none can be recovered from the old
   host, so all must be regenerated and redistributed to their consumers
   (website, blog, shim, Alertmanager) per the credentials table above.
   **`run-all.sh` runs `64` before `63`, not in numeric order** — the
   alerting credential is provisioned before the shim deploy specifically so
   a shim-deploy failure never leaves a rebuilt host unable to alert that it
   failed. If ever provisioning these by hand rather than through
   `run-all.sh`, keep that order: `60`, `61`, `62`, `64`, then `63`.
6. **DKIM.** New keys are generated the moment Stalwart bootstraps. Retrieve
   and publish them per `mail/RUNBOOK-mx1-provision.md`'s "DKIM records to
   publish" section **before** resuming any outbound send (see "Ordering and
   gates" above).
7. **Resolver and DNSBL monitoring** (`65`, `70`). **[transcribed]** — no
   disaster-specific difference from first-time provisioning.
8. **Local recursive resolver and Prometheus.** `30-deploy-stalwart.sh` mints
   a fresh `STALWART_PROMETHEUS_SECRET` when `/opt/stalwart/.env` doesn't
   exist yet, which it never will on a new host — **[transcribed]** per
   `mail/RUNBOOK-mx1-provision.md`'s "How to re-run safely" section, this
   means Prometheus scraping is broken until an operator runs
   `mail/RUNBOOK-mx1-prometheus-metrics.md` step 5 to copy the new secret to
   `edge1`. This is a monitoring gap, not an exposure — the endpoint stays
   authenticated and closed — but it means the dashboards will show mx1 as
   unscraped immediately after a rebuild even once mail itself is flowing
   again. Do this promptly so "is it healthy" (see below) has a real signal
   to check.

## Pulumi state after a rebuild

**[inferred] — no runbook in this repo has done this for mx1 specifically.**
Both `mx1` and `mailFirewall` carry `protect: true`
(`mail/server.ts`, `mail/firewall.ts`), and a new physical server or firewall
object from any Path above gets a **new Hetzner resource ID**. Pulumi's state
still points at the old ID. Left alone, the next `pulumi preview` against
this stack will not cleanly diff — it will either report the old resource as
gone (if Hetzner's provider distinguishes "not found" from drift) or, worse,
propose replacing the live new host with a Pulumi-managed one matching the
old import's captured inputs, which `protect: true` should refuse to execute
but which is not something to discover for the first time during a live
incident.

The inferred correction, modelled on `mail/RUNBOOK-import-mail-host.md`'s own
"two-step apply" reasoning:

```bash
cd mail
# --force is required: both resources carry `protect: true`, and Pulumi's
# own CLI help is explicit that a protected resource is not deleted from
# state without it. This check is a pre-flight, atomic refusal, not a
# partial delete -- confirmed against the installed CLI's help text before
# writing this, not merely assumed.
pulumi state delete --force 'urn:pulumi:production::branchleft-mail::hcloud:index/server:Server::mx1'
pulumi state delete --force 'urn:pulumi:production::branchleft-mail::hcloud:index/firewall:Firewall::mail-firewall'
```

then re-run `mail/RUNBOOK-import-mail-host.md`'s import steps 1–7 against the
new server and firewall IDs, ending with that runbook's own zero-diff gate
(step 5) before trusting `pulumi preview` again. **This has not been tried.**
The exact URNs above are constructed from this stack's known project/stack
names (`mail/Pulumi.yaml`'s `name: branchleft-mail`, `mail/Pulumi.production.yaml`)
and the resource names in `mail/server.ts`/`mail/firewall.ts` — confirm them
with `pulumi stack --show-urns` before deleting anything, rather than trusting
a URN string frozen into this file.

## Verify the rebuild — what "healthy again" means

Three independent signals, none of which alone is sufficient:

1. **The provisioning runbook's own checks.** `mail/RUNBOOK-mx1-provision.md`'s
   "Confirming the result" section — **[transcribed]**, proven on this exact
   host once: listener check inside the container, port 25 ESMTP banner
   (on-box and externally), TLS certificate check, DKIM key presence, and the
   admin-interface-unreachable check (`421` on 443, timeout on 8080).
2. **Prometheus scraping is live**, not just that the container is up.
   `mail/RUNBOOK-mx1-prometheus-metrics.md`'s "Verify" section, V1–V3 —
   **[transcribed]** — confirms the exporter answers `edge1` authenticated,
   refuses unauthenticated and refuses everyone else. This is the signal that
   turns "the host is up" into "the host is observable", which per that
   runbook's own "What is wrong" section is the entire point: a host that
   looks fine on liveness probes alone can still be silently failing
   deliverability.
3. **Role-address forwarding actually works**, not just that mailboxes exist.
   `mail/RUNBOOK-mx1-provision.md`'s "Live validation" table — send one
   message per role address, confirm it lands in both the role mailbox and
   `rob@`. **[transcribed]** for Path B/D where mailboxes are freshly created;
   for Path A/C (backup restore) this check still has value as a
   confidence check, even though the Sieve scripts should already be
   correctly configured from the restored state.

Do not treat "the containers are `Up`" or "the blackbox liveness probe is
green" as sufficient on its own — `mail/RUNBOOK-mx1-prometheus-metrics.md`'s
own "What is wrong" section is explicit that liveness probes "stay green
through a deliverability collapse."

## What is genuinely unrecoverable

State this plainly rather than assume a mitigation exists:

- **Mailbox content received or sent between the last usable backup and the
  loss, in any path.** There is no secondary backup, no off-host mail
  archive, and no journaling described anywhere in this repo. If Stalwart's
  own volumes are gone and no Hetzner backup restores cleanly, **every
  mailbox's historical content is gone**, permanently, for every one of
  `rob@`, `contact@`, `info@`, `sales@`, `complaints@`, `abuse@`, `blog@`,
  `acme@` and `alerts@`.
- **IP reputation, DNSBL history and warm-up progress**, in any path where
  the primary IP is lost (C/D). Nothing recovers this faster than time and a
  deliberate low-volume resend; there is no shortcut described anywhere in
  this estate's mail programme.
- **The exact historical DKIM keypair**, in any path that generates new keys
  (B/D). Old signatures on already-delivered mail remain valid at the
  receiving end (they don't get revalidated), but nothing on this platform
  can re-sign anything retroactively, and this was never a goal.
- **Precisely how long a real rebuild takes.** Every step above has a
  documented mechanism; none has a measured wall-clock time under disaster
  conditions, because none has been run under disaster conditions. Do not
  quote a recovery-time estimate to anyone until the rehearsal below has
  produced one.

## The rehearsal this runbook still needs

[branchLeft/workspace#173](https://github.com/branchLeft/workspace/issues/173)'s
action item 3 — "rehearse against a lab host, a real restore, not a config
review" — is **not done by this document**. It cannot be: the hard
constraints this runbook was written under forbid SSH to mx1, forbid any
Hetzner API call, and forbid running anything against a real host at all.
Writing the runbook and rehearsing it are two different pieces of work, and
only the first is complete.

What the rehearsal needs to actually prove, that this document could only
infer:

- Whether a Hetzner backup restore behaves the way Path A/C above assumes —
  the exact console/API steps, and whether the restored containers come up
  clean without manual intervention.
- Whether the "Pulumi state after a rebuild" section's `pulumi state delete`
  - re-import sequence actually produces a zero-diff `pulumi preview`, on a
    server and firewall that were never the original import target.
- A measured wall-clock time for Path B/D end-to-end, from bare host to the
  "Verify the rebuild" checks all passing.
- Whether anything in `mail/provision/` assumes host state that a genuinely
  fresh Debian 13 box doesn't have (an untested assumption every
  **[inferred]** tag above is flagging).

Record the result in this file, converting each **[inferred]** tag to
**[transcribed]** where the rehearsal confirmed it, and correcting anything
the rehearsal proved wrong, the same way `mail/RUNBOOK-mx1-provision.md`'s
own ACME section documents a corrected mechanism after an incident rather
than silently fixing it.

## Out of scope for this runbook

- **[branchLeft/workspace#173](https://github.com/branchLeft/workspace/issues/173)'s
  action item 1** (verifying and recording the primary IP's `auto_delete` /
  delete-protection state) is not done — see "What this runbook could not
  verify" above.
- **Action item 4** (the interaction with doc 14 §3.5's open default on
  whether the mail stack joins CI-applied delivery) is a platform-owner
  decision this runbook does not make; it is noted here as a pointer, not
  resolved.
- A scripted, one-command restore. Every path above is a manual sequence
  because the source material (`mail/RUNBOOK-mx1-provision.md`,
  `mail/RUNBOOK-import-mail-host.md`) is itself manual end-to-end — there is
  no CI credential for this project and no automation to lean on
  (`mail/RUNBOOK-mx1-provision.md`: "this project has no credential CI can
  hold").
