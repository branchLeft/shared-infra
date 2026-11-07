# Runbook — move the publicpress.co.uk zone to Hetzner DNS

Refs branchLeft/workspace#1887. The zone is the second one in the `dns` stack,
built by the same code as branchleft.co.uk (`../dns.ts`, `ZONE_FILES` in
`../dnsZone.ts`) from `publicpress.co.uk.json`. Every step is inlined here; the
first-time setup of the stack is in `RUNBOOK-dns-cutover.md` and is **not**
repeated: the stack, its token and its passphrase already exist.

## What the zone carries

Read from all four IONOS authoritative servers (`ns1049.ui-dns.de`,
`ns1088.ui-dns.org`, `ns1094.ui-dns.biz`, `ns1098.ui-dns.com`), which agree, by
`zonecheck.py capture` run on a GitHub runner. The dig answers, with dig's
banners stripped by `zonecheck.py strip-transcript`, are
`captures/publicpress.co.uk.ionos-dig.txt`; CI re-proves on every run that
`publicpress.co.uk.json` declares exactly what that transcript shows
(`zonecheck.py check-capture`).

| Host                 | Type  | TTL  | Value                   |
| -------------------- | ----- | ---- | ----------------------- |
| @                    | A     | 3600 | 46.225.95.167           |
| @                    | MX    | 3600 | 10 mx00.ionos.co.uk.    |
| @                    | MX    | 3600 | 10 mx01.ionos.co.uk.    |
| @                    | TXT   | 3600 | the SPF record          |
| \_dmarc              | TXT   | 3600 | the DMARC record        |
| \_domainconnect      | CNAME | 3600 | \_domainconnect.ionos.… |
| autodiscover         | CNAME | 3600 | adsredir.ionos.info.    |
| bl.\_domainkey       | TXT   | 3600 | our DKIM public key     |
| id                   | A     | 3600 | 46.225.95.167           |
| portal               | A     | 3600 | 46.225.95.167           |
| s1-ionos.\_domainkey | CNAME | 3600 | s1.dkim.ionos.com.      |
| s2-ionos.\_domainkey | CNAME | 3600 | s2.dkim.ionos.com.      |

The apex SOA and NS are IONOS's own and are recorded in the transcript but not
declared: Hetzner serves its own. That is the only difference in what resolves.

**The registrar refuses zone transfers, so no list of names is exhaustive.**
The first capture missed the two `*-ionos._domainkey` CNAMEs: `_domainkey`
answered NOERROR with no data, so a name sat below it, and a dictionary probe
found them. It also missed `bl._domainkey` (our own DKIM key), which the
IONOS panel listing showed on 7 Nov 2026 as a twelfth record; a test now
names every known selector (`bl`, `s1-ionos`, `s2-ionos`) so one missing from
the zone file, the probe list or the transcript fails. Step 6 is the one
complete check.

## Blast radius

| Phase             | What changes                                                                              | Who notices                   | Undo                                          |
| ----------------- | ----------------------------------------------------------------------------------------- | ----------------------------- | --------------------------------------------- |
| Steps 1-5, create | A zone exists at Hetzner. Nothing resolves through it: the registry still points at IONOS | Nobody                        | Lift delete protection in the console, delete |
| Step 8, switch    | The `.uk` registry delegates to Hetzner. Every lookup moves over within 48 hours          | Everyone, if the zones differ | Switch the nameservers back (same 48h tail)   |

The `.uk` delegation TTL is 172800 seconds, so for up to two days some resolvers
ask IONOS and some ask Hetzner. **No record is edited at either provider from the
final comparison until 48 hours after the switch**; if one must change, it
changes at both.

**This workstation intercepts port 53.** Every `dig +norec` to an authoritative
server from it comes back `REFUSED` with no `aa` flag, so `zonecheck.py` exits 2.
Run steps 4 and 5 from a network that does not (a phone hotspot), or from the
GitHub runner.

## The owner's steps

### 1. Credentials

Nothing to export. The DNS credentials (the dns project token, the stack
passphrase and salt, the Object Storage keys) are held by CI in the `dns-plan`
and `production-dns` environments, and the plan and the apply run there. Do
**not** run `pulumi stack init` or a hand apply: the `production` stack exists,
a second `init` mints a new salt and orphans its secrets, and a hand apply
bypasses the review below.

### 2. Merge, then read the plan

Merge the pull request that carries this runbook. The merge to `main` touches
`hetzner/dns/`, which starts the CI `dns-plan` run on the merge commit. Open
that run, wait for **Plan (hetzner dns, pulumi preview)** to go green, and read
its summary, **Hetzner dns plan - read before approving the apply**. The
**Apply (hetzner dns, pulumi up)** job then waits in `production-dns`.

Expected: 12 resources to create and nothing else: `hcloud:index/zone:Zone`
`publicpress-co-uk` and 11 `hcloud:index/zoneRrset:ZoneRrset`, each named
`publicpress-co-uk-` followed by the owner and type (`publicpress-co-uk-apex-a`,
`publicpress-co-uk-apex-mx`, `publicpress-co-uk-apex-txt`,
`publicpress-co-uk-_dmarc-txt`, `publicpress-co-uk-_domainconnect-cname`,
`publicpress-co-uk-autodiscover-cname`, `publicpress-co-uk-bl._domainkey-txt`,
`publicpress-co-uk-id-a`, `publicpress-co-uk-portal-a`,
`publicpress-co-uk-s1-ionos._domainkey-cname`,
`publicpress-co-uk-s2-ionos._domainkey-cname`). In the JSON, `changeSummary`
must show `create` 12, with only `same` besides it (the existing
branchleft.co.uk resources).

**Any `update`, `delete` or `replace`, or any `create` that is not a
`publicpress-co-uk` resource, is a STOP.** An update or delete on a
`branchleft-co-uk` resource means a URN moved. Do not approve: choose Reject in
the review dialog. The apply job's delete guard covers the zone itself only, so
this read is the control for a record change.

The stack outputs change as well, and the plan shows it: `zone` and `rrsets`
are removed, and `zones` and `authoritativeNameserversByZone` are added.
`authoritativeNameservers` keeps its value. Removing an output changes no
resource, so it is not a stop.

### 3. Approve the apply

Open the waiting run, click **Review deployments**, tick `production-dns` alone,
and choose **Approve and deploy**. Never tick a second environment in the same
approval: an approval releases every job waiting in the environments ticked.

The apply re-plans after approval, and its delete guard covers the zone only, so
the step 2 read is what protects the branchleft.co.uk records. A later push to
`main` that touches the dns inputs cancels a run still waiting here and queues a
new one: approve the newest run, and merge nothing under the dns inputs between
step 2 and this approval.

Creating the zone and its records changes no resolution: the registry still
points at IONOS until step 8. Expected in the apply job log: `Resources: 12
created`. Then, from a network that does not intercept port 53 (see above),
read the nameservers Hetzner assigned (read only):

```bash
dig +short NS publicpress.co.uk @hydrogen.ns.hetzner.com
```

Expected: `hydrogen.ns.hetzner.com.`, `oxygen.ns.hetzner.com.` and
`helium.ns.hetzner.de.` (order may differ). If the names differ, use the
printed names everywhere below.

### 4. Confirm Hetzner serves the zone before it is delegated

```bash
dig +norec @hydrogen.ns.hetzner.com publicpress.co.uk SOA | grep -E 'status|flags'
```

Expected: `status: NOERROR` and `flags: qr aa`. `REFUSED` or no `aa` is a stop
(on this workstation, first switch network: see above).

### 5. Compare the two providers, record by record

```bash
cd ~/branchLeft/shared-infra
python3 hetzner/dns/zonecheck.py compare --zone-file hetzner/dns/publicpress.co.uk.json --left ns1049.ui-dns.de,ns1088.ui-dns.org,ns1094.ui-dns.biz,ns1098.ui-dns.com --right hydrogen.ns.hetzner.com,oxygen.ns.hetzner.com,helium.ns.hetzner.de --check-ttl --dig-time 5 --dig-tries 5
dig +short DS publicpress.co.uk @1.1.1.1
```

`--dig-time 5 --dig-tries 5` because Hetzner's servers rate-limit the checker at
its defaults (found at the branchleft.co.uk cutover). Expected, and nothing else:

```text
no differences: 11 rrsets, 144 names, 12 types, 7 servers; both controls caught
```

and an empty line for the DS query (the zone is unsigned; a signed zone moved
this way would fail validation everywhere). Any `DIFF`, `ERROR` or `CONTROL
FAILED` is a stop.

### 6. Count the records against the registrar's own listing

In the IONOS panel, open **Domains & SSL → publicpress.co.uk → DNS** and check
it lists exactly the 12 records in the table at the top (the MX counts twice),
besides the NS records. **Any extra record is a stop**: add its name to
`probe_names` in `hetzner/dns/publicpress.co.uk.json`, re-run the capture from a network that does not intercept port 53, which writes
the verbose transcript to a temporary file and then the minimal form to the
committed path:

```text
VERBOSE=$(mktemp)
python3 hetzner/dns/zonecheck.py capture --server ns1049.ui-dns.de --zone-file hetzner/dns/publicpress.co.uk.json --out hetzner/dns/publicpress.co.uk.json --transcript "$VERBOSE" --dig-time 5 --dig-tries 3
python3 hetzner/dns/zonecheck.py strip-transcript < "$VERBOSE" > hetzner/dns/captures/publicpress.co.uk.ionos-dig.txt
rm "$VERBOSE"
```

then land that by PR. The merge queues a new `production-dns` apply: read its
plan and approve it the same way as steps 2 and 3, before going on.

Rollback is not instant: switching the nameservers back takes up to the 172800 s
delegation TTL to propagate. For that long, mail continuity rests on both
servers holding identical records, which step 5 checks and the rollback check
re-checks.

### 7. Record the mail baseline (before the switch)

Run the two mail tests from step 9 now, while the registry still points at IONOS,
so there is a recorded state to hold the switch against. Mail already runs on
IONOS's mail servers, so this is the state the switch must not make worse.

1. Send a message from the outside account to the publicpress.co.uk mailbox.
   Observed: arrived, or not.
2. Send a message from the publicpress.co.uk mailbox to the outside account.
   Observed: arrived, or not.
3. In the message that arrived at the outside account, open the full headers
   (Gmail: **Show original**; other clients: view source) and copy the spf and
   dkim results from the `Authentication-Results:` header. Observed: the spf and
   dkim results as the header writes them. Do not paste addresses.

Write the three results down. This step records them and does not judge them:
the SPF record authorises only the mx1 host's addresses, with `-all`, so the
spf result here may already not be `pass`. Step 9 compares against this record.

### 8. Switch the nameservers (IONOS panel; the only step that changes resolution)

In the IONOS panel, open **Domains & SSL → publicpress.co.uk → Nameservers**,
choose custom nameservers, and enter exactly:

```text
hydrogen.ns.hetzner.com
oxygen.ns.hetzner.com
helium.ns.hetzner.de
```

### 9. Verify the registry, the propagation and mail

```bash
dig +norec @nsd.nic.uk publicpress.co.uk NS
```

Expected: the three Hetzner names. Then, once a resolver has caught up:

```bash
dig +short publicpress.co.uk A @1.1.1.1
dig +short _dmarc.publicpress.co.uk TXT @1.1.1.1
```

Expected: `46.225.95.167` and the DMARC record.

Mail stays on IONOS's mail servers, so the MX answer has to come through
Hetzner's delegation unchanged:

```bash
dig +short MX publicpress.co.uk @1.1.1.1
```

Expected, and nothing else: `10 mx00.ionos.co.uk.` and `10 mx01.ionos.co.uk.`,
one per line. Any other answer is a stop.

Then test mail both ways, with an account you own outside publicpress.co.uk and
a mailbox on publicpress.co.uk. Write down what you observed: the step passes
only on what you saw.

1. Send a message from the outside account to the publicpress.co.uk mailbox.
   Observed: arrived, or not.
2. Send a message from the publicpress.co.uk mailbox to the outside account.
   Observed: arrived, or not.
3. In the message that arrived at the outside account, open the full headers
   (Gmail: **Show original**; other clients: view source) and find the
   `Authentication-Results:` header. Expected: the spf and dkim results match
   the baseline from step 7, or are better. Observed: the spf and dkim results
   as the header writes them. Do not paste addresses.

A message that does not arrive, or any spf or dkim result worse than the
baseline from step 7 (for example `pass` recorded there and `fail` here), is a
stop: switch back under Rollback.

## Rollback

1. Check the IONOS copy still holds all 11 rrsets, from a network that does not
   intercept port 53 (as in step 5). Every server is compared against the
   committed zone file, in step 5's shape: the four IONOS servers on the left,
   the three Hetzner servers on the right. The comparison needs two different
   providers, so the two sides must not share a server:

   ```bash
   cd ~/branchLeft/shared-infra
   python3 hetzner/dns/zonecheck.py compare --zone-file hetzner/dns/publicpress.co.uk.json --left ns1049.ui-dns.de,ns1088.ui-dns.org,ns1094.ui-dns.biz,ns1098.ui-dns.com --right hydrogen.ns.hetzner.com,oxygen.ns.hetzner.com,helium.ns.hetzner.de --check-ttl --dig-time 5 --dig-tries 5
   ```

   Expected, and nothing else:

   ```text
   no differences: 11 rrsets, 144 names, 12 types, 7 servers; both controls caught
   ```

   Any `DIFF` line names its server and record. A DIFF on an IONOS server means
   IONOS no longer serves that record. Re-enter it in the IONOS
   panel (**Domains & SSL → publicpress.co.uk → DNS**) from the table at the top
   of this runbook, with full values in `hetzner/dns/publicpress.co.uk.json`,
   **before** switching back, then run this check again. `ERROR` (exit 2) is the
   port 53 problem; `CONTROL FAILED` is a stop.

2. Switch the nameservers back to the four IONOS names in step 5's `--left` list.
   The IONOS copy then answers, and the same 48-hour tail applies in reverse.

## After 48 hours

Re-run step 5 against the Hetzner servers alone and leave the IONOS zone in
place for as long as you like; nothing depends on it.
