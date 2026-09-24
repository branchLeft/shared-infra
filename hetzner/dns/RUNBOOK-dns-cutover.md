# Runbook — move the branchleft.co.uk zone to Hetzner DNS

Refs branchLeft/workspace#1164. That issue stays open after this runbook: it
closes when DNS-01 completes against the zone and a wildcard certificate
issues, which is follow-up work that needs this move first.

## Why

The zone is edited by hand in the registrar's panel, and the registrar's DNS
has no API the estate uses. That blocks every certificate that needs a DNS-01
challenge (wildcards above all) and any DKIM record a program has to publish.
Owner ruling D18 moves the zone to Hetzner DNS, which is API-driven and free.
IONOS stays the registrar and nothing else.

## Blast radius

| Phase                              | What changes                                                                                 | Who notices                                               | Undo                                                              |
| ---------------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------- |
| A. Create the Hetzner zone         | A zone exists at Hetzner. Nothing resolves through it: the registry still delegates to IONOS | Nobody                                                    | Remove it in the console (delete protection is on; lift it first) |
| B. Lower TTLs at IONOS             | Record TTLs at IONOS drop from 3600 to 300                                                   | Nobody; resolvers re-ask more often                       | Set them back to 3600                                             |
| C. Switch the nameservers at IONOS | The `.uk` registry delegates to Hetzner. Every lookup moves over within 48 hours             | Everyone, if the two zones differ. Nobody, if they do not | Switch the nameservers back — with the same 48-hour tail          |
| D. Afterwards                      | Nothing; the IONOS copy is left alone for at least 48 hours                                  | —                                                         | —                                                                 |

**The tail is 48 hours and cannot be shortened.** The `.uk` registry serves the
delegation with a TTL of 172800 seconds (checked 2026-09-23 with
`dig +norec @nsd.nic.uk branchleft.co.uk NS`), and IONOS serves its own apex
NS with 86400. For up to two days after phase C, some resolvers ask IONOS and
some ask Hetzner. Both must give identical answers for the whole window, which
is what phase A's comparison proves, and why **no record may be changed at
either provider from the final comparison until 48 hours after the switch** —
or, if one must change, it changes at both.

**Mail.** The zone carries everything mail depends on, and all of it is in
`zone.json`: the MX (`10 mx1.branchleft.co.uk.`), `mx1`'s A and AAAA, the SPF
TXT at the apex, `_dmarc`, and three DKIM keys — mx1's own two
(`v1-ed25519-20260811._domainkey`, `v1-rsa-20260811._domainkey`) and a legacy
`google._domainkey`. `mx1` itself is not touched by anything here, and its
reverse DNS is set at Hetzner Cloud per address, not in this zone, so it is
unaffected. Mail breaks only if the two zones differ, and the comparison below
is what rules that out; step 12 proves it end to end.

**DNSSEC.** The zone is unsigned — there is no DS record at the registry — so
there is no key to carry over and no DS to remove first. Step 7 re-checks it,
because a signed zone moved this way would fail validation everywhere.

## Before you start

- This PR merged, and `~/branchLeft/shared-infra` on `main` at or after it.
- `dig` on the workstation (macOS ships it).
- The Object Storage credential pair for the `branchleft-pulumi-state` bucket
  (`hel1`), from ProtonPass — the same pair every other Hetzner stack here uses.
- A new passphrase for this stack, generated fresh and saved in ProtonPass
  **before** step 3, then read back out of ProtonPass when step 3 asks for it
  (see `hetzner/RUNBOOK-new-stack.md` "Before you start" for why the
  read-back is the custody check).

## Phase A — create the zone at Hetzner

### 1. Generate a Read & Write token in the existing dns project (console)

**Which project holds the zone is already settled — [ISSUE
branchLeft/workspace#1165](https://github.com/branchLeft/workspace/issues/1165):
the estate's seven Hetzner projects, this zone's among them.** A Hetzner
token has full power over its project, so whichever project holds this zone,
every token for it can rewrite the organisation's MX, SPF and DKIM records;
a DNS-only project bounds that to DNS alone, with no host's token — and in
particular no DNS-01 credential placed on an edge or demo host for some
other zone — able to reach it.

The project already exists: **branchLeft dns**, Hetzner Console project id
**16139783**, created and proven isolated by `RUNBOOK-seven-projects.md` on
2026-09-23 ([comment
5802428073](https://github.com/branchLeft/workspace/issues/1165#issuecomment-5802428073)).
It holds no servers, and one unattached marker firewall,
`project-marker-dns`, created by that runbook — do not remove it: the
program refuses to apply without it (see "If it fails" below).

In the Hetzner Console, open the **branchLeft dns** project (id 16139783) —
do not create a new one. **Security → API tokens → Generate API token**,
description `pulumi branchleft-hetzner-dns`, permission **Read & Write**.
Save it in ProtonPass as `hcloud / dns / pulumi-branchleft-hetzner-dns`,
alongside the project's existing `probe-dns` Read-only token.

Expected: the project already has the marker firewall and now has this one
new Read & Write token, alongside its existing Read-only probe token.

**If it fails** with `the hcloud token addresses the X project, not the dns
project`, the token is from the wrong project: go back to the console and
generate one from **branchLeft dns** (16139783). If it fails with `cannot
see the firewall project-marker-dns`, the token's project has no marker —
confirm you generated it inside **branchLeft dns**, not a lookalike empty
project; the marker is what tells them apart, and a servers-only check
would have let a wrong empty project's token through silently
([ISSUE branchLeft/workspace#1306](https://github.com/branchLeft/workspace/issues/1306)).

### 2. Supply the state and API credentials

Every block from here runs in one zsh session. Close it at the end.

```bash
cd ~/branchLeft/shared-infra/hetzner
nvm use
npm ci
export AWS_REGION=hel1
export AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
```

```bash
read -rs "AWS_ACCESS_KEY_ID?Object Storage access key: "; echo; export AWS_ACCESS_KEY_ID
```

```bash
read -rs "AWS_SECRET_ACCESS_KEY?Object Storage secret: "; echo; export AWS_SECRET_ACCESS_KEY
```

```bash
read -rs "HCLOUD_TOKEN?dns project (16139783) Read & Write token: "; echo; export HCLOUD_TOKEN
```

The provider reads `HCLOUD_TOKEN` from the environment, so the token is never
written to `Pulumi.production.yaml` at all.

Expected: `npm ci` ends without errors; the three reads print nothing.

### 3. Create the stack

```bash
cd ~/branchLeft/shared-infra/hetzner/dns
umask 077
install -m 600 /dev/null ~/.pulumi-passphrase-tmp
```

```bash
read -rs "PASSPHRASE?Stack passphrase (read back from ProtonPass): "; echo; printf '%s' "$PASSPHRASE" > ~/.pulumi-passphrase-tmp; unset PASSPHRASE
```

```bash
export PULUMI_CONFIG_PASSPHRASE_FILE=~/.pulumi-passphrase-tmp
pulumi whoami --verbose
pulumi stack init production --secrets-provider passphrase
```

Expected: `whoami` names the backend
`s3://branchleft-pulumi-state?endpoint=hel1.your-objectstorage.com&s3ForcePathStyle=true&region=hel1`;
`stack init` prints `Created stack 'production'`. It appends an
`encryptionsalt:` line to `Pulumi.production.yaml` — **never commit it**.
Run it only this once: against an existing stack, `stack init` mints a new
salt and silently orphans every secret the stack holds.

### 4. Preview

```bash
cd ~/branchLeft/shared-infra/hetzner/dns
pulumi preview --diff
```

Expected: 19 resources to create — the stack, `hcloud:index/zone:Zone`
`branchleft-co-uk`, and 17 `hcloud:index/zoneRrset:ZoneRrset` (`apex-a`,
`apex-mx`, `apex-txt`, `_acme-challenge-cname`, `_acme-challenge.blog-cname`,
`_acme-challenge.www-cname`, `_dmarc-txt`, `_domainconnect-cname`, `blog-a`,
`book-a`, `cloud-a`, `google._domainkey-txt`, `mx1-a`, `mx1-aaaa`,
`v1-ed25519-20260811._domainkey-txt`, `v1-rsa-20260811._domainkey-txt`,
`www-a`). Nothing to update or delete.

If it fails with `the hcloud token addresses the X project, not the dns
project` or `cannot see the firewall project-marker-dns`, the token is from
the wrong project or lacks the dns project's marker: go back to step 1.

### 5. Apply

```bash
cd ~/branchLeft/shared-infra/hetzner/dns
pulumi up
```

Read the plan it prints; confirm only if it matches step 4 exactly.

Expected: `Resources: 19 created`. Nothing resolves through this zone yet.

```bash
pulumi stack output authoritativeNameservers
```

Expected: `{"assigneds":["hydrogen.ns.hetzner.com","oxygen.ns.hetzner.com","helium.ns.hetzner.de"]}`
(the order may differ). If the names differ, use the names printed here, not
these, everywhere below.

### 6. Confirm Hetzner serves the zone before it is delegated

```bash
dig +norec @hydrogen.ns.hetzner.com branchleft.co.uk SOA | grep -E 'status|flags'
```

Expected: `status: NOERROR` and `flags: qr aa`. `aa` is the point: the server
answers as the zone's authority even though nothing delegates to it yet. If
the status is `REFUSED`, stop — the zone cannot be verified before the switch,
and this runbook's safety argument no longer holds.

### 7. Compare the two providers, record by record

```bash
cd ~/branchLeft/shared-infra
python3 hetzner/dns/zonecheck.py compare --left ns1049.ui-dns.de,ns1067.ui-dns.com,ns1109.ui-dns.biz,ns1116.ui-dns.org --right hydrogen.ns.hetzner.com,oxygen.ns.hetzner.com,helium.ns.hetzner.de
dig +short DS branchleft.co.uk @1.1.1.1
```

Expected, and nothing else:

```text
no differences: 17 rrsets, 112 names, 12 types, 7 servers; both controls caught
```

and an empty line for the DS query. The check compares every server on both
sides with `hetzner/dns/zone.json`, including 97 names that must _not_ exist
(NXDOMAIN on both). It only prints the all-clear after proving it can fail:
each provider must serve its own apex NS set, and a deliberately altered copy
of one record must be reported. Any `DIFF` line, `ERROR` or
`CONTROL FAILED` is a stop.

### 8. Count the records against the registrar's own listing

The comparison can only see names it knows to ask about — the registrar
refuses zone transfers, so no list of names is exhaustive. The first capture
missed mx1's two DKIM keys for exactly that reason. The registrar's panel is
the one complete listing.

In the IONOS panel, open **Domains & SSL → branchleft.co.uk → DNS** and check
it lists exactly these 18 records besides the NS records:

| Host                            | Type  | Value (start)                                |
| ------------------------------- | ----- | -------------------------------------------- |
| @                               | A     | 46.225.95.167                                |
| @                               | MX    | 10 mx1.branchleft.co.uk                      |
| @                               | TXT   | google-site-verification=P0Ms…               |
| @                               | TXT   | v=spf1 ip4:167.233.252.240 …                 |
| www                             | A     | 46.225.95.167                                |
| blog                            | A     | 46.225.95.167                                |
| book                            | A     | 46.225.95.167                                |
| cloud                           | A     | 46.225.95.167                                |
| mx1                             | A     | 167.233.252.240                              |
| mx1                             | AAAA  | 2a01:4f8:1c18:866::1                         |
| \_dmarc                         | TXT   | v=DMARC1; p=none; …                          |
| google.\_domainkey              | TXT   | v=DKIM1;k=rsa;p=MIIB…                        |
| v1-ed25519-20260811.\_domainkey | TXT   | v=DKIM1; k=ed25519; …                        |
| v1-rsa-20260811.\_domainkey     | TXT   | v=DKIM1; k=rsa; …                            |
| \_acme-challenge                | CNAME | 74bab56b-….authorize.certificatemanager.goog |
| \_acme-challenge.www            | CNAME | fda3887d-….authorize.certificatemanager.goog |
| \_acme-challenge.blog           | CNAME | f60916b8-….authorize.certificatemanager.goog |
| \_domainconnect                 | CNAME | \_domainconnect.ionos.com                    |

Expected: a match. **Any extra record is a stop**: add its name to
`probe_names` in `hetzner/dns/zone.json`, re-run
`python3 hetzner/dns/zonecheck.py capture --server ns1049.ui-dns.de --out hetzner/dns/zone.json`,
land that by PR, and apply before going on.

## Phase B — lower the TTLs (at least one hour before phase C)

### 9. Lower every record's TTL at IONOS to 300 seconds

In the same IONOS DNS page, edit each of the 18 records above and set its TTL
to the lowest value offered, 5 minutes if available. Leave the values alone.
If the panel lets you edit the NS records' TTL, lower those too; if not, the
86400 stays.

Then wait at least one hour — the TTL being replaced — before phase C, so no
resolver still holds an answer with the old, long TTL.

```bash
dig +norec @ns1049.ui-dns.de branchleft.co.uk MX +noall +answer
cd ~/branchLeft/shared-infra
python3 hetzner/dns/zonecheck.py compare --left ns1049.ui-dns.de,ns1067.ui-dns.com,ns1109.ui-dns.biz,ns1116.ui-dns.org --right hydrogen.ns.hetzner.com,oxygen.ns.hetzner.com,helium.ns.hetzner.de
```

Expected: the MX answer shows TTL 300, and the comparison still prints
`no differences … both controls caught`. It compares values, not TTLs, so the
IONOS side's shorter TTLs are not a diff. This is also the **final
comparison**: from here, no record changes at either provider until 48 hours
after step 10.

Why at IONOS and why before: through the switch window, a resolver can keep
an IONOS answer for as long as its TTL. Short TTLs mean that if the switch has
to be reversed, or a record has to be corrected at IONOS during the window,
the correction reaches everyone in five minutes rather than an hour. Lowering
them during the switch would be too late — the long TTLs would already be
cached.

## Phase C — switch the nameservers

### 10. Point the registration at Hetzner (IONOS panel)

**Domains & SSL → branchleft.co.uk → Nameservers → use custom name servers**,
and enter, replacing the four IONOS servers:

```text
hydrogen.ns.hetzner.com
oxygen.ns.hetzner.com
helium.ns.hetzner.de
```

Save. If IONOS offers to delete or reset the domain's DNS records, **decline**:
resolvers that still hold the old delegation keep asking IONOS for up to 48
hours, and must get the same answers.

### 11. Verify the registry and the propagation

```bash
dig +norec @nsd.nic.uk branchleft.co.uk NS | grep -A4 AUTHORITY
dig +norec @ns1049.ui-dns.de branchleft.co.uk MX | grep -E 'status|flags|MX'
```

Expected, within an hour of step 10: the registry's AUTHORITY section lists
the three Hetzner names; IONOS still answers `NOERROR`, `aa`, with the MX.

**If IONOS no longer answers** (`REFUSED` or a timeout) the registrar stopped
serving the zone when the delegation moved. Resolvers still holding the old
delegation — up to 48 hours' worth — now fail rather than getting an answer.
Decide at once between rolling back (below) and riding out the tail; there is
no third option.

Then, over the following 48 hours:

```bash
for r in 1.1.1.1 8.8.8.8 9.9.9.9; do echo "$r: $(dig +short NS branchleft.co.uk @$r | sort | tr '\n' ' ')"; done
for r in 1.1.1.1 8.8.8.8 9.9.9.9; do echo "$r: $(dig +short MX branchleft.co.uk @$r)"; done
```

Expected: the NS answers move from the `ui-dns` names to the Hetzner names as
caches expire; the MX answer is `10 mx1.branchleft.co.uk.` from every resolver
at every point, before, during and after.

### 12. Verify mail end to end

Once 1.1.1.1 and 8.8.8.8 both return the Hetzner NS set:

1. From an external mailbox (Gmail or similar), send a message to
   `rob@branchleft.co.uk`. Expected: it arrives.
2. From `rob@branchleft.co.uk`, send a message to that external mailbox.
   Expected: it arrives in the inbox, and its original headers
   (Gmail: ⋮ → Show original) read `SPF: PASS`, `DKIM: 'PASS' with domain
branchleft.co.uk`, `DMARC: 'PASS'`, with the DKIM selector one of
   `v1-rsa-20260811` or `v1-ed25519-20260811`.

A receiving server that already followed the new delegation read the key from
Hetzner, so a DKIM pass here proves the Hetzner copy of the key.

```bash
dig +norec @hydrogen.ns.hetzner.com v1-rsa-20260811._domainkey.branchleft.co.uk TXT +short | head -c 60; echo
```

Expected: `"v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA`.

## Phase D — after 48 hours

### 13. Final check, and close the session

```bash
cd ~/branchLeft/shared-infra
python3 hetzner/dns/zonecheck.py compare --left ns1049.ui-dns.de,ns1067.ui-dns.com,ns1109.ui-dns.biz,ns1116.ui-dns.org --right hydrogen.ns.hetzner.com,oxygen.ns.hetzner.com,helium.ns.hetzner.de
git -C ~/branchLeft/shared-infra checkout -- hetzner/dns/Pulumi.production.yaml
rm -f ~/.pulumi-passphrase-tmp
unset HCLOUD_TOKEN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY PULUMI_CONFIG_PASSPHRASE_FILE
```

Expected: `no differences` if IONOS is still serving its copy; `ERROR …
REFUSED` from an IONOS server is also fine at this point, since nothing
delegates to it any more. `git status` in `shared-infra` is clean.

From here on, **records change in `hetzner/dns/zone.json` and nowhere else**,
by PR. The IONOS panel copy is dead and must not be edited — or deleted —
until someone decides to; leaving it costs nothing.

## Rollback

Until 48 hours after step 10 the rollback is the same switch in reverse, with
the same tail:

1. IONOS panel, **Domains & SSL → branchleft.co.uk → Nameservers → use IONOS
   name servers** (the default). Save.
2. `dig +norec @nsd.nic.uk branchleft.co.uk NS | grep -A4 AUTHORITY` — expected
   within an hour: the four `ui-dns` names.
3. Leave the Hetzner zone as it is: resolvers that already moved keep asking
   it for up to 48 hours.

If IONOS dropped its copy of the records at step 10, re-enter them in its
panel from the table in step 8 (full values in `hetzner/dns/zone.json`)
**before** step 1 of the rollback, then run step 7's comparison to prove the
two copies match again.

## After it succeeds

Comment on branchLeft/workspace#1164 with the output of step 7, step 11's
registry answer, and step 12's header lines (`SPF`, `DKIM` with selector,
`DMARC` — no addresses). Leave the issue open: it closes when DNS-01 completes
against the zone, which is its own follow-up.
