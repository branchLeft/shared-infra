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
| id                   | A     | 3600 | 46.225.95.167           |
| portal               | A     | 3600 | 46.225.95.167           |
| s1-ionos.\_domainkey | CNAME | 3600 | s1.dkim.ionos.com.      |
| s2-ionos.\_domainkey | CNAME | 3600 | s2.dkim.ionos.com.      |

The apex SOA and NS are IONOS's own and are recorded in the transcript but not
declared: Hetzner serves its own. That is the only difference in what resolves.

**The registrar refuses zone transfers, so no list of names is exhaustive.**
The first capture missed the two `*-ionos._domainkey` CNAMEs: `_domainkey`
answered NOERROR with no data, so a name sat below it, and a dictionary probe
found them. Step 6 is the one complete check.

## Blast radius

| Phase             | What changes                                                                              | Who notices                   | Undo                                          |
| ----------------- | ----------------------------------------------------------------------------------------- | ----------------------------- | --------------------------------------------- |
| Steps 1-5, create | A zone exists at Hetzner. Nothing resolves through it: the registry still points at IONOS | Nobody                        | Lift delete protection in the console, delete |
| Step 7, switch    | The `.uk` registry delegates to Hetzner. Every lookup moves over within 48 hours          | Everyone, if the zones differ | Switch the nameservers back (same 48h tail)   |

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

```bash
cd ~/branchLeft/shared-infra/hetzner
nvm use
pnpm install --frozen-lockfile
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

```bash
umask 077
install -m 600 /dev/null ~/.pulumi-passphrase-tmp
read -rs "PASSPHRASE?Stack passphrase (read back from ProtonPass): "; echo; printf '%s' "$PASSPHRASE" > ~/.pulumi-passphrase-tmp; unset PASSPHRASE
export PULUMI_CONFIG_PASSPHRASE_FILE=~/.pulumi-passphrase-tmp
```

Expected: the reads print nothing. **Do not run `pulumi stack init`**: the
`production` stack exists, and a second `init` mints a new salt and orphans its
secrets.

### 2. Preview

```bash
cd ~/branchLeft/shared-infra/hetzner/dns
pulumi preview --diff
```

Expected: 11 resources to create — `hcloud:index/zone:Zone`
`publicpress-co-uk` and 10 `hcloud:index/zoneRrset:ZoneRrset`, each named
`publicpress-co-uk-` followed by the owner and type (`publicpress-co-uk-apex-a`,
`publicpress-co-uk-apex-mx`, `publicpress-co-uk-apex-txt`,
`publicpress-co-uk-_dmarc-txt`, `publicpress-co-uk-_domainconnect-cname`,
`publicpress-co-uk-autodiscover-cname`, `publicpress-co-uk-id-a`,
`publicpress-co-uk-portal-a`, `publicpress-co-uk-s1-ionos._domainkey-cname`,
`publicpress-co-uk-s2-ionos._domainkey-cname`). **Any update, replace or delete
of a `branchleft-co-uk` resource is a stop**: it means a URN moved.

The stack outputs change as well, and the preview shows it: `zone` and `rrsets`
are removed, and `zones` and `authoritativeNameserversByZone` are added.
`authoritativeNameservers` keeps its value. Removing an output changes no
resource, so it is not a stop.

### 3. Apply

```bash
cd ~/branchLeft/shared-infra/hetzner/dns
pulumi up
```

Confirm only if the plan matches step 2 exactly. Expected: `Resources: 11
created`.

```bash
pulumi stack output authoritativeNameserversByZone
```

Expected: `publicpress.co.uk` lists `hydrogen.ns.hetzner.com`,
`oxygen.ns.hetzner.com` and `helium.ns.hetzner.de` (order may differ). If the
names differ, use the printed names everywhere below.

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
no differences: 10 rrsets, 143 names, 12 types, 7 servers; both controls caught
```

and an empty line for the DS query (the zone is unsigned; a signed zone moved
this way would fail validation everywhere). Any `DIFF`, `ERROR` or `CONTROL
FAILED` is a stop.

### 6. Count the records against the registrar's own listing

In the IONOS panel, open **Domains & SSL → publicpress.co.uk → DNS** and check
it lists exactly the 11 records in the table at the top (the MX counts twice),
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

then land that by PR, and apply
before going on.

Rollback is not instant: switching the nameservers back takes up to the 172800 s
delegation TTL to propagate. For that long, mail continuity rests on both
servers holding identical records, which step 5 checks and the rollback check
re-checks.

### 7. Switch the nameservers (IONOS panel; the only step that changes resolution)

In the IONOS panel, open **Domains & SSL → publicpress.co.uk → Nameservers**,
choose custom nameservers, and enter exactly:

```text
hydrogen.ns.hetzner.com
oxygen.ns.hetzner.com
helium.ns.hetzner.de
```

### 8. Verify the registry, the propagation and mail

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
   `Authentication-Results:` header. Expected: `spf=pass` and `dkim=pass`, both
   for publicpress.co.uk. Observed: the spf and dkim results as the header
   writes them. Do not paste addresses.

A message that does not arrive, or a result other than `spf=pass` and
`dkim=pass`, is a stop: switch back under Rollback.

## Rollback

1. Check the IONOS copy still holds all 10 rrsets, from a network that does not
   intercept port 53 (as in step 5). Each IONOS server is queried directly and
   compared against the committed zone file:

   ```bash
   cd ~/branchLeft/shared-infra
   python3 hetzner/dns/zonecheck.py compare --zone-file hetzner/dns/publicpress.co.uk.json --left ns1049.ui-dns.de,ns1088.ui-dns.org --right ns1094.ui-dns.biz,ns1098.ui-dns.com --check-ttl --dig-time 5 --dig-tries 5
   ```

   Expected, and nothing else:

   ```text
   no differences: 10 rrsets, 143 names, 12 types, 4 servers; both controls caught
   ```

   Any `DIFF` names a record IONOS no longer serves. Re-enter it in the IONOS
   panel (**Domains & SSL → publicpress.co.uk → DNS**) from the table at the top
   of this runbook, with full values in `hetzner/dns/publicpress.co.uk.json`,
   **before** switching back, then run this check again. `ERROR` (exit 2) is the
   port 53 problem; `CONTROL FAILED` is a stop.

2. Switch the nameservers back to the four IONOS names in step 5's `--left` list.
   The IONOS copy then answers, and the same 48-hour tail applies in reverse.

## After 48 hours

Re-run step 5 against the Hetzner servers alone and leave the IONOS zone in
place for as long as you like; nothing depends on it.
