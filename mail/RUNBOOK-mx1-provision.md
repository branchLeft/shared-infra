# RUNBOOK: provisioning Stalwart on mx1

Scope: gets Stalwart running, hardened and DKIM-capable on the mail delivery
host (`mx1.branchleft.co.uk`), provisions branchLeft's own mailboxes with
role-address forwarding, and provisions the dedicated submission-only SMTP
credentials the website contact form, the blog and the bulk-mail shim each
send with.

It does **not** touch `branchleft.co.uk`'s MX record — that is a manual DNS
change at the registrar, described under "The MX cutover" below. Read "What
this does not prove" at the end before relying on anything here for real mail
traffic.

## What the scripts do

All under `mail/provision/`, run in order by `run-all.sh`. Every script
checks current state before changing anything, so re-running the whole set
is safe — the only side effect of a clean re-run is confirming nothing
needed to change.

| Script                                                                                         | Does                                                                                                                                                                                                                                             |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `00-harden-ssh.sh`                                                                             | Writes an sshd drop-in forcing key-only auth (`PasswordAuthentication no`, `PermitRootLogin prohibit-password`) and reloads sshd if it changed.                                                                                                  |
| `10-harden-updates-fail2ban.sh`                                                                | Installs `unattended-upgrades` + `fail2ban` if missing, writes this repo's own `20auto-upgrades` and `jail.local`, enables both services.                                                                                                        |
| `20-install-docker.sh`                                                                         | Installs Docker CE from Docker's own apt repo (trixie has no current `docker.io` package). No-ops entirely once Docker is present and running.                                                                                                   |
| `docker-compose.yml`                                                                           | Pins `stalwartlabs/stalwart:v0.16.17`. Publishes 25/443/465/587/993 on all interfaces (matching `mail/firewall.ts` exactly) and 8080 on `127.0.0.1` only.                                                                                        |
| `30-deploy-stalwart.sh`                                                                        | Copies the compose file to `/opt/stalwart` and runs `docker compose up -d`; waits for the container's own healthcheck.                                                                                                                           |
| `40-configure-stalwart.sh` / `configure_stalwart.py`                                           | Reconciles Stalwart's _own_ settings (see below) via its JMAP-style management API — network listeners, the ACME provider, the domain's SAN list and ACME provider reference, HTTP access control, and the log tracer.                           |
| `50-provision-mailboxes.sh` / `provision_mailboxes.py`                                         | Creates branchLeft's mailboxes (`MAILBOXES`) and the role-address Sieve forwarding scripts (`ROLE_ADDRESSES`). See "Mailbox provisioning" below.                                                                                                 |
| `60-provision-website-submission-credential.sh` / `provision_website_submission_credential.py` | Creates the website contact form's dedicated, submission-only SMTP credential (send-as `info@`). See "Website submission credential" below.                                                                                                      |
| `61-provision-blog-submission-credential.sh` / `provision_website_submission_credential.py`    | Same script as `60-...sh`, parameterised via environment variables for the blog's dedicated, submission-only SMTP credential (send-as `blog@`) instead. See "Blog submission credential" below.                                                  |
| `62-provision-shim-submission-credential.sh` / `provision_website_submission_credential.py`    | Same script again, parameterised for the mailgun-shim's own bulk-mail submission credential (send-as `blog@`, independently revocable from `61`'s transactional one). See "Mailgun shim (bulk mail)" below.                                      |
| `63-deploy-mailgun-shim.sh` / `render_shim_env.py`                                             | Installs and starts the mailgun-shim + Caddy compose stack (`shim-compose.yml`, `Caddyfile`) behind TLS on `8443`. See "Mailgun shim (bulk mail)" below.                                                                                         |
| `65-install-local-resolver.sh`                                                                 | Installs `unbound` as a loopback-only, fully recursive resolver (no forwarders) so DNSBL queries originate from mx1's own IP. Leaves `/etc/resolv.conf` alone. See "Local recursive resolver" below.                                             |
| `70-schedule-dnsbl-check.sh`                                                                   | Idempotently installs the hourly `/etc/cron.d/dnsbl-check` entry that runs `check_dnsbl_blocklist.py`. See "DNSBL blocklist monitoring" below.                                                                                                   |
| `check_dnsbl_blocklist.py`                                                                     | Not part of `run-all.sh` directly (it's what the cron entry above runs) — checks mx1's IP against five DNSBLs, alerting on any listing. `--status` prints the last recorded result without querying DNS. See "DNSBL blocklist monitoring" below. |
| `rotate_admin_credential.py`                                                                   | Not part of `run-all.sh` — a standalone, on-demand rotation for the admin credential. See "Rotating the admin credential" below.                                                                                                                 |
| `list_and_clear_blocked_ips.py`                                                                | Not part of `run-all.sh` — lists (`--list-only`), and clears specific (`--ip`, repeatable) or all (`--all`) IPs Stalwart's own scan-ban has blocked. See "Scan-ban" below.                                                                       |
| `trigger_acme_renewal.py`                                                                      | Not part of `run-all.sh` — manually triggers a certificate renewal check. See "What remains owner-gated" below; normally unnecessary, since renewal is self-scheduled.                                                                           |

Run the whole set:

```bash
scp -r mail/provision root@<mail-host>:/root/mail-provision
ssh root@<mail-host> 'chmod +x /root/mail-provision/*.sh /root/mail-provision/*.py && /root/mail-provision/run-all.sh'
```

(No CI/CD path deploys this. `.github/workflows/ci.yml`'s `mail-typecheck`
job type-checks the Pulumi program and its `mail-provision-checks` job
shellchecks these scripts and runs their unit tests, but neither holds a
credential or touches the host — this project has no credential CI can hold.
Deploying is a manual `scp` + `ssh`, the same posture as the Pulumi side.)

## Why a Python script, not a TOML file, is "config-as-code" here

Stalwart is often described as offering "TOML config-as-code". That is **not
quite what the installed version (0.16.17) does**. The only file at `/etc/stalwart/` is a
JSON stub naming the storage backend (RocksDB, path, buffer sizes) — a
one-time bootstrap descriptor, not a config file you hand-edit. Every other
setting (network listeners, ACME providers, DKIM keys, domains) is a
database-backed object, read and written through the same JMAP-style
method-call API Stalwart uses for email itself (`POST /jmap`, methods named
`x:<ObjectType>/get` and `x:<ObjectType>/set` — the `x:` prefix marks a
Stalwart-specific "registry object" rather than a JMAP-standard one like
`Email/get`).

`configure_stalwart.py` is the config-as-code artifact for that reason: it
computes the exact diff between live state and the state this platform
needs (pure functions, unit-tested in `test_configure_stalwart.py` with no
network access), and only issues the JMAP calls a diff actually requires. A
second run against already-reconciled state makes five `get` calls and no
`set` calls at all.

**This matters beyond tidiness**: an earlier version of this script fixed
the "admin app reachable on 443" problem below by changing that listener's
`protocol` to `smtp`, which happened to also silently disable ACME on that
listener and broke every certificate issuance until the mistake was found.
Because the fix now lives in this script rather than as a one-off change
made by hand on the box, a rebuild can't lose it — see "The ACME decision"
below for the incident and the corrected mechanism.

### What it reconciles, and why

Stalwart's own setup wizard (triggered automatically on first boot against
empty volumes) already gets most of this right from the `STALWART_HOSTNAME`
env var alone — it infers `branchleft.co.uk` as the mail domain, generates
two DKIM keys, and registers a Let's Encrypt ACME account with
`challengeType: tls-alpn-01` as its own default (see "The ACME decision"
below — Stalwart picked the same challenge type this brief's own evaluation
landed on, independently). What it does _not_ get right for this host, all
fixed by the script:

1. **The default `https` (443) listener serves the webadmin app**, making
   the admin UI and JMAP internet-reachable on 443 the moment that port
   opens, which this deployment must not do. The listener's `protocol` stays
   `http` (ACME depends on that — see "The ACME decision"); instead the
   script sets the `Http` singleton's `allowedEndpoints` rule to deny any
   request arriving via the `https` listener with `421`. Verified:
   `curl -k https://<host>/` against this listener returns `421`, not a
   302 to `/account`.
2. **No STARTTLS submission (587) listener exists by default**, despite
   587 being in `mail/firewall.ts`'s rule set and in the transactional-mail
   design this platform sends through. The script creates one.
3. **The ACME provider's fields aren't asserted, only assumed correct.**
   Bootstrap happens to default to the right challenge type and directory
   today, but nothing kept that true if a future Stalwart version changed
   its defaults, or if a field drifted from manual testing (this round's
   own postmortem involved a temporary staging-directory provider that had
   to be cleaned up by hand). The script now checks and corrects
   `challengeType`, `directory`, `contact`, `renewBefore`, `maxRetries`
   and `reuseKey` field-by-field, keyed on `directory` since
   `AcmeProvider` objects have no name field.
4. **The DKIM domain's ACME certificate only covers `branchleft.co.uk`**,
   not `mx1.branchleft.co.uk` — the actual hostname every mail listener's
   TLS handshake presents via SNI — and its `acmeProviderId` isn't
   asserted to actually match the provider the script manages. The script
   adds the missing SAN and corrects the provider reference together.

It also switches the log tracer from Stalwart's default (a file under
`/var/log/stalwart/`, a path this deployment never mounts anywhere durable,
so those log lines currently go nowhere) to stdout, so `docker logs
stalwart` shows live activity — this is what let the ACME/TLS evidence
below get captured at all.

Two listeners the wizard creates by default (`pop3s` on 995, `sieve` /
ManageSieve on 4190) are removed — neither protocol is in scope here and
neither port is in `mail/firewall.ts`, so there is no reason to leave the
protocol handler running.

`smtp` (25), `submissions` (465) and `imaps` (993) are left exactly as the
wizard creates them.

## The ACME decision: TLS-ALPN-01

The original planned inbound set (25/465/587/993) includes neither 80 nor
443, but Stalwart's certificate issuance needs an ACME challenge to reach it
somehow. Evaluated against Stalwart's actual
source (`stalwartlabs/stalwart` main, `crates/common/src/network/acme/` and
`crates/common/src/network/tls.rs`), not just its docs:

- **HTTP-01** — needs port 80. Nothing in this design runs an HTTP service
  on 80, and opening it would add a second unrelated port purely for a
  one-time-per-renewal challenge.
- **DNS-01 / DNS-PERSIST-01** — needs a DNS provider Stalwart can write TXT
  records to via API (`crates/registry/src/schema/structs.rs`'s
  `DnsServer` object). The zone is at a registrar with no API, and this is
  not a workaround-able gap: DNS-PERSIST-01 avoids _per-renewal_ DNS writes but still needs one
  real API-driven write to establish the persistent record in the first
  place, per Stalwart's own `AcmeProvider`/`DnsServer` config shape. Ruled
  out, matching the brief's own instinct to avoid it.
- **TLS-ALPN-01** — needs port 443 reachable, nothing else. RFC 8737 fixes
  the CA's validation connection at port 443 specifically (not
  configurable, by any implementation).

**Decided: TLS-ALPN-01.** One port (443), no DNS-provider API dependency,
and it's what Stalwart's own setup wizard already defaults to for this
exact shape of deployment (mail-only, no port 80) — independent
corroboration, not just this brief's own reasoning.

**Corrected mechanism (post-incident — the first version of this section
was wrong about which listener field gates ACME eligibility, and shipping
that mistake broke every issuance attempt until it was found and fixed).**
The `acme-tls/1` ALPN interception itself does run on any _implicit-TLS_
listener (`crates/common/src/network/tls.rs:105-190`) — but interception
is only ever _enabled_ for a listener whose declared `protocol` is
`"http"`. Confirmed from source
(`crates/common/src/network/listen.rs:47,128`):

```rust
let is_https = is_tls && self.protocol == ServerProtocol::Http;
// ...
let enable_acme = (is_https && server.has_acme_tls_providers()).then(|| server.clone());
```

An earlier fix set the 443 listener's `protocol` to `"smtp"` specifically to
keep the webadmin/JMAP app off that public port. That worked for the goal, but
as a side effect `is_https` became `false` for the listener, so `enable_acme`
was `None` for every connection to it — including real validation attempts
from Let's Encrypt. Every TLS-ALPN-01 authorization failed immediately with
`urn:ietf:params:acme:error:unauthorized: Cannot negotiate ALPN protocol
"acme-tls/1" for tls-alpn-01 challenge`: a clean, specific error, but the
repeated failures also tripped Let's Encrypt's failed-authorization rate
limit, which surfaced first and read like the root cause on its own.

**The actual fix keeps the 443 listener's `protocol` as `"http"`** (ACME
eligibility restored) and blocks the webadmin/JMAP app at the HTTP-request
layer instead, via the `Http` singleton's `allowedEndpoints` rule
(`configure_stalwart.py`'s `HTTP_DENY_HTTPS_LISTENER`). Confirmed from
source that this check (`crates/http/src/request.rs`'s
`parse_http_request`, calling `ctx.has_endpoint_access`) runs strictly at
the HTTP-request layer, _after_ `tls.rs`'s ACME interception has already
either served the challenge and closed the connection, or passed a
non-challenge handshake through — so this rule can never interfere with a
real validation, unlike the listener-protocol approach it replaces.

**`Http.useXForwarded` must stay off unless a trusted-proxy allowlist lands
in the same change.** The `421` rule exempts loopback callers, so tunnelled
admin access over `127.0.0.1` keeps working. That setting changes which
address the exemption treats as the caller's, and Stalwart applies no check on
which upstream is entitled to assert it — so turning it on without an
allowlist widens who the exemption covers. Nothing here needs it: this host
has no reverse proxy in front of it.

**Port 443 is in `mail/firewall.ts`** with a comment stating this exact
constraint. The apply:

```bash
cd mail && pulumi preview   # expect: one rule addition (443/tcp), nothing else
cd mail && pulumi up
```

This is the same firewall `RUNBOOK-import-mail-host.md` covers a two-step
import for; 443 is part of the target rule set that runbook's step 6 applies.
If the import has not run at all, 443 lands in the same `pulumi up` that opens
25/465/587/993.

## Mailbox provisioning

`50-provision-mailboxes.sh` runs `provision_mailboxes.py`, which creates real
mailbox accounts — `rob@`, `contact@`, `info@`, `sales@`, `complaints@`,
`abuse@` and `blog@` at `branchleft.co.uk` (`MAILBOXES`) — each with its own
storage, not an alias, and gives each role address (not `rob@`;
`ROLE_ADDRESSES`) a per-mailbox Sieve script that copies inbound mail to
`rob@` without suppressing the original delivery. `blog@` gets a mailbox and
the same copy-forward as the other role addresses; the credential the blog
uses to _send_ mail is a separate app password, see "Blog submission
credential" below.

Any standard IMAP client reads these mailboxes: `<mail-host>` port 993
(SSL/TLS) for IMAP, port 587 (STARTTLS) for submission, username the full
address. There is no autoconfig record, so every client asks for the settings
manually.

### The API shape, and the trap in it

Confirmed from Stalwart's own source (`stalwartlabs/stalwart`), not by
analogy to `configure_stalwart.py`'s listener/domain endpoints, since those
are a different part of the API surface:

- **Mailbox accounts** are a registry object in the same `x:<Type>/get` /
  `x:<Type>/set` family `configure_stalwart.py` already uses —
  `x:Account/set`, `{"@type": "User", "name": <local-part>, "domainId":
<id>, "credentials": {"0": {"@type": "Password", "secret": <password>}}}`.
  The primary address is `name@domain` — Stalwart indexes it as a single
  global-unique `(name, domainId)` composite (`UserAccount::index` in
  `crates/registry/src/schema/structs_impl.rs`), no separate alias entry
  needed. One thing this got wrong on the first pass: `credentials` is a
  `List<Credential>` (`crates/registry/src/types/list.rs`), which serializes
  as a JSON **object** keyed `"0"`, `"1"`, ... — not a JSON array. Sending an
  array is silently the wrong shape for this field family (same convention
  `configure_stalwart.py`'s `subjectAlternativeNames` map already uses, just
  not obviously so from the field's own name).
- **Per-mailbox Sieve scripts are not `x:SieveUserScript`**, despite the
  name. That registry object is an admin-managed _global_ script, included
  by name into any account's own script via Sieve's `:global` extension
  (RFC 6609) — `tests/src/jmap/mail/sieve_script.rs` in Stalwart's own repo
  shows a `SieveUserScript` created under one account affecting delivery for
  an unrelated account, which is the tell. The real per-mailbox mechanism is
  the _standard_ JMAP Sieve capability (`urn:ietf:params:jmap:sieve`,
  `SieveScript/set` — draft-ietf-jmap-sieve, not a Stalwart-specific `x:`
  method): upload the script text as a blob, then create a `SieveScript`
  object referencing that blob, activating it in the same call via
  `onSuccessActivateScript`.

Captured against the live server (ids and blob hashes are this run's, not
stable across a rebuild):

```text
POST /jmap/upload/d/  (Content-Type: application/sieve)
  -> {"accountId": "d", "blobId": "eamcfltw...", "type": "application/sieve", "size": 57}

POST /jmap  {"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:sieve"],
             "methodCalls": [["SieveScript/set", {
               "accountId": "d",
               "create": {"s": {"name": "forward-copy-to-rob", "blobId": "eamcfltw..."}},
               "onSuccessActivateScript": "#s"
             }, "0"]]}
  -> {"created": {"s": {"id": "b", "blobId": "ch7s9x33...", "isActive": true}}}
```

Note the blob id changes between upload and the created script — the
temporary upload blob gets promoted to a permanent one; reconciliation reads
back the _script's_ `blobId`, not the upload response's.

### Idempotency

`provision_mailboxes.py` follows `configure_stalwart.py`'s diff-before-write
pattern: an existing mailbox is never touched (this script does not rotate
passwords — that's `rotate_admin_credential.py`'s model, not this one's) and
each role's script is left alone once its content matches and it's active,
corrected otherwise (content drift, not just presence, is checked — the
script's content is downloaded and compared, not assumed from existence
alone). Run twice against a fully-reconciled box:

```console
$ ssh root@<mail-host> /root/mail-provision/50-provision-mailboxes.sh
provision_mailboxes: created mailbox info@branchleft.co.uk (id e)
provision_mailboxes: created mailbox sales@branchleft.co.uk (id f)
provision_mailboxes: created mailbox complaints@branchleft.co.uk (id g)
provision_mailboxes: forwarding script for contact@branchleft.co.uk already up to date, no-op
provision_mailboxes: created and activated the forwarding script for info@branchleft.co.uk
provision_mailboxes: created and activated the forwarding script for sales@branchleft.co.uk
provision_mailboxes: created and activated the forwarding script for complaints@branchleft.co.uk

$ ssh root@<mail-host> /root/mail-provision/50-provision-mailboxes.sh
provision_mailboxes: all five mailboxes already exist, no-op
provision_mailboxes: forwarding script for contact@branchleft.co.uk already up to date, no-op
provision_mailboxes: forwarding script for info@branchleft.co.uk already up to date, no-op
provision_mailboxes: forwarding script for sales@branchleft.co.uk already up to date, no-op
provision_mailboxes: forwarding script for complaints@branchleft.co.uk already up to date, no-op
provision_mailboxes: nothing left to reconcile
```

(`rob@` and `contact@` pre-existed from earlier API exploration, so the first
run above shows exactly the mixed "some already there, some new" case a real
re-run hits.)

### Live validation

Forwarding is proven rather than assumed: send a real message to each role
address and confirm it lands both there and in `rob@`. Done via
authenticated SMTP submission against
`127.0.0.1:465` on mx1 (the same listener external clients would use — see
`mail/firewall.ts`), authenticated as `rob@branchleft.co.uk`, one message per
role address with a unique per-message nonce in the subject so delivery
can be attributed unambiguously. Delivery is confirmed by an
admin-impersonated `Email/query` + `Email/get` against each mailbox (the
admin credential's `Impersonate` permission covers standard JMAP mail
methods the same way it covers the `x:` registry ones) — not IMAP, since the
JMAP admin API this repo already depends on for everything else covers it
without a second protocol. Result, all four pairs:

| Role address | Landed in role mailbox | Copy landed in rob@ |
| ------------ | ---------------------- | ------------------- |
| contact@     | yes                    | yes                 |
| info@        | yes                    | yes                 |
| sales@       | yes                    | yes                 |
| complaints@  | yes                    | yes                 |

`rob@` received exactly the four expected copies and nothing unaccounted
for; each role mailbox received exactly its own test message. No credential
material was printed at any point in this process — the mailbox password
used to authenticate was read from `/root/.stalwart-mailbox-credentials` and
handed directly to `smtplib`, never echoed.

## The MX cutover

Nothing in this repository declares DNS: `branchleft.co.uk`'s zone is manual at
the registrar, and the cutover is a hand-made change there. What follows is the
shape of it, not a record of any particular zone's contents.

Audit the zone first, against at least two public resolvers, over both UDP and
TCP — `+tcp` rules out a UDP-truncated answer hiding additional records:

```bash
dig +short MX branchleft.co.uk
dig +short +tcp MX branchleft.co.uk
dig +short TXT branchleft.co.uk
dig +short TXT _dmarc.branchleft.co.uk
dig +short CAA branchleft.co.uk
```

The change itself is one record removed and one added:

| Record | Target                     |
| ------ | -------------------------- |
| MX     | `10 mx1.branchleft.co.uk.` |

**SPF is not part of this step.** Receiving on the new host is independent of
where mail is sent from; changing SPF before the outbound path moves would
break sending for no gain.

### Before treating the cutover as safe

**Wait a full TTL from the moment the record changes, regardless of what
traffic looks like.** Traffic counters are not a safe signal: what they measure
is bot traffic turning over, not resolver caches expiring, and they read as
drained well before it is actually safe. A separate cutover on this platform
also found a record type nobody was tracking still routing real traffic into a
path believed retired, a full day later.

**Check the outgoing provider's own admin console** for any mailbox, alias or
group at the domain beyond the ones provisioned here. MX is domain-wide, so a
repoint silently stops inbound mail for anything that provider still handles.

## Website submission credential

`provision_website_submission_credential.py` is parameterised via three
environment variables — `SEND_AS_LOCAL`, `CREDENTIAL_LABEL`,
`APP_PASSWORD_DESCRIPTION` — so the same script provisions every
submission-only credential this platform needs. This section covers the
mechanism in full, using the website's credential (`60-...sh`, the original,
default-parameterised invocation) as the worked example; "Blog submission
credential" below covers the second invocation (`61-...sh`) and only the
parts that differ.

`60-provision-website-submission-credential.sh` runs
`provision_website_submission_credential.py` with its default parameters,
creating a dedicated SMTP credential for the website's contact form:
it can authenticate and send as `info@branchleft.co.uk`, and nothing else —
it cannot read `info@`'s mailbox, or any mailbox, via IMAP. This is what
fills `CONTACT_SMTP_USER`/`CONTACT_SMTP_PASSWORD` in the website repo's
production Pulumi config; setting that config is the platform owner's, not this repo's (see
"Retrieving the credential" below).

### Why a credential on the existing info@ account, not a new one

Two things were checked against Stalwart's own source before building this,
not assumed by analogy to mailbox-account creation:

1. **No separate "submission-only" principal type exists.** The registry's
   `AccountType` enum is only `User`/`Group`
   (`crates/registry/src/schema/enums.rs`). A brand-new account was the
   first design tried — call it `svc-website-contact`, restricted to send
   only as `info@branchleft.co.uk` via an `EmailAlias`. **It doesn't work**:
   both an account's own primary address and every `EmailAlias` register
   the _same_ global-unique `(name, domainId)` index
   (`Property::Email` in `UserAccount::index` and `EmailAlias::index`,
   `crates/registry/src/schema/structs_impl.rs`) — and `info@branchleft.co.uk`
   is already claimed as the real `info@` mailbox's own primary address. A
   second account can't also claim it as an alias; Stalwart rejects the
   collision.
2. **The mechanism that does work is a _secondary credential_** — an "app
   password" — **attached to the existing `info@` account**, created via
   `x:AppPassword/set` (a distinct registry object, `ObjectType::AppPassword`,
   from the account's own `credentials` list — passing a secondary
   credential there directly is explicitly rejected: "Secondary credentials
   cannot be set directly",
   `crates/jmap/src/registry/mapping/principal.rs`). The server generates
   and returns the secret exactly once, in the create response — same as
   any real app-password flow, it can never be retrieved again.

This sidesteps the alias collision entirely: authenticating with this app
password already makes `authenticated_as` equal to `info@branchleft.co.uk`
(it's the same account), so Stalwart's sender-restriction check
(`must_match_sender`, next section) is satisfied trivially, no alias needed.
The account's _own_ password credential (the real one, from "Mailbox
provisioning") is completely untouched by any of this — a human can still
IMAP into `info@` normally with it, verified live (see below).

### Sender restriction: must-match-sender

The generic concept here is a "sender-login map". Stalwart's actual mechanism
is `MtaStageAuth`'s `mustMatchSender` expression
(`crates/common/src/config/smtp/session.rs`,
`crates/smtp/src/inbound/mail.rs`). **It already defaults to `true`** when
unconfigured (`MtaStageAuth::ctx_must_match_sender`'s default expression,
`crates/registry/src/schema/structs_impl.rs`) — nothing on this box has
ever overridden it, and nothing here does either, so no global config change
is needed. The check: on `MAIL FROM`, if the address doesn't equal
`authenticated_as` and isn't in `authenticated_emails()` (the account's own
primary address plus its enabled aliases), the session gets `501 5.5.4 You
are not allowed to send from this address.` — verified live, below.

### IMAP is blocked for this credential specifically, not the account

An app password's own `permissions` field
(`CredentialPermissions::Disable`) clears listed permissions from a _copy_
of the account's effective permissions, scoped to sessions authenticated
with that one credential (`crates/common/src/auth/access_token.rs`) — every
other credential on the same account (here, `info@`'s real password) is
unaffected. This credential disables exactly `imapAuthenticate` — the
permission IMAP's own `LOGIN`/`AUTHENTICATE` handlers assert before
anything else runs (`crates/imap/src/op/authenticate.rs`,
`crates/imap/src/op/login.rs` — both converge on the same
`Session::authenticate()`, so both commands are blocked identically).

### Live validation

All captured against the actual box, using the credential this script
itself generated (not a hand-poked one — the credential was destroyed and
recreated via a real, fresh `60-provision-website-submission-credential.sh`
run specifically to prove this):

- **SMTP submission succeeds.** Authenticated on 587/STARTTLS as
  `info@branchleft.co.uk` with this app password, sent a real message —
  accepted and delivered.
- **Sending as a different address is rejected.** Same session,
  `MAIL FROM:<contact@branchleft.co.uk>` → `501 5.5.4 You are not allowed
to send from this address.`
- **IMAP login is rejected, distinctly from a wrong password.** A genuinely
  wrong password against `info@branchleft.co.uk` gets a normal tagged
  response: `a1 NO [AUTHENTICATIONFAILED] Authentication failed`. This
  credential's _correct_ password instead gets the connection closed
  immediately with no response at all — a stricter, different rejection,
  confirming the permission check is what's firing, not a credential
  mismatch.
- **The real `info@` password is unaffected.** IMAP login with `info@`'s
  own password (from "Mailbox provisioning") succeeds normally:
  `a1 OK [...] Authentication successful`.
- **Idempotency**: `60-provision-website-submission-credential.sh` run
  twice from a clean slate (credential destroyed, local record deleted)
  — first run creates it, second run:

```console
  provision_website_submission_credential: already provisioned, no-op
```

### Retrieving the credential

Stalwart returns the secret exactly once, in the create response, and
`provision_website_submission_credential.py` persists it to the root-only
service-credentials file named by its own `CREDENTIALS_PATH` constant, one
line per credential keyed by `CREDENTIAL_LABEL`.

The operator reads it from that file directly, on the host, and pastes it into
wherever the sending service reads its configuration from. It never touches
this repository, a pull request or a chat transcript. Submit via 587
(STARTTLS) or 465 (implicit TLS), matching `mail/firewall.ts`'s open ports.

### If the create response is lost (the credential-loss-analogous case)

`provision_mailboxes.py`'s credential-loss fix (persist the secret to disk
_before_ the network call that sets it) doesn't transfer directly here —
Stalwart, not this script, generates the app-password secret, so there's
nothing to persist until the create call actually returns. If that
response is lost after Stalwart already applied the create (crash, dropped
connection), the plaintext is gone for good — same as any real app-password
UX. `provision_website_submission_credential.py` detects this state
(a credential with the expected description exists remotely, but nothing
is recorded in `/root/.stalwart-service-credentials`) and exits non-zero
with a clear message instead of silently reporting a no-op. Recovery is
manual: destroy the orphaned credential via `x:AppPassword/set`
(`{"accountId": "<info@'s id>", "destroy": ["<credential id from
x:AppPassword/get>"]}`) and re-run the script for a fresh one.

## Blog submission credential

`61-provision-blog-submission-credential.sh` runs the same
`provision_website_submission_credential.py` as `60-...sh` above, with
`SEND_AS_LOCAL=blog`, `CREDENTIAL_LABEL=blog-ghost-smtp` and
`APP_PASSWORD_DESCRIPTION=blog-ghost-transactional-submission` instead of
the website's defaults. Everything in "Website submission credential" above
— the app-password mechanism, why it's a credential on an existing account
rather than a new one, `mustMatchSender`, the IMAP-disable scope, the
idempotency key, and the orphaned-credential recovery path — applies
identically, substituting `blog@branchleft.co.uk` for `info@branchleft.co.uk`
throughout. `50-provision-mailboxes.sh` must have already created the
`blog@` account (it runs first in `run-all.sh`) or this script's account
lookup fails with a clear "expected provision_mailboxes.py to have already
created it" error.

This credential is what the blog (Ghost on Cloud Run) authenticates with to
send transactional mail as `blog@branchleft.co.uk` over SMTP AUTH on 587 —
Stalwart's default `mustMatchSender` requires the authenticated account to
match `MAIL FROM`, hence a real account rather than a bare alias. Retrieved
the same way as the website's credential (see "Retrieving the credential"
above), substituting the label.

## Mailgun shim (bulk mail)

Puts the mailgun-shim (a separate service, image built by a parallel PR)
on mx1 behind its own TLS front, so Ghost (on GCP Cloud Run) can reach it
at `https://mx1.branchleft.co.uk:8443` for bulk mail, without touching
Stalwart's own listeners or ACME in any way. Three new artifacts under
`mail/provision/`:

- `shim-compose.yml` — a compose project separate from Stalwart's own
  (`docker-compose.yml`): the `mailgun-shim` service (host-loopback
  `127.0.0.1:8825`, matching Stalwart's own `127.0.0.1:8080` admin-port
  convention) and a `caddy` service terminating TLS on `8443`, publishing
  `80` for ACME HTTP-01 only. Never publishes `443`.
- `Caddyfile` — Caddy's site config: `https_port 8443` plus
  `disable_tlsalpn_challenge` on its ACME issuer, so this Caddy instance can
  structurally never attempt (let alone complete) a TLS-ALPN-01 handshake
  on any port, and never binds `443` at all.
- `62-provision-shim-submission-credential.sh` — a third invocation of
  `provision_website_submission_credential.py` (see "Website submission
  credential" above), send-as `blog@`, labelled `blog-shim-bulk-submission`
  — independently revocable from `61`'s transactional `blog-ghost-smtp`
  credential, so retiring or rotating the shim's bulk-mail path never
  touches transactional mail or vice versa.
- `63-deploy-mailgun-shim.sh` / `render_shim_env.py` — installs the compose
  file and Caddyfile, seeds `/var/lib/mailgun-shim/throttle.json` only if
  absent, renders `/etc/mailgun-shim/env` (mode 600) from `62`'s credential,
  and brings the stack up.

### ACME coexistence

Stalwart's ACME is TLS-ALPN-01 and owns port 443; Caddy's ACME is HTTP-01
and owns port 80; the Caddyfile's `https_port 8443` +
`disable_tlsalpn_challenge` make it impossible for Caddy to touch 443,
including on renewal.

`shim-compose.yml` backs this structurally, not just by convention: it
publishes only `80` and `8443` to the host, so even if Caddy's own
automatic-HTTPS logic ever considered port 443 internally, there is no
published mapping for it to reach the host network on. Verified against
Caddy's own documentation (not assumed from this brief) that `https_port`
is an internal-listener setting, not a client-facing one, and that
`disable_tlsalpn_challenge` is a real, documented subdirective of an
`acme` issuer block.

### Filling in the image digest

The mailgun-shim image (`ghcr.io/branchleft/mailgun-shim`) is built by a
shim's own repository, so `shim-compose.yml` ships with a placeholder until a
real digest exists:

```yaml
image: ghcr.io/branchleft/mailgun-shim@sha256:IMAGE_DIGEST_PLACEHOLDER
```

Once that image has a real published digest, edit the line in place (exact
`sed`, run from a checkout of this repo, or hand-edit — either way, commit
the result through the normal PR flow, the same as any other change to
`mail/`):

```bash
sed -i '' 's/sha256:IMAGE_DIGEST_PLACEHOLDER/sha256:<the real digest>/' mail/provision/shim-compose.yml
```

(`sed -i ''` is the macOS/BSD form; drop the empty `''` argument on Linux.)
`63-deploy-mailgun-shim.sh` refuses to run — loudly, before touching
anything — while the installed copy of `shim-compose.yml` still has an
`image:` line whose digest reads as a placeholder. The guard is scoped to
`image:` lines specifically, not a whole-file match: an earlier version of
this check grepped the entire file for the literal string `PLACEHOLDER`,
which also matched this section's own explanatory header comment inside
`shim-compose.yml` — since the `sed` above only ever rewrites the `image:`
line, that file-wide form kept refusing to deploy forever, even after a
real digest had been filled in. Reworded to avoid the false positive at
both ends: the header comment does not spell out the placeholder token, and
the guard only ever looks at `image:` lines:

```bash
if grep -qE '^\s*image:.*PLACEHOLDER' "$DEST_COMPOSE"; then
    echo "63-deploy-mailgun-shim: $DEST_COMPOSE has an image line with an unfilled PLACEHOLDER digest -- fill it in before deploying (see mail/RUNBOOK-mx1-provision.md's 'Mailgun shim' section)" >&2
    exit 1
fi
```

Verify by reproducing the operator sequence against a scratch copy: run the
`sed` above against the pristine file, then run the guard's own `grep -qE`
against both. Pristine matches (refuses to deploy, correctly); the rewritten
copy does not.

The `caddy` image is pinned to a real digest, resolved against the registry
API — see `shim-compose.yml`'s own header comment for how. The same guard
covers it, in case a future edit reverts that pin to a placeholder.

### Deploy / upgrade procedure

Re-running `63-deploy-mailgun-shim.sh` is the whole procedure, for a first
deploy and for every later change (a new compose file, a new Caddyfile, a
rotated credential via a fresh `62` run, or a new shim image digest):

```bash
scp -i ~/.ssh/id_ed25519_hetzner -r mail/provision root@mx1.branchleft.co.uk:/root/mail-provision
ssh root@<mail-host> 'chmod +x /root/mail-provision/*.sh /root/mail-provision/*.py && /root/mail-provision/62-provision-shim-submission-credential.sh && /root/mail-provision/63-deploy-mailgun-shim.sh'
```

### Idempotence

Safe to run twice in a row, by construction, not just by convention:

- Installing `shim-compose.yml`/`Caddyfile` to `/etc/mailgun-shim/` is a
  byte-compare-then-copy (identical pattern to `30-deploy-stalwart.sh`) —
  a re-run with no source changes copies nothing.
- `/var/lib/mailgun-shim/throttle.json` is seeded only if absent. Once it
  exists, `63-deploy-mailgun-shim.sh` never writes it again — an
  operator's own throttle tuning (see "Throttle tuning" below) survives
  every future re-run.
- `/etc/mailgun-shim/env` is re-rendered from `62`'s recorded credential on
  every run, atomically (a temp file in the same directory, then
  `os.replace`) — a crash or disk-full mid-write can never leave a
  truncated env file behind, and re-rendering the same credential always
  produces byte-identical output.
- `docker compose -p mailgun-shim -f shim-compose.yml up -d --wait` is
  itself a no-op once the running containers already match the compose
  file — the same property `30-deploy-stalwart.sh` relies on for
  Stalwart's own compose file.

### Tenant registration

The shim tracks registered sending tenants itself. Register the blog:

```bash
ssh root@<mail-host> 'docker compose -p mailgun-shim -f /etc/mailgun-shim/shim-compose.yml exec mailgun-shim node dist/cli.js register blog.branchleft.co.uk'
```

This prints an API key exactly once. Where it goes next (Ghost's own
config, a secret store) is the platform owner's call — it never belongs in
this repo, a PR, or a chat transcript.

### Throttle tuning

Edit `/var/lib/mailgun-shim/throttle.json` directly on the box; no restart
needed (the shim reads it live, per the image's own contract):

```bash
ssh root@<mail-host> 'vi /var/lib/mailgun-shim/throttle.json'
```

### Log access

```bash
ssh root@<mail-host> 'docker compose -p mailgun-shim -f /etc/mailgun-shim/shim-compose.yml logs -f mailgun-shim'
ssh root@<mail-host> 'docker compose -p mailgun-shim -f /etc/mailgun-shim/shim-compose.yml logs -f caddy'
```

### Backup

No dedicated backup job for the shim's own SQLite state
(`/var/lib/mailgun-shim/shim.db`) — deliberately deferred, not an
oversight. Coverage today is the WAL-mode SQLite file itself (crash-safe on
its own) plus Hetzner's existing server-level backups for mx1 (already
enabled, see `mx1`'s `backups: true` in `server.ts`); the shim's own
send path is at-least-once, so a snapshot restore that loses a few
in-flight seconds of queue state is tolerated by design, not a correctness
gap. A dedicated `sqlite3 .backup` cron is a reasonable follow-up if
retention needs ever exceed what the server-level snapshot cadence gives —
not built here.

### Owner-execution sequence

In order, once the image digest is real:

1. `cd mail && pulumi preview` — expect exactly two rule additions (80/tcp,
   8443/tcp), nothing else; then `pulumi up`.
2. Fill in the real `IMAGE_DIGEST_PLACEHOLDER` in `shim-compose.yml` (see
   "Filling in the image digest" above) and land that as its own commit.
3. Run the deploy procedure above (`62` then `63`).
4. Run the tenant registration command above and hand the printed API key to
   wherever the sending application reads it from.

## DNSBL blocklist monitoring

A listed IP silently kills deliverability for everyone sending through this
host, and this is the check that catches it instead of waiting for a
complaint. `check_dnsbl_blocklist.py` resolves the mail host's own address and
queries it against five DNSBLs every hour via `/etc/cron.d/dnsbl-check`
(installed idempotently by `70-schedule-dnsbl-check.sh`, part of
`run-all.sh`):

| List                            | Zone                     |
| ------------------------------- | ------------------------ |
| Spamhaus ZEN                    | `zen.spamhaus.org`       |
| Barracuda Reputation Block List | `b.barracudacentral.org` |
| SpamCop Blocking List           | `bl.spamcop.net`         |
| SORBS                           | `dnsbl.sorbs.net`        |
| UCEPROTECT Level 1              | `dnsbl-1.uceprotect.net` |

### Query mechanics, verified per-list rather than assumed identical

Every list above uses the same reversed-octet query — `<reversed IP>.<zone>`,
answered either NXDOMAIN (not listed) or one or more A records in
`127.0.0.0/8` (listed; the exact last octet encodes the sub-list/reason and
differs per list — e.g. Spamhaus's `127.0.0.2`/`.4`/`.10` mean SBL/XBL/PBL
respectively — the script logs the raw codes but doesn't need to interpret
them further). Confirmed against each list's own documentation, not assumed
from one list to the next, and then checked live:

```console
$ dig +short A 2.0.0.127.zen.spamhaus.org        # industry-standard "always listed" test address
127.0.0.2
127.0.0.10
127.0.0.4
$ dig +short A 1.1.1.1.zen.spamhaus.org           # well-known clean IP
                                                    # (empty = NXDOMAIN = not listed)
$ dig +short A <mail host's IP, reversed>.zen.spamhaus.org
                                                    # (empty = not listed)
```

Same pattern (test address listed, `1.1.1.1` and the mail host's own address
clean) confirmed live for Barracuda, SpamCop and UCEPROTECT Level 1.

**Spamhaus also documents a distinct error range**, `127.255.255.0/24`,
that is a _query_ error (e.g. "this resolver is a public/open one and is
blocked" — Spamhaus's free DNSBL access is conditioned on queries coming
from a mail server's own resolver, not a shared public one like Google or
Cloudflare DNS) — not a reputation signal, and must never be read as one.
`check_dnsbl_blocklist.py` checks for this prefix before treating any
address as a listing, applied to every zone defensively since no other list
in this set is documented to use that range for a real listing.

**That guard does fire on ZEN specifically** — the sentinel and the target
both come back `127.255.255.254` when queried through the host provider's
default resolvers, and identically through `8.8.8.8` and `1.1.1.1`. All
three are shared resolvers carrying far more DNSBL traffic than Spamhaus's
free tier allows from one source, so ZEN reports inconclusive every hour
rather than clean: correct behaviour from the check, but no signal from the
single most important list in the set. "Local recursive resolver" below is
the fix.

**SORBS is currently dead — a real, live finding, not a hypothetical.**
`dnsbl.sorbs.net` has no DNS delegation at all:

```console
$ dig SOA dnsbl.sorbs.net
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN
;; AUTHORITY SECTION:
net.  900  IN  SOA  a.gtld-servers.net. nstld.verisign-grs.com. ...
```

The `net.` SOA in the authority section means the _.net_ TLD servers have no
delegation for `sorbs.net` at all — every query against it, including the
industry-standard test address, returns NXDOMAIN. Without a guard, a naive
"NXDOMAIN means not listed" check would report SORBS as permanently clean
while providing zero actual signal. The self-test below is what catches
this — for SORBS specifically today, and for any other list in this set if
it ever goes the same way.

### The self-test: why "not listed" is only trusted after the zone proves it's answering

Before trusting a "not listed" result for the real target IP, every run
first queries each zone for the industry-standard always-listed test
address (`127.0.0.2`, confirmed live above for four of the five lists). If
that sentinel query doesn't come back listed, the zone isn't providing a
real signal right now — dead (SORBS, today), unreachable, or rate-limiting
this host — and that list's result for this run is reported
**inconclusive**, not folded into "clean". This is the concrete answer to
"a check that always reports clean regardless of input is worse than no
check": the self-test runs on a live target every hour, not just once at
review time, so a zone that goes dark later is caught the same way SORBS's
state was caught while this was written.

### Local recursive resolver

`65-install-local-resolver.sh` installs `unbound` on mx1, listening on
`127.0.0.1` and `::1` only, and `check_dnsbl_blocklist.py` addresses it
explicitly (`DNSBL_RESOLVER_ADDRESS`, default `127.0.0.1`) instead of going
through the system resolver.

**No forwarders — that is the whole point.** Forwarding to any shared
resolver, the host provider's or a public one, puts the query back on an
address Spamhaus rate-limits, which is the failure being fixed. unbound
recurses from the root servers itself, so queries reach Spamhaus from the mail
host's own address, whose DNSBL volume is a handful of queries an hour. Anyone editing
`/etc/unbound/unbound.conf.d/10-branchleft-local-recursive.conf` should
treat "add a forwarder" as reverting this change.

**`/etc/resolv.conf` is deliberately untouched.** Everything else on the box
— Stalwart, Docker, apt, ACME — keeps resolving exactly as it did, so the
blast radius of this change is the DNSBL check and nothing else. Debian's
`unbound` package ships `unbound-resolvconf.service`, which would repoint
the whole box at unbound on install; the script masks that unit _before_
installing and verifies `/etc/resolv.conf` is byte-identical afterwards,
failing loudly if it is not.

Moving the system resolver over to unbound later is a reasonable follow-up —
it would give the whole box DNSSEC validation and a warm cache — but it is a
separate change with a separate blast radius (a broken unbound would then
take mail delivery with it, not just the hourly check), and it should be
made deliberately rather than as a side effect of this one.

If unbound is stopped, broken, or has no path to the root servers, every
lookup fails, the per-zone self-test fails with it, and the run reports
**inconclusive** for every list. It cannot produce a false "clean".

Port 53 is not exposed: the listeners are loopback-only, and `mail/firewall.ts`
was not touched by this change.

```bash
# Is the resolver up, and does recursion work?
ssh root@<mail-host> 'systemctl is-active unbound && dig +short @127.0.0.1 A deb.debian.org'

# Does Spamhaus answer this host for real? The industry-standard test point
# must come back in the 127.0.0.2 range, NOT 127.255.255.254:
ssh root@<mail-host> 'dig +short @127.0.0.1 A 2.0.0.127.zen.spamhaus.org'
```

### Alerting

No existing alerting/webhook channel exists anywhere else in this repo
(checked — no cron, systemd timer, or scheduling pattern currently exists
in `shared-infra` at all, so there was no existing convention to reuse for
either the schedule or the alert path). The chosen mechanism, in order of
what it costs to build and run:

- **Log level is the signal.** A routine "still clean" run logs one `INFO`
  line. Anything needing attention — a new or ongoing listing, or an
  inconclusive check (lookup failure or a zone that failed its self-test) —
  logs at `ERROR`, one line per finding. The two are never mixed into the
  same level, so `journalctl -t dnsbl-check -p err` on mx1 is a direct
  answer to "does anything need attention", not something a human has to
  parse out of routine noise.
- **journald**, because it's already the logging fabric this box relies on
  for everything else operational (`fail2ban`'s own jail backend is
  `systemd`; `unattended-upgrades` and `fail2ban` are both `systemctl`-managed
  services whose status is read the same way) — reusing it needed no new
  infrastructure, no new credential, and no recurring spend. The script logs
  via Python's stdlib `logging.handlers.SysLogHandler(address="/dev/log")`,
  which Debian's journald accepts as a standard syslog socket. If `/dev/log`
  isn't reachable (confirmed live during development on a non-Linux
  machine — the fallback path is exercised, not just theoretical) it falls
  back to stderr, which cron's own redirect (below) still captures.
- **A cron-redirected log file as a backstop**, `/var/log/dnsbl-check.cron.log`,
  for the case where something goes wrong before the script's own logger is
  even configured (e.g. a Python import failure) — journald would never see
  that at all otherwise. No rotation is configured; expected volume is a
  handful of lines a month at most (one line per run only when something's
  actionable), revisit if that assumption turns out wrong.
- **No email, no webhook, no new external service.** Explicitly considered
  and rejected: mx1 hosts `rob@branchleft.co.uk` now, which makes
  cron's traditional `MAILTO` mechanism tempting, but wiring cron's local
  mail delivery to Stalwart would mean touching mx1's actual mail-serving
  config (authenticated SMTP submission from a local MTA, or a local
  sendmail shim) — out of scope here. A genuine push notification (a webhook,
  a paging service) would be a new external service and either a new
  credential or recurring spend, so it is flagged rather than built.

**This is a judgement call left deliberately open.** journald-based alerting
means somebody has to go looking rather than being pushed to. Since
deliverability is what this check protects, an hourly `journalctl -t
dnsbl-check -p err -b` spot-check, or a small forwarder that pushes journald
`ERROR` lines from this identifier somewhere more proactive, is worth adding
before real tenant traffic depends on it.

### Checking current status manually

```bash
# Read the last recorded state without querying DNS again:
ssh root@<mail-host> 'python3 /root/mail-provision/check_dnsbl_blocklist.py --status'

# Force a fresh live check right now:
ssh root@<mail-host> 'python3 /root/mail-provision/check_dnsbl_blocklist.py'

# Anything the automated hourly run has flagged as needing attention:
ssh root@<mail-host> 'journalctl -t dnsbl-check -p err -b'
```

`--status` reads `/root/.dnsbl-check-state.json` (not secret — just the last
verdict per list) without touching the network; the bare invocation always
performs a live check and exits non-zero if anything needs attention, the
same way the hourly cron run does.

### If a listing is found

This script deliberately does not attempt to guess or summarize each list's
delisting process — those are list-specific, change without notice, and
delisting is a human escalation rather than an automated one — the requests
typically need a human-submitted form, sometimes region- or
account-specific. Each alert
line names the list and links directly to that list's own current process,
also collected here for convenience:

| List                            | Start here                                                                                                                              |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Spamhaus ZEN                    | <https://check.spamhaus.org/>                                                                                                           |
| Barracuda Reputation Block List | <https://www.barracudacentral.org/rbl/removal-request>                                                                                  |
| SpamCop Blocking List           | <https://www.spamcop.net/bl.shtml>                                                                                                      |
| SORBS                           | <http://www.sorbs.net/lookup.shtml> (see "SORBS is currently dead" above — this list is not currently providing real signal either way) |
| UCEPROTECT Level 1              | <http://www.uceprotect.net/en/rblcheck.php>                                                                                             |

## Secrets: what is secret, and where it lives

**Nothing secret is in this repository, and nothing here ever prints one.**
Every secret this platform uses is generated on the host — by Stalwart itself
for the admin password and the DKIM keys, by `provision_mailboxes.py` for the
mailbox passwords, by Stalwart again for each submission-only app password —
and written to a root-only file whose path is a constant in the script that
writes it. Read those constants rather than a second list here, which is the
kind of index that goes stale and then gets trusted.

Wiping `/opt/stalwart`'s volumes regenerates all of them with new random
values, and **invalidates the DKIM records published in DNS**. Delete the
recorded-credential files first, so each script re-detects a fresh server
rather than trying stale credentials against one that no longer recognises
them.

### Rotating the admin credential

Use `mail/provision/rotate_admin_credential.py` any time the credential in
`/root/.stalwart-admin-credentials` needs rotating — suspected exposure
(e.g. it ended up somewhere it shouldn't have, such as pasted into a
review transcript), routine hygiene, or a handover:

```bash
ssh root@<mail-host> 'python3 /root/mail-provision/rotate_admin_credential.py'
```

It generates a new secret on-box, applies it via
`x:AccountPassword/set` (the current secret is required even for an
already-authenticated admin changing their own password — Stalwart
returns a `forbidden` response otherwise, not a silent no-op), verifies
the new credential authenticates _and_ the old one no longer does, and
only then overwrites the credentials file (mode `600`). If verification
fails for any reason, the file is left untouched rather than pointing at
a credential nobody has — the script reports `FAILED` with the reason
and makes no destructive change.

**Never paste any part of either credential anywhere** — including into
this file, a PR, a chat transcript, or a terminal recording. The script's
own output is a single status line by design, precisely so a routine
rotation never has anything worth redacting. Not run by `run-all.sh`:
rotation is a deliberate one-off action taken when needed, not a state to
continuously reconcile towards.

## How to SSH-tunnel to the admin interface

Port 8080 (webadmin + the JMAP management API `configure_stalwart.py` uses)
is published as `127.0.0.1:8080:8080` in `docker-compose.yml` — Docker's
own port-publish restriction, not an application-level bind. (An earlier
version of this deployment also tried binding _Stalwart's own_ listener to
`127.0.0.1` for defense in depth; that broke it outright — Docker's
port-forwarding for a published container port connects to the container's
bridge-network address, not its loopback, so an app bound to `127.0.0.1`
inside the container becomes unreachable from the very port-publish
mechanism meant to expose it. Docker's host-side restriction is the single,
sufficient control point here.)

```bash
ssh -L 18080:127.0.0.1:8080 root@<mail-host>
# then, on the host:
curl -u "$(cat <the admin credentials file>)" http://127.0.0.1:18080/api/account
```

Confirm from an outside machine — not the host, not tunnelled — that `nc -zv
-w3 <mail-host> 8080` times out. The Docker-level restriction holds
independently of whatever the firewall allows, and 8080 is deliberately never
in `mail/firewall.ts`'s rule set at all.

## Hardening: what's active and how it was checked

| Control                                | How it's enforced                                                                                                                                   | Executed check                                                                                                                                                                                                                                                                                                                                                                           |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SSH key-only                           | `00-harden-ssh.sh`'s drop-in                                                                                                                        | `sshd -T` shows `passwordauthentication no`, `permitrootlogin without-password`                                                                                                                                                                                                                                                                                                          |
| Unattended security upgrades           | `unattended-upgrades` package + this repo's `20auto-upgrades`                                                                                       | `systemctl is-active unattended-upgrades` → `active`; `systemctl is-enabled` → `enabled`                                                                                                                                                                                                                                                                                                 |
| Brute-force protection, SSH            | `fail2ban`, jail defined in this repo's `jail.local`                                                                                                | `fail2ban-client status sshd` — real bans already recorded against internet background-noise scanning of port 22                                                                                                                                                                                                                                                                         |
| Brute-force protection, mail protocols | Stalwart's own built-in auto-ban (documented default: 100 auth failures/day before a ban, scoped per-IP, covering SMTP/IMAP/JMAP/ManageSieve alike) | **Not independently load-tested** — relying on Stalwart's documented default rather than an executed brute-force attempt against production infrastructure. `fail2ban` is not asked to also cover these protocols because it has no filter for Stalwart's structured log format out of the box; writing one is a reasonable follow-up if the built-in mechanism ever proves insufficient |

Two mechanisms split by what each is actually built to parse, not
redundancy — fail2ban already had a working `sshd` filter before this
work started; Stalwart's own auto-ban already covers its own protocols
without needing one written for it.

### Scan-ban: expect it to fire on your own verification commands

Stalwart's auto-ban (above) protects against real abuse, but it is not
tuned to distinguish "an operator checking their own TLS setup" from "a
port scanner" — a bare `openssl s_client` connect that never sends a
protocol command can be enough to trip `security.scan-ban` with
`reason = "portScanning"` — confirmed live, more than once, while verifying
the ACME setup from an outside machine. Once blocked, every
connection from that IP is refused at the listener, so **the operator's
own next verification command will time out** — the exact scenario this
section exists to head off.

Check and clear it with `mail/provision/list_and_clear_blocked_ips.py` —
**by specific IP, not a blanket clear.** A real scanner can be blocked at the
same moment as an operator's own false positive, and this is not
hypothetical: it has happened here. An earlier version of this script cleared
everything unconditionally, which would have released the scanner too.

```bash
ssh root@<mail-host> 'python3 /root/mail-provision/list_and_clear_blocked_ips.py --list-only'
# prints one line per blocked IP, e.g.:
#   198.51.100.7    reason=portScanning    since=2026-08-11T22:50:18Z

ssh root@<mail-host> 'python3 /root/mail-provision/list_and_clear_blocked_ips.py --ip 198.51.100.7'
# clears only that IP and reloads the live block list (see below for why the
# reload step is necessary) -- repeat --ip for more than one address

# --all clears every blocked IP, including ones that aren't yours -- only use
# it if you've checked --list-only's output first and mean all of them.
```

Bare invocation (no `--list-only`, `--ip`, or `--all`) lists and then
refuses with a nonzero exit rather than guessing which mode was intended.

Two things worth knowing about the mechanism itself, both confirmed from
source (`crates/registry/src/schema/structs.rs`'s `BlockedIp` object,
`Action::ReloadBlockedIps`):

- Destroying the `BlockedIp` registry object alone is **not** enough — the
  live block is enforced from an in-memory cache the registry write
  doesn't automatically refresh. `list_and_clear_blocked_ips.py` always
  follows the destroy with a `ReloadBlockedIps` action; doing this by hand
  via `x:BlockedIp/set` without the reload leaves the block in place.
- There's no separate allow-list for "trusted" IPs to pre-empt this
  entirely — the only lever is clearing the ban after it happens.

## Confirming the result

Run these after a provisioning round, against the actual host. Each is a read.

- **Idempotence.** Run `run-all.sh` twice from a clean slate (wiped
  `stalwart-etc`/`stalwart-data` volumes and the recorded admin credential).
  The first run completes bootstrap and reconciles the ACME provider,
  listeners, domain SANs, HTTP access control and tracer; the second run's
  `40-configure-stalwart.sh` output is five `no-op` lines and nothing else.
- **Listeners inside the container.** `docker exec stalwart cat /proc/net/tcp
/proc/net/tcp6`, filtered to `LISTEN`: expect 25, 443, 465, 587 and 993 on
  `[::]`, and 8080 on `127.0.0.1` only. No 995, no 4190.
- **Port 25** answers with the host's own ESMTP banner, both on-box against
  `127.0.0.1:25` and externally.
- **TLS.** `openssl s_client -connect <mail-host>:465 -servername <mail-host>`
  from a machine that is neither the host nor tunnelled into it: expect a
  Let's Encrypt certificate whose subject is the mail hostname and
  `Verify return code: 0 (ok)`.
- **DKIM.** Two active signing keys for the mail domain (an Ed25519 and an RSA
  selector), with the matching TXT records published and resolving.
- **The admin interface stays unreachable.** `nc -zv -w3 <mail-host> 8080`
  from outside times out, and `curl -k https://<mail-host>/` against 443
  returns `421 Misdirected Request` — the webadmin/JMAP app never executes for
  that request. See "The ACME decision" for why the block lives at the
  HTTP-request layer rather than on the listener.

A certificate's `notValidBefore` reading roughly an hour before the container
that requested it was created is expected, not a defect: Let's Encrypt
backdates it so clients with a slightly-behind clock do not reject a fresh
certificate. Compare the issuance-completion log line against the container's
`Created` time for the causally-correct ordering.

## DKIM records to publish

**Where the selector records live.** For a tenant on someone else's domain,
the design is a CNAME at that domain delegating to a platform-controlled zone,
so key rotation only ever touches the platform's own DNS and never needs the
tenant to act. For branchLeft's own domain the two are the same zone —
`branchleft.co.uk` is both the mail domain being signed and the zone the
platform controls directly — so there is no second party to decouple from and
the selector TXT records publish there without indirection. The
CNAME-delegation mechanism becomes load-bearing at the first tenant domain
the platform does not control.

Regenerate from the live instance via the admin API rather than copying values
from this runbook. DKIM keys are generated fresh by Stalwart on first boot
(see "How to re-run safely" below) — any static copy in this doc will
eventually drift and break domain-wide DKIM signing if used verbatim.

To retrieve the current DKIM records:

```bash
ssh root@<mail-host> 'python3 <<EOFPYTHON
import json
import urllib.request
import base64

auth = open("/root/.stalwart-admin-credentials").read().strip()
body = json.dumps({
    "using": ["urn:ietf:params:jmap:core"],
    "methodCalls": [["x:Domain/get", {}, "0"]]
}).encode()

req = urllib.request.Request(
    "http://127.0.0.1:8080/jmap",
    data=body,
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Basic {base64.b64encode(auth.encode()).decode()}"
    }
)

response = json.loads(urllib.request.urlopen(req).read())
domains = response["methodResponses"][0][1]["list"]
for domain in domains:
    if domain.get("name") == "branchleft.co.uk":
        print(json.dumps(domain, indent=2))
        break
else:
    print("Domain branchleft.co.uk not found. Here are all domains:", file=__import__("sys").stderr)
    for d in domains:
        print(json.dumps(d, indent=2), file=__import__("sys").stderr)
EOFPYTHON
'
```

The output is the domain object for `branchleft.co.uk`. Look for the `dnsZoneFile`
field — it contains the complete zone file including all DKIM selectors as TXT
records. Copy the two `_domainkey.branchleft.co.uk` TXT records from the zone
file and publish them at IONOS. If `dnsZoneFile` is not present in the output,
the field may have a different name — examine the full domain object and look
for a field containing DKIM records or zone data.

The RSA record's value is split across two quoted strings in a raw zone file
purely because of DNS's 255-byte string limit per TXT segment — most registrar
UIs, IONOS included, either handle that wrapping themselves or accept the value
as one field.

**Publishing these two records is safe to do now, independent of the
firewall or the next story** — DKIM signing needs no inbound port at all,
just a published public key. They do nothing until mail actually gets
signed and sent (next story), but there's no reason to wait.

**Deliberately not included in this handoff**, even though Stalwart's
`dnsZoneFile` field generates them too: the MX record, SPF, the
`_submissions`/`_imaps`/`_pop3s`/`_jmap`/`_caldavs`/`_carddavs` SRV records,
`autoconfig`/`autodiscover`/`ua-auto-config` CNAMEs, and the CAA/MTA-STS/
TLS-RPT records. All of those are mailbox-and-cutover concerns (this
story's explicit out-of-scope list) or optional hardening with no bearing
on getting the host serving. They are listed here so the next person picking
up mailboxes and cutover knows what Stalwart will hand them, not as proposed
changes.

(The MX record is specified under "The MX cutover" above. SPF changes with the
outbound cutover, not with the receive-only step.)

## How to re-run safely

Every script in `mail/provision/` is idempotent by design — see the table
above. The one operation that is **not** idempotent in the everyday sense
is a full volume wipe (`docker compose down && docker volume rm
stalwart-etc stalwart-data`): that's a deliberate reset back to a fresh
install, not a normal re-run, and it invalidates every secret in the table
above (new admin password, new DKIM keys, new ACME account). **A volume wipe
also invalidates any DKIM records previously published at IONOS** — the new
keys generated by Stalwart will not match the old ones, breaking domain-wide
DKIM signing. After a wipe, regenerate the DKIM records from the live
instance (see "DKIM records to publish" above) and update DNS at IONOS.
Delete `/root/.stalwart-admin-credentials` before the next `run-all.sh` if
you do this, so `configure_stalwart.py` correctly detects bootstrap mode
rather than trying a credential the fresh instance has never seen.

Ordinary re-runs (checking nothing has drifted, or applying a change to one
of these scripts) need no manual steps beyond `run-all.sh` itself.

## What remains owner-gated

Three things this procedure cannot do for itself, in order:

- **The firewall apply**, opening 25/443/465/587/993. Confirm with
  `hcloud firewall describe <firewall>` and an external `nc` to each port.
- **Publishing the DKIM TXT records** at the registrar — regenerate from the
  live instance via the admin API (see "DKIM records to publish" above). A
  standing requirement rather than a one-time task, because the keys rotate
  with any volume wipe.
- **The first ACME issuance**, which cannot succeed until 443 is open.

**Triggering a renewal manually should not be needed going forward.** The
`AcmeProvider`'s `renewBefore` setting drives Stalwart's own internal
scheduling — after the issuance above, the platform recorded its own next
renewal task due shortly before the certificate expires, not left for a
human to remember (visible live on the `AcmeRenewal` task's `due` field,
`x:Task/get`). If a manual trigger is ever needed anyway (testing, a
suspected scheduling problem),
use `mail/provision/trigger_acme_renewal.py` rather than a raw JMAP call. The
domain's registry id is not stable across a rebuild, and building the request
by hand means copying the admin credential into the operator's own shell.
The script looks the id up live and runs entirely on-box:

```bash
ssh root@<mail-host> 'python3 /root/mail-provision/trigger_acme_renewal.py'
```

If a certificate is already valid and not yet due for renewal, Stalwart
itself refuses the request with a clear reason (confirmed live:
`"Certificate for domain branchleft.co.uk is still valid; renewal is not
due until <date>"`) rather than silently wasting a Let's Encrypt request —
this script doesn't need its own guard against that case.

Also standing, unrelated to ACME: anything needing the host provider's
console or CLI writes, and the MX cutover itself — see "The MX cutover" above
for the record and the pre-flight checks.

## What this does not prove

- **Deliverability.** The test sends in "Mailbox provisioning" above are
  local, host-to-host: they prove Sieve forwarding works, not inbox placement,
  spam scoring, or anything DNS-cutover-dependent. Warm-up, DMARC alignment
  and seed-list placement testing are separate work.
- **The MX cutover.** Mailboxes exist and forwarding is proven, but nothing
  here changes which server actually receives the domain's mail — see "The MX
  cutover" above.
- **Any sending application's actual use of a submission credential.** The
  credential itself is proven (real SMTP submission, real sender and IMAP
  restriction); nothing here exercises the calling application's code.
- **Sieve behaviour at real mail volume.** The forwarding scripts are proven
  correct for one message each, not under sustained load or against
  malformed or adversarial mail. There is no reason to expect a problem — this
  is Stalwart's own Sieve engine, not custom logic — it is simply untested.
- **Unattended renewal actually firing on schedule.** A real issuance is
  confirmed; the _next_ one happening automatically, ~90 days out, with nobody
  re-running anything, is a scheduling claim backed by Stalwart's own recorded
  due date rather than an observation.
- **Stalwart's brute-force protection under real load.** This relies on its
  documented default behaviour, not an executed attack simulation against
  production infrastructure. The _scan-ban_ half was triggered for real,
  repeatedly, by ordinary verification traffic (see "Scan-ban" above) — that
  part is verified; the higher-volume auth-failure thresholds are not.
