# The sign-in service's submission credential

`provision_zitadel_submission_credential.py`, run by
`68-provision-zitadel-submission-credential.sh`, gives the sign-in service
(Zitadel, on `ops1`) one SMTP submission credential on Stalwart. It can send as
`noreply@publicpress.co.uk` and as nothing else.
`check_zitadel_sender_scope.py` proves that on the live server. Tracking:
[branchLeft/workspace#1892](https://github.com/branchLeft/workspace/issues/1892).

Read from Stalwart's source at the pinned version `v0.16.17`
(`docker-compose.yml`); the mechanism is the one
`provision_collector_submission_credential.md` documents, minus the
server-wide expressions.

## Why a different shape from the collector's

The collector sends as any address in a set of domains, so it needs two
server-wide sender expressions edited. This credential sends as exactly one
address, which is what Stalwart's shipped default already enforces: with
`MtaStageAuth.mustMatchSender = true`, the `MAIL FROM` must equal the
authenticated account's own address or one of its aliases
(`crates/smtp/src/inbound/mail.rs`). This account has no alias. So the script
changes **no server-wide setting and never restarts Stalwart**; it only
**checks** that the default still holds for this account and refuses if not.

## What it reconciles

All through the loopback admin API, the same `x:<Type>/get` and
`x:<Type>/set` methods the other provisioning scripts use.

1. **An account `noreply@publicpress.co.uk` with no password of its own.**
   Nothing can sign in as it except the app password below. It has no mailbox
   anyone reads.
2. **One app password on that account**, permissions **replaced** by exactly
   `authenticate` and `emailSend`, so this credential cannot open IMAP, POP3,
   JMAP or DAV. Stalwart returns the secret once.

The secret is appended to `/root/.stalwart-service-credentials` under the label
`zitadel-smtp` **before** it is shown, so a lost terminal does not lose it. It
is then printed once, only when standard output is a terminal (`ssh -t`); in a
pipe, a log or any non-terminal it is not printed at all. A second run prints
`already provisioned, no-op` and never shows it again.

## What it refuses, before writing anything

- **A domain that is the main domain or under it** (`branchleft.co.uk`): this
  credential must never be able to send as it. The unit tests fail if the
  committed domain ever is.
- **`MtaStageAuth.mustMatchSender` not falling back to the shipped `true`**, or
  carrying a branch that names this account. Either would let the account send
  as any address. Another account's branch (the collector's) is left alone.
- **A sending domain that does not exist on the server yet.**
  `provision_sending_domain.py publicpress.co.uk --dkim-only` creates it.
- **A secret recorded under `zitadel-smtp` with no matching credential on the
  server**, which would be shadowed by a second line under the same label.

An app password that exists with nothing recorded locally is the orphaned
case: reported, exit 1. `--revoke` destroys it and its local record; the
account stays, and cannot sign in without it. `--dry-run` performs every read
and every refusal and writes nothing.

## What the credential can and cannot do, if it leaks

- **Can:** authenticate to `mx1` on 587 and submit mail whose `MAIL FROM` is
  `noreply@publicpress.co.uk`, to any recipient, signed with that domain's DKIM
  key. That is a spam and phishing channel under the product's name. Nothing this
  script sets bounds the volume; the mail host's own limits and the IP's
  warm-up ceiling are the only brake, and neither was checked here.
- **Cannot:** send as any other address or domain; read any mailbox over IMAP,
  POP3, JMAP or DAV; reach the admin API; change any setting.
- **Contained by:** `--revoke` (the secret is dead the moment the app password
  is destroyed), and one place to look: the account's outbound log.

## The check

`check_zitadel_sender_scope.py` runs on the mail host. One SMTP session to port
587 with STARTTLS, one login, and no message body at all:

1. **Accept (the control):** `MAIL FROM` the account's own address, `RCPT` to a
   local mailbox. Both must return `250`. If this fails the refusals below prove
   nothing.
2. **Refuse:** `MAIL FROM` another address on the same domain, then one on the
   main domain. Each must return a permanent `5xx`; a `4xx` is a deferral and
   fails the check.

No `DATA` is sent, so nothing is delivered and no reputation is spent. One
session and one login keep the probe to a single connection: repeated
authentication failures count towards Stalwart's auto-ban, so on an
authentication failure the script says stop rather than retry.
