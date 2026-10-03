# The collector's submission credential

`provision_collector_submission_credential.py`, run by
`67-provision-collector-submission-credential.sh`, gives the mail collector
one SMTP submission credential on Stalwart. It can send as any address in
`COLLECTOR_SENDING_DOMAINS`, and as nothing else. It can never send as the
main domain, `branchleft.co.uk`, or anything under it.
`check_collector_sender_scope.py` proves that on the live server.

Everything below was read from Stalwart's source at the pinned version,
`v0.16.17` (`docker-compose.yml`), and from its documentation for the two
settings involved:
[MAIL stage, "Allowed senders"](https://stalw.art/docs/mta/inbound/mail#allowed-senders)
and [AUTH stage, `mustMatchSender`](https://stalw.art/docs/mta/inbound/auth).

## Why this is a different shape from the other credentials

Every other submission credential here sends as exactly one address, its
account's own, and Stalwart's default `mustMatchSender = true` enforces that.
That check is an exact-address match: the sender must equal the account's
address or one of its aliases (`crates/smtp/src/inbound/mail.rs`). It cannot
say "any local part of this domain".

The collector needs exactly that. It submits mail drained from demo and
tenant hosts, whose Ghost instances choose their own local parts, and a demo
visitor holds administrator rights over the address their slot sends from.
So the restriction has to be per domain, and it has to hold at the mail host
whatever a slot asks for.

## What it reconciles

All through the loopback admin API, the same `x:<Type>/get` and
`x:<Type>/set` methods `configure_stalwart.py` uses.

1. **An account, `collector@trypublicpress.co.uk`, with no password of its
   own.** Nothing can sign in as it except the app password below. With
   `mustMatchSender` off for it, its own address grants nothing.
2. **One app password on that account**, with permissions **replaced** by
   exactly `authenticate` and `emailSend`. Those are the only two an SMTP
   submission asserts (`crates/common/src/auth/authentication.rs`,
   `crates/smtp/src/inbound/auth.rs`). `Replace` intersects the list with
   the account's own permissions (`crates/common/src/auth/access_token.rs`),
   so this credential cannot open IMAP, POP3, JMAP or DAV. The other
   credentials use `Disable` of `imapAuthenticate` instead. Stalwart returns
   the secret once, and the script appends it to
   `/root/.stalwart-service-credentials` under the label `collector-smtp`.
   The secret is never printed.
3. **One extra branch on two server-wide expressions.** The branch matches
   only `authenticated_as == 'collector@trypublicpress.co.uk'`. Each
   expression's `else` stays Stalwart's shipped default, so every other
   account behaves exactly as before.

| Setting                        | Collector's branch                        | Everyone else (shipped default)                                             |
| ------------------------------ | ----------------------------------------- | --------------------------------------------------------------------------- |
| `MtaStageMail.isSenderAllowed` | `sender_domain == 'trypublicpress.co.uk'` | `!is_empty(authenticated_as) \|\| !key_exists('spam-block', sender_domain)` |
| `MtaStageAuth.mustMatchSender` | `false`                                   | `true`                                                                      |

`isSenderAllowed` is evaluated on every `MAIL FROM`. When it is false, the
reply is `550 5.7.1 Sender address not allowed.` Several sending domains are
joined with `||`, the same operator Stalwart's own default uses.

Both checks act on the SMTP envelope sender (`MAIL FROM`).

## Failure modes

There are three ways an expression can fail. Only the third is open, and it
needs a version upgrade to arise.

- **It fails to evaluate on a message.** Stalwart treats both as `true`
  (`unwrap_or(true)` at each call site). `mustMatchSender = true` then refuses
  every collector sender, because the collector account owns no address it
  could legitimately send as. Closed.
- **It fails to compile when written.** The admin API compiles every
  expression on `/set` and rejects one that does not parse
  (`crates/jmap/src/registry/set.rs`). The script stops on that rejection.
  Because the domain check is written first, a rejected domain check means
  `mustMatchSender` is never relaxed. Closed.
- **It fails to compile at startup after a Stalwart upgrade.** Here Stalwart
  logs the error and silently uses that field's shipped default
  (`compile_expr`, `crates/common/src/expr/if_block.rs`). If only
  `isSenderAllowed` fell back like this, the collector would be exempt from
  the exact-address check and not held to its domains. **Open.** So after
  any change to the pinned Stalwart version, re-run
  `check_collector_sender_scope.py` before the collector sends again.
  A unit test enforces the reminder: it fails when `docker-compose.yml` pins
  a version other than `VERIFIED_STALWART_VERSION`, and its message says to
  re-run the check and then update that constant.

The domain check is written before `mustMatchSender` is relaxed. So during a
run there is no moment where the collector is exempt from the exact-address
check but not yet held to its domains.

`--dry-run` performs every read and every refusal, prints what it would
write, and writes nothing.

## What it refuses, before writing anything

- **A sending domain that is the main domain or under it**, or anything that
  is not a plain lower-case domain name. That pattern also keeps a quote out
  of the expression. The unit tests fail if the committed set ever includes
  the main domain.
- **Either expression holding something it did not write.** Only Stalwart's
  default, or this script's own earlier output (the same collector branch,
  perhaps with a different domain list), is replaced. A hand edit is never
  overwritten.
- **`MtaStageMail.rewrite` or `MtaStageMail.script` being set.** Both run
  after `isSenderAllowed` and can change the envelope sender. With
  `mustMatchSender` off for the collector, nothing would check it again.
- **A sending domain that does not exist on the server yet.**
  `provision_sending_domain.py` creates them.
- **A secret recorded under `collector-smtp` with no matching credential on
  the server.** A second line under the same label would be shadowed by the
  stale first one.

An app password that exists on the server with nothing recorded locally is
the orphaned case. It is reported and exits non-zero, as in
`provision_website_submission_credential.py`.

## Idempotence and restart

A second run against reconciled state makes only GET calls and does not
restart Stalwart. When either expression changes, the script restarts
Stalwart straight after writing them, before it creates the account or the
credential. It waits for the admin API to answer, the same way
`configure_stalwart.py` does. Restarting at that point means a failure later
in the run cannot leave expressions that are stored but not loaded, which a
re-run would then skip as already reconciled. At the end, the script reads
both expressions back and fails if they differ from what was written.

That read-back proves storage, not enforcement.
`check_collector_sender_scope.py` proves enforcement.

## Revoking

`--revoke` destroys the collector's app password and removes its line from
the service-credentials file, leaving every other line in place. It leaves
the account and both expressions alone: they only match the collector
account, which cannot sign in once its app password is gone. Running the
wrapper again afterwards mints a fresh credential.

## Why it is not in `run-all.sh`

Its sending domains have to exist first, and `run-all.sh` does not create
them: `provision_sending_domain.py` takes the domain as an argument. Run it
after that step, on its own.

## Adding a tenant domain

Create the domain with `provision_sending_domain.py <domain> --dkim-only`.
Then add it to `COLLECTOR_SENDING_DOMAINS` and re-run the wrapper. The script
recognises its own earlier branch and replaces it. Then re-run the check.

## The check

`check_collector_sender_scope.py` runs on the mail host. It opens one SMTP
session to port 587 with STARTTLS, authenticates once with the recorded
secret, and runs two transactions.

1. **Accept:** `MAIL FROM` an address in the first sending domain, to a
   local mailbox on the main domain that has no forwarding script. Every
   step must return `250`. This is the control: if the credential cannot
   submit at all, a refusal in step 2 would prove nothing. The address is
   deliberately **not** the account's own: Stalwart's default exact-address
   check accepts the account's own address with no domain rule loaded, so
   only a different address can show the rule is active. The script refuses
   to run with the account's own address.
2. **Refuse:** `MAIL FROM` an address in the main domain. It must return a
   permanent `5xx`. A `4xx` is a deferral, not a refusal, and fails the
   check.

One session and one login keep the probe to a single connection. Repeated
connections and authentication failures count towards Stalwart's auto-ban. A
refused `MAIL FROM` does not. On an authentication failure, the script says
stop rather than retry.
