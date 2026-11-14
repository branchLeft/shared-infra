# provision_website_submission_credential.py

The module docstring of `provision_website_submission_credential.py` kept its summary; the rest of the narrative, usage notes and rationale is below, unchanged.

Every caller must use a distinct CREDENTIAL_LABEL. They share one flat
label:secret file, _load_recorded_secret returns the first matching line and
_record_secret appends unconditionally, so a duplicate label mints a real app
password and then permanently returns another service's secret instead --
while reporting success. test_provision_mailboxes.py asserts the labels in
mail/provision/*.sh are unique.

Confirmed from Stalwart's own source before writing this, not assumed by
analogy to provision_mailboxes.py's Account creation:

1. Stalwart has no separate "submission-only" principal type -- the
   registry's AccountType enum is only User/Group (crates/registry/src/
   schema/enums.rs). The idiomatic mechanism for a narrowly-scoped,
   independently-revocable credential is instead a _secondary credential_
   (an "app password") attached to an _existing_ account, created via
   `x:AppPassword/set` -- a different registry object (ObjectType::AppPassword)
   from the account's own `credentials` list, which explicitly refuses
   secondary credentials passed there directly ("Secondary credentials
   cannot be set directly", crates/jmap/src/registry/mapping/principal.rs).
   The server generates and returns the secret once, in the create
   response -- it can never be retrieved again, same as a real app-password
   flow anywhere else.
2. A **separate account** claiming the target address (e.g.
   `info@branchleft.co.uk`) as a send-as alias was the first design
   considered and doesn't work: both an account's own primary address and
   every `EmailAlias` register the same global-unique `(name, domainId)`
   index (`Property::Email` in UserAccount::index and EmailAlias::index,
   crates/registry/src/schema/structs_impl.rs) -- and that address is
   already claimed as the real mailbox's own primary address. A second
   account can't alias it, for any local part under this domain. An app
   password attached to the _existing_ account sidesteps this entirely:
   `authenticated_as` for that session already _is_ the target address, so
   Stalwart's sender-restriction check (`must_match_sender`,
   crates/smtp/src/inbound/mail.rs -- defaults to `true` when unconfigured,
   per crates/registry/src/schema/structs_impl.rs's
   MtaStageAuth::ctx_must_match_sender, and nothing on this box has ever
   overridden it) is satisfied trivially, with no alias needed.
3. IMAP access is blocked _for this credential specifically_, not the
   account as a whole: an app password's own `permissions` field
   (`CredentialPermissions::Disable`) clears listed permissions from a
   _copy_ of the account's effective permissions for sessions authenticated
   with that credential only (crates/common/src/auth/access_token.rs) --
   the account's real password credential is untouched, so a human can
   still IMAP into the account normally with its own password if ever
   needed. `imapAuthenticate` is the permission IMAP's own
   LOGIN/AUTHENTICATE handler asserts before anything else runs
   (crates/imap/src/op/authenticate.rs) -- disabling it blocks IMAP login
   outright, verified live (see
   mail/RUNBOOK-mx1-provision.md#website-submission-credential): a wrong
   password gets a normal tagged NO response; this credential's _correct_
   password instead gets the connection closed immediately, a distinctly
   different, stricter rejection.

Idempotent: keyed on the app password's `description` (the only
free-text, listable-without-secret field on this object) -- a second run
finds one already present and no-ops. If Stalwart's create response is
lost after it actually applied (the same class of risk
provision_mailboxes.py's credential-loss fix addresses) there is no way to
recover the plaintext after the fact -- this script detects that state
(a credential with the right description exists remotely, but nothing is
recorded locally) and reports it loudly rather than treating it as a
silent no-op; see plan_app_password_action.
