# RUNBOOK: migrating a mailbox's history onto the mail host

Scope: an IMAP-to-IMAP copy of an existing mailbox's mail from whatever
provider currently holds it into the matching mailbox on the delivery host,
run and verified **before** that provider is cancelled.

Zero mail loss is the requirement, and it is independent of every other
cancellation precondition — billing, identity, anything else. All of them must
clear; none of them alone is sufficient.

This can run at any time, independent of the MX cutover: it touches no DNS,
changes nothing currently live, and waits on nothing. Running it early and
re-running closer to the cancellation date, to pick up whatever arrived at the
old provider in between, is good practice rather than overkill.

## Why this needs the account holder's own hands

Google removed plain username/password sign-in for third-party apps in
2025-05. IMAP access needs an **app-specific password** generated from the
account's own security settings, which requires 2-Step Verification on that
account. **A Workspace admin cannot generate one on a user's behalf**, even for
an account they administer — it has to come from signing in as that account.
Other providers impose comparable constraints.

That credential and the destination mailbox's own password must never be typed
into a command an automated agent can see, or one that lands in a transcript.

## Tool: imapsync

`imapsync` is the long-established, purpose-built tool for this: IMAP-to-IMAP
mailbox sync, preserving folders and labels, flags and dates. It copies from
the source and **does not delete or modify anything there** unless explicitly
told to, so the step cannot damage what is still at the old provider no matter
how it goes.

```bash
brew install imapsync
```

Check the flags below against `imapsync --help` before running for real. Unlike
the scripts in this repository, this procedure has not been proven against a
live run — close that gap the first time it actually runs rather than trusting
it blind.

## Steps

1. **Enable IMAP access** for the mailbox at the source provider, if it is not
   already on. In Google Workspace: Apps → Google Workspace → Gmail → End User
   Access → POP and IMAP access.
2. **Generate an app password**, signed in as the mailbox's own account. Copy
   it immediately; providers typically show it once.
3. **Retrieve the destination mailbox's password** from the root-only
   credentials file `provision_mailboxes.py` wrote it to on the host — the path
   is that script's own `CREDENTIALS_PATH` constant. Lines are
   `<local-part>:<password>`.
4. **Dry run first** — preview what would happen, write nothing:
   ```bash
   imapsync \
     --host1 imap.gmail.com --user1 <address> --password1 '<source app password>' --ssl1 --gmail1 \
     --host2 <mail-host> --user2 <address> --password2 '<destination password>' --ssl2 \
     --dry
   ```
   `--gmail1` enables imapsync's Gmail-specific handling. Gmail's IMAP exposes
   `[Gmail]/All Mail` containing every message regardless of label, so a naive
   folder-by-folder copy double-counts anything carrying more than one label.
   Confirm the dry run's folder mapping looks sane — no unexpected
   duplication, no folders silently skipped — before proceeding.
5. **Run for real**, the same command without `--dry`. This takes a long time
   for a real mailbox history, and providers rate-limit IMAP. `imapsync` tracks
   what it has already copied and is safe to re-run; a second run should be
   fast and mostly no-ops.
6. **Verify, do not assume.** Compare per-folder message counts between the two
   mailboxes, and open a handful of actual messages in the destination mailbox
   — something old, something with an attachment, something from a known
   sender — rather than trusting a matching count.
7. **Re-run closer to the cancellation date** to pick up anything that arrived
   at the source since the first run, then re-verify.

## What this does not cover

- Calendar, contacts, files, or any other data at the source provider. Mail
  only.
- Any other precondition on cancelling the source account. Those are separate
  and independent.
- Actually cancelling the source account.
