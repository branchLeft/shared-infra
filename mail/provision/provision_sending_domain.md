# provision_sending_domain.py

The module docstring of `provision_sending_domain.py` kept its summary; the rest of the narrative, usage notes and rationale is below, unchanged.

The same call serves the demo sending domain and a tenant's domain -- only
the name differs. `--dkim-only` is for a domain whose MX and SPF belong to
someone else (a tenant's), so only the DKIM record is ours to publish.

**It never touches a key that already exists.** A domain that already has
the selector's key is a no-op; a domain with any _other_ key, or one whose
keys Stalwart manages itself, is refused before any write -- adding a key
there would make Stalwart sign production mail under a selector nobody has
published. See "Sending domains" in mail/RUNBOOK-mx1-provision.md.

**The key is fixed, not rotated.** A created domain gets
`dkimManagement: Manual`. Stalwart's default is `Automatic`, which carries
a rotation schedule and date-stamped selectors; its rotation needs
Stalwart-managed DNS, which this estate does not use, and a key rotated
under a hand-published record fails DKIM for every message after it. Manual
means Stalwart never generates, retires or deletes a key on this domain on
its own.

Stalwart will not generate a key for a Manual domain, so this script does:
`openssl genpkey` on the mail host itself, piped straight into the loopback
API call. The private key is never written to disk, printed or logged, and
never leaves the host. Stalwart redacts it on every read.
