# The read-only diagnostic API key

`provision_diagnostic_credential.py` gives agents one Stalwart API key that can
read the outbound queue, the DMARC, TLS and abuse reports and the server log,
and nothing else. It is run on mx1 by the owner, as root, over SSH.

## Why Stalwart's own permissions are the control

Stalwart v0.16 manages itself through JMAP at `/jmap`. Each `x:<Object>/get`
and `x:<Object>/query` call needs the permission `sys<Object>Get` or
`sys<Object>Query`, and each write needs a different one (`Create`, `Update`,
`Destroy`). A role is a named set of permissions, so a role holding only the
read pair for seven objects can read those objects and is refused everything
else by the server, whatever a client sends. That is the whole read-only
guarantee; the agent-side client (`stalwart_diag.py` in the workspace repo)
only keeps honest callers from asking.

A credential can only remove permissions from its account, never add them
(`CredentialPermissions`, `Inherit`, `Disable` or `Replace`). So the account
itself must be narrow, and the key repeats the same list as a second fence.

## What it reconciles

All through the loopback admin API, with the same `x:<Type>/get` and
`x:<Type>/set` calls `configure_stalwart.py` uses.

1. **A role**, `Diagnostic read-only`, whose `enabledPermissions` is exactly
   `PERMISSIONS`: `authenticate` and Get and Query of `QueuedMessage`, the
   five report objects and `Log`. It extends no role and disables nothing. A
   role of that name holding anything else is refused, not edited.
2. **An account**, `diagnostic@branchleft.co.uk`, with that one custom role,
   inherited permissions and no password. It has no mailbox permission, so the
   address receives mail nobody can read.
3. **One API key** on that account, with its permissions **replaced** by the
   same list, no source-address restriction (an agent's address changes) and an
   expiry of 180 days. Stalwart returns the secret once; the script appends it
   to `/root/.stalwart-service-credentials` under `diagnostic-read-only`
   (mode 600) and never prints it.

Not granted, on purpose: `fetchAnyBlob` (a queued message's body),
`impersonate`, every `jmap*` mail permission, any account, role, credential or
settings object, any action or task. `Metric` and `Trace` are Enterprise-only
in v0.16 and the instance is the community edition, so Prometheus metrics stay
on their own scrape credential.

## It proves the scope before it finishes

After creating the key the script uses it, against the loopback API, to run
one `query` on each of the seven objects (each must be allowed) and then
`DENIED_PROBES`: reads of accounts, roles, keys, domains, settings and DKIM
signatures, and writes that name an id that does not exist, so they change
nothing even if the server wrongly allowed them (each must answer
`forbidden`). Anything else, including an answer it does not recognise, counts
as a failure: a key it just made is destroyed and its record removed, and the
run exits 1 saying which probe differed. A re-run with the key in place makes
no change and runs the same proof against the recorded secret; if that fails
it reports and leaves the key for `--revoke`.

**Not proven before the first run on the host:** that Stalwart v0.16.17
accepts a bearer API key for an account whose only permissions are these, and
that a refused call answers a JMAP method error `forbidden` (the script treats
HTTP 403 the same). If either differs the script fails closed and no key
survives.

## Rotation and removal

`--revoke` destroys the key and its local record and leaves the role and the
account, which can sign in as nothing without a credential. Re-run the script
to make a fresh key; the owner then replaces the Proton Pass and Keychain
copies. The 180-day expiry makes that routine.

`VERIFIED_STALWART_VERSION` pins the Stalwart version the scope was written
against; the test fails when `docker-compose.yml` pins another, so a version
bump asks the question again.
