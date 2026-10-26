# configure_stalwart.py

## Module overview

Reconciles Stalwart's own settings (network listeners, the mail domain's
ACME SAN list, log output) to the state this platform needs, using
Stalwart's JMAP-style management API -- see
mail/RUNBOOK-mx1-provision.md#stalwart-config-as-code for why this script,
not a TOML file, is the config-as-code artifact for this version of
Stalwart.

Idempotent: every change is computed as a diff against live state, so a
second run with nothing left to do makes zero API calls beyond the GETs
used to compute that. Uses only the standard library (no `requests`, no
`jq` -- neither is assumed present on the host) so it runs anywhere
python3 does.

## Scrape path and source allowlist

Prometheus scrape path, and the only source address allowed to reach it on
the public listener. `edge1` runs the estate's monitoring stack; the
address is its own, because mx1 sits in a separate hcloud project with no
private network to scrape across (mail/server.ts, and
hetzner/edge/render.ts's NOT_AN_UPSTREAM records the same fact for the
edge's own proxying).

**IPv4 only, deliberately.** edge1's IPv6 address was listed here at first,
because mx1 publishes an AAAA record and curl duly preferred it -- and the
rule did not match. Measured against the live server: the same host, same
credential and same path returns 200 over IPv4 and 421 over IPv6, so
`remote_ip` does not compare equal to the compressed literal
`2a01:4f8:1c19:a1a8::1` that this file would naturally spell.

The form Stalwart actually renders was not established, and a rule written
against a guess is worse than no rule -- it never fires while reading as
coverage. So IPv6 is not allowed at all, and the scrape is pinned to IPv4
at the Prometheus end to match. Re-adding v6 needs the rendered value
observed on the host first, not inferred here.

## HTTP endpoint policy

Keeps the webadmin off port 443 without touching ACME eligibility --
reasoning and incident history: mail/RUNBOOK-mx1-provision.md's "The
ACME decision" -- while letting exactly one path through for the metrics
scrape.

Two properties are load-bearing and neither is obvious from the shape:

- **The allow rules come first.** Rules are evaluated in key order and
  the first match wins, so the blanket 421 has to be last or it would
  swallow the metrics path too.
- **One rule per source address, rather than one rule with `||`.** `&&`
  is confirmed in Stalwart's own expression examples; `||` is not, and a
  condition that fails to parse on a live access-control rule is not a
  thing to find out by deploying it. The comprehension below still
  generates one rule per source even though there is a single source
  today, so adding one back is a tuple entry rather than a rewrite.

Source-address matching is defence in depth, not the control: basic auth
on the endpoint is mandatory (see METRICS_TARGET). Opening a path on a
listener reachable from 0.0.0.0/0 with only a password in front of it is
the weaker posture, and the endpoint serves queue and delivery telemetry.
`useXForwarded` is managed here, not merely left alone, because the metrics
allowances above match on `remote_ip`. With it enabled and no trusted-proxy
allowlist, `X-Forwarded-For: 46.225.95.167` makes any client on the internet
match the pin -- the same bypass RUNBOOK-mx1-provision.md already records for
the 421 webadmin rule. Nothing fronts mx1, so the correct value is False and
the reconciler now holds it there rather than assuming nobody flips it in the
admin UI.

## Prometheus exporter

Stalwart's Prometheus exporter. Enabled with credentials set, never
without: `authUsername` and `authSecret` are both optional in Stalwart's
schema and leaving them unset publishes the endpoint unauthenticated,
which on a listener bound to [::]:443 means publishing queue depth and
delivery outcomes to the internet.

The secret is read from the container's environment rather than passed as
a `Value`, so the plaintext never enters this repo, this script's API call
or the settings store. mail/provision/docker-compose.yml passes it
through; the operator writes it once into the env file beside that
compose file.

`openTelemetry` is absent from the _diff target_ deliberately -- it is not
a field this platform manages, and naming it there would mean fighting
whatever it is set to on every run. It is nonetheless required by the
object, so the create path (a singleton that has never materialised) has
to supply it; METRICS_CREATE_DEFAULTS is that, and only that.

## Prometheus reconciliation

Deliberately does **not** compare `authSecret`. Stalwart may redact a
credential field on read, and a target that can never equal what comes
back makes every run rewrite the singleton and `docker restart stalwart`
-- bouncing production mail on a sequence documented as safe to re-run.
So the secret is written on the transitions that need it (create, or
prometheus not yet Enabled as us) and not compared thereafter. Rotating
it is a deliberate act, not something a reconciler discovers.

## Security ban-rate diff

Security has no Create/Destroy method -- unlike Http, the singleton
always exists, so this only ever produces an update.

`_field_diff` compares with `current.get(field) != value`. A dict
missing a key and a dict holding that key set to `None` both read back
as Python `None` from `.get`, so a live Rate diffing against a `None`
target compares unequal (change needed) and an already-`None` field
diffing against a `None` target compares equal (no-op) with no
special-casing required here.
