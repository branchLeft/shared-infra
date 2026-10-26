`pulumi stack export --show-secrets` exits 0 even under a wrong passphrase (observed
Pulumi v3.255.0, INC-4 in ghost-platform-docs/INCIDENTS.md), so any verification built
on it passes vacuously. `pulumi preview` fails closed on a wrong passphrase with
"error: getting stack configuration: get stack secrets manager: incorrect passphrase".

Detection here is deny-by-default on the literal `--show-secrets` flag,
never on recognising "a passphrase-verification section" or "a command
shaped like the anti-pattern": free-prose shape matching cannot distinguish
a reworded anti-pattern from a legitimate warning against one, so any
rewording it doesn't already know about passes silently -- keying on the
literal flag text has no such blind spot. The ALLOWLIST below keys each
accepted occurrence on its exact line text _and_ its occurrence count
together, not text alone: keying on text alone would let a verbatim copy of
an allowlisted line, pasted into a new location, pass unnoticed even though
it is a second, unreviewed occurrence there.

Known, deliberate limits of this design: a flag built from string
fragments that no single scanned line contains in full (e.g. concatenated
shell variables) is invisible to a per-line literal scan; the allowlist's
exact-text keying means reformatting an allowlisted line for any reason --
punctuation, a typo fix, a rewrap -- fails the check even though nothing
security-relevant changed, which is an accepted trade against fuzzy matching
that could hide a real reintroduction; and `scripts/pulumi-stack-inventory.json`
is deliberately out of scope, since it is a data file recording completed
operations rather than prose or code a future reader could learn the
anti-pattern from.
