# branchleft_promote.py

Narrative for `branchleft_promote.py`, cited from the code by heading.

## Module overview

A tenant host runs this as a root timer. It reads a signed ledger over public
HTTPS and, for each slot the ledger moves, calls the existing wrapper
(`branchleft-deploy <stack> <image@sha256:...>`). It holds no credential, opens
no port, and takes no argument from a tenant repository, an agent or an approval.

Two things are kept apart on purpose:

- **Who decides** is the ring controller. It writes the ledger and signs it with
  a key that never leaves the machine it runs on.
- **Who acts** is this program. It trusts exactly one public key, placed by an
  owner-merged role, and acts only on what that key signed.

The image itself is never checked here. The wrapper verifies the registered
image's attestation before it takes the stack lock, writes the pin or restarts
anything, so there is one verifier and one register. This program imports the
wrapper's register and image grammar from the installed wrapper at run time
(`load_wrapper`) and keeps no copy of either.

The program is pull, not push. With no reachable, fresh, correctly signed ledger
it changes nothing: it fails static.

## The ledger

Two files at one URL: `<url>` is the body and `<url>.sig` is an `ssh-keygen -Y
sign` signature over the body's exact bytes, in namespace
`branchleft-promotion-ledger`, by the principal `ring-controller`. The host's
`allowed_signers` file holds one key.

The body is JSON with exactly these keys, and a repeated key is refused:

    {"v":1,"seq":<int>,"issued":"<UTC>","expires":"<UTC>",
     "entries":[{"uid":<30000-30999>,"image":"<name>@sha256:<64 hex>","version":"<X.Y.Z>"}]}

There is no stack name, slug, tag or tenant name in it. A slot is an opaque uid;
the host's own slot map (`[{"slot": uid, "stack": name}]`, installed by the role
from private host inputs) turns it into a stack. `expires` is at most 36 hours
after `issued`, so the controller re-signs at least daily and a quiet fleet stays
fresh. Times are `YYYY-MM-DDTHH:MM:SSZ` only.

The body and the signature are two requests. A publish that lands between them
gives a mismatched pair, which the signature check refuses; the next tick fetches
a consistent pair.

## What is refused

Each refusal happens before any wrapper call. A ledger-level refusal acts on
nothing; an entry-level refusal leaves the other entries to proceed.

Ledger-level:

- signature not valid for the trusted signer, wrong namespace, signer not in
  `allowed_signers`, signature missing or truncated, `ssh-keygen` unable to run;
- schema: not exactly the keys above, a wrong type, a bad time, a window over 36
  hours, a uid outside the range, a uid twice, a version not `MAJOR.MINOR.PATCH`;
- expired, or issued more than five minutes in the future;
- `seq` lower than the last one seen (replay), or equal with different content.
  The same `seq` with the same content is the normal quiet state and is not an
  error.

Entry-level:

- a uid with no row in the slot map;
- an image that is not `name@sha256:<digest>` exactly (a tag or registry port is
  refused even where the wrapper would accept it), or whose name is not on the
  wrapper's register;
- a version lower than the slot's applied version, unless the image is the
  slot's recorded previous digest. That one exception is the revert;
- a digest that already failed, or was interrupted, on this slot.

A refused entry is reported by uid and reason only.

## State

A root-only directory holds `state.json`, replaced atomically, and a lock file so
two runs cannot interleave. Per slot it records the applied and previous image
and version, the image the ledger last asked for (`desired_image`, which is what
drift is computed from), the image being applied (`pending_image`) and a short
list of blocked digests.

The pending image is written before the wrapper is called. A run killed in the
middle therefore leaves that digest blocked, and a digest that kills its own run
is not retried on every tick. A digest the wrapper failed on is blocked the same
way. It is tried again only if a later ledger names a different digest.

When a move goes back to the previous digest, the digest it left is blocked too,
so a revert cannot be undone by the next ledger.

An unreadable state file refuses everything: without it the replay protection
would be silently gone. A missing state file is a first run.

`last_seq` is advanced after the whole ledger has been handled, so a crash
before that lets the same ledger be handled again, never an older one.

## Trust anchors

The trusted-signers file, the slot map, the wrapper and the state directory must
be what the role installed: not a link, owned by root, not writable by group or
others. The role is what places them and sets the modes on their parents; this
program refuses to run on any it finds loose. The owner uid is a field of the
program's configuration and is not reachable from the command line.

## Output and metrics

The program's own log lines name a slot by uid and say why, and never carry a
stack, an image or a tenant name. The wrapper's output is left alone: its
`verified <image> attested by <signer>` line is the evidence, in the host's
journal, that the verifier ran before the pin moved.

With `--metrics-file` it writes a Prometheus textfile each run: the run time, the
last successful run, the ledger `seq`, and per uid a drift gauge that is 1 when
the ledger's image is not the one running. A run that could not fetch a ledger
leaves the last success where it was, which is how staleness shows.

Exit status: 0 when every entry was applied, unchanged or already current; 1 when
anything was refused or failed; 2 for a usage error.

## What is not here

The role that installs this program, its unit and timer, the slot map, the trusted
key and the metrics directory; the daily self-test that proves on the host that
a tampered ledger and an unattested digest are refused; and the independent
promotion attestation. Each is a later piece of the same route.
