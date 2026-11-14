# verify-archive-passphrase.py

The module docstring of `verify-archive-passphrase.py` kept its summary paragraph; the rest of the narrative, usage notes and rationale is below, unchanged.

The six post-wrap archives in offsite object storage are the only surviving
copies of those stacks' state once the GCP KMS key version is destroyed, and
every one of them is passphrase-wrapped. That moves the whole risk from the
key to the escrow: a passphrase that was mis-transcribed, truncated on paste,
or filed under the wrong entry looks identical in a password manager to one
that works, and the difference only shows up after the key is gone, when
there is nothing left to fall back to.

"It is in the password manager" and "it opens the archive" are different
claims. This script turns the second one into an exit code.

It does not re-implement Pulumi's decryption. It drives the real `pulumi`
binary against a throwaway local file backend in a temporary directory, and
lets Pulumi's own answer be the answer. Two stages, both of which must pass:

1. **Salt stage.** The archive's `secrets_providers.state.salt` is written
   into a scratch `Pulumi.<stack>.yaml` and `pulumi stack init` is run over
   it. A passphrase salt carries a known plaintext encrypted under the key it
   derives, so Pulumi validates the passphrase against the salt alone and
   fails with `incorrect passphrase`. This stage holds even for an archive
   with no encrypted values in it.
2. **Ciphertext stage.** `pulumi stack import` reads the archive into that
   stack. Deserialising a deployment decrypts every encrypted value it
   contains, so a wrong passphrase fails here with `failed to decrypt`. This
   is the stage that proves the archive's actual secrets open, not merely
   that the passphrase matches the salt.

`pulumi stack export --show-secrets` is deliberately _not_ used. It is the
decryption proof the migration runbook uses against a live stack, but its
output is every secret the stack holds in plaintext, and an import already
forces the same decryption while emitting nothing.

Nothing decrypted is ever printed. Pulumi's own stderr is captured and
matched against known markers, never echoed: with the _correct_ passphrase, a
corrupt archive makes Pulumi report a JSON parse error over the decrypted
plaintext, quoting a character of it. Classifying the stream instead of
relaying it is what keeps that out of a terminal scrollback.

Nothing touches a real backend or a real stack. `pulumi login` is never run --
it rewrites `~/.pulumi/credentials.json` for every project on the machine --
and the backend is passed per invocation through `PULUMI_BACKEND_URL`, pinned
to a `file://` path inside a temporary directory that is removed on every
exit path. `PULUMI_HOME` and `PULUMI_ACCESS_TOKEN` are redirected and dropped
so no invocation can reach the Pulumi service.

Usage:

    verify-archive-passphrase.py ARCHIVE [ARCHIVE ...]
                                 [--passphrase-file PATH] [--json]

The passphrase is never an argument: it is prompted for without echo, or read
from a file. Several archives may be given at once because the passphrases
are one per repository rather than one per stack -- `shared-infra` covers two
archives and `ghost-platform` covers two -- and re-typing one passphrase per
archive is itself a transcription risk.

Exit codes, deliberately distinct so that "the passphrase does not work" can
never be confused with "the check did not run":

    0  PASS          every archive opened with the supplied passphrase
    1  FAIL          Pulumi reported an incorrect passphrase for an archive.
                     This blocks the KMS key destruction.
    2  USAGE         the invocation or the environment is wrong -- no
                     passphrase, an empty one, a missing `pulumi` binary.
                     Nothing was verified.
    3  ARCHIVE       an archive is unusable as evidence: unreadable, not a
                     stack export, not passphrase-wrapped, or carrying
                     plaintext secrets. Says nothing about the passphrase.
    4  INCONCLUSIVE  the check could not reach a verdict -- an archive with
                     no encrypted values in it, or a Pulumi failure that is
                     neither a passphrase nor an archive problem.

With several archives the worst outcome wins, in the order
FAIL > ARCHIVE > INCONCLUSIVE > PASS. A usage error aborts before any
archive is read.
