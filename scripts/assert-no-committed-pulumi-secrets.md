# assert-no-committed-pulumi-secrets.py

The module docstring of `assert-no-committed-pulumi-secrets.py` kept its summary paragraph; the rest of the narrative, usage notes and rationale is below, unchanged.

The salt is an offline verifier for the stack passphrase: whoever holds it can
test candidate passphrases at their own rate, with nothing in the loop to
notice and no service to rate-limit them. It does not belong in a repository
anyone can clone.

A `secure:` ciphertext is deliberately _not_ a finding. `branchLeft/standards`
PUL-12 is explicit that a ciphertext with no salt beside it is not an oracle --
nothing in such a file lets an attacker derive the key or verify a guess
offline -- and that rejecting it would ban the safe half of the pattern with
the unsafe half for no security gain. Widening this matcher past the clause
would also make this hook and the standards gate disagree, and the one that
fires first would be the one nobody believes.

This has to be a mechanical check rather than a rule people follow, because the
salt is not added by hand. Pulumi writes it back into the file itself, during
an ordinary `pulumi config set` or `pulumi stack init`, and the diff then looks
like exactly what the command was asked to do.

Usage:

    assert-no-committed-pulumi-secrets.py PATH [PATH...]   # scan named files
    assert-no-committed-pulumi-secrets.py --scan-tree DIR  # find them itself
    assert-no-committed-pulumi-secrets.py --self-test

`--scan-tree` exists so CI does not inherit pre-commit's `files:` pattern as
its only definition of which files matter. A hook whose pattern silently stops
matching is a hook that passes everything, and the pattern lives in a different
file from this one.

**What it does not see.** It reads lines, not YAML: a real parser is not
available here, the same stdlib-only constraint every script in this repo works
under. Three shapes are therefore missed:

- a key inside an inline flow mapping (`config: {encryptionsalt: x}`);
- a quoted key (`"encryptionsalt": v1:...`), which every YAML parser reads as
  the same key this one is looking for;
- a stack config named `Pulumi.<stack>.yml` or `Pulumi.<stack>.json`, both of
  which Pulumi accepts and `STACK_CONFIG` below does not match.

Pulumi emits none of them -- it writes block style, unquoted keys and `.yaml`
throughout -- so each gap is between what Pulumi writes and what Pulumi would
accept, not a case anything here produces. They are listed because an
undisclosed gap in a security check is indistinguishable from an absent one.
