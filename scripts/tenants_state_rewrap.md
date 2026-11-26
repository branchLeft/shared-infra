# tenants_state_rewrap.py

Re-keys the `branchleft-hetzner-tenants` stack's state under a new passphrase, in CI,
when the passphrase that wrapped it is lost. It runs from
`.github/workflows/tenants-state-rewrap.yml`, by hand, from `main`.

## Why this is possible

A passphrase stack keeps its resources in plaintext and wraps only encrypted values
(config secrets, `pulumi.secret` outputs) under a key derived from the passphrase and a
salt, recorded in the checkpoint's `deployment.secrets_providers`. The tenants program
declares no secret and takes its Hetzner token from the environment, so the state is
expected to hold no encrypted value. If that is true, nothing in it needs the old
passphrase, and replacing the `secrets_providers` block (and nothing else) re-keys it.
The tool does not assume it: the count of encrypted values is its first gate.

## The commands

`inspect` (read only, no passphrase, no environment): exports the stack with its secrets
left encrypted and prints counts and resource types: the secrets provider, resources by
type, encrypted values, plaintext values, pending operations. It also lists each encrypted
value by resource type, URN name, side (`inputs` or `outputs`) and key path, never a
value, with what `--drop-reproducible` would do to it. Exit 1 if any gate fails.

`--drop-reproducible` (for `inspect` and `rewrap`, off by default): the encrypted values
cannot be read once the passphrase is lost, so the only ones the route may go past are
those CI itself re-derives on every run. `REPRODUCIBLE` in the script is that allowlist, by
exact resource type, side and key path: the `token` key, in `inputs` and in `outputs`, of
a `pulumi:providers:hcloud` resource (the tenants program passes `HCLOUD_TOKEN` by
environment, and the provider records the token it was given). Those keys are deleted from
the export before anything else. If any other encrypted value remains, the gate refuses
and the listing names it. The equality proof then allows exactly the dropped keys: the
document imported is the export minus those keys and with a new `secrets_providers`, and
nothing else, or the run restores the aside copy. The aside copy is the unmodified original.
Whether a state imported without the token still previews with no change is read from the
real preview: a change there is a failure, and it restores. A new entry is added only for a
value CI supplies at run time, with a test.

The same flag also drops the Terraform bridge's raw-state record, `__pulumi_raw_state_delta`
in a resource's `outputs`, of any resource type, when an encrypted value sits anywhere below
it (the tenants state has them on `PrimaryIp` and `ServerNetwork`: a datacenter name, an IP
network, a subnet id, wrapped as secrets). The whole key goes, never only the ciphertext
inside it, because a record with one entry missing reads as "no change needed" for that
property. The record only says how to turn the Pulumi outputs back into the provider's raw
state (`pkg/tfbridge/rawstate.go` in pulumi-terraform-bridge). The bridge decodes state the
older way when the key is absent or does not apply (`makeTerraformStateViaUpgrade` and the
plugin-framework `parseAndUpgradeResourceState` both fall back), and its own error message
says "try removing the key and run Pulumi again". A later refresh writes it back. The
listing says `DROP (the Terraform bridge's raw-state record ...)`. The same equality proof,
the preview that may hold no change to an old resource (so no replace, update or delete), the delete
guard and the refresh preview all still run after the import, and any failure restores the
aside copy. An encrypted value anywhere else in a resource, including a sibling of the
record, still refuses.

`rewrap` (needs the new passphrase in `PULUMI_CONFIG_PASSPHRASE`):

1. Refuse unless the stack config carries no `encryptionsalt`, a passphrase is set, and
   Pulumi reports the backend this run is for.
2. Export the stack and apply the gate (with `--drop-reproducible`, to the export after the
   drop). It refuses on any encrypted value, any
   `plaintext` value, any pending operation, a provider that is not `passphrase`, or an
   empty state.
3. Copy the raw state object to `aside/<project>/<stack>.<UTC stamp>.<run tag>.json`
   (outside `.pulumi/`), read the copy back, and compare hashes of the copy and of a
   second read of the state object. Any difference stops the run before anything changes.
4. Point of no return. `stack rm --force --preserve-config`, then `stack init` with
   `--secrets-provider passphrase`, which mints the new salt. Take the new
   `secrets_providers` block from that empty stack's own export, write it into the old
   checkpoint, and prove by canonical-JSON equality that it is the only difference.
   `stack import` the result.
5. Prove, applying nothing: `preview --show-sames` (no `--expect-no-changes`) is judged step
   by step. Every URN the old checkpoint holds must be a `same` step, apart from a provider
   (never listed) and the StackReference (a `read`). A `create` or an `import` is allowed
   only for a URN the old checkpoint does not hold: that is the program declaring something
   the state never had (the report says `new, not in the old checkpoint, allowed: ...`),
   which a rewrite cannot cause. A `create` or `import` of an old URN means the rewrite lost
   the resource, and refuses. Every other op, and a preview that exits non-zero, refuses.
   The delete guard must pass that plan; the refresh preview must show no change against
   the live project.
6. Any failure, any interrupt and any termination signal after step 4 writes the aside
   copy back over the state object and reads it back. Exit codes: 0 done, 1 refused
   (nothing changed), 2 usage, 3 failed before the removal (nothing changed), 4 failed
   after it and restored, 5 failed after it and could not restore (the output names the
   aside key).

`restore` is for a runner that was killed between steps 4 and 6: it finds this run's aside
copy by run tag and writes it back. It uses only the store, never Pulumi, and is a no-op
when the run copied nothing aside.

## What it prints

Counts and resource types, and for each encrypted value the resource type, the URN's last
segment (its name), the side and the key path. No id, no full URN, no salt, no value, and no text from Pulumi's
own stderr (a correct passphrase over a corrupt document makes Pulumi quote the plaintext
it could not parse, so stderr is classified and dropped). A test pins this.

## What it touches

The Hetzner API is read only (the program's `getServers` and `getFirewalls` reads and the
refresh preview). The state bucket takes one object read, one write of the aside copy, and,
through Pulumi, the removal and re-creation of one stack's objects. `AwsCliStore` has no
delete method. `stack rm` also deletes the stack's history and backup objects; the aside
copy holds the checkpoint only, which is what a restore needs.

## What the preview shows

`pulumi preview --json` lists `same` steps only for the root stack unless it is given
`--show-sames`: without it, 17 resources read as one step (a production run showed 5 steps
for 17 resources, 3 of them changes the program declares for `app-t1`). `--expect-no-changes`
makes the preview exit 7 for any change at all, a create included, and exit 1 for a real
error (a program that fails), so `exited 7` means "changes were proposed", never an error.
The preview therefore runs with `--show-sames` and without `--expect-no-changes`, and
`plan_problems` does the judging. A test pins both exit codes and the step lists on a real
binary.

## What it cannot prove

- `preview` compares the program to state, not to the live project; the refresh preview is
  what compares to live, and any drift stops the run (resolving drift is a reviewed change,
  never an automatic refresh).
- The refresh preview cannot see a resource the program and the state both omit.
- A runner killed hard between the removal and the restore leaves the state object absent
  until the `restore` step (or a person) puts the aside copy back.

## Tests

`test_tenants_state_rewrap.py` runs unit tests anywhere and drives a real `pulumi` binary
on a throwaway `file://` backend where one is on PATH: a plaintext-only state is re-keyed
and then plans clean under the new passphrase and is refused under the old; a state with
one encrypted value is refused and left byte-identical; an injected failure, an interrupt
and drift each put the original bytes back. A second class applies the bridged `random`
provider (`RealBridgeTests`), whose resources carry the same encrypted entries inside the
raw-state record: with `--drop-reproducible` the record goes, the preview and the refresh
preview show no change, and a real `up` and `refresh` under the new passphrase replace
nothing and write the record back identically; a real secret beside the record still
refuses. It copies the plugin from the default Pulumi home, or installs it (network), and
skips if neither works. The workflow sets `REWRAP_REQUIRE_PULUMI=1`,
which turns a skipped real-pulumi test into a failure. `test_tenants_state_rewrap_workflow.py`
pins the workflow's shape.

Type-check with the shared policy: `mypy --config-file <standards>/templates/mypy.ini`.

## After it ran

Delete the workflow in a follow-up pull request once the stack has applied once from CI.
The tenants plan job then reads the salt from the state at run time rather than from a
`PULUMI_SALT_HETZNER_TENANTS` secret; that is an amendment to the CI pull request, not
to this one.
