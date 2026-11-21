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
type, encrypted values, plaintext values, pending operations. Exit 1 if any gate fails.

`rewrap` (needs the new passphrase in `PULUMI_CONFIG_PASSPHRASE`):

1. Refuse unless the stack config carries no `encryptionsalt`, a passphrase is set, and
   Pulumi reports the backend this run is for.
2. Export the stack and apply the gate. It refuses on any encrypted value, any
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
5. Prove, applying nothing: `preview --expect-no-changes` must hold only `same` steps and
   the `read` of a StackReference; the delete guard must pass that plan; the refresh
   preview must show no change against the live project.
6. Any failure, any interrupt and any termination signal after step 4 writes the aside
   copy back over the state object and reads it back. Exit codes: 0 done, 1 refused
   (nothing changed), 2 usage, 3 failed before the removal (nothing changed), 4 failed
   after it and restored, 5 failed after it and could not restore (the output names the
   aside key).

`restore` is for a runner that was killed between steps 4 and 6: it finds this run's aside
copy by run tag and writes it back. It uses only the store, never Pulumi, and is a no-op
when the run copied nothing aside.

## What it prints

Counts and resource types only. No id, no URN, no salt, no value, and no text from Pulumi's
own stderr (a correct passphrase over a corrupt document makes Pulumi quote the plaintext
it could not parse, so stderr is classified and dropped). A test pins this.

## What it touches

The Hetzner API is read only (the program's `getServers` and `getFirewalls` reads and the
refresh preview). The state bucket takes one object read, one write of the aside copy, and,
through Pulumi, the removal and re-creation of one stack's objects. `AwsCliStore` has no
delete method. `stack rm` also deletes the stack's history and backup objects; the aside
copy holds the checkpoint only, which is what a restore needs.

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
and drift each put the original bytes back. The workflow sets `REWRAP_REQUIRE_PULUMI=1`,
which turns a skipped real-pulumi test into a failure. `test_tenants_state_rewrap_workflow.py`
pins the workflow's shape.

Type-check with the shared policy: `mypy --config-file <standards>/templates/mypy.ini`.

## After it ran

Delete the workflow in a follow-up pull request once the stack has applied once from CI.
The tenants plan job then reads the salt from the state at run time rather than from a
`PULUMI_SALT_HETZNER_TENANTS` secret; that is an amendment to the CI pull request, not
to this one.
