# ovh/copy2/probe

The lock probe for the second backup copy at OVHcloud London. The workflow `.github/workflows/ovh-copy2-probe.yml` runs it; nothing else does. It creates three throwaway buckets through the `probe` stack of the parent Pulumi project, checks how OVHcloud object lock behaves, and destroys everything in the same job.

## Running it

The workflow is dispatch-only and runs from `main`. The job waits on the protected environment `ovh-copy2-probe`: its required reviewer approves the run in the Actions tab before any step starts. That environment alone holds the two secrets `OVH_CLIENT_ID` and `OVH_CLIENT_SECRET`. The first step, `gate`, reads the environment and fails the job if it no longer has a required-reviewer rule and a branch policy.

The probe project id is the owner's id for the dedicated project `branchleft-backup-copy2`, committed in both places: `OVH_CLOUD_PROJECT_SERVICE` in the workflow and `allowedProjectId` in `Pulumi.probe.yaml`. The first step, `project`, still fails the job before the checkout and before any secret is read unless the workflow's value is a 32-character lower-case hex id, and the program's project guard still refuses `UNSET` and any mismatch. A test pins the two places equal and well formed.

Cost: three empty buckets and one 5-byte object for a few minutes, in the London region, with no egress. It rounds to nothing.

## The checks

| Code | What it proves                                                     | How                                                                                         |
| ---- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| P1   | A London bucket is reachable with the scoped credential            | List bucket A at the London endpoint; read its location.                                    |
| P2   | Default retention is applied to a new object                       | Write one object to A; its retention is Governance for one day.                             |
| P3   | A delete is refused, then allowed with bypass                      | Delete that version plainly, then with the bypass header; check it is held, then gone.      |
| P4   | A second bucket refuses the credential                             | List and write bucket B, list bucket C, all with the credential that reaches only A.        |
| P5   | A lock cannot be added to an existing bucket                       | A second credential, allowed to try, asks bucket B (no lock) for a one-day Governance lock. |
| P6   | Compliance for one day is accepted as a default on an empty bucket | Read bucket C's default retention and list it; it is Compliance, one day and empty.         |

P5 needs its own credential on purpose. With the credential that reaches only bucket A, a refusal on B would prove nothing but "not permitted". The second user, `zz-probe-admin`, may ask B for a lock and read C's settings, and can write or delete no object anywhere.

Nothing is ever written to bucket C. An object under Compliance retention cannot be deleted by anyone, nor can its bucket.

A row is PASS, FAIL (the platform did something other than expected) or ERROR (the check could not be carried out, so it proves nothing). A connection fault is an ERROR, never a refusal. Only a pass on every row keeps the step green. The table, with the observed result of each row, goes to the job summary.

## Destroying

The destroy step has `if: always()`, so it runs after a failed check, a failed create and a cancelled run. It empties bucket A (Governance bypass, which P3 has just shown works), then runs `pulumi destroy` up to three times, then reads the stack's state. Any resource left in the state, or any pending operation, makes the job red and is printed by name in an error annotation and in the summary. The summary states plainly whether everything was destroyed.

If OVHcloud accepts the lock request that P5 sends to bucket B, P5 is a FAIL and bucket B is left with a one-day Governance default that cannot be removed: a lock, once set, stays. That does not stop the cleanup, because the lock is a bucket default and bucket B never holds an object: the probe writes nothing to B, the P4 write to B is sent with a credential that cannot reach it, and the lock-attempt credential has no object action. `pulumi destroy` then deletes B as it deletes A and C, which also carry a default lock and are empty (A after the bypass delete above). What is not verified: no OVHcloud call has been made, so whether OVHcloud deletes an empty bucket that carries a default lock, Compliance on C included, is an assumption the first run tests. If it refuses, the bucket stays in the state, the job is red, and the bucket is named in the error annotation and in the summary. An empty bucket costs nothing worth counting.

Its limit: "destroyed" means Pulumi's state is empty after the destroy. A resource that OVHcloud created but Pulumi never recorded (a run killed mid-create) cannot be seen from here. After the first run, look at the OVHcloud console for anything named `zz-probe-`.

## Secrets and state

- The two OVHcloud secrets are read by the `up`, `check` and `destroy` steps only. The package install and the self-test never see them.
- The Pulumi CLI gets a short allow-list of environment variables, not the runner's tokens.
- The Pulumi backend is a `file://` directory under the runner's scratch area, with a random passphrase in a mode 0600 file there. Nothing is uploaded, cached or logged.
- Every credential the stack mints is registered for masking before it is used, and scrubbed from check details.
- The S3 client (`boto3`) is installed from `requirements.txt`: exact versions, a hash each, `--require-hashes`.
- The Pulumi OVHcloud provider is pinned to an exact version (`@ovhcloud/pulumi-ovh` in `package.json`) but its plugin binary is fetched at the first `pulumi up` and is not checked against a checksum. Pulumi's `plugin install` accepts `--checksum`, but the expected SHA256 of the release archive has to be read from the provider's published release, and that was not obtained here: nothing was downloaded and no value is guessed. Adding a pinned install step is a follow-up that needs that value. Until then the plugin comes from the provider's GitHub release at the pinned version, runs only in the job that holds the OVHcloud secrets, and the run needs the owner's approval first.
- The stack outputs are read with secrets shown, in `probe_stack.py` only. That output is captured, never printed, and each credential is registered for masking before it is used.

## Files

| File               | What it holds                                                             |
| ------------------ | ------------------------------------------------------------------------- |
| `probe.py`         | The four steps: `gate`, `up`, `check`, `destroy`.                         |
| `probe_checks.py`  | P1 to P6 over the `Ops` interface.                                        |
| `probe_s3.py`      | `Ops`, `S3Error` and the boto3 adapter (the only import of boto3).        |
| `probe_stack.py`   | The Pulumi CLI as an argv list, and reading the state.                    |
| `probe_report.py`  | Results, the summary table, the cleanup text, secret scrubbing.           |
| `fake_s3.py`       | An in-memory stand-in for the three buckets, with a switch per behaviour. |
| `test_*.py`        | Offline tests. They import no third-party package and contact nothing.    |
| `requirements.txt` | The hashed lock for the S3 client.                                        |

Run the tests with `python3 -m unittest discover -s probe -p 'test_*.py'` from `ovh/copy2`.
