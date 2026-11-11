# probe_object_lock.py

The steps of the probe workflow (`.github/workflows/ovh-copy2-probe.yml`) that are not Pulumi. Standard library only, except `preflight`, which reads the stack file with PyYAML. Tests: `scripts/test_ovh_copy2_probe.py` (the script, against a fake S3) and `scripts/test_ovh_copy2_probe_workflow.py` (the workflow file's pins, each shown red by a sabotaged copy).

## Subcommands

| Command     | What it does                                                                                      |
| ----------- | ------------------------------------------------------------------------------------------------- |
| `preflight` | Refuses the run, before any dependency or resource, then exports the project id and run suffix.   |
| `backend`   | Makes a `file://` Pulumi state directory and a random passphrase, masked, for this runner only.   |
| `probe`     | Reads the stack outputs from stdin, runs the checks below, writes `result.json` and `result.md`.  |
| `cleanup`   | Deletes every object version in bucket A with the Governance bypass, so the destroy is not stuck. |
| `finish`    | Writes the lifecycle table and, if the destroy did not succeed, the names to delete by hand.      |

## What `preflight` refuses

- `allowedProjectId` still `UNSET`, missing, or not 32 lower-case hex characters;
- either OVHcloud secret missing or empty (the names are reported, never a value);
- any bucket that is not named `zz-probe-*`, is outside region `UK`, or locks for more than one day;
- Compliance on a bucket the probe credential can write to, and a write target that is not Governance.

Compliance declared on an empty bucket the credential cannot reach (bucket C in the committed stack file) is allowed and reported as a notice. This workflow never writes to it, and the script cannot build a Compliance request at all (`lock_configuration_xml` refuses it).

## The checks

| Id  | Question                                                                                                                   |
| --- | -------------------------------------------------------------------------------------------------------------------------- |
| P0  | Did the provider make A, B and C on the London endpoint? (read from the outputs)                                           |
| P1  | Does the scoped credential write to A, and does the write return a version id?                                             |
| P1b | Does A read back as Enabled, Governance, one day?                                                                          |
| P2  | Does the new object carry Governance and a retain-until date about a day out?                                              |
| P3a | Does listing A show the version?                                                                                           |
| P3b | Is a delete inside the window refused? A 404 or a 5xx is not a refusal.                                                    |
| P3c | Does the same delete with the Governance bypass succeed?                                                                   |
| P3d | Is A empty afterwards?                                                                                                     |
| P4  | Is the credential refused on B, for a put and for a listing?                                                               |
| P5  | Is a lock configuration refused on B? An access refusal here cannot be told from the policy scope, and the detail says so. |

Each result is PASS, FAIL (the platform did the wrong thing) or INCONCLUSIVE (no answer: a timeout, a 5xx, a skipped dependency). Only all PASS exits zero.

## Limits

- The credential's policy covers bucket A only, so the lock read-back on C and an in-place change of a default rule are not probed.
- The S3 pair is masked as soon as it is read, scrubbed from every detail line, and never written to a file. The Pulumi passphrase is throwaway and sits in the runner's environment file for the length of the run.
- The Pulumi state is on the runner. If the destroy fails the state is gone, which is why `cleanup` runs first and `finish` lists what to remove by hand.
