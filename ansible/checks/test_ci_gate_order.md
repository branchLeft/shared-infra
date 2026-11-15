# test_ci_gate_order.py: the workflow order and gate

These tests hold the CI workflows to what `ci_select.py` assumes:

- the shard job waits for the quick lint gate (yamllint and `test_ci_select.py`) and not for
  the full lint, so a malformed file starts no container and the shards start sooner;
- the blocking shard job and the advisory shard job each run only when discover chose shards
  of their kind, and refuse the entry that stands for none; the advisory job runs the same
  steps as the blocking job (compared step for step), and both are named
  `Harness: <id>` and `Advisory harness: <id>`, which `shard_results.py` reads;
- the gate job (the check the ruleset requires) fails unless the quick gate and the full lint
  both passed, and fails when blocking shards were chosen and did not all pass. It needs the
  blocking shard job and not the advisory one. The one exception is
  the merge queue, where the shard job is skipped by a condition on `github.event_name`
  and the gate accepts the skip for that event alone; a skipped, failed or cancelled shard job
  fails it on every other event. The gate's own script is run under bash against a table of
  outcomes, with a control that cuts the full-lint refusal out and one that widens the queue
  skip to every event, and shows the table sees each go;
- only the issue job has a write permission, it runs for a red scheduled run alone, and no step
  in the workflow starts, wakes or prompts an agent or dispatches another workflow;
- the quick gate builds its tool environment with the same steps as the full lint, and the
  full lint keeps every step it had;
- the merge queue still triggers the workflow, and the daily sweep is scheduled;
- the lint and every shard restore the tool environment from a SHA-pinned `actions/cache`
  keyed on the lock files, and install only on a miss;
- the CrowdSec pin check opens a pull request on a stale pin and still fails when it cannot
  run;
- the ansible-hosts environment probe is scheduled and judges the environment;
- Dependabot runs monthly and grouped.
