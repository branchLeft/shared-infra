# blocking_shards.json: which container tests fail the required check

Every container test (harness shard) runs on every pull request and stays visible. Only the
shards named in `blocking_shards.json` fail the required check, `Lint and test the Ansible
roles`; every other shard is advisory. An advisory shard that fails shows red on its own
check line, the required check does not wait for it, and the `report` job lists it in the
step summary. A scheduled or manual run treats every shard as blocking, so the daily run
catches what an advisory shard hides. The merge queue runs no shard, as before.

One exception, on a pull request only. When a changed file is one that makes every shard run
(`EVERY_SHARD` in `ci_select.py`: the harness, the lint config, the lock, the three checks files,
the workflow), `ci_select.py` also prints `direct=`, the shards the pull request's own role and
pattern files select, and `run_everything_files=`. `blocking_shards.py split` then runs the
blocking shards and those `direct` shards, and leaves every other advisory shard to the daily
run, where it is blocking. The step summary and the log of the split step name each shard left
out and the file that caused it. If the pull request's own files cannot narrow the choice (an
unrecognised file under `ansible/`, a role reference the scan cannot map), `direct` is every
shard and nothing is left out. A missing or unreadable `direct=` line leaves nothing out too.

The file is one JSON object with the single key `blocking`: a list of shard ids, sorted,
each once, each one a shard that exists in the tree. A shard id is the name `list_shards.py`
gives it: `ansible/roles/ci_jump`, or `ansible/roles/ci_jump (refusals)` for a second
scenario. `blocking_shards.py validate` and `test_blocking_shards.py` hold those rules; the
discover job runs the same checks before it splits the shards, and fails when the list is
bad, which fails the required check.

The rules for the list:

- It starts with the shards of the lock-out roles, the ones whose break can cut the operator
  or the pipeline off a host: `pull_trigger`, `ci_jump`, `breakglass_mint_host`,
  `host_baseline`, `tunnel_account`, `edge_firewall`, `egress_nat` and `deploy_tooling`.
  They stay. A test fails when one of their shards is not listed, and takes any new scenario
  of one of those roles in too. Taking one off needs an owner-approved edit to
  `LOCKOUT_PATHS` in `test_blocking_shards.py` as well as to the list.
- A shard goes on the list by a reviewed pull request that cites the failing run that
  tripped it.
- A shard comes off the list by a pull request that cites five passes in a row of the daily
  run: `advisory_passes.py <shard id> --n 5` prints `PASS-STREAK=<k>` and the run URLs, and
  exits 0 only when k is at least n. It reads the newest completed scheduled runs of the
  workflow on `main`; a run in which the shard did not pass, or had no job, ends the streak.
  It reads only, with the token in `GH_TOKEN` or `GITHUB_TOKEN`; `--fixture FILE` runs it
  offline on recorded answers (`advisory_passes_fixture.json`).
- The approver records every red advisory shard of the pull request, from the `report` job's
  table, on the pull request.
- A red daily run is red on its own status and writes its date, the run link and the failed
  shard ids to its step summary (`daily_red_issue.py --summary`, job `daily-summary`, read
  permissions only). No workflow in this repository grants `issues: write` except the drift
  check caller, which `test_ci_gate_order.py` allowlists until its reusable workflow moves.
  The program's issue-opening code is not run by any workflow now. Nothing there mentions,
  assigns or prompts anyone or anything.

Two things to know. A new role or scenario starts advisory: it is on no list until a pull
request puts it there. And the delivery workflow (`ansible-delivery.yml`) runs the harness
before it applies anything over the roles `delivery_select.py` names, which is every role
unless the diff says fewer (`delivery_select.md`); this list does not change that run.
