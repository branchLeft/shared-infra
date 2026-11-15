# test_ci_skip.py

Pins the changed-path skip in `ci.yml`. A wrong path
map skips a required check without any sign, so the file proves the map, and then
proves the proof.

## What it pins

- **The decision rules.** `check_decisions` states every rule of
  `ci_skip.decide` as an invariant: a push runs, an unreadable or empty diff runs,
  an unmapped path (a root-level file, an unknown directory, an empty name) runs,
  an always-run or unknown job runs, a read path or a universal path runs, and only
  a fully mapped diff that misses every read skips. A table says which jobs read
  which paths.
- **The census of `ci.yml`.** `check_workflow` requires every job reachable on
  `pull_request` or `merge_group` to be in exactly one of `UNITS` or `ALWAYS_RUN`;
  `ALWAYS_RUN` to equal the literal set of six written in this file (so changing
  it is a reviewed edit) and to include the two owner-ruled jobs
  (`scripts-tests`, `pulumi-inventory-audit`); a skippable job to have no
  job-level `if`, a ci-skip step directly after Checkout whose `unit` is the
  job's own key, and every later step guarded by exactly one `if:` in one of the
  two `!= 'false'` forms; any other job to have none of it; and every required
  `ci.yml` check name to still map to a classified job.
- **The static read census.** `check_reads_named` requires every repository path a
  skippable job's `run:`, `env:` or `with:` names to be inside that job's map
  entry (or to be a file whose change runs every job anyway).
- **The script around the rules.** `changed_files` against a scripted runner and
  against a real shallow clone that must fetch its base; `main` printing exactly
  two lines, never a path, and `run=true` on a crash.

## How the proof is proved

`MutantTests` apply one deliberate break each, in memory, to the decision code, to
the map or to the `ci.yml` text, and require the same checker the real code
passes to raise. The control case (the real code passes) runs first in each.

| Mutant | Break                                                  |
| ------ | ------------------------------------------------------ |
| a      | an unmapped path no longer fails open                  |
| b      | an empty diff skips                                    |
| c      | an unreadable diff skips                               |
| d      | monitoring's reads lose `hetzner/monitoring/`          |
| e      | an always-run job appears in the map                   |
| f      | a step guard is written `== 'true'`                    |
| g      | a job's `unit` names another job's key                 |
| h      | a ci-skip step is added to an always-run job           |
| i      | a job-level `if` is added to a skippable job           |
| j      | a later step is left unguarded                         |
| k      | a new job is in neither set                            |
| l      | the always-run set loses a job                         |
| m      | the event rule is dropped                              |
| n      | the universal list forgets `ci.yml`                    |
| o, p   | a step names a path, or a root file, outside its entry |
| q      | `docs/` leaves the zones, so a docs-only change runs   |

`test_trace_reads.py` does the same for the run-time trace: a fixture that reads
`ansible/x` must exit non-zero, a clean one must exit zero.
