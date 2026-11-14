# ci_skip.py

Decides, from the paths a pull request or merge queue entry changes, whether one
`ci.yml` job needs to run its steps. It is the single home of the path map: the
composite action `.github/actions/ci-skip` runs it, `trace_reads.py` and
`test_ci_skip.py` import it, and nothing keeps a copy.

## Interface

```sh
EVENT_NAME=pull_request BASE_SHA=<sha> HEAD_SHA=<sha> \
  python3 scripts/ci_skip.py --unit monitoring-config-validate
```

It prints two lines for `$GITHUB_OUTPUT`: `run=true|false` and `reason=<one line>`.
The reason never carries a changed path, so a file name cannot write an output.
Standard library only, because it runs right after Checkout, before a job has set
up a Python of its own. The base commit is fetched with one anonymous depth-1
`git fetch` of that sha when the shallow checkout lacks it; the diff is two-point
(`git diff --name-only -z --no-renames base head`). No credential is involved.

## Which jobs may skip

Eight check jobs are in `UNITS`: `mail-typecheck`, `mail-provision-checks`,
`shim-image-starts`, `ovh-copy2-checks`, `edge-config-validate`,
`monitoring-config-validate`, `nextcloud1-config-validate` and
`control-plane-config-validate`. Each job's
entry lists every repository path it reads. `shim-image-starts` reads only
`mail/provision/` (its script renders and starts the image from there), so it sits
in `UNITS` with `mail/provision/`, not in `ALWAYS_RUN`. Every job reachable on
`pull_request` or `merge_group` is in exactly one of the two sets.

## The rules, in order (every error resolves to `run=true`)

1. The event is not `pull_request` or `merge_group` (a push to `main`, anything
   else): run. The push to `main` therefore runs every job, which is the
   compensating control for two queued pull requests interacting (CI-3).
2. The job is in `ALWAYS_RUN`, or is not in the map: run.
3. Base or head is missing or not a sha, the fetch fails, or `git diff` fails or
   raises: run.
4. The diff is empty: run.
5. A changed path is outside every zone (`ansible/`, `hetzner/`, `hetzner-host/`,
   `mail/`, `ovh/`, `scripts/`, `docs/`, `.github/`, `.claude/`): run. Root-level files and unknown
   directories are in this case.
6. A changed path is one the job reads (`UNITS`), or one that changes the skip
   machinery itself (`UNIVERSAL`: `ci.yml`, the ci-skip action, `ci_skip.py`,
   `trace_reads.py`): run.
7. Otherwise `run=false`.

## What the workflow does with it

Each of the seven skippable jobs keeps its place and name, so every required check
still reports and the ruleset is untouched. The step after Checkout is
`uses: ./.github/actions/ci-skip` with `unit:` set to the job's own key, and every
later step carries `if: steps.skip.outputs.run != 'false'` (a cleanup step
`always() && ...`). An empty or missing output runs the step. There is no
job-level `if`, because a required check that is skipped counts as passing.

## Why six more jobs than the first plan never skip

`scripts-tests` and `pulumi-inventory-audit` run tree-wide guards
(`assert-no-committed-pulumi-secrets.py --scan-tree`, `audit-pulumi-secrets.py`),
so the owner ruled them always-run. Tracing what the other jobs open found four
more: `typecheck` runs `prettier --check .` over the whole tree,
`hetzner-typecheck` and `hetzner-host-typecheck` import the root `sites.ts`, and
`hetzner-provision-checks` reads every ansible role and runs `git ls-files`. They
stay in `ALWAYS_RUN`. The saving that matters is `monitoring-config-validate`
(promtool) and `edge-config-validate`; an ansible-only pull request skips both.

## trace_reads.py

The map says what a job reads; two layers keep it honest. `test_ci_skip.py` checks
statically that every repository path a skippable job's steps name is inside its
map entry. `trace_reads.py` checks at run time, inside the job, the two Python
steps whose reads are not visible in `ci.yml`: it runs the unittest command under
an audit hook and exits 1 if anything opens, lists or scans a repository path
outside the job's entry, or starts `git ls-files`. The trace lives in the job
rather than in `scripts-tests` on purpose: a test that starts reading outside the
map has to be edited inside the map, which runs the job and turns it red.

Limits, stated: `os.stat`, `pathlib.exists` and the like raise no audit event, so a
bare existence check is not seen; an `open` relative to a directory descriptor
(`shutil.rmtree` does this) cannot be attributed, so a relative name that does not
exist beside the working directory is ignored; only Python is traced, and the
shell steps are covered by the static census.

## Adding a job

A new job reachable on `pull_request` must be in exactly one of `UNITS` or
`ALWAYS_RUN`, or `test_ci_skip.py` fails. Widening `ALWAYS_RUN` is a reviewed edit
to the literal set in that test. Narrowing it needs the evidence the section above
gives: what the job opens, read from a trace.
