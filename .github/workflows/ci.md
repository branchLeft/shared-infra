# ci.yml: guardrails and deploy pipelines

The narrative that used to sit above the jobs in `ci.yml`. The file keeps a
pointer beside each block; the rules live here.

## Guardrails for the credentialed jobs

`ci.yml` type-checks every Pulumi program on every pull request, and applies the
CI-owned stacks on every push to `main`, each through a plan job whose output a
human approves before the paired apply job runs.

The GCP edge program that used to live at the repository root (`edge.ts` and its
deploy-plan/deploy-apply jobs) is gone: the GCP estate was destroyed 2026-09-13
and the program was removed once it described infrastructure that no longer
existed. What is left is Hetzner-native: the mail stack and both `hetzner/`
stacks. The guardrails below are unchanged for them.

1. Anything credentialed runs only on `push` to `main`, a reviewed, merged
   commit. Pull requests get type-check only, and no credentials of any kind.
2. Hetzner has no Workload Identity Federation equivalent, because its API
   accepts a bearer token and nothing else. So each stack's token is scoped to
   one hcloud project and one pipeline (`hetzner/RUNBOOK-new-stack.md` section 7),
   a trade doc 14 section 3.5 records deliberately.
3. A preflight parses the real `pulumi preview` plan for this exact run and
   aborts before `pulumi up` if it would destroy protected infrastructure
   (`scripts/assert-no-hetzner-deletes.py`).
4. Every apply job declares an `environment` and a concurrency group. The
   environment's protection rule is what pauses the apply until the plan job's
   summary has been read and approved. The delete guard catches the destruction
   class mechanically; the reviewer catches the plan that is green,
   non-destructive and still wrong. An environment with no protection rule pauses
   nothing and says nothing, so verify the rule via the API before trusting the
   gate. The mail apply is in its own environment, `production-mail`, and the DNS
   apply is in its own, `production-dns`, so no approval meant for another stack's
   apply can release either (GitHub approves per environment per run). The mail
   and DNS plan jobs each have a main-only environment with no reviewer
   (`mail-plan`, `dns-plan`) that holds their credentials.
5. The apply job re-runs preview and the guard immediately before `pulumi up`:
   what was approved and what is applied can diverge only inside one run's window,
   and never past the guard.
6. The two Hetzner applies are routed by the spend gate (github-workflows'
   `spend-gate` action). A plan whose every change is a free resource type runs
   its apply in `production-free`, which only the reviewer App's protection rule
   answers. Every other plan, and any plan the gate could not read, runs in
   `production`, where the owner approves. Only the exact string `production-free`
   selects the free environment, the apply re-gates its own preview before
   `pulumi up`, and the apply refuses an environment without a rule. The mail apply
   is never routed: it stays in `production-mail`, and the DNS apply is never
   routed either: it stays in `production-dns` (`scripts/choose-apply-environment.py`,
   `scripts/test_ci_apply_environments.py`).

## Why there is no preview job on pull requests

There is deliberately no `pulumi preview` job on pull requests. It is the obvious
next step, but it means handing credentials to a job running unmerged code, and a
bearer token would work from anywhere, which makes the risk live rather than
blocked. The plan-then-approve split above is the compensating control: no plan
applies unread.

## Deploy pipelines

Each stack gets a plan job and an apply job: the plan job writes the real
`pulumi preview` plan for this exact commit to its job summary, and the apply job,
gated by its environment's protection rules (`production`, `production-mail` for
the mail stack alone, or `production-dns` for the DNS stack alone), runs only
after the plan has been read and approved. The apply job re-runs preview and the
delete guard itself, so the approved window can never smuggle a plan past the
gate.

`changes` decides which of the four pairs even start: a push that touches none of
a stack's own inputs skips that stack's plan, and its apply with it. A job that
`needs` a skipped dependency inherits the skip by default, so nothing downstream
has to repeat the condition. None of these eight jobs are required-status-check
contexts (checked against this repo's ruleset before this filter was written), so
a skip here can never satisfy a branch-protection gate; it only decides whether an
apply gets queued at all.

A second, finer skip: each plan job that ran also outputs `has_changes`, and its
apply job's `if:` skips only on an explicit `'false'`. A plan that changes nothing,
stack outputs included, skips its apply, so no approval is asked for it and the
run graph shows the apply skipped; the plan job's summary says so on its first
line. An unset output does not skip, and a plan job that was skipped or failed
still skips its apply (the implicit `success()` of an `if:` with no status
function). The shared plan-has-changes action computes it and fails closed: only a
plan that parsed and is wholly `same` is `false`. It reads `preview.json` and a
saved update plan (a second preview, in its own step), because `preview.json`
cannot show an outputs-only change. The environments, their reviewers and the
ungated-environment refusal are untouched: only when the gate is asked changes.

A wrong filter, a path that feeds a stack's plan but isn't listed here, produces a
skip with no red anywhere, which would be worse than the unread-approval habit
this exists to fix. The lists in `changes` are traced against each program's
actual import graph, not guessed, and kept coarse on purpose: a whole dependency
directory such as `hetzner-host/**` rather than the individual files inside it,
because a coarse filter's failure mode is an unnecessary plan and a precise one's
is a missed apply.

Three things the machinery cannot enforce, on the approver:

- Approve each queued apply individually, with its own plan summary open. The
  pending-deployments screen offers a multi-select approve, and using it signs off
  plans nobody read.
- The environment rule itself lives in repo settings. Each apply job's first step
  verifies via the API that its environment pauses it and fails the apply if not,
  so an unconfigured gate is a red run, not a silent unattended apply.
  `production-mail` and `production-dns` must each have a required-reviewer rule
  (the DNS gate accepts nothing else, so the reviewer App's custom rule can never
  release a DNS apply). `mail-plan` and `dns-plan` must have a main-only branch
  policy and no reviewer, and `dns-plan` and `production-dns` each hold the three
  DNS secrets. `production` may have a required-reviewer rule or an enabled custom
  deployment protection rule of the reviewer App (integration id 5090756).
  `production-free`, which only a plan the spend gate reads as free reaches, needs
  that App rule: a plan job routes to it only while the rule is there, and the
  apply checks again.
- A newer push run cancels older runs of this workflow still `waiting` for
  approval, from each plan job (the step after its checkout, which the script it
  runs needs on disk). The workflow-level group does not do this job. It is keyed
  on the run id for every push, so no push run queues behind a run paused for
  approval, and its cancel-in-progress is false for every such run (pinned by
  `scripts/test_workflow_concurrency.py`).
