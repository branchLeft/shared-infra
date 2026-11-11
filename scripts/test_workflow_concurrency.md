# Workflow concurrency pin tests

`scripts/test_workflow_concurrency.py` pins the rule that a pull_request run is
grouped per pull request, and that only those runs cancel. This page holds the
rule narrative; the module docstring points here.

Every workflow is parsed, and every rule is checked on the parsed data, never on
the text. So a quoted key, an escaped quote, a multi-line quoted value, a
list-form or quoted trigger, and a `#` inside a value cannot hide a concurrency
key.

## The parser

The parser is PyYAML (pinned in `ci.yml`) behind a loader that reads a file the
way GitHub does where PyYAML's YAML 1.1 differs, and refuses what it cannot
match:

- a duplicate key is refused (`safe_load` keeps the last one silently);
- a merge key (`<<`) is refused;
- only true and false (any case) are booleans, so `on`, `off`, `yes` and `no`
  stay strings, as in YAML 1.2. The `on:` trigger key is then the string "on";
- an explicit tag on any node (`!!bool "off"`, `!!str true`, a bare `!`) is
  refused: it bypasses the resolver above, and how GitHub reads it is
  unverified.

## The rules

Each rule is checked on the parsed data.

- A workflow with a pull_request or pull_request_target trigger has one
  top-level concurrency block, exactly the run-keyed block below: its group is
  keyed on the pull request number and falls back to the run id, and its
  cancel-in-progress is the pull_request expression. pull_request_target counts
  as pull_request: it has a pull request number, and the expression is false for
  it, so it is grouped and never cancels.
- A workflow without one has a top-level group, if any, that is run-keyed: made
  only of literal text and the expressions `github.workflow` and
  `github.run_id`, with at least one expression holding `github.run_id`. So no
  two runs share a group. The run id counts only as a term inside `${{ }}`: the
  text "github.run_id" in a literal or a quoted string does not. The pull
  request number with the run id fallback is a term only in a workflow with a
  pull_request trigger (the exact block above); a workflow that also has a
  pull_request_review or pull_request_review_comment trigger is refused, because
  those events carry the number with no fallback and every run for one pull
  request would share the group.
- A merge_group workflow has a top-level group that is run-keyed in that sense
  and does not hold the ref, so queued checks never replace one another.
- cancel-in-progress is a whitelist: absent or the boolean false on a job. The
  one other value is the pull_request expression, and only on the top-level
  pull_request block. On a job it is refused: a job group every run shares would
  let a pull request run cancel a push run, and the per-pull-request group is
  the workflow's own group. Anything else (true, a string, "false", an
  expression, null) is refused.
- A job that has a concurrency block has a group that is a non-empty string and
  a plain literal: any `${{` in it is refused, whatever it would evaluate to, so
  no expression can make it equal the workflow's group. A group that is missing,
  empty, null or not a string (`group: 123`, `group: true`) is refused too. This
  test does not evaluate the job's expressions, because it refuses them.

## A job literal against the workflow group

GitHub keeps one group namespace for a run and its jobs, so a job whose group is
the workflow's own group would wait on its own run. A job literal is refused
when it is equal to the workflow's group, compared with `str.casefold()` because
GitHub treats group names as case-insensitive. `casefold()` also folds some
characters GitHub may not (the sharp s equals "ss"): a deliberate over-refusal,
since a false refusal costs a rename and a miss costs a cancelled deploy.

- A literal workflow group is compared with the job literal as text.
- A workflow group that holds expressions is not unique to a run. The pull
  request block is keyed on the pull request number, so every run of one pull
  request evaluates to the same, predictable value (`CI-369`). A run id is not
  predictable in advance, but a literal can still hard-code one that already
  exists (`x-39646213815` under `x-${{ github.run_id }}`). So the job literal is
  refused when it fully matches the workflow group's template, ignoring case.
  The template is built from the group's literal text, escaped, with
  `github.workflow` replaced by the workflow's `name:` (or its file path,
  `.github/workflows/<file>`, when there is no `name:`), and each run id or pull
  request number term replaced by a run of digits. A present `name:` that is not
  a string (an integer, a float or a boolean), or is empty or blank, is refused
  as unreadable, so the file path is never substituted for it.
- Surrounding whitespace is not part of a group name, so the job literal, a
  literal workflow group and the `name:` substituted for `github.workflow` are
  stripped before the comparison. `" CI-369"` and `"CI-369 "` under `name: CI`
  are refused like `CI-369`, and `name: " CI"` makes `CI-369` a refused job
  literal.
- A sibling name that is not that template is accepted: `x-mail` under
  `x-${{ github.run_id }}`, `-deploy` under
  `${{ github.workflow }}-${{ github.run_id }}`, and the real `pulumi-*-deploy`
  groups. A prefix match is not a refusal.
- A group term the template does not know matches anything, so the job literal
  is refused. That workflow group is already a violation of the run-keyed rule.

## A job literal against another workflow's group

Concurrency groups are one namespace for the whole repository, not per workflow.
So a job literal equal to another workflow's top-level group would queue behind
that workflow's runs, or replace a pending one. Each workflow's job literals are
compared with every other workflow's top-level group, by `same_literal_group`
and the same template rules as above: a literal top group is compared as text
with `str.casefold()`, and a top group that holds expressions is compared with
its template. A top group that is absent, or has no group key, is not compared.
A workflow file that does not parse is skipped here, since its own rules refuse it.

## Failing closed

Every check fails closed: a file that does not parse, whose top level is not a
mapping, whose trigger block is missing or unreadable, or whose concurrency
value is not a mapping with only the keys `group` and `cancel-in-progress`, and
whose `name:`, when present, is not a string or is empty, is a violation.
