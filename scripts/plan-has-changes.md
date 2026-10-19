# plan-has-changes

`plan-has-changes.py` decides whether a plan job's Pulumi plan would change
anything. Each plan job publishes the answer as the step output `has_changes`.
Its apply job skips on an explicit `false`, so a no-op plan never reaches the
apply's environment and the owner is not asked to approve it. The first line of
the plan job's summary says which way it went.

## The rule

Only a recognised, clean plan is `false`. Everything else is `true`: a missing
or unparseable file, an unknown shape, an unexpected error. A wrong `true`
costs one approval click. A wrong `false` would silently skip a real change, so
the script is built so that it can only err towards `true`.

The script reads two files from the same plan job:

- `preview.json`, from `pulumi preview --json`. The root stack step is always
  listed here; other unchanged resources are hidden, so a real no-op lists one
  step while its change summary counts several `same`. The summary's `same`
  count must therefore be at least the number of `same` steps listed, not equal
  to it.
- The saved update plan, from `pulumi preview --save-plan`. The preview JSON
  has no outputs section, so an output-only change is invisible in it. The
  saved plan carries the root stack's output diff (`adds`, `updates`,
  `deletes`). UNVERIFIED, from the CLI source and not observed live: the diff
  is computed on decrypted in-memory values, so an unchanged secret is no diff
  and a changed one is an entry. The plan holds secrets as ciphertext and
  unknown values as a sentinel string; neither is ever read or printed here.

The plan relies on `--save-plan`, which the CLI help labels as a preview
feature. It is run in its own step, so the `preview.json` that the delete guard
and the apply jobs read is produced exactly as before.

## What a clean plan carries

The allowlists in the script (`PREVIEW_KEYS`, `PLAN_KEYS`, `STEP_KEYS`,
`ENTRY_KEYS`, `GOAL_KEYS`) hold the keys seen in a real plan and preview from a
local run against a throwaway stack, plus the preview step's own fields from
the CLI source. Any other key at those levels is a shape change and gives
`true`.

- The preview carries `steps`, `duration` and `changeSummary`, and optionally
  `config`. `diagnostics` and `maybeCorrupt` are absent in a clean run.
- A plan entry carries `goal`, `steps`, `state` and `seed`. A goal carries
  `type`, `name`, `custom`, `inputDiff`, `outputDiff`, `protect`,
  `customTimeouts`, and for a child `parent`, `provider` and
  `propertyDependencies`. Every entry seen had an `outputDiff`.
- Keys the CLI can write that none of those runs showed, such as
  `dependencies`, `ignoreChanges` or `aliases` on a goal, are not allowlisted.
  A stack whose resources use them gets `true` until the allowlist is widened
  from a real clean plan.
- No `same` step was observed. By the CLI source a `same` step has both states:
  the old one holds the `id` and `outputs`, and the new one is read before it
  copies them. So a state may hold `outputs`, `id` or `provider` on one side
  only, and those are compared only when both sides hold them.

## What makes a plan `false`

All of these hold:

- Both files parse as JSON, with no duplicate keys, no `NaN`, `Infinity` or
  overflowing number, and no nesting beyond a fixed depth. They are two
  different files.
- Both carry only the allowlisted keys at every level above.
- Exactly one step in the preview, and exactly one entry in the plan, has the
  stack type `pulumi:pulumi:Stack` as its own type, and it is the exact type,
  named `<project>-<stack>`. A second stack-typed resource, even one nested
  under a parent type, or a stack type matched only as a suffix, is not a root.
  A resource name containing `::` is refused, so a name cannot imitate another
  URN.
- The preview and the plan name the same root stack URN, so a plan for another
  stack or project is refused.
- Every preview step is `same`. A `same` step has both states as objects, and
  its `detailedDiff`, `diffReasons` and `replaceReasons` are absent, null or
  empty; any other type is refused. Its states agree: `inputs` and `parent`
  must match exactly, a key missing on one side counting as a difference, and
  `outputs`, `id` and `provider` must match when both sides hold them. Whether
  Pulumi ever emits a `same` step that fails this is not verified; the rules
  can only push towards `true`.
- The change summary counts nothing but `same`: a zero count for another
  operation is allowed. The summary's `same` is at least the `same` steps listed.
- `diagnostics` is absent, null or an empty list, and `maybeCorrupt` is absent,
  null or `false`; any other value is refused.
- Every plan entry, the root's included, has a non-empty list of string steps,
  all `same`, and a goal with an `outputDiff`. A goal `type`, if present, is the
  resource's own type. Its input and output diffs are empty objects of the
  expected collection types: `adds` and `updates` are objects and `deletes` is
  a list. A null collection is not an empty one.
- A non-root entry with a non-empty output diff is a change too, because
  registering outputs on a component sets its entry's output diff.

## Reason codes

The script prints `has_changes=<bool> reason=<code> count=<n>` and nothing from
either file. The codes are `no-changes`, `steps-changed`, `summary-changed`,
`output-changed`, `no-root-stack`, `stack-mismatch`, `same-file`,
`preview-unreadable`, `preview-shape`, `preview-diagnostics`, `plan-unreadable`,
`plan-shape` and `internal-error`.

## Output paths

Both `--github-output` and `--github-summary` are required. A blank path, an
existing target that is not a regular file (a device such as `/dev/null`, a
symlink to one, a directory), and one file named for both flags are refused
with exit 1 and nothing written. An unwritable path also exits 1. A skipped
write would turn an unpublished verdict into no approval.

## Limits

- The output-only skip rests on the saved plan's root output diff as observed
  on a local create case against a throwaway local stack. A real `same` plan and
  a real output-only change have not been observed. If a real plan fails one of
  the strict checks, the answer is `true`, which is the behaviour before this
  script existed.
- The plan describes what the CLI would do given the state it reads. A change
  made outside Pulumi (drift) shows up only if a refresh is part of the preview.
- The Pulumi CLI is not pinned. A version that changes the shape makes the
  script fall back to `true`.

## Tests

`test_plan_has_changes.py` holds a fixture and a test for each rule above.
`test_ci_apply_environments.py` checks that each apply job's `if:` is exactly
the push, main and `has_changes != 'false'` operands joined by `&&`.
