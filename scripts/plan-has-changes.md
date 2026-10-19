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
  `deletes`), computed by the CLI on decrypted in-memory values. An unchanged
  secret is therefore no diff, and a changed one is an entry. The plan holds
  secrets as ciphertext and unknown values as a sentinel string; neither is
  ever read or printed here.

The plan relies on `--save-plan`, which the CLI help labels as a preview
feature. It is run in its own step, so the `preview.json` that the delete guard
and the apply jobs read is produced exactly as before.

## What makes a plan `false`

All of these hold:

- Both files parse as JSON, with no duplicate keys, no `NaN` or `Infinity`, and
  no nesting beyond a fixed depth. They are two different files.
- Both carry only top-level keys listed as `PREVIEW_KEYS` and `PLAN_KEYS` in the
  script. A key never seen before is a shape change and gives `true`.
- Exactly one step in the preview, and exactly one entry in the plan, has the
  exact type `pulumi:pulumi:Stack`, and it is named `<project>-<stack>`. A
  second stack-typed resource, or a stack type matched only as a suffix, is not
  a root. A resource name containing `::` is refused, so a name cannot imitate
  another URN.
- Every preview step is `same`, and none carries its own evidence of a
  difference: a non-empty `diffs`, `detailedDiff`, `diffReasons` or
  `replaceReasons`, or an `oldState` and `newState` that both hold `inputs` or
  `outputs` and differ. Whether Pulumi ever emits such a `same` step is not
  verified; the rule can only push towards `true`.
- The change summary counts nothing but `same`, and the preview is not marked
  `maybeCorrupt`.
- Every plan entry, the root's included, has a non-empty list of string steps,
  all `same`, and a goal whose `type`, if present, is the resource's own type.
  Its input and output diffs, if present, are empty objects of the expected
  collection types: `adds` and `updates` are objects and `deletes` is a list. A
  null collection is not an empty one.
- The root entry has an output diff. A non-root entry with a non-empty output
  diff is a change too, because registering outputs on a component sets its
  entry's output diff.

## Reason codes

The script prints `has_changes=<bool> reason=<code> count=<n>` and nothing from
either file. The codes are `no-changes`, `steps-changed`, `summary-changed`,
`output-changed`, `no-root-stack`, `same-file`, `preview-unreadable`,
`preview-shape`, `plan-unreadable`, `plan-shape` and `internal-error`.

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
- Both `--github-output` and `--github-summary` are required and must name a
  writable file. A silent skip would turn an unpublished verdict into no
  approval, so the script exits non-zero instead.

## Tests

`test_plan_has_changes.py` holds a fixture and a test for each rule above.
`test_ci_apply_environments.py` checks that each apply job's `if:` is exactly
the push, main and `has_changes != 'false'` operands joined by `&&`.
