# test_check_hetzner_projects.py

The module docstring of `test_check_hetzner_projects.py` kept its summary paragraph; the rest of the narrative, usage notes and rationale is below, unchanged.

Every fault this checker looks for is silent in production, so the tests are
written the other way round from the usual: each one builds the broken layout
and asserts the checker _notices_, because a checker that has stopped noticing
is indistinguishable from a clean tree.

The three that matter most, in order of what they cost when missed:

- **A shared project `name`.** Two projects over one state file. An apply in
  the second loads the first's checkpoint and plans to delete its resources,
  and it gets part-way through before anyone reads the plan.
- **A `main` that names the package's own entry point.** The same fault as
  omitting `main`, spelled out, so a checker that only tests for absence passes
  the very edit it exists to catch.
- **Reader edge cases.** A trailing comment, a duplicate key or an inline flow
  mapping each make the reader answer confidently and wrongly, which surfaces
  as a failure naming the wrong fault -- worse than no check, because it sends
  someone to fix a thing that is not broken.

The last case builds nothing: it runs the check against this repository's own
`hetzner/` tree, so the tree drifting is itself a test failure rather than
something only CI notices.

No network. No subprocess.
