# test_suite_size.py

## Module overview

Two ways a test module can vanish from a run both leave `unittest discover`
reporting a smaller number with no other signal: an interpreter below the
suite's floor turns each module it cannot import into one `_FailedTest`
placeholder, and a
module deleted from disk is simply not there to find. Either way the suite
can still exit 0 if everything it did collect passes -- a shrunken run looks
identical to a smaller, still-complete one unless something states what the
count should be.

The floor is `MIN_PYTHON` (3.9, macOS's system `python3`). The refusal is the pure
function `interpreter_below_floor`, so its tests drive it with a 3.8 value (refused,
naming the interpreter) and a 3.9 value (accepted) without needing a 3.8 interpreter.
The CI check reads the `run:` value of the step named "Python version floor" in
`ci.yml` and must equal the floor command. Four committed fixtures must each fail it:
a commented-out step, a disabled `run:`, a renamed step, and another version. A module
that uses `X | None` in an annotation carries `from __future__ import
annotations`, so it imports on 3.9.

The expected number is kept per module, in `test_counts/<module>.txt`
(one integer and a newline), not as one constant for the directory. A single
number was a line every pull request that adds a test had to edit, so
unrelated pull requests collided on it; one file per module means two pull
requests adding tests to different modules touch different files. The test
fails on a test module with no count file, a count file with no module (the
module was deleted or failed to import), and a module whose count differs.
`test_counts/` is owned by the same CODEOWNERS owner as this file.

This can only guard the rest of the directory, never itself: a test that
vanished along with this file would leave nothing here to notice the drop.
Change `test_counts/<module>.txt` in the same change that adds or removes a
test method in that module, and add or delete the file with the module,
including for this file's own `test_counts/test_suite_size.txt`.
