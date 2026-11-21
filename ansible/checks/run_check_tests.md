# run_check_tests.py

## What it does

Runs the unit tests of `ansible/checks/` in one of two parts, so the full lint can
run them in two legs at once. `main` is every `test_*.py` except the modules
named in `SLOW_MODULES`; `slow` is only those. The workflow's step "Test the
checks" (leg `checks`) runs `main` and the step "Test the slow checks" (leg
`slow`) runs `slow`.

## Why

In one step the tests of the checks took 7 to 12 minutes, the longest leg of the
full lint (the owner's ruling on the Desk, rerun-si771: make the step faster, do
not accept longer runs). The ten slowest tests, printed by the step, are a few
modules that start many `ansible-playbook` processes. Two legs on two runners
halve the time without dropping a test.

## Nothing is dropped

- The parts are chosen by file. `main` is everything not named as slow, so a new
  test module needs no entry and runs in `main`.
- Each module is loaded by its own `discover` call, as `discover -p <file>` does,
  so a module that fails to import is a failed test in its own part.
- A part with no tests exits 1.
- `test_run_check_tests.py` holds that the two parts are every module exactly
  once, that every name in `SLOW_MODULES` is a module that exists, and that the
  workflow runs each part in its own leg.

Moving a module between the parts changes which leg runs it and nothing else.
The slowest ten tests of each part are printed after its run.
