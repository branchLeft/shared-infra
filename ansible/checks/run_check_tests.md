# run_check_tests.py

## What it does

Runs the unit tests of `ansible/checks/` in one of two parts, two worker processes at
a time. `main` is every `test_*.py` except the modules named in `SLOW_MODULES`;
`slow` is only those. The workflow's step "Test the checks" (leg `checks`) runs
`main` and the step "Test the slow checks" (leg `slow`) runs `slow`.

Within a part the tests are cut into slices of one module and at most
`SLICE_SIZE` tests, and the slices run side by side, two
`run_check_tests.py --worker` processes at a time (`CHECK_TESTS_JOBS` sets the
number; `1` runs everything in the one process, as before). The tests are the
same, run by unittest the same way; only the number of them running at once
changes.

## Why

In one step the tests of the checks took 7 to 12 minutes, the longest leg of the
full lint (the owner's ruling on the Desk, rerun-si771: make the step faster, do
not accept longer runs). The ten slowest tests, printed by the step, are a few
modules that start many `ansible-playbook` processes, and the whole step used one
of the runner. Two workers take the same tests in about 58% (`main`) and 57%
(`slow`) of the time, measured on the runner; three and four workers were slower
than two for `slow`, because the tests start heavy processes of their own. The
CI pool is counted in runner minutes, so the saving is paid back to every other job.

## Nothing is dropped

- The parts are chosen by file. `main` is everything not named as slow, so a new
  test module needs no entry and runs in `main`.
- Each module is loaded by its own `discover` call, as `discover -p <file>` does,
  so a module that fails to import is a failed test in its own part. The runner
  reports it itself and never hands it to a worker.
- A part with no tests exits 1.
- Every collected test id goes to exactly one slice (`slices` is tested for it).
- The run fails closed. A worker that exits non-zero, writes no result file,
  reports a failure, or runs a different number of tests than it was given
  fails the run, and so does a total that differs from the number of tests
  collected. A class whose `setUpClass` fails runs fewer tests than its slice
  holds, so it fails on both counts.
- `test_run_check_tests.py` holds that the two parts are every module exactly
  once, that every name in `SLOW_MODULES` is a module that exists, that the
  workflow runs each part in its own leg, and that a failing test, a dying
  worker, a failing `setUpClass` and an import error each end the run red.

Moving a module between the parts changes which leg runs it and nothing else.
The slowest ten tests of each part are printed after its run.
