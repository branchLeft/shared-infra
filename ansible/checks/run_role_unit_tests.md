# run_role_unit_tests.py: the role unit suites

The lint job runs `run_role_unit_tests.py` once, and it runs the unit tests of every
`roles/*/tests/unit` directory found by glob, with no list to edit. A suite fails the step when it
fails, runs no test, or skips or expected-fails a test: a role suite is a control, and a skipped
test is a control that does not run, so `OK (skipped=N)` and `OK (expected failures=N)` both fail
the step and name the role.
