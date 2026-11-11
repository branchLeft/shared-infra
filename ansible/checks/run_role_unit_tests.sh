#!/usr/bin/env bash
# Runs the unit tests of every Ansible role that ships a tests/unit directory.
#
# Usage: run_role_unit_tests.sh <ansible-dir>
#   PYTHON  the interpreter that runs the tests (the pinned tool venv in CI).
#
# Discovery is a glob, so a new role is picked up with no edit here. The script
# fails when no role has a tests/unit directory, when a tests/unit is not a
# directory or holds no test_*.py, when a suite runs zero tests or its unittest
# summary is missing or not the one result line after the last Ran line, when any
# suite fails, and when a suite skips or expected-fails a test: a role suite is a
# control, so a skipped test is a control that does not run. Each suite runs from
# its role's directory with files/ and library/ on PYTHONPATH, because the roles'
# tests import from both.
#
# The roles run side by side, one background process each, so the step takes as long
# as its slowest role rather than the sum of all of them. Each role writes its own log,
# and the logs are printed in role order once every role has finished, so the output
# reads the same as a serial run. A role's verdict is its own exit status.
set -euo pipefail
shopt -s nullglob

if [ "$#" -ne 1 ]; then
  echo "usage: run_role_unit_tests.sh <ansible-dir>" >&2
  exit 2
fi
ansible_dir="$1"
python="${PYTHON:?PYTHON must name the interpreter that runs the tests}"

unit_dirs=("$ansible_dir"/roles/*/tests/unit)
if [ "${#unit_dirs[@]}" -eq 0 ]; then
  echo "No role under $ansible_dir/roles has a tests/unit directory, so no role unit test would run."
  exit 1
fi

# Runs one role's suite and prints its log. Returns 0 when the role passes and 1 when it
# fails or does not run. It runs in a background subshell, so it never changes the caller.
check_role() {
  local unit="$1"
  local role name status output ran_no ran after result_line extra_line result_match
  role="$(dirname "$(dirname "$unit")")"
  name="$(basename "$role")"
  echo "::group::$name unit tests"
  if [ ! -d "$unit" ]; then
    echo "$name: tests/unit is not a directory, so its tests would not run."
    echo "::endgroup::"
    return 1
  fi
  local suites=("$unit"/test_*.py)
  if [ "${#suites[@]}" -eq 0 ]; then
    echo "$name: tests/unit holds no test_*.py, so nothing would be tested."
    echo "::endgroup::"
    return 1
  fi
  status=0
  output="$(cd "$role" && PYTHONPATH=files:library "$python" -m unittest discover -b -s tests/unit -p 'test_*.py' 2>&1)" || status=$?
  printf '%s\n' "$output"
  # The summary is the last "Ran N tests in X.XXXs" line, then the one result line
  # after it. Lines before it are test output and are not read as a result.
  ran_no="$(printf '%s\n' "$output" | sed -n -E '/^Ran [0-9]+ tests? in [0-9.]+s$/=' | tail -n 1)"
  ran="$(printf '%s\n' "$output" | sed -n -E 's/^Ran ([0-9]+) tests? in [0-9.]+s$/\1/p' | tail -n 1)"
  after="$(printf '%s\n' "$output" | tail -n +$((${ran_no:-0} + 1)) | sed -n '/./p')"
  result_line="$(printf '%s\n' "$after" | sed -n '1p')"
  extra_line="$(printf '%s\n' "$after" | sed -n '2p')"
  result_match="$(printf '%s\n' "$result_line" | sed -n -E '/^(OK|FAILED)( \(.*\))?$/p')"
  local verdict=0
  if [ "$status" -ne 0 ]; then
    echo "$name: unit tests failed (exit $status)."
    verdict=1
  elif [ -z "$ran_no" ]; then
    echo "$name: no unittest summary (a 'Ran N tests in X.XXXs' line) was printed, so the run is unknown."
    verdict=1
  elif [ -z "$ran" ] || [ "$ran" -eq 0 ]; then
    echo "$name: the unit suites ran zero tests."
    verdict=1
  elif [ -z "$result_match" ]; then
    echo "$name: no OK or FAILED result line follows the Ran line, so the outcome is unknown."
    verdict=1
  elif [[ "$result_line" == *skipped=* || "$result_line" == *"expected failures="* ]]; then
    echo "$name: unit suites skipped or expected-failed a test, so it does not count as passed (a control suite may not skip)."
    verdict=1
  elif [[ "$result_line" == FAILED* ]]; then
    echo "$name: unit suites reported FAILED."
    verdict=1
  elif [ -n "$extra_line" ]; then
    echo "$name: output follows the unittest result line, so the summary is not trusted."
    verdict=1
  else
    echo "$name: $ran unit tests passed."
  fi
  echo "::endgroup::"
  return "$verdict"
}

logs="$(mktemp -d)"
trap 'rm -rf "$logs"' EXIT
pids=()
for i in "${!unit_dirs[@]}"; do
  check_role "${unit_dirs[$i]}" > "$logs/$i.log" 2>&1 &
  pids+=("$!")
done

failed=0
for i in "${!unit_dirs[@]}"; do
  if ! wait "${pids[$i]}"; then
    failed=$((failed + 1))
  fi
  cat "$logs/$i.log"
done

if [ "$failed" -ne 0 ]; then
  echo "$failed role unit suite(s) failed or did not run."
  exit 1
fi
echo "Ran the unit tests of ${#unit_dirs[@]} role(s) in ${SECONDS}s."
