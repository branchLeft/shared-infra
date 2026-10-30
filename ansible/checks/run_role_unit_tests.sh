#!/usr/bin/env bash
# Runs the unit tests of every Ansible role that ships a tests/unit directory.
#
# Usage: run_role_unit_tests.sh <ansible-dir>
#   PYTHON  the interpreter that runs the tests (the pinned tool venv in CI).
#
# Discovery is a glob, so a new role is picked up with no edit here. The script
# fails when no role has a tests/unit directory, when a tests/unit is not a
# directory or holds no test_*.py, when a suite runs zero tests, and when any
# suite fails. Each suite runs from its role's directory with files/ and library/
# on PYTHONPATH, because the roles' tests import from both.
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

failed=0
for unit in "${unit_dirs[@]}"; do
  role="$(dirname "$(dirname "$unit")")"
  name="$(basename "$role")"
  echo "::group::$name unit tests"
  if [ ! -d "$unit" ]; then
    echo "$name: tests/unit is not a directory, so its tests would not run."
    failed=$((failed + 1))
    echo "::endgroup::"
    continue
  fi
  suites=("$unit"/test_*.py)
  if [ "${#suites[@]}" -eq 0 ]; then
    echo "$name: tests/unit holds no test_*.py, so nothing would be tested."
    failed=$((failed + 1))
    echo "::endgroup::"
    continue
  fi
  status=0
  output="$(cd "$role" && PYTHONPATH=files:library "$python" -m unittest discover -b -s tests/unit -p 'test_*.py' 2>&1)" || status=$?
  printf '%s\n' "$output"
  ran="$(printf '%s\n' "$output" | sed -n 's/^Ran \([0-9][0-9]*\) test.* in .*/\1/p' | tail -n 1)"
  if [ "$status" -ne 0 ]; then
    echo "$name: unit tests failed (exit $status)."
    failed=$((failed + 1))
  elif [ -z "$ran" ] || [ "$ran" -eq 0 ]; then
    echo "$name: the unit suites ran zero tests."
    failed=$((failed + 1))
  else
    echo "$name: $ran unit tests passed."
  fi
  echo "::endgroup::"
done

if [ "$failed" -ne 0 ]; then
  echo "$failed role unit suite(s) failed or did not run."
  exit 1
fi
echo "Ran the unit tests of ${#unit_dirs[@]} role(s) in ${SECONDS}s."
