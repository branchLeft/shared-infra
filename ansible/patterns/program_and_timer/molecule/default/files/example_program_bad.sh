#!/bin/sh
# PLACEHOLDER program whose install-time check fails. The scenario must refuse it
# and keep the installed program.
if [ "${1:-}" = "--check" ]; then
  echo PLACEHOLDER_CHECK_FAILED
  exit 1
fi
echo PLACEHOLDER_PROGRAM_BAD
