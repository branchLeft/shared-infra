#!/bin/sh
# PLACEHOLDER program for the program_and_timer pattern. It does nothing useful.
# Its install-time check is --check: exit 0 when the program is fit to run.
if [ "${1:-}" = "--check" ]; then
  exit 0
fi
echo PLACEHOLDER_PROGRAM_V1
