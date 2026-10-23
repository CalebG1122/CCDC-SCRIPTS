#!/bin/bash
# Safe Linux checks: no scan, cleanup, sudo or writes to system directories.
set -eu
script=${1:-./06-hunt.sh}
bash -n -- "$script"
printf 'PASS: Bash syntax\n'
bash "$script" --help >/dev/null
printf 'PASS: help\n'
expect_usage_error() {
  local code=0
  bash "$script" "$@" >/dev/null 2>&1 || code=$?
  [[ $code == 2 ]] || { printf 'FAIL: expected exit 2, got %s\n' "$code"; exit 1; }
}
expect_usage_error --unknown-option
expect_usage_error --since
expect_usage_error --root
expect_usage_error --limit
expect_usage_error --limit 0
expect_usage_error --limit nope
expect_usage_error --root relative/path
expect_usage_error --since not-a-date
printf 'PASS: argument and date validation\n'
printf 'Checks complete. Full scans and interactive quarantine require separate Linux validation.\n'
