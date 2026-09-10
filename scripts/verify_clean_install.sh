#!/usr/bin/env bash
# Proves README's claim of a clean environment by building one.
#
# An L6 review 2026-09-10 pointed out that README claimed "the suite was run in a
# fresh virtual environment" directly above the sentence "Nothing in this repository
# asks to be believed" -- and that this exact claim could not be run. The script
# verify_claims.sh always runs against the same fixed venv and can therefore never
# show it.
#
# This script is deliberately separate from verify_claims.sh: it requires the
# network and takes a dozen or so seconds, and a verification that is too slow to
# run stops being run.
# Run it when the dependencies or the packaging change.
#
# No expected test count appears here. The suite is the source of truth for how
# many tests it has; the script only requires that zero fail and that the count is
# greater than zero.
set -uo pipefail

VENV="$(mktemp -d)/venv"
trap 'rm -rf "$(dirname "$VENV")"' EXIT

echo "== Clean venv at $VENV =="
python3 -m venv "$VENV" || { echo "FAIL: could not create venv"; exit 1; }

echo "== Installing the package and its dev dependencies =="
"$VENV/bin/pip" install -q -e ".[dev]" || { echo "FAIL: install failed"; exit 1; }

# env -i empties the environment completely: no PYTHONPATH, no inheritance from
# the developer shell. That way we measure the packaging, not the machine that
# happens to run the script.
echo "== Running the suite without PYTHONPATH and without an inherited environment =="
OUT="$(env -i "$VENV/bin/python" -m pytest -q 2>&1 | tail -3)"
echo "$OUT"

PASSED="$(echo "$OUT" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | head -1)"
FAILED="$(echo "$OUT" | grep -oE '[0-9]+ (failed|error)' | grep -oE '[0-9]+' | head -1)"

echo
if [ -n "${FAILED:-}" ] || [ -z "${PASSED:-}" ] || [ "$PASSED" -eq 0 ]; then
  echo "-------- FAIL: the clean install is not green --------"
  exit 1
fi
echo "-------- PASS: $PASSED tests passed in a clean venv --------"
