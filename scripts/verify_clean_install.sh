#!/usr/bin/env bash
# Bevisar README:s pastaende om en ren miljo genom att bygga en.
#
# En L6-granskning 2026-09-10 papekade att README hävdade "the suite was run in a
# fresh virtual environment" direkt ovanfor meningen "Nothing in this repository
# asks to be believed" -- och att just det pastaendet inte kunde koras. Skriptet
# verify_claims.sh kor alltid mot samma fasta venv och kan darfor aldrig visa det.
#
# Detta skript ar medvetet skilt fran verify_claims.sh: det kraver natverk och tar
# tiotalet sekunder, och en verifiering som ar for langsam att kora slutar koras.
# Kor det nar beroendena eller paketeringen andras.
#
# Ingen forvantad testsiffra star har. Sviten ar sanningskallan for hur manga tester
# den har; skriptet kraver att noll faller och att antalet ar storre an noll.
set -uo pipefail

VENV="$(mktemp -d)/venv"
trap 'rm -rf "$(dirname "$VENV")"' EXIT

echo "== Ren venv i $VENV =="
python3 -m venv "$VENV" || { echo "FAIL: kunde inte skapa venv"; exit 1; }

echo "== Installerar paketet och dess dev-beroenden =="
"$VENV/bin/pip" install -q -e ".[dev]" || { echo "FAIL: installationen gick inte"; exit 1; }

# env -i tommer miljon helt: ingen PYTHONPATH, inget arv fran utvecklarskalet.
# Da mater vi paketeringen, inte den maskin som rakar kora skriptet.
echo "== Kor sviten utan PYTHONPATH och utan arvd miljo =="
OUT="$(env -i "$VENV/bin/python" -m pytest -q 2>&1 | tail -3)"
echo "$OUT"

PASSED="$(echo "$OUT" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | head -1)"
FAILED="$(echo "$OUT" | grep -oE '[0-9]+ (failed|error)' | grep -oE '[0-9]+' | head -1)"

echo
if [ -n "${FAILED:-}" ] || [ -z "${PASSED:-}" ] || [ "$PASSED" -eq 0 ]; then
  echo "-------- FAIL: ren installation ar inte gron --------"
  exit 1
fi
echo "-------- PASS: $PASSED tester passerade i en ren venv --------"
