#!/usr/bin/env bash
# Independent review of a change, by a model that did not write it.
#
# L6: the one who built it does not approve it. A model family reviewing its own
# output carries the same blind spots into the review as it did into the code, so
# a clean verdict from it means nothing.
#
# The script cannot see who wrote the diff -- git records a human author, not a
# model -- so it cannot enforce that on its own. Set L6_AUTHOR_VENDOR to the
# vendor that wrote the change, or `human` if a person did, and the matching
# reviewers are skipped. It is required: left unset this script would skip
# nobody, which is the case where a model reviews its own work under a command
# that reads like a review.
#
# Run:  bash scripts/l6-review.sh [git-ref]
#       bash scripts/l6-review.sh HEAD~1     # everything since HEAD~1, committed
#                                            # or not -- this is a diff against
#                                            # the working tree, not HEAD~1..HEAD
#       bash scripts/l6-review.sh            # review uncommitted work
#
# Two things keep this cheap, and both matter more than which model is picked:
#
#   1. The mechanical gate runs FIRST. verify_claims.sh and the suite cost
#      nothing and catch drifted line numbers, stale counts and broken claims.
#      A model must never be paid to find what a script already finds.
#   2. The reviewer reads a DIFF, not the repository. Pointing a reviewer at the
#      tree cost 81,875 input tokens to read a single file, because it pulls in
#      surrounding context whether the prompt asks for it or not. A diff is also
#      the correct unit: L6 reviews a change, not a codebase.
#
# The reviewer therefore runs in an empty working directory with the diff
# inlined in the prompt. It has nothing to wander into, which is the point.
#
# Cost note, measured rather than assumed: a 14 KB diff still cost ~150k input
# tokens, because agy runs an agent loop and every turn pays for the context
# again. The diff is the right review unit; it is not the cost lever. The lever
# is turn count.

set -uo pipefail
cd "$(dirname "$0")/.."

REF="${1:-}"
# LOCAL GATE ONLY: these machine-specific paths and pins are not a CI setup.
# Do not run this L6 configuration in CI; a portable CI trust policy is separate.
# Known CI markers are a convenience guard, not universal CI detection or host
# attestation. The pinned local installation remains mandatory on every route.
case "${CI:-}" in
  ""|0|[Ff][Aa][Ll][Ss][Ee]) ;;
  *) echo "BLOCKED: LOCAL_ONLY_CI: these reviewer pins are local-only." >&2; exit 3 ;;
esac
if [[ -n "${JENKINS_URL:-}" ]]; then
  echo "BLOCKED: LOCAL_ONLY_CI: these reviewer pins are local-only." >&2
  exit 3
fi

# Re-pinning after a legitimate mise/npm update (never automatic):
# 1. Keep the old installation until its replacement is approved. A newly
#    installed version does not require a pin change if the old path still works.
# 2. Verify the new canonical executable/package path, package version, source
#    and update history against the intended installation. Do not execute an
#    unexplained replacement just to ask it for its version. A hash mismatch
#    alone proves neither a legitimate update nor malicious replacement.
# 3. Obtain a candidate hash without changing trust, for example:
#      /usr/bin/python3 scripts/l6_binary_identity.py --fingerprint file /absolute/path
#    Use "tree" for the Gemini package, and pin its Node executable separately.
#    Record the old/new paths, hashes and provenance evidence outside this repo.
# 4. Prepare a diff of the explicit paths and hashes below. Have a different
#    vendor review it with the evidence, then obtain maintainer approval before
#    applying it. Run the identity regression tests and required repo gates.
#    Do not use the unverified replacement to approve its own new pin.
# 5. For an independently approved in-place update awaiting final re-pinning,
#    a reviewed APPROVED_UPDATES entry can record its exact new fingerprint.
#    Only a match to that record is diagnosed as PIN_STALE_APPROVED_UPDATE;
#    it STILL exits 3. Promote the approved hash to the active pin and remove
#    the transition record in the final approved diff. Never populate this map
#    from environment variables or by copying an unexplained mismatch blindly.
# Missing paths report PIN_TARGET_MISSING: restore the pinned installation or
# follow the same approval procedure for a new path. Unexplained changed bytes
# report PIN_CONTENT_CHANGED_UNVERIFIED: investigate before any re-pinning.
# A selected route's identity failure blocks the gate; it never triggers fallback.
# Pins prove inventoried file identity, not publisher authenticity or backend
# vendor identity. Provider/model routing still needs its separate trust policy.
declare -Ar APPROVED_UPDATES=()  # Keys: agy, codex, opencode, gemini-node, gemini-tree.
AGY="$HOME/.local/bin/agy"
CODEX_CLI="$HOME/.local/share/mise/installs/codex/0.153.4/bin/codex"
OPENCODE_CLI="$HOME/.local/share/mise/installs/opencode/1.18.29/opencode"
GEMINI_NODE="$HOME/.local/share/mise/installs/node/26.7.0/bin/node"
GEMINI_PACKAGE="$HOME/.local/share/mise/installs/node/26.7.0/lib/node_modules/@google/gemini-cli"
GEMINI_CLI="$GEMINI_PACKAGE/bundle/gemini.js"

# Reject legacy routing overrides rather than silently ignoring caller intent.
if [[ ${AGY_BIN+x} || ${GEMINI_CLI_BIN+x} ]]; then
  echo "BLOCKED: AGY_BIN/GEMINI_CLI_BIN overrides are not allowed by the binary pins." >&2
  exit 3
fi
PYTHON="${AXIOMGATE_KERNEL_PYTHON:-python3}"

# Scratch goes on the data disk. /tmp here is tmpfs -- writing a large diff
# there spends RAM on a machine that has little, and the root filesystem is the
# one that fills up first.
# Named once, absolute. The verdict reader was reached as "scripts/l6_verdict.py"
# from two places, which only resolves when the caller happened to start in the
# repository root -- and one of those places decides whether to keep looking for
# a reviewer, so a path that silently fails there loses the fallback chain.
VERDICT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/l6_verdict.py"

SCRATCH_ROOT="${AXIOMGATE_SCRATCH:-/mnt/storage/tmp/l6}"
mkdir -p "$SCRATCH_ROOT" 2>/dev/null || SCRATCH_ROOT="${TMPDIR:-/tmp}"

# Cheapest capable model first. These are not interchangeable fallbacks: the
# first two run *inside* agy and go down with it, so the third lives outside it.
MODELS=(
  "gemini-3.8-flash-low"      # routine review
  "gpt-oss-120b-medium"       # still inside agy: covers a Gemini outage only
)

# Which vendor each model belongs to, written out. A substring test against the
# model name cannot do this: "openai" appears nowhere in "gpt-oss-120b-medium",
# so the guard would have passed an OpenAI reviewer onto OpenAI-written code --
# silently, and only in the case the guard exists for.
model_vendor() {
  # Strip a gateway prefix first: "opencode/gpt-4o" is an OpenAI model reached
  # through opencode, and matching on the full string would place it nowhere.
  case "${1##*/}" in
    gemini-*)             echo "google" ;;
    # mimo is Xiaomi's, minimax is MiniMax's. Named separately rather than
    # lumped under "opencode": opencode is the gateway, not the vendor, and a
    # guard that confuses the two would clear a model it should have skipped.
    mimo-*)               echo "xiaomi" ;;
    minimax-*)            echo "minimax" ;;
    gpt-*|o[0-9]*|codex*) echo "openai" ;;
    claude-*)             echo "anthropic" ;;
    *)                    echo "unknown" ;;
  esac
}
CODEX_FALLBACK="gpt-5.6-luna" # outside agy, on a plan that is already paid for

# Invoke the pinned Google CLI package through pinned Node, never the PATH
# shim named gemini (which delegates to agy on this machine). This separates
# the executable routes, not necessarily their quota: both reach Google and
# a shared account-level ceiling has not been ruled out. The existing auth
# check below is only a configuration hint, not proof of working credentials.

# opencode reaches models from vendors none of the layers above touch. That is
# what makes it worth a layer of its own: it can review OpenAI-written code and
# Google-written code alike, which nothing else here can. Prose only -- opencode
# run has no schema flag -- so like every prose layer it is read, not judged.
OPENCODE_MODEL="${L6_OPENCODE_MODEL:-opencode/mimo-v2.5-free}"

AUTHOR="$(printf '%s' "${L6_AUTHOR_VENDOR:-}" | tr '[:upper:]' '[:lower:]')"
# The name people reach for is the model's, not the company's. Someone told to
# name the vendor that wrote the change writes "gemini", and comparing that to
# "google" would have failed to skip Gemini in the one case the guard exists
# for -- a guard failing open exactly where it is needed is worse than no guard,
# because it reports that it ran.
case "$AUTHOR" in
  gemini|google)           AUTHOR="google" ;;
  openai|gpt|codex|chatgpt) AUTHOR="openai" ;;
  anthropic|claude)        AUTHOR="anthropic" ;;
  xiaomi|mimo)             AUTHOR="xiaomi" ;;
  minimax)                 AUTHOR="minimax" ;;
  human|none|unknown-author)
     # A person wrote it. Every reviewer is independent of a human author, so
     # nothing is skipped -- but it was said, not assumed.
     AUTHOR="" ;;
  "") echo "L6_AUTHOR_VENDOR is not set, so this script cannot tell whether any" >&2
      echo "reviewer shares a vendor with whoever wrote the change. Leaving it" >&2
      echo "unset used to skip nobody, which let a model approve its own work" >&2
      echo "under a command that looked like a review." >&2
      echo "Set it to the vendor whose model wrote this, or to 'human'." >&2
      exit 3 ;;
  *) echo "L6_AUTHOR_VENDOR=$AUTHOR is not a vendor this script knows." >&2
     echo "Use: gemini/google, openai, anthropic, xiaomi/mimo, minimax." >&2
     echo "Refusing rather than guessing -- a guard that guesses is not a guard." >&2
     exit 3 ;;
esac

# Whether an answer is usable is decided by the same code that later reads it.
# This was spelled out separately here once, more loosely, and the two disagreed:
# an answer with findings but no valid verdict passed this copy, broke the loop,
# and so skipped the fallback reviewers -- then failed in l6_verdict.py, which is
# the one place that was never going to accept it. A weaker second opinion about
# what counts as an answer costs the whole fallback chain.
usable() {
  printf '%s' "$1" | "$PYTHON" "$VERDICT" >/dev/null 2>&1
  [ "$?" -ne 3 ]
}

# The single place that decides whether a reviewer is allowed to review this
# change. Every layer calls it. It was previously spelled out separately per
# layer, and two of the three spellings failed open -- which is what a second
# way to compute the same thing buys you.
reviewer_allowed() {
  local model="$1" vendor
  vendor="$(model_vendor "$model")"
  if [ "$vendor" = "unknown" ]; then
    echo "   skipping $model: this script cannot say which vendor it belongs to," >&2
    echo "   so it cannot say the review is independent of the author." >&2
    return 1
  fi
  if [ -n "$AUTHOR" ] && [ "$vendor" = "$AUTHOR" ]; then
    echo "   skipping $model (vendor: $vendor): that vendor wrote this change." >&2
    return 1
  fi
  return 0
}

# This verifier is part of the reviewed gate. System Python and the operating
# system are trusted here; the review Python override does not select it.
IDENTITY="$(dirname "$VERDICT")/l6_binary_identity.py"
check_binary() {
  local role="$1"
  if [[ ! -x /usr/bin/python3 || ! -r "$IDENTITY" ]]; then
    echo "BLOCKED: PIN_VERIFIER_UNAVAILABLE: need /usr/bin/python3 and $IDENTITY." >&2
    return 3
  fi
  case "$role" in
    agy)
      /usr/bin/python3 "$IDENTITY" file "$AGY" \
        38f130cdd0757e1d22e151baa48ace4074a5bd3d960eb2dcc7f44bdf2ad4c0fd "${APPROVED_UPDATES[agy]:-}" ;;
    codex)
      /usr/bin/python3 "$IDENTITY" file "$CODEX_CLI" \
        56ef98ab4032d317ab26e9b5e5a175650717351edb16ed9cde0cb6d1734d62da "${APPROVED_UPDATES[codex]:-}" ;;
    opencode)
      /usr/bin/python3 "$IDENTITY" file "$OPENCODE_CLI" \
        ca6c0e1f42be3120595bf6848937e7586ec862c87fa7aa111e89c7cc6e9a4650 "${APPROVED_UPDATES[opencode]:-}" ;;
    gemini)
      /usr/bin/python3 "$IDENTITY" file "$GEMINI_NODE" \
        ad19784f7e90ba789a099eccba77ede8dc90a778c424f1c10a70fed3ff903fdc "${APPROVED_UPDATES[gemini-node]:-}" &&
      /usr/bin/python3 "$IDENTITY" tree "$GEMINI_PACKAGE" \
        6d56bfc5446b14774578e5a719bff0a1a89f072e1b6732485ef5a47bcd8641d4 "${APPROVED_UPDATES[gemini-tree]:-}" ;;
    *) return 3 ;;
  esac
}

# Check only an allowed reviewer that is actually about to run. An unused
# fallback's installation must not block the chosen independent reviewer.
# Recheck immediately before each attempt because previous gates/reviews can
# take time and an installer may have changed bytes in between. This narrows,
# but does not eliminate, the documented check/launch race.

WORK="$(mktemp -d "$SCRATCH_ROOT/review-XXXXXX")"
# EMPTY is created below, outside WORK, so it needs naming here: a trap written
# before the variable exists removes an empty string, which rm treats as nothing
# and leaves a directory behind on every run.
EMPTY=""
trap 'rm -rf "$WORK" ${EMPTY:+"$EMPTY"}' EXIT

# The reviewer runs here, and this stays empty. The brief, the schema and the
# gate logs live in $WORK instead: a reviewer that can read the gate logs can
# report what the gate found and call it its own finding.
# TMPDIR points here too: handing the reviewer $WORK as its temp directory
# would hand it claims.log and suite.log, and a reviewer that reads the gate's
# output can report the gate's findings back as its own. The brief still tells
# it the gates are green -- that is the one fact it needs to not re-report them,
# and it is not the same as giving it the logs to quote from.
# Outside $WORK, not under it. A reviewer running in $WORK/cwd reaches the gate
# logs with `../claims.log` -- and a reviewer that can read what the gate found
# can hand it back as its own finding, which is a review of the gate, not of the
# change.
EMPTY="$(mktemp -d "${SCRATCH_ROOT}/l6-cwd-XXXXXX")"

# --- 1. the mechanical gate -------------------------------------------------

echo "== gate: verify_claims.sh =="
# Exported, not just set: verify_claims.sh resolves its own interpreter, and an
# unexported PYTHON would let the two gates test two different kernels.
export AXIOMGATE_KERNEL_PYTHON="$PYTHON"
if ! bash scripts/verify_claims.sh > "$WORK/claims.log" 2>&1; then
  tail -20 "$WORK/claims.log"
  echo
  echo "BLOCKED: the claim verifier is red. Nothing goes to a reviewer until it is"
  echo "green -- a red baseline makes the change unmeasurable, and a model would be"
  echo "paid to rediscover what the script already reported."
  exit 2
fi
tail -1 "$WORK/claims.log"

echo "== gate: pytest =="
# python3 -m pytest, not the pytest console script: the two disagree here,
# because -m puts the repo root on sys.path and the script does not. One
# interpreter, named once, is the only way the gate and the package agree on
# which kernel was tested.
if ! "$PYTHON" -m pytest -q > "$WORK/suite.log" 2>&1; then
  tail -20 "$WORK/suite.log"
  echo
  echo "BLOCKED: the suite is red. Same reason."
  exit 2
fi
tail -1 "$WORK/suite.log"

# --- 2. the diff ------------------------------------------------------------

BASE="${REF:-HEAD}"
{
  git diff "$BASE"

  # Untracked files are invisible to git diff, and a brand-new file is exactly
  # what most needs an independent read. --no-index against /dev/null renders
  # one as a diff without touching the index, so this stays read-only.
  git ls-files --others --exclude-standard -z | while IFS= read -r -d '' f; do
    # --no-index exits 1 whenever the files differ, which is every time here:
    # the comparison is against /dev/null. That is a difference, not a failure.
    git diff --no-index --no-color -- /dev/null "$f" || true
  done
} > "$WORK/change.diff"

if [ -n "$REF" ]; then
  SUBJECT="the change from $REF to the working tree"
else
  SUBJECT="the uncommitted change in the working tree"
fi

DIFF_BYTES=$(wc -c < "$WORK/change.diff")
if [ "$DIFF_BYTES" -lt 2 ]; then
  # Not 0. An empty diff is the most common way this script is called wrongly --
  # the wrong base ref, a branch that was already merged, a clean tree in CI --
  # and exiting 0 would report "reviewed, nothing found" about a review that
  # never happened. Nothing to review and nothing found are different answers,
  # and only one of them is evidence.
  echo "Nothing to review: the diff against $BASE is empty. No reviewer ran."
  echo "If a change was expected here, the base ref is wrong."
  exit 3
fi
echo "== diff: $DIFF_BYTES bytes =="

# A diff past this size is usually several changes wearing one coat, and a
# reviewer holding all of it reports less about each part than it would alone.
if [ "$DIFF_BYTES" -gt 120000 ]; then
  echo "WARNING: large diff. Consider reviewing it in parts -- a reviewer given"
  echo "everything at once finds less in each piece."
fi

# --- 3. the brief -----------------------------------------------------------

cat > "$WORK/schema.json" <<'JSON'
{
  "type": "object",
  "properties": {
    "verdict": {"type": "string", "enum": ["CLEAN", "FINDINGS"]},
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "severity": {"type": "string", "enum": ["blocker", "major", "minor"]},
          "file": {"type": "string"},
          "line": {"type": "integer"},
          "claim": {"type": "string"},
          "why_wrong": {"type": "string"},
          "how_to_verify": {"type": "string"}
        },
        "required": ["severity", "file", "claim", "why_wrong", "how_to_verify"]
      }
    }
  },
  "required": ["verdict", "findings"]
}
JSON

{
  cat <<'BRIEF'
You are reviewing a change to AxiomGate Kernel, a governance kernel that decides
whether an agent's action is allowed and leaves a checkable record of the decision.

Your brief is to FIND FAULTS. If you find none, you have not looked hard enough.
Do not summarise the change, do not praise it, do not restate what it does.

The mechanical checks have ALREADY PASSED on this change -- the claim verifier
and the full test suite are both green. So report nothing a script would catch:
test counts, line numbers, formatting, style, typos. Those are settled. Report
only what a script cannot see.

Look hardest at these, in this order:

1. A claim in prose that the code does not support. This repo grades its own
   invariants ENFORCED / PARTIAL / MODEL-ONLY / ANALOGY ONLY, and overstating a
   grade is the most damaging defect possible here -- worse than a crash, because
   a crash is visible. A function can be correct while the sentence describing it
   is wrong.
2. A protection that can be bypassed, or that fails OPEN instead of closed.
3. A missing value treated as zero, or a default that hides an unset state.
4. Two places computing the same thing -- a second way to compute a value is a
   second place to be wrong.
5. A test that would also pass against the unfixed code, and therefore proves
   nothing.

For each finding give the file, the claim being made, why it is wrong, and the
command or observation that would settle it. Be concrete. A vague finding is not
a finding.

Here is the diff:

BRIEF
  printf '%s\n' '```diff'
  cat "$WORK/change.diff"
  printf '%s\n' '```'
  printf '\nReview %s. Answer as the schema requires.

"verdict" is mechanical, not a judgement: CLEAN means the findings array is
empty. If you report even one finding of any severity, including minor, the
verdict is FINDINGS. The two are cross-checked and an answer where they
disagree is discarded unread.\n' "$SUBJECT"
} > "$WORK/brief.txt"

# --- 4. the reviewer, cheapest first ---------------------------------------

RESULT=""
USED=""
# Lowercased: the model names are lowercase, so an author who writes "OpenAI"
# would match nothing and the check would fail open -- silently, which is the
# worst way for a guard to fail.
for M in "${MODELS[@]}"; do
  # A reviewer from the vendor that wrote the change is not an L6 review.
  # An unrecognised model counts as a match: a guard that cannot place a model
  # must refuse it, not wave it through.
  reviewer_allowed "$M" || continue
  check_binary agy || exit 3
  echo "== reviewer: $M =="
  OUT="$( cd "$EMPTY" && TMPDIR="$EMPTY" timeout 600 "$AGY" -p "$(cat "$WORK/brief.txt")" \
      --model "$M" --output-format json --json-schema "$WORK/schema.json" 2>/dev/null )"
  # SUCCESS is agy's own status field. Anything else means the model never ran,
  # and an empty answer must not read as a clean review.
  # SUCCESS alone is not an answer: agy reports it for a run that finished
  # without producing the structured output the schema asked for. Accepting
  # that would stop the fallback chain on a review that never happened.
  if [ -n "$OUT" ] \
     && printf '%s' "$OUT" | grep -q '"status":"SUCCESS"' \
     && usable "$OUT"; then
    RESULT="$OUT"; USED="$M"; break
  fi
  echo "   no usable answer from $M, falling through"
done

# --- 4b. the gemini CLI, outside agy --------------------------------------

if [ -z "$RESULT" ] && reviewer_allowed "gemini-cli"; then
  # Unauthenticated is not the same as broken, and neither is a reason to treat
  # the change as reviewed. It is skipped with a reason rather than counted.
  if [ -z "${GEMINI_API_KEY:-}" ] && [ -z "${GOOGLE_GENAI_USE_GCA:-}" ] \
     && [ ! -s "$HOME/.gemini/settings.json" ]; then
    echo "== skipping the gemini CLI: no auth configured =="
    echo "   Authenticate the pinned Google CLI in a terminal, or set GEMINI_API_KEY."
    echo "   This layer is skipped until authentication is configured."
  else
    check_binary gemini || exit 3
    echo "== reviewer: gemini CLI (outside agy) =="
    TEXT="$( cd "$EMPTY" && TMPDIR="$EMPTY" timeout 600 "$GEMINI_NODE" "$GEMINI_CLI" \
        --skip-trust -p "$(cat "$WORK/brief.txt")" < /dev/null 2>/dev/null )"
    if [ -n "${TEXT//[[:space:]]/}" ]; then
      printf '%s\n' "$TEXT"
      echo
      echo "reviewer: gemini-cli (plain text, no schema)"
      # Same rule as the codex branch: prose that was never parsed cannot be
      # reported as a pass. A human reads it.
      echo "NOT AUTOMATICALLY JUDGED: the text above has not been parsed for findings."
      exit 5
    fi
    echo "   no usable answer from the gemini CLI, falling through"
  fi
fi

# --- 4c. opencode, a vendor none of the above share ------------------------

if [ -z "$RESULT" ] && reviewer_allowed "$OPENCODE_MODEL"; then
  check_binary opencode || exit 3
  echo "== reviewer: $OPENCODE_MODEL via opencode =="
  TEXT="$( cd "$EMPTY" && TMPDIR="$EMPTY" timeout 600 "$OPENCODE_CLI" run --pure \
      -m "$OPENCODE_MODEL" "$(cat "$WORK/brief.txt")" < /dev/null 2>/dev/null )"
  if [ -n "${TEXT//[[:space:]]/}" ]; then
    printf '%s\n' "$TEXT"
    echo
    echo "reviewer: $OPENCODE_MODEL (plain text, no schema)"
    echo "NOT AUTOMATICALLY JUDGED: the text above has not been parsed for findings."
    exit 5
  fi
  echo "   no usable answer from $OPENCODE_MODEL, falling through"
fi

if [ -z "$RESULT" ]; then
  # Same guard as every other layer, different consequence: this is the last
  # reviewer there is, so a refusal here means no review happens at all. It still
  # cannot be waved through silently -- it has to be accepted in writing. The
  # guard prints its own reason to stderr, which is why nothing here repeats it:
  # restating the reason would be a second place to get the reason wrong.
  if ! reviewer_allowed "$CODEX_FALLBACK"; then
    if [ "${L6_ALLOW_SELF_REVIEW:-}" != "1" ]; then
      echo "BLOCKED: no reviewer is left that this script can call independent of"
      echo "the author -- see the line above for why this last one was refused."
      echo "Running it anyway would produce a clean-looking result carrying the"
      echo "author's own blind spots. Authenticate a reviewer from another vendor,"
      echo "or set L6_ALLOW_SELF_REVIEW=1 to accept a degraded read knowingly."
      exit 3
    fi
    echo "== fallback: codex $CODEX_FALLBACK, NOT AN INDEPENDENT REVIEWER =="
    echo "   This is not an L6 review: the line above says why it was refused,"
    echo "   and L6_ALLOW_SELF_REVIEW=1 overrode that refusal. Treat anything it"
    echo "   says as a hint, and nothing it stays silent about as cleared."
  fi
  check_binary codex || exit 3
  echo "== reviewer: codex $CODEX_FALLBACK (outside agy) =="
  TEXT="$( cd "$EMPTY" && TMPDIR="$EMPTY" timeout 600 "$CODEX_CLI" exec --model "$CODEX_FALLBACK" \
      --sandbox read-only --skip-git-repo-check "$(cat "$WORK/brief.txt")" \
      < /dev/null 2>/dev/null )"
  if [ -z "${TEXT//[[:space:]]/}" ]; then
    echo "BLOCKED: no reviewer answered. The change is NOT reviewed -- which is not"
    echo "the same as reviewed and clean."
    exit 3
  fi
  printf '%s\n' "$TEXT"
  echo
  echo "reviewer: codex:$CODEX_FALLBACK (plain text, no schema)"
  echo
  # Exit 5, never 0. This branch cannot tell a clean review from a damning one --
  # it has prose, not a parsed verdict -- and a gate that cannot tell must not
  # report success. Read the text above and decide; do not let CI decide.
  echo "NOT AUTOMATICALLY JUDGED: the text above has not been parsed for findings."
  echo "A human reads it. This exits non-zero on purpose."
  exit 5
fi

# --- 5. the verdict ---------------------------------------------------------

printf '%s' "$RESULT" | "$PYTHON" "$VERDICT"
RC=$?
echo "reviewer: $USED"
# 0 clean | 1 blocker | 4 findings, none blocking | 2 gate red | 3 no review
# | 5 a reviewer answered in prose and nothing parsed it.
#
# 5 is separate from 2 deliberately. A red gate means the change is broken and no
# reviewer ever ran; prose means a reviewer did run and no machine read what it
# said. One code for both left CI unable to tell "the tests broke" from "somebody
# has to read this" -- and only the second of those is fixed by a human, not a
# rerun.
# 4 is separate from both 0 and 1 on purpose: whether a major stops a change is
# the caller's policy, and folding it into either answer decides it for them.
exit $RC


