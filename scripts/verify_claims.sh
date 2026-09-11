#!/usr/bin/env bash
# Mechanical source of truth for AxiomGate Kernel.
# Every claim in README.md and docs/TRACEABILITY.md that has a known
# command and a known expected value is checked here -- never by a model.
#
# Run:  bash scripts/verify_claims.sh
set -uo pipefail
cd "$(dirname "$0")/.."

# The interpreter is taken from the environment first, then whichever is
# already active, then python3 on PATH. An absolute path to a single machine
# has no place in a public repo: it leaked a local directory layout and broke
# for everyone else.
PY="${AXIOMGATE_KERNEL_PYTHON:-${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}}"
PY="${PY:-$(command -v python3 || command -v python)}"
if [ -z "$PY" ] || ! "$PY" -c "import axiomgate_kernel" 2>/dev/null; then
  echo "ERROR: found no interpreter with axiomgate_kernel importable." >&2
  echo '     Run: pip install -e ".[dev]"   -- or point to an interpreter with' >&2
  echo "     AXIOMGATE_KERNEL_PYTHON=/path/to/python bash scripts/verify_claims.sh" >&2
  exit 2
fi
PASS=0; FAIL=0

ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; echo "        expected: $2"; echo "        actual:   $3"; FAIL=$((FAIL+1)); }

check_eq() { # name expected actual
  [ "$2" = "$3" ] && ok "$1" || bad "$1" "$2" "$3"
}

# roadmap_section <heading-prefix> -- the text under '## <prefix>...' up to the
# next '## '. The status lines are not unique in ROADMAP.md since both R1 and
# R2 are marked CLOSED with the same date; an unbounded grep would count the
# other entry's status.
roadmap_section() {
  awk -v h="$1" '$0 ~ "^## " h {p=1; next} /^## /{p=0} p' docs/ROADMAP.md
}
# has <name> <expected 0|1> <text> <section-prefix> -- does the text exist in the section
has_in_section() {
  # Not a pipe into grep -q. With `set -o pipefail`, grep exiting early on its
  # first match kills awk with SIGPIPE and the pipeline reports 141, so the
  # assignment was skipped for exactly the sections long enough that grep
  # finished first. The check went red on a document it had just confirmed.
  local got; got=0
  local body; body="$(roadmap_section "$4")"
  case "$body" in *"$3"*) got=1;; esac
  check_eq "$1" "$2" "$got"
}

# anchor <name> <file> <line> <regex> -- asserts that the line matches
anchor() {
  local got; got="$(sed -n "${3}p" "$2")"
  if echo "$got" | grep -qE "$4"; then ok "$1 ($2:$3)"
  else bad "$1 ($2:$3)" "line matches /$4/" "$(echo "$got" | head -c 90)"; fi
}

echo "== 1. Test suite =="
# The expected count is read out of README.md rather than written here. Twice now a
# number in prose drifted from the run while a second copy of it in this script stayed
# green, which makes the check agree with itself instead of with the repository.
SUITE_CLAIMED="$(grep -oE '# [0-9]+ tests' README.md | head -1 | grep -oE '[0-9]+')"
T="$("$PY" -m pytest tests -q 2>&1 | tail -1)"
check_eq "whole suite green, at the count README states" "$SUITE_CLAIMED passed" "$(echo "$T" | grep -oE '^[0-9]+ passed')"
check_eq "README's two suite counts agree with each other" "$SUITE_CLAIMED" "$(grep -oE 'mature — [0-9]+ tests' README.md | grep -oE '[0-9]+')"

echo "== 2. Standalone: no dependency on the old src package =="
LEAK="$(grep -rn 'src\.kernel\|from src\b\|"src\.' axiomgate_kernel/ tests/ 2>/dev/null | wc -l)"
check_eq "no src references" "0" "$LEAK"
ISO="$("$PY" -c "
import sys
class B:
    def find_spec(self, n, p=None, t=None):
        if n=='src' or n.startswith('src.'): raise ImportError(n)
sys.meta_path.insert(0,B())
import pytest; sys.exit(pytest.main(['tests','-q','--tb=no']))
" 2>&1 | tail -1 | grep -oE '^[0-9]+ passed')"
check_eq "green even with src blocked" "$SUITE_CLAIMED passed" "$ISO"

echo "== 3. No false formal traceability =="
INV="$(grep -rn 'I-[0-9]' axiomgate_kernel/ tests/ 2>/dev/null | wc -l)"
check_eq "no I-N citations in code or tests" "0" "$INV"
# Review finding 2026-09-10: domain.py cited 'I10_EnfBeforeExec' and slipped
# past the check above, which only looks for the form 'I-N'. The code must not
# name a TLA invariant at all; the correspondence should live only in
# TRACEABILITY.md.
TLANAME="$(grep -rnE 'I[0-9]+_[A-Za-z]' axiomgate_kernel/ tests/ 2>/dev/null | wc -l)"
check_eq "no TLA invariant names in code or tests" "0" "$TLANAME"

echo "== 4. Anchors in docs/TRACEABILITY.md =="
anchor "I2  check_capability"        axiomgate_kernel/authorization.py   91 'def check_capability'
anchor "I3  seal()"                  axiomgate_kernel/capability.py     167 'def seal'
anchor "I7  producer != verifier" axiomgate_kernel/evidence.py      174 'producer cannot verify own evidence'
anchor "I7  producer != authority" axiomgate_kernel/evidence.py       229 'producer cannot be final authority'
anchor "I8  policy_hash in grant"     axiomgate_kernel/grant.py           46 'policy_hash'
anchor "I9  authenticate"            axiomgate_kernel/authentication.py 179 'def authenticate'
anchor "I9  constant-time comparison"  axiomgate_kernel/authentication.py 200 'hmac_equal'
anchor "I10 consume_if_valid"        axiomgate_kernel/grant.py          149 'def consume_if_valid'
anchor "audit append"                axiomgate_kernel/audit.py          139 'def append'
anchor "audit verify_chain"          axiomgate_kernel/audit.py          223 'def verify_chain'
anchor "audit verify_prefix"         axiomgate_kernel/audit.py          237 'def verify_prefix'
anchor "audit _verify_links"         axiomgate_kernel/audit.py          361 'def _verify_links'
anchor "COMMIT is Owner-only"        axiomgate_kernel/domain.py          15 'OWNER_MANDATORY_ACTIONS = frozenset'
anchor "COMMIT gate (single point)" axiomgate_kernel/authorization.py 158 'OWNER_MANDATORY_ACTIONS'
anchor "Verdict"                     axiomgate_kernel/domain.py          79 'class Verdict'
anchor "I1  observe after authn"     axiomgate_kernel/mediator.py       169 'self\._observe\(canon, authn\.principal\)'
anchor "I4  observation_seq in audit" axiomgate_kernel/mediator.py      757 '"observation_seq": self\._observation_seq'
anchor "I1/I4/I6 check_invariants"   axiomgate_kernel/observation.py    143 'def check_invariants'
anchor "I5  execution recorded"      axiomgate_kernel/grant.py          222 'rec = self\._executions\.record\('
anchor "I5  rollback marked"         axiomgate_kernel/grant.py          253 'self\._executions\.mark_rolled_back\(seq\)'
anchor "I5  check_execution_invariant" axiomgate_kernel/execution.py    123 'def check_execution_invariant'

# The anchors above are checked against the CODE. Review finding 2026-09-10:
# the numbers stated in TRACEABILITY.md were a second, disconnected set --
# 'audit.py:87' became wrong as audit.py grew, and nothing alarmed. Every
# file:line the document cites must exist in the anchor table above.
DOCREFS="$(grep -oE '[a-z_]+\.py:[0-9]+' docs/TRACEABILITY.md | sort -u)"
STALE=""
for ref in $DOCREFS; do
  file="axiomgate_kernel/${ref%%:*}"; line="${ref##*:}"
  grep -qE "^anchor .*[[:space:]]$file[[:space:]]+$line[[:space:]]" scripts/verify_claims.sh \
    || STALE="$STALE $ref"
done
check_eq "every file:line in TRACEABILITY.md is an anchor" "" "$STALE"

echo "== 4b. Grant fields are counted, not asserted =="
# README and API.md assert a NUMBER of bound fields. Count them in the
# signature instead of trusting the prose -- 'all twelve' was wrong in three
# documents.
NKW="$("$PY" -c "
import inspect
from axiomgate_kernel.grant import ReservedGrantStore as S
p = inspect.signature(S.consume_if_valid).parameters
print(sum(1 for v in p.values() if v.kind is v.KEYWORD_ONLY))
")"
check_eq "consume_if_valid bound fields" "11" "$NKW"
check_eq "README says eleven" "1" "$(grep -c 'only if \*\*eleven\*\* bound fields' README.md)"

echo "== 4c. The redaction boundary is the one README describes =="
# README explicitly promises that format-recognized secrets are redacted and
# that field names do NOT protect. Both halves are checked live against a
# real log.
RED="$("$PY" -c "
import tempfile, os
from axiomgate_kernel.audit import AuditLog
d = tempfile.mkdtemp(); p = os.path.join(d,'a.log')
a = AuditLog(p, b'0'*32)
a.append({'password':'hunter2','key':'sk-'+'A'*30})
t = open(p).read()
print(('LEAK' if 'hunter2' in t else 'noleak') + '/' + ('MISS' if 'sk-'+'A'*30 in t else 'redacted'))
")"
check_eq "both redaction rules hold" "noleak/redacted" "$RED"
# The naming rule must not swallow the kernel's own audit fields. Run against
# a real decision flow, not a handwritten dict.
FALSKPOS="$("$PY" -c "
import sys; sys.path.insert(0,'examples')
from _setup import build, request
from axiomgate_kernel import ActionType, RiskLevel
from axiomgate_kernel.redaction import _is_sensitive_key
m, ak, _o, audit, _t = build()
m.evaluate(request(ak, action=ActionType.EXECUTE.value, domain='code',
                   risk_level=RiskLevel.LOW.value, payload={'file':'a.py'}))
m.evaluate(request(ak, action=ActionType.COMMIT.value, domain='code',
                   risk_level=RiskLevel.LOW.value, payload={'file':'a.py'}))
keys = set()
for e in audit.entries(): keys |= set(e.keys())
print(sum(1 for k in keys if _is_sensitive_key(k)))
")"
check_eq "naming rule masks no audit fields" "0" "$FALSKPOS"

echo "== 4d. Grant bindings per reason class -- counted, not asserted =="
# README and API.md assert 11 normally and 8 for POLICY/PROVENANCE. Count by
# actually mutating one field at a time and seeing which fail. A claim about
# a number should never stand unchallenged in prose.
GRANTCOUNT="$("$PY" -c "
from datetime import timedelta
from axiomgate_kernel import GrantError, ReservedGrantStore, ReasonClass
BASE = dict(principal_id='p', agent_id='a', request_id='r', action='EXECUTE',
            domain='code', risk_level='MEDIUM', payload_hash='h',
            capability_id='c', capability_scope_hash='s', policy_hash='ph',
            provenance_identity='pi')
out = []
for rc in (ReasonClass.OTHER, ReasonClass.POLICY, ReasonClass.PROVENANCE):
    bound = 0
    for field in BASE:
        st = ReservedGrantStore(ttl=timedelta(hours=1))
        st.create_pending_context(escalation_id='e', policy_version='v1',
                                  provenance_kind='match', reason_class=rc, **BASE)
        st.attach_owner_decision('e', 'permit')
        args = dict(BASE); args[field] = 'CHANGED'
        try:
            st.consume_if_valid('e', **args)
        except GrantError:
            bound += 1
    out.append(str(bound))
print('/'.join(out))
")"
check_eq "bound fields: other/policy/provenance" "11/8/8" "$GRANTCOUNT"
check_eq "README says eleven and eight" "1" "$(grep -c 'of the eleven are skipped' README.md)"
check_eq "no 'all twelve' left" "0" "$(grep -rc 'all twelve' README.md docs/API.md | grep -vc ':0$')"

echo "== 4e. The log cannot hide a truncated tail =="
# Self-certifying log: without anchoring, a truncated chain is still
# internally consistent. Both halves are run live -- that it is missed
# without an anchor is just as important to show as that it is caught with
# one.
TRUNC="$("$PY" -c "
import tempfile, os
from axiomgate_kernel.audit import AuditLog
d = tempfile.mkdtemp(); p = os.path.join(d, 'a.log')
a = AuditLog(p, b'0'*32)
for i in range(5): a.append({'i': i})
head, count = a.head()
lines = open(p).read().splitlines(True)[:-1]
open(p, 'w').writelines(lines)
b = AuditLog(p, b'0'*32)
blind = b.verify_chain()[0]
caught = b.verify_chain(expected_head=head, expected_count=count)[0]
print(('blind-ok' if blind else 'blind-caught') + '/' + ('MISSED' if caught else 'caught'))
")"
check_eq "truncated tail: missed without anchor, caught with" "blind-ok/caught" "$TRUNC"
# A format change must not look like tampering -- the operator's action is entirely different.
LEGACY="$("$PY" -c "
import tempfile, os, json
from axiomgate_kernel.audit import AuditLog, AuditError
d = tempfile.mkdtemp(); p = os.path.join(d, 'a.log')
a = AuditLog(p, b'0'*32); a.append({'i': 0})
e = json.loads(open(p).read()); e.pop('seq')
open(p, 'w').write(json.dumps(e, sort_keys=True, separators=(',', ':')) + '\n')
try:
    AuditLog(p, b'0'*32); print('ACCEPTED')
except AuditError as exc:
    print('legacy' if 'pre-sequence format' in str(exc) else 'wrong-message')
")"
check_eq "log without seq is rejected as a format change" "legacy" "$LEGACY"

echo "== 4f. Fail-closed: no exit from the mediator is an exception =="
# Audit is an injected dependency. A backend that raises something other than
# AuditError previously made it all the way out of evaluate().
FAILCLOSED="$("$PY" -c "
import sys; sys.path.insert(0, 'examples')
from _setup import build, request
from axiomgate_kernel import ActionType, RiskLevel, Verdict
class Boom:
    def append(self, record): raise OSError('disk full')
    def entries(self): return []
m, ak, _o, _a, _t = build(); m._audit = Boom()
try:
    d = m.evaluate(request(ak, action_type=ActionType.EXECUTE.value, domain='code',
                           risk_level=RiskLevel.LOW.value, payload={'f': 'a.py'}))
    print('ESCAPED' if False else d.verdict.value)
except Exception as exc:
    print('ESCAPED:' + type(exc).__name__)
")"
check_eq "OSError from the audit backend becomes DENY" "DENY" "$FAILCLOSED"

# Same class of bug, different injected dependency: building the audit record
# itself used to sit outside every try. A canon that does not behave as the
# kernel assumed then escaped evaluate() as an exception instead of a verdict.
RECORDNET="$("$PY" -c "
import sys; sys.path.insert(0, 'examples')
import axiomgate_kernel.mediator as mm
from _setup import build, request
from axiomgate_kernel import ActionType, RiskLevel
class NoHash:
    def __init__(self, inner): self._inner = inner
    def get(self, k, d=None): return self._inner.get(k, d)
    def full_payload_hash(self): raise RuntimeError('hash backend unavailable')
    def __getattr__(self, n): return getattr(self._inner, n)
real = mm.snapshot_request
mm.snapshot_request = lambda r: NoHash(real(r))
m, ak, _o, _a, _t = build()
try:
    d = m.evaluate(request(ak, action_type=ActionType.EXECUTE.value, domain='code',
                           risk_level=RiskLevel.LOW.value, payload={'f': 'a.py'}))
    print(d.verdict.value + ('+net' if 'record.build_failed' in d.applied_rules else '+NONET')
          + ('+nogrant' if d.grant is None else '+GRANT'))
except Exception as exc:
    print('ESCAPED:' + type(exc).__name__)
finally:
    mm.snapshot_request = real
")"
check_eq "broken canon becomes DENY without authority" "DENY+net+nogrant" "$RECORDNET"

echo "== 4i. Regulatory claims are dated and the right tier =="
# README used to pair the high-risk requirement with 35M/7%. That is Art.
# 99(3) and applies to Art. 5, prohibited practices. For logging and
# oversight it is 99(4): 15M/3%. Overstating your own regulatory exposure is
# the same mistake as citing an invariant the model does not define -- and
# just as easy to see through.
# Review finding 2026-09-10: the check only required that 99(3) and
# "prohibited practices" appeared SOMEWHERE in the file. A new, unbound
# sentence ("A missing audit trail alone risks fines of up to EUR 35 000 000")
# therefore passed. The binding must be per line -- the figure and the
# qualifier in the same sentence, where a reader actually sees them together.
# Markdown wraps in the middle of sentences, so the comparison runs on
# unwrapped text: each paragraph becomes one line. That puts the figure and
# the qualifier in the same comparison unit, the way a reader actually sees
# them.
UNWRAP="$(awk 'BEGIN{ORS=""} /^[[:space:]]*$/{print "\n\n"; next} {gsub(/^[[:space:]]+/,""); print $0 " "}' README.md)"
UNBOUND="$(echo "$UNWRAP" | grep -E '35M|35 000 000' | grep -vE '99\(3\)' || true)"
check_eq "every 35M mention is bound to 99(3)" "" "$UNBOUND"
if echo "$UNWRAP" | grep -qE '35M|35 000 000'; then
  check_eq "the 35M paragraph states what 99(3) covers" "ok" \
    "$(echo "$UNWRAP" | grep -E '35M|35 000 000' | grep -qiE 'prohibited practices' \
       && echo ok || echo MISSING)"
fi
check_eq "README states 99(4) for logging" "ok" \
  "$(grep -qE '99\(4\)' README.md && echo ok || echo MISSING)"

# The postponed date must not silently fall back to the old one.
check_eq "README states the postponed date" "ok" \
  "$(grep -qE '2 December 2027' README.md && echo ok || echo MISSING)"

# The source material must exist and keep its own uncertainty marker. EUR-Lex
# could not be fetched; if that line disappears, someone has tidied away the
# caveat instead of resolving it.
check_eq "REGULATORY.md keeps its caveat" "ok" \
  "$(grep -q 'Not primary-verified' docs/REGULATORY.md \
     && grep -q 'Not retrieved' docs/REGULATORY.md && echo ok || echo MISSING)"
check_eq "REGULATORY.md is dated" "ok" \
  "$(grep -q '2026-09-10' docs/REGULATORY.md && echo ok || echo MISSING)"

echo "== 4g. No foreign identity baked in =="
# A hardcoded owner in a security check makes an unknown person's id the only
# trusted approver in a customer's installation. Fail-closed: refuse instead.
# The pattern is the shape, not the identity: a 17-19-digit literal in the
# code is the bug regardless of which account it points to. That way the
# check itself never has to print a traceable account id into a public repo.
check_eq "no baked-in account id in code or tests" "0" \
  "$(grep -rlE '[0-9]{17,19}' --include='*.py' axiomgate_kernel/ tests/ 2>/dev/null | wc -l)"
# The package may root itself only in its own dotdir, never anyone else's.
# This check has had two bugs: first it named the directory in plain text --
# and carried that name into a public repo. Then it searched with a regex
# over the source, and six of eight ways of writing it slipped past, because
# a regex sees how the string is *written*. The rule therefore now lives in
# one place: check_dotdirs.py, which reads the package as a syntax tree. The
# exit code, not a line count: the script reports two kinds of failure
# (FOREIGN, SCATTERED HOME REFERENCE) and also fails when it no longer tests
# anything.
DOTDIRS="$("$PY" scripts/check_dotdirs.py 2>&1)"; DOTRC=$?
check_eq "no foreign home directory in the package" "0" "$DOTRC"
NOOWNER="$("$PY" -c "
import os
os.environ.pop('AXIOMGATE_OWNER_ID', None)
from axiomgate_kernel.approval import ApprovalVerifier
try:
    ApprovalVerifier(public_key_bytes=b'\x01'*32); print('ACCEPTED')
except ValueError:
    print('refused')
")"
check_eq "ApprovalVerifier refuses without a configured owner" "refused" "$NOOWNER"

echo "== 4h. Declared debt is kept alive =="
# R1 is open for as long as the kernel does not read principal_context. The
# check runs both ways: the document must not claim "open" when the code is
# wired in, and NOT WIRED must not disappear while it is still disconnected.
# Since 2026-09-10 the other branch applies -- and then it is not enough for
# R1 to have stopped saying OPEN: it must say CLOSED with a date, the module
# must have stopped saying NOT WIRED, and the flag must still default to off,
# since that is the deviation R1 itself declares.
WIRED="$(grep -rl 'principal_context' axiomgate_kernel/*.py | grep -v 'principal_context.py' | wc -l)"
R1OPEN="$(grep -c '^## R1 .*$' docs/ROADMAP.md)"
check_eq "ROADMAP has R1"                    "1" "$R1OPEN"
if [ "$WIRED" -eq 0 ]; then
  check_eq "R1 open while the module is disconnected" "1" "$(grep -c '^\*\*Status: OPEN\.\*\*' docs/ROADMAP.md)"
  check_eq "the module itself says NOT WIRED"        "1" "$(grep -c 'NOT WIRED' axiomgate_kernel/principal_context.py)"
else
  check_eq "R1 closed when the kernel reads the module"   "0" "$(grep -c '^\*\*Status: OPEN\.\*\*' docs/ROADMAP.md)"
  has_in_section "R1 is CLOSED with a date" "1" "**Status: CLOSED 2026-09-10**" "R1 "
  check_eq "NOT WIRED is gone from the module"        "0" "$(grep -c 'NOT WIRED' axiomgate_kernel/principal_context.py)"
  check_eq "TRACEABILITY has a provenance row"     "1" "$(grep -c '^| Provenance-bounded authority |' docs/TRACEABILITY.md)"
  # The flag defaults to off. That is not a convenience but the declared
  # deviation from R1 condition 1; if the default changes without R1 being
  # rewritten, the document is no longer true.
  check_eq "require_principal_context defaults to off" "False" \
    "$("$PY" -c "import inspect;from axiomgate_kernel import Mediator;print(inspect.signature(Mediator.__init__).parameters['require_principal_context'].default)")"
fi

echo "== 4j. R1: the provenance ceiling is mutation-tested =="
# Mechanical verification, not a judgment call: the script carries its own
# expected outcomes and fails if a mutation stops producing what it declares.
if MUT="$("$PY" scripts/mutate_r1.py 2>&1)"; then
  ok "scripts/mutate_r1.py: all mutations came out as declared"
else
  bad "scripts/mutate_r1.py" "exit 0" "$MUT"
fi
check_eq "two of three R1 checks have no second barrier" "1" \
  "$(echo "$MUT" | grep -c '2 of 3 have no second barrier')"

echo "== 4k. R2: prefix verification and anchored startup are mutation-tested =="
if MUT2="$("$PY" scripts/mutate_r2.py 2>&1)"; then
  ok "scripts/mutate_r2.py: all mutations came out as declared"
else
  bad "scripts/mutate_r2.py" "exit 0" "$MUT2"
fi
check_eq "two of three R2 checks have no second barrier" "1" \
  "$(echo "$MUT2" | grep -c '2 of 3 have no second barrier')"
# One source of truth for link verification: both verify_integrity and
# verify_prefix must go through _verify_links, never have their own loop.
check_eq "a single link loop in audit.py" "1" \
  "$(grep -c 'for index, line in enumerate' axiomgate_kernel/audit.py)"
check_eq "README says the same thing about second barriers" "1" \
  "$(grep -c 'two of the three checks' README.md)"
# The audit record must not re-read the bound context: between
# check_capability and the write, an injected provenance backend runs, and a
# backend that swaps the context there could otherwise make the log describe
# a different frame than the one that made the decision. The frame is carried
# along as CapabilityCheck instead.
check_eq "mediator does not re-read the context at write time" "0" \
  "$(grep -c 'bound_context' axiomgate_kernel/mediator.py)"

echo "== 5. The examples run =="
for ex in examples/0*.py; do
  if "$PY" "$ex" >/dev/null 2>&1; then ok "$ex"; else bad "$ex" "exit 0" "exit $?"; fi
done

echo "== 6. The TLC run =="
check_eq "states generated" "373933" "$(grep -oE '^[0-9]+ states generated' formal/tlc-run-2026-09-08.log | grep -oE '^[0-9]+')"
check_eq "distinct states"  "345322" "$(grep -oE '[0-9]+ distinct states found' formal/tlc-run-2026-09-08.log | grep -oE '^[0-9]+')"
check_eq "no errors found"    "1"      "$(grep -c 'No error has been found' formal/tlc-run-2026-09-08.log)"
check_eq "model size bound to 1 authority" "1" "$(grep -c 'Authority = {auth1}' formal/GovernanceMCV6.cfg)"

echo "== 6b. Strict wiring: the two opt-in protections cannot be half-set =="
# These run the real constructors rather than reading strict.py, because the
# claim is about behavior: a strict kernel that can be talked into the weak
# configuration is worth nothing, and only a run can tell.
STRICT="$(python3 - <<'PY'
import os, tempfile
from axiomgate_kernel import (
    AuditLog, Authenticator, CapabilityRegistry, FixedProvenanceChecker,
    Mediator, NEW_LOG, PrincipalKeyStore, ProvisioningToken, StrictnessError,
    generate_key, strict_audit_log, strict_mediator, strictness_report,
)
from axiomgate_kernel.provenance import ProvenanceKind, ProvenanceResult

def path(n):
    return os.path.join(tempfile.mkdtemp(prefix="axiomgate-claims-"), n)

def wiring():
    # One provisioning token per store: a token is consumed on seal, and
    # reusing it across the two raises ProvisioningError. That is I3 working.
    ktok, rtok = ProvisioningToken(), ProvisioningToken()
    keys = PrincipalKeyStore(); keys.register("owner", generate_key(), ktok); keys.seal(ktok)
    reg = CapabilityRegistry(); reg.seal(rtok)
    return Authenticator(keys), reg, FixedProvenanceChecker(ProvenanceResult(ProvenanceKind.MATCH, "ok"))

out = []

# A plain log reports itself unanchored; a strict one reports itself anchored.
out.append("plain_anchored=%s" % AuditLog(path("a.log"), generate_key()).anchored)
out.append("strict_anchored=%s" % strict_audit_log(path("b.log"), generate_key(), NEW_LOG).anchored)

# NEW_LOG over an existing chain is refused.
p = path("c.log"); lg = AuditLog(p, generate_key()); lg.append({"x": 1})
try:
    strict_audit_log(p, generate_key(), NEW_LOG); out.append("newlog_over_chain=allowed")
except StrictnessError:
    out.append("newlog_over_chain=refused")

authn, reg, prov = wiring()

# A strict mediator on an unanchored log is refused.
try:
    strict_mediator(authenticator=authn, registry=reg,
                    audit=AuditLog(path("d.log"), generate_key()), provenance=prov)
    out.append("strict_on_plain_log=allowed")
except StrictnessError:
    out.append("strict_on_plain_log=refused")

# The ceiling cannot be declined through the strict door.
try:
    strict_mediator(authenticator=authn, registry=reg,
                    audit=strict_audit_log(path("e.log"), generate_key(), NEW_LOG),
                    provenance=prov, require_principal_context=False)
    out.append("ceiling_declinable=yes")
except StrictnessError:
    out.append("ceiling_declinable=no")

# The report: default kernel, half-wired kernel, strict kernel.
plain_m = Mediator(authn, reg, AuditLog(path("f.log"), generate_key()), prov)
out.append("default_strict=%s" % strictness_report(plain_m)["strict"])
out.append("default_gaps=%d" % len(strictness_report(plain_m)["gaps"]))

half = Mediator(authn, reg, AuditLog(path("g.log"), generate_key()), prov,
                require_principal_context=True)
r = strictness_report(half)
out.append("half_strict=%s" % r["strict"])
out.append("half_gaps=%d" % len(r["gaps"]))

full = strict_mediator(authenticator=authn, registry=reg,
                       audit=strict_audit_log(path("h.log"), generate_key(), NEW_LOG),
                       provenance=prov)
r = strictness_report(full)
out.append("full_strict=%s" % r["strict"])
out.append("full_gaps=%d" % len(r["gaps"]))
out.append("full_ceiling=%s" % full.require_principal_context)

print(" ".join(out))
PY
)"
get() { echo "$STRICT" | tr ' ' '\n' | grep "^$1=" | cut -d= -f2; }
check_eq "a plain audit log reports itself unanchored" "False" "$(get plain_anchored)"
check_eq "a strict audit log reports itself anchored"  "True"  "$(get strict_anchored)"
check_eq "NEW_LOG over an existing chain is refused"   "refused" "$(get newlog_over_chain)"
check_eq "strict_mediator refuses an unanchored log"   "refused" "$(get strict_on_plain_log)"
check_eq "the ceiling cannot be declined through the strict door" "no" "$(get ceiling_declinable)"
check_eq "the default kernel reports itself not strict" "False" "$(get default_strict)"
check_eq "the default kernel names both gaps"           "2"     "$(get default_gaps)"
check_eq "a half-wired kernel is still not strict"      "False" "$(get half_strict)"
check_eq "a half-wired kernel names exactly one gap"    "1"     "$(get half_gaps)"
check_eq "a strict kernel reports itself strict"        "True"  "$(get full_strict)"
check_eq "a strict kernel names no gaps"                "0"     "$(get full_gaps)"
check_eq "a strict kernel has the ceiling on"           "True"  "$(get full_ceiling)"

echo "== 6c. The observation log: I1, I4 and I6 are answerable at runtime =="
# Same principle as 6b. The claim in docs/TRACEABILITY.md is that these three
# invariants can now be *checked* rather than read out of _gated's source, and
# a claim about checking is only settled by running the check. Every value
# below comes from a real Mediator deciding a real signed request.
OBS="$(python3 - <<'PY2'
import os, sys, tempfile
sys.path.insert(0, os.path.join(os.getcwd(), "examples"))
from _setup import build, request
from axiomgate_kernel import (
    ActionType, Mediator, ObservationError, ObservationLog, RiskLevel,
    check_invariants, generate_key,
)

def watched():
    m, agent_key, owner_key, audit, tmp = build()
    obs = ObservationLog()
    return Mediator(
        authenticator=m._authn, registry=m._registry, audit=audit,
        provenance=m._provenance, policy=m._policy, observations=obs,
    ), obs, audit, agent_key

def act(m, key):
    return m.evaluate(request(
        key, action_type=ActionType.EXECUTE.value, domain="code",
        risk_level=RiskLevel.LOW.value, payload={"file": "a.py"},
    ))

out = []

# A kernel with no observation log must answer "unobservable", never "holds".
# Unconfirmed is not true, and this is the check that keeps it that way.
m0, agent0, _o0, audit0, _t0 = build()
act(m0, agent0)
r0 = check_invariants(None, audit0.entries())
out.append("no_log_i1=%s" % r0["I1"]["status"])
out.append("no_log_holds=%s" % r0["holds"])

# An empty observation log against a non-empty chain is not a pass either:
# vacuous truth is the failure mode this kind of check dies of.
r1 = check_invariants(ObservationLog(), audit0.entries())
out.append("empty_log_i1=%s" % r1["I1"]["status"])

# The observed kernel: all three hold, and the audit chain carries the binding.
m, obs, audit, key = watched()
act(m, key); act(m, key)
r = check_invariants(obs, audit.entries())
out.append("i1=%s" % r["I1"]["status"])
out.append("i4=%s" % r["I4"]["status"])
out.append("i6=%s" % r["I6"]["status"])
out.append("holds=%s" % r["holds"])
out.append("seqs=%s" % ",".join(str(e["observation_seq"]) for e in audit.entries()))

# The honest gap: a decision reached before an identity exists has no
# observation, is counted, and drops I1 to PARTIAL rather than being excluded.
m.set_available(False); act(m, key)
rp = check_invariants(obs, audit.entries())
out.append("partial_i1=%s" % rp["I1"]["status"])
out.append("partial_count=%s" % rp["I1"]["unobserved_enforcements"])
out.append("partial_named=%s" % ("mediator.unavailable" in rp["I1"]["unobserved_rules"]))
out.append("partial_holds=%s" % rp["holds"])

# A check that cannot fail is not a check: a tampered principal must be caught.
entries = audit.entries(); entries[0]["bound_principal"] = "someone-else"
out.append("tampered_i6=%s" % check_invariants(obs, entries)["I6"]["status"])

# The log establishes ordering, so it must not be rewritable.
o = ObservationLog(); o.record("agent-a", "req-1", "h")
try:
    o.entries()[0].seq = 99; out.append("rewritable=yes")
except ObservationError:
    out.append("rewritable=no")

print(" ".join(out))
PY2
)"
oget() { echo "$OBS" | tr ' ' '\n' | grep "^$1=" | cut -d= -f2; }
check_eq "a kernel with no observation log answers UNOBSERVABLE" "UNOBSERVABLE" "$(oget no_log_i1)"
check_eq "UNOBSERVABLE does not count as holding"                "False"        "$(oget no_log_holds)"
check_eq "an empty observation log is not a pass"                "VIOLATED"     "$(oget empty_log_i1)"
check_eq "I1 holds over an observed kernel"                      "HOLDS"        "$(oget i1)"
check_eq "I4 holds over an observed kernel"                      "HOLDS"        "$(oget i4)"
check_eq "I6 holds over an observed kernel"                      "HOLDS"        "$(oget i6)"
check_eq "all three hold together"                               "True"         "$(oget holds)"
check_eq "the audit chain carries the observation sequence"      "1,2"          "$(oget seqs)"
check_eq "a pre-identity denial drops I1 to PARTIAL"             "PARTIAL"      "$(oget partial_i1)"
check_eq "the unobserved enforcement is counted"                 "1"            "$(oget partial_count)"
check_eq "its rule is named, not just counted"                   "True"         "$(oget partial_named)"
check_eq "PARTIAL does not count as holding"                     "False"        "$(oget partial_holds)"
check_eq "a tampered principal is caught by I6"                  "VIOLATED"     "$(oget tampered_i6)"
check_eq "the observation log cannot be rewritten"               "no"           "$(oget rewritable)"

echo "== 6d. Numbers and samples stated in prose =="
# The README example is code nobody runs. This one said check_invariants(obs.entries(), ...)
# on first writing -- the function takes the log, not its entries, and the sample would
# have raised AttributeError in a reader's hands. Cheap to state, cheap to check.
README_CI="$(grep -oE 'check_invariants\([a-z_.()]+, audit\.entries\(\)\)' README.md | head -1)"
check_eq "README shows the real call shape" "check_invariants(obs, audit.entries())" "$README_CI"

# Test counts stated in prose drift the moment a test is added or removed. R4's
# entry said 12 where the file holds 10 -- written from memory, not from a run.
# The claimed number is read out of ROADMAP.md rather than restated here: a check
# that compares a run against a second copy of the same guess proves nothing.
collected() {
  "$PY" -m pytest "$1" --collect-only -q 2>/dev/null \
    | grep -oE '^[0-9]+ tests collected' | grep -oE '^[0-9]+'
}
claimed() { grep -oE "[0-9]+ tests in \`$1\`" docs/ROADMAP.md | grep -oE '^[0-9]+'; }
check_eq "ROADMAP's count for test_observation.py is the collected one" \
  "$(collected tests/test_observation.py)" "$(claimed tests/test_observation.py)"
check_eq "ROADMAP's count for test_strict.py is the collected one" \
  "$(collected tests/test_strict.py)" "$(claimed tests/test_strict.py)"
check_eq "ROADMAP's count for test_execution.py is the collected one" \
  "$(collected tests/test_execution.py)" "$(claimed tests/test_execution.py)"

echo "== 7. Code volume (README figures) =="
check_eq "core files (.py)" "28" "$(find axiomgate_kernel -name '*.py' | wc -l)"
check_eq "test files"       "22" "$(find tests  -name '*.py' | wc -l)"

echo "== 8. README and docs say the same thing as the source of truth =="
# The number used to be hardcoded both here and in README -- two places that
# could drift apart. Now it is taken from the actual suite (line 29) and
# compared.
NTESTS="$(echo "$T" | grep -oE '^[0-9]+ passed' | grep -oE '^[0-9]+')"
check_eq "README: the test count matches the suite" "2" \
  "$(grep -c "$NTESTS tests" README.md)"
check_eq "README: 373 933 states"  "1" "$(grep -c '373 933 states' README.md)"
check_eq "TRACEABILITY: 373 933"   "1" "$(grep -c '373 933' docs/TRACEABILITY.md)"
check_eq "API.md: the dump script exists" "1" "$([ -f scripts/dump_api.py ] && echo 1 || echo 0)"
# The clean install cannot be run from here (network), but README points to
# the script -- so the script must exist, otherwise the reference is an empty
# promise.
check_eq "the clean-install script exists" "1" \
  "$([ -x scripts/verify_clean_install.sh ] && echo 1 || echo 0)"
check_eq "README points to the clean install" "1" \
  "$(grep -c 'scripts/verify_clean_install.sh' README.md)"

echo "== 9. The anchoring note (ROADMAP R2) =="
# The document quotes the probe's output verbatim. If the behavior in
# audit.py changes, the quotes should stop matching -- so they are compared
# line by line, not by hand.
APROBE="$("$PY" scripts/anchor_probe.py 2>&1)"
for line in \
  "truncated, no anchor -> (True, 'ok'" \
  "truncated, with anchor -> (False, 'log truncated: 2 entries, anchor expected 4')" \
  "count only -> (False, 'log truncated: 2 entries, anchor expected 4')" \
  "head only -> (False, 'head mismatch: log does not end at the anchored entry')" \
  "stale anchor -> (False, 'log longer than anchor: 4 entries, anchor expected 3')" \
  "stale anchor, prefix -> (True, 'prefix ok: 3 anchored entries verified, 1 appended since')" \
  "truncated, prefix -> (False, 'log truncated: 2 entries, anchor expected at least 4')" \
  "substituted chain, prefix -> (False, 'prefix mismatch: the entry at the anchored position is not the anchored entry -- the log was replaced, not appended to')" \
  "half anchor, prefix -> (False, 'prefix verification needs both halves of the anchor (head and count from a single head() call)')" \
  "zero count with head, prefix -> (False, 'invalid anchor: anchor_count is 0 but anchor_head is set -- there is no entry at position zero for that hash to be')"
do
  if echo "$APROBE" | grep -qF "$line"; then ok "the probe: ${line%% ->*}"
  else bad "the probe: ${line%% ->*}" "$line" "$(echo "$APROBE" | head -c 120)"; fi
  # The same message must appear in the document -- otherwise it quotes
  # something that does not happen. Only the text between the quote marks is
  # compared: the document shows them partly as tuples, partly in a table
  # without the tuple wrapper.
  q="$(echo "$line" | sed -n "s/.*'\\(.*\\)'.*/\\1/p")"
  if grep -qF "${q}" docs/ANCHORING.md; then ok "ANCHORING.md quotes it"
  else bad "ANCHORING.md quotes it" "$q in docs/ANCHORING.md" "missing"; fi
done
# R2 moved to CLOSED 2026-09-10 when (1) prefix verification and (2) anchored
# startup were built and mutation-tested. Point (3) -- that the kernel itself
# sends the anchor somewhere -- is deployment, not the library, and remains a
# declared gap in the note. The check ties the three together: if R2 is
# CLOSED, both the code and the note must exist.
has_in_section "R2 is CLOSED with a date" "1" "**Status: CLOSED 2026-09-10**" "R2 "
check_eq "anchored constructor exists"  "1" \
  "$("$PY" -c "import inspect;from axiomgate_kernel import AuditLog;print(int('anchor' in inspect.signature(AuditLog.__init__).parameters))")"
check_eq "the note says the kernel does not emit the anchor" "1" \
  "$(grep -c 'The kernel does not emit the anchor' docs/ANCHORING.md)"
has_in_section "R2 points to the note" "1" "ANCHORING.md" "R2 "
check_eq "README points to the note"      "2" "$(grep -c 'docs/ANCHORING.md' README.md)"

echo "== 10. Market figures are sourced, not rewritten =="
# The figures used to stand as paraphrases marked "not independently
# verified". Two of five did not hold up on retrieval: the 16% line concerned
# a narrower population, and the price range could not be substantiated with
# the source it was attributed to. The quotes now stand verbatim -- and a
# paraphrase must not creep back in.
for q in \
  "92% are concerned about the use of AI agents across the workforce" \
  "92% of organizations lack full visibility into AI identities" \
  "86% don’t enforce access policies for AI identities" \
  "71% of CISOs say AI has access to core business systems, but only 16% govern that access effectively"
do
  if grep -qF "$q" README.md; then ok "verbatim: ${q:0:44}..."
  else bad "verbatim: ${q:0:44}..." "$q" "missing from README.md"; fi
done
# The two errors that were actually found must not return as claims.
check_eq "the 16% paraphrase is not back as a claim" "1" \
  "$(grep -c 'used to read \*\*"16% have effective access control."\*\*' README.md)"
check_eq "the price range is attributed to no source" "0" \
  "$(grep -c '\$4K–\$15K/month | ' README.md)"
check_eq "the sources are dated" "3" \
  "$(grep -cE '(27 May|21 April|29 January) 2026' README.md)"

echo "== 11. The name and the packaging =="
# The rename happened 2026-09-10. The old name was an established infosec
# term for a hardened jump server and thereby miscast the category. The check
# exists because a single leftover occurrence is enough to make the repo
# inconsistent to the outside world. The pattern is written with a character
# class so the check does not match itself.
check_eq "the distribution name" "1" \
  "$(grep -c '^name = "axiomgate-kernel"$' pyproject.toml)"
check_eq "the import package exists" "1" "$([ -f axiomgate_kernel/__init__.py ] && echo 1 || echo 0)"
check_eq "packages.find points to it" "1" \
  "$(grep -c 'include = \["axiomgate_kernel\*"\]' pyproject.toml)"
# The search runs over tracked files, not the working directory. README asks
# the reader to create a venv here, and a venv carries third-party packages'
# own files -- they are never published and must not be able to fail the
# check.
check_eq "no trace of the old name" "0" \
  "$(git ls-files -z | xargs -0 grep -niIE 'bas[t]ion' 2>/dev/null | wc -l)"
# The product is called AxiomGate. The old project name and the channel the
# owner previously approved through were left sitting in environment
# variables, a payload field name, and a ContextVar -- invisible externally,
# but the code said one thing and the documentation another. The patterns are
# written with a character class so the check does not match itself.
check_eq "no trace of the old project name" "0" \
  "$(git ls-files -z | xargs -0 grep -niIE 'aeg[i]s' 2>/dev/null | wc -l)"
check_eq "no channel-bound owner identity" "0" \
  "$(git ls-files -z | xargs -0 grep -niIE 'disc[o]rd' 2>/dev/null | wc -l)"
# The owner's nickname and the company name are internal; externally this is
# AxiomGate by Robin Svensson. Checked here because it was *not* checked here:
# the nickname reached docs/ROADMAP.md in cd2de2d and an L6 review caught it by
# eye. Anything a reviewer finds twice by reading belongs in this file.
check_eq "no internal nickname or company name" "0" \
  "$(git ls-files -z | xargs -0 grep -niIE 'bob[a]n|north[l]ine' 2>/dev/null | wc -l)"
check_eq "the clone URL points to robin-svensson" "1" \
  "$(grep -c 'github.com/robin-svensson/axiomgate-kernel.git' README.md)"
# README promises that a single import line gives three names. The names are
# read from __all__, not from README, so the line cannot rot silently.
check_eq "README's import line holds" "3" \
  "$(PYTHONPATH=. $PY -c 'import axiomgate_kernel as k; print(sum(n in k.__all__ for n in ("Mediator","AuditLog","Verdict")))')"
# README asserts one runtime dependency and one dev dependency. The
# declaration is the source of truth, not the installed tree (cryptography
# pulls in cffi, pytest pulls in four more).
check_eq "one declared runtime dependency" "1" \
  "$(sed -n '/^dependencies = \[/,/^\]/p' pyproject.toml | grep -c '"')"
check_eq "one declared dev dependency" "1" \
  "$(sed -n '/^dev = \[/,/^\]/p' pyproject.toml | grep -c '"')"

echo "== 12. The license =="
# The 2026-09-10 build produced two SetuptoolsDeprecationWarnings:
# 'project.license as a TOML table' (removed 2027-02-18) and 'License
# classifiers are deprecated' (PEP 639). Both are fixed; the checks exist so
# they cannot creep back and make the package unbuildable sometime after
# February 2027.
check_eq "SPDX expression, not a TOML table" "1" \
  "$(grep -c '^license = "PolyForm-Noncommercial-1.0.0"$' pyproject.toml)"
check_eq "license-files points to LICENSE" "1" \
  "$(grep -c '^license-files = \["LICENSE"\]$' pyproject.toml)"
check_eq "no deprecated license classifier" "0" \
  "$(grep -c 'Classifier.*License\|"License ::' pyproject.toml)"
check_eq "LICENSE exists" "1" "$([ -f LICENSE ] && echo 1 || echo 0)"
# The license text is taken verbatim from the SPDX license list and must not
# be paraphrased. The line count only shows the text has the right length --
# an L6 review 2026-09-10 pointed out that verbatim-ness was unverified, and a
# negative test confirmed the gap: a rewritten clause in the middle of the
# text gave 0 FAIL. So the 131 license lines are hashed against the SPDX
# original (PolyForm-Noncommercial-1.0.0.txt, retrieved 2026-09-10 from
# spdx/license-list-data). A paraphrase changes the hash.
check_eq "LICENSE carries the full PolyForm text" "149" "$(wc -l < LICENSE)"
check_eq "the LICENSE text is verbatim against SPDX" \
  "ffcca38841adb694b6f380647e15f17c446a4d1656fed51a1e2041d064c94cc8" \
  "$(tail -131 LICENSE | sha256sum | cut -d' ' -f1)"
check_eq "LICENSE names the correct license" "1" \
  "$(grep -c '^# PolyForm Noncommercial License 1.0.0$' LICENSE)"
check_eq "LICENSE carries the Required Notice with the author" "1" \
  "$(head -1 LICENSE | grep -c '^Required Notice: Copyright (c) 2026 Robin Svensson$')"
# The old proprietary language is incompatible with a public repo: GitHub's
# terms D.4 give every visitor the right to view and fork it, and
# "CONFIDENTIAL" would be self-contradicting the instant the repo goes
# public.
# Tracked files, for the same reason as above: a stranger following README
# got a FAIL on "All rights reserved" from a dependency's README in their
# freshly created venv.
check_eq "nothing left of the proprietary language" "0" \
  "$(git ls-files -z '*.md' 'LICENSE' \
     | xargs -0 grep -niIE 'CONFIDENTIAL|conveys no right to use|All rights reserved' \
       2>/dev/null | wc -l)"
# A license that says "get in touch to obtain rights" must have an address
# that receives mail. GitHub's noreply addresses do not, and may therefore
# only appear as attribution in pyproject -- never as a contact channel.
check_eq "the LICENSE contact address is reachable" "1" \
  "$(grep -c '^Contact: robinsvensson493@gmail.com$' LICENSE)"
check_eq "no noreply address as a contact channel" "0" \
  "$(grep -c 'Contact:.*noreply' LICENSE)"
check_eq "README names the same license as LICENSE" "1" \
  "$(grep -c 'PolyForm Noncommercial License 1.0.0' README.md)"
check_eq "README points to both contact channels" "2" \
  "$(grep -cE 'open an issue|robinsvensson493@gmail.com' README.md)"
check_eq "still only one runtime dependency" "1" \
  "$(sed -n '/^dependencies = \[/,/^\]/p' pyproject.toml | grep -c 'cryptography')"

echo "== 13. Document figures and signatures =="
# API.md:3 claims the signatures are extracted from the running package. Up
# until 2026-09-10 the check only verified that dump_api.py *existed* --
# never that the document matched what the package exposes. Three handwritten
# lines had drifted, and a fourth (set_available) was found only when this
# check was written. The exit code, not a line count: the script reports
# three kinds of failure (DRIFTED, UNRESOLVED, UNKNOWN ARGUMENT) and a fourth
# kind may be added later. A grep on just one of them would have stayed
# silent about the rest.
APIDOC="$("$PY" scripts/check_api_doc.py 2>&1)"; APIRC=$?
check_eq "API.md: all documented signatures match" "0" "$APIRC"
# Silence must not count as a pass: if the parser stops matching, it should
# fail. 43 were compared on 2026-09-10; the threshold is set lower than that
# with margin so the document can grow and shrink without the check becoming
# a false alarm.
APICOUNT="$(echo "$APIDOC" | grep -oE '^[0-9]+ signatures' | grep -oE '^[0-9]+')"
check_eq "API.md: signatures were compared at all" "1" \
  "$([ "${APICOUNT:-0}" -ge 40 ] && echo 1 || echo 0)"
# One truth source: the figure API.md states about itself is the figure the
# check reports. It was written by hand once and was stale within two commits.
check_eq "API.md: the figure it states is the one the check reports" "$APICOUNT" \
  "$(grep -oE 'quoted in this file it checks [0-9]+' docs/API.md | grep -oE '[0-9]+')"

# check_api_doc.py catches drift in what API.md already documents. It cannot
# catch absence, and absence is what actually happened: R3, R4 and R5 each
# added public names that README goes on to name, while the API reference
# never mentioned them at all. Six names were undocumented before this check
# existed.
MISSING_API="$("$PY" - <<'PYEOF'
import re, sys
sys.path.insert(0, ".")
import axiomgate_kernel

readme = open("README.md", encoding="utf-8").read()
api = open("docs/API.md", encoding="utf-8").read()
missing = [n for n in axiomgate_kernel.__all__
           if re.search(rf"\b{re.escape(n)}\b", readme)
           and not re.search(rf"\b{re.escape(n)}\b", api)]
print(",".join(sorted(missing)))
PYEOF
)"
check_eq "every public name README mentions is documented in API.md" "" "$MISSING_API"

# The field count in README rotted once because nothing recomputed it.
FIELDS="$("$PY" scripts/count_audit_fields.py 2>&1)"
check_eq "the audit entry has 22 fields in a real run" "fields=22" \
  "$(echo "$FIELDS" | grep -oE 'fields=[0-9]+')"
check_eq "no field is masked in that flow" "masked=0" \
  "$(echo "$FIELDS" | grep -oE 'masked=[0-9]+')"
check_eq "README: same field count as the real run" "1" \
  "$(grep -c 'of the 22 fields written in a real decision flow' README.md)"

echo
echo "-------- $PASS PASS / $FAIL FAIL --------"
[ "$FAIL" -eq 0 ] || exit 1
