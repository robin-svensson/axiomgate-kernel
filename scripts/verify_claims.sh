#!/usr/bin/env bash
# Mekaniskt facit för AxiomGate Kernel.
# Varje påstående i README.md och docs/TRACEABILITY.md som har ett känt
# kommando och ett känt förväntat värde kontrolleras här — aldrig av en modell.
#
# Kör:  bash scripts/verify_claims.sh
set -uo pipefail
cd "$(dirname "$0")/.."

# Tolken tas ur miljon i forsta hand, annars den som redan ar aktiv, annars
# python3 pa PATH. En absolut sokvag till en enskild maskin hor inte i ett
# publikt repo: den lackte en lokal katalogstruktur och foll for alla andra.
PY="${AXIOMGATE_KERNEL_PYTHON:-${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}}"
PY="${PY:-$(command -v python3 || command -v python)}"
if [ -z "$PY" ] || ! "$PY" -c "import axiomgate_kernel" 2>/dev/null; then
  echo "FEL: hittar ingen tolk med axiomgate_kernel importerbar." >&2
  echo '     Kor: pip install -e ".[dev]"   -- eller peka ut en tolk med' >&2
  echo "     AXIOMGATE_KERNEL_PYTHON=/sokvag/till/python bash scripts/verify_claims.sh" >&2
  exit 2
fi
PASS=0; FAIL=0

ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; echo "        förväntat: $2"; echo "        faktiskt:  $3"; FAIL=$((FAIL+1)); }

check_eq() { # namn förväntat faktiskt
  [ "$2" = "$3" ] && ok "$1" || bad "$1" "$2" "$3"
}

# roadmap_section <rubrikprefix> — texten under '## <prefix>...' till nasta '## '.
# Statusraderna ar inte unika i ROADMAP.md sedan bade R1 och R2 star CLOSED med
# samma datum; en ograensad grep skulle rakna den andra postens status.
roadmap_section() {
  awk -v h="$1" '$0 ~ "^## " h {p=1; next} /^## /{p=0} p' docs/ROADMAP.md
}
# has <namn> <forvantat 0|1> <text> <sektionsprefix> — finns texten i sektionen
has_in_section() {
  local got; got=0
  roadmap_section "$4" | grep -qF "$3" && got=1
  check_eq "$1" "$2" "$got"
}

# anchor <namn> <fil> <rad> <regex> — påstår att raden matchar
anchor() {
  local got; got="$(sed -n "${3}p" "$2")"
  if echo "$got" | grep -qE "$4"; then ok "$1 ($2:$3)"
  else bad "$1 ($2:$3)" "rad matchar /$4/" "$(echo "$got" | head -c 90)"; fi
}

echo "== 1. Testsviten =="
T="$("$PY" -m pytest tests -q 2>&1 | tail -1)"
check_eq "hela sviten grön" "299 passed" "$(echo "$T" | grep -oE '^[0-9]+ passed')"

echo "== 2. Fristående: inget beroende till det gamla src-paketet =="
LEAK="$(grep -rn 'src\.kernel\|from src\b\|"src\.' axiomgate_kernel/ tests/ 2>/dev/null | wc -l)"
check_eq "inga src-referenser" "0" "$LEAK"
ISO="$("$PY" -c "
import sys
class B:
    def find_spec(self, n, p=None, t=None):
        if n=='src' or n.startswith('src.'): raise ImportError(n)
sys.meta_path.insert(0,B())
import pytest; sys.exit(pytest.main(['tests','-q','--tb=no']))
" 2>&1 | tail -1 | grep -oE '^[0-9]+ passed')"
check_eq "grön även med src blockerad" "299 passed" "$ISO"

echo "== 3. Ingen falsk formell spårbarhet =="
INV="$(grep -rn 'I-[0-9]' axiomgate_kernel/ tests/ 2>/dev/null | wc -l)"
check_eq "inga I-N-citat i kod eller test" "0" "$INV"
# Granskningsfynd 2026-09-10: domain.py citerade 'I10_EnfBeforeExec' och slapp
# forbi kontrollen ovan, som bara letar efter formen 'I-N'. Koden far inte
# namnge en TLA-invariant alls; korrespondensen bor bara i TRACEABILITY.md.
TLANAME="$(grep -rnE 'I[0-9]+_[A-Za-z]' axiomgate_kernel/ tests/ 2>/dev/null | wc -l)"
check_eq "inga TLA-invariantnamn i kod eller test" "0" "$TLANAME"

echo "== 4. Ankare i docs/TRACEABILITY.md =="
anchor "I2  check_capability"        axiomgate_kernel/authorization.py   91 'def check_capability'
anchor "I3  seal()"                  axiomgate_kernel/capability.py     167 'def seal'
anchor "I7  producent != verifierare" axiomgate_kernel/evidence.py      174 'producer cannot verify own evidence'
anchor "I7  producent != auktoritet" axiomgate_kernel/evidence.py       229 'producer cannot be final authority'
anchor "I8  policy_hash i grant"     axiomgate_kernel/grant.py           45 'policy_hash'
anchor "I9  authenticate"            axiomgate_kernel/authentication.py 179 'def authenticate'
anchor "I9  konstanttidsjämförelse"  axiomgate_kernel/authentication.py 200 'hmac_equal'
anchor "I10 consume_if_valid"        axiomgate_kernel/grant.py          137 'def consume_if_valid'
anchor "audit append"                axiomgate_kernel/audit.py          133 'def append'
anchor "audit verify_chain"          axiomgate_kernel/audit.py          217 'def verify_chain'
anchor "audit verify_prefix"         axiomgate_kernel/audit.py          231 'def verify_prefix'
anchor "audit _verify_links"         axiomgate_kernel/audit.py          355 'def _verify_links'
anchor "COMMIT ar Owner-only"        axiomgate_kernel/domain.py          15 'OWNER_MANDATORY_ACTIONS = frozenset'
anchor "COMMIT-grinden (enda punkt)" axiomgate_kernel/authorization.py 158 'OWNER_MANDATORY_ACTIONS'
anchor "Verdict"                     axiomgate_kernel/domain.py          79 'class Verdict'

# Ankarna ovan lases mot KODEN. Granskningsfynd 2026-09-10: siffrorna som star
# i TRACEABILITY.md var en andra, okopplad uppsattning -- 'audit.py:87' blev
# felaktig nar audit.py vaxte, och ingenting larmade. Varje fil:rad som
# dokumentet citerar maste finnas i ankartabellen ovan.
DOCREFS="$(grep -oE '[a-z_]+\.py:[0-9]+' docs/TRACEABILITY.md | sort -u)"
STALE=""
for ref in $DOCREFS; do
  file="axiomgate_kernel/${ref%%:*}"; line="${ref##*:}"
  grep -qE "^anchor .*[[:space:]]$file[[:space:]]+$line[[:space:]]" scripts/verify_claims.sh \
    || STALE="$STALE $ref"
done
check_eq "varje fil:rad i TRACEABILITY.md ar ett ankare" "" "$STALE"

echo "== 4b. Grantfalten raknas, inte pastas =="
# README och API.md pastar ett ANTAL bundna falt. Rakna dem i signaturen i
# stallet for att lita pa texten -- 'all twelve' var fel i tre dokument.
NKW="$("$PY" -c "
import inspect
from axiomgate_kernel.grant import ReservedGrantStore as S
p = inspect.signature(S.consume_if_valid).parameters
print(sum(1 for v in p.values() if v.kind is v.KEYWORD_ONLY))
")"
check_eq "consume_if_valid bundna falt" "11" "$NKW"
check_eq "README sager elva" "1" "$(grep -c 'only if \*\*eleven\*\* bound fields' README.md)"

echo "== 4c. Redaction-gransen ar den README beskriver =="
# README lovar uttryckligen att formatigenkanda hemligheter redigeras och att
# faltnamn INTE skyddar. Bada halvorna kontrolleras skarpt mot en riktig logg.
RED="$("$PY" -c "
import tempfile, os
from axiomgate_kernel.audit import AuditLog
d = tempfile.mkdtemp(); p = os.path.join(d,'a.log')
a = AuditLog(p, b'0'*32)
a.append({'password':'hunter2','key':'sk-'+'A'*30})
t = open(p).read()
print(('LEAK' if 'hunter2' in t else 'noleak') + '/' + ('MISS' if 'sk-'+'A'*30 in t else 'redacted'))
")"
check_eq "bada redaktionsreglerna haller" "noleak/redacted" "$RED"
# Namnregeln far inte svalja karnans egna granskningsfalt. Kors mot ett riktigt
# beslutsflode, inte mot en handskriven dict.
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
check_eq "namnregeln maskerar inga auditfalt" "0" "$FALSKPOS"

echo "== 4d. Grantbindningar per reason class -- raknade, inte pastadda =="
# README och API.md pastar 11 normalt och 8 vid POLICY/PROVENANCE. Rakna genom
# att faktiskt mutera ett falt i taget och se vilka som fallerar. Ett pastaende
# om ett antal ska aldrig sta oemotsagt i text.
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
check_eq "bundna falt: other/policy/provenance" "11/8/8" "$GRANTCOUNT"
check_eq "README sager elva och atta" "1" "$(grep -c 'of the eleven are skipped' README.md)"
check_eq "inga 'all twelve' kvar" "0" "$(grep -rc 'all twelve' README.md docs/API.md | grep -vc ':0$')"

echo "== 4e. Loggen kan inte doljja en kapad svans =="
# Sjalvcertifierande logg: utan forankring ar en kapad kedja fortfarande
# internt konsistent. Bada halvorna kors skarpt -- att den missas utan ankare
# ar lika viktigt att visa som att den fangas med.
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
check_eq "kapad svans: missas utan ankare, fangas med" "blind-ok/caught" "$TRUNC"
# Formatbyte far inte se ut som manipulation -- operatorens atgard skiljer sig helt.
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
check_eq "logg utan seq avvisas som formatbyte" "legacy" "$LEGACY"

echo "== 4f. Fail-closed: ingen utgang ur mediatorn ar ett undantag =="
# Audit ar ett injicerat beroende. En backend som kastar nagot annat an
# AuditError tog sig tidigare hela vagen ut ur evaluate().
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
check_eq "OSError fran auditbackend blir DENY" "DENY" "$FAILCLOSED"

# Samma klass av fel, annat injicerat beroende: sjalva bygget av auditposten
# lag tidigare utanfor varje try. Ett canon som inte beter sig som kernan antog
# tog sig da ut ur evaluate() som ett undantag i stallet for ett verdikt.
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
check_eq "trasigt canon blir DENY utan behorighet" "DENY+net+nogrant" "$RECORDNET"

echo "== 4i. Regulatoriska pastaenden ar daterade och ratt tier =="
# README parade tidigare hogriskkraven med 35M/7%. Det ar Art. 99(3) och galler
# Art. 5, forbjudna praktiker. For loggning och tillsyn ar det 99(4): 15M/3%.
# Att overdriva sin egen rattsliga drivkraft ar samma fel som att citera en
# invariant modellen inte definierar -- och lika latt att genomskada.
# Granskningsfynd 2026-09-10: kontrollen krävde bara att 99(3) och
# "prohibited practices" fanns NAGONSTANS i filen. En ny, obunden mening
# ("A missing audit trail alone risks fines of up to EUR 35 000 000") passerade
# darfor. Bindningen maste vara per rad -- siffran och kvalificeringen i samma
# mening, dar en lasare faktiskt ser dem tillsammans.
# Markdown radbryts mitt i meningar, sa jamforelsen sker pa avwrappad text:
# varje stycke blir en rad. Da ligger siffran och kvalificeringen i samma
# jamforelseenhet, sa som en lasare faktiskt ser dem.
UNWRAP="$(awk 'BEGIN{ORS=""} /^[[:space:]]*$/{print "\n\n"; next} {gsub(/^[[:space:]]+/,""); print $0 " "}' README.md)"
UNBOUND="$(echo "$UNWRAP" | grep -E '35M|35 000 000' | grep -vE '99\(3\)' || true)"
check_eq "varje 35M-omnamnande ar bundet till 99(3)" "" "$UNBOUND"
if echo "$UNWRAP" | grep -qE '35M|35 000 000'; then
  check_eq "35M-stycket sager vad 99(3) galler" "ok" \
    "$(echo "$UNWRAP" | grep -E '35M|35 000 000' | grep -qiE 'prohibited practices' \
       && echo ok || echo SAKNAS)"
fi
check_eq "README anger 99(4) for loggning" "ok" \
  "$(grep -qE '99\(4\)' README.md && echo ok || echo SAKNAS)"

# Det uppskjutna datumet far inte tyst falla tillbaka till det gamla.
check_eq "README anger det uppskjutna datumet" "ok" \
  "$(grep -qE '2 December 2027' README.md && echo ok || echo SAKNAS)"

# Underlaget maste finnas och behalla sin egen osakerhetsmarkering. EUR-Lex gick
# inte att hamta; forsvinner den raden har nagon stadat bort forbehallet i
# stallet for att uppfylla det.
check_eq "REGULATORY.md behaller sitt forbehall" "ok" \
  "$(grep -q 'Not primary-verified' docs/REGULATORY.md \
     && grep -q 'Not retrieved' docs/REGULATORY.md && echo ok || echo SAKNAS)"
check_eq "REGULATORY.md ar daterad" "ok" \
  "$(grep -q '2026-09-10' docs/REGULATORY.md && echo ok || echo SAKNAS)"

echo "== 4g. Ingen frammande identitet inbakad =="
# En hardkodad agare i en sakerhetskontroll gor en okand persons id till enda
# betrodda godkannare i en kunds installation. Fail-closed: vagra i stallet.
# Monstret ar formen, inte identiteten: ett 17-19-siffrigt literal i koden ar
# felet oavsett vilket konto det pekar pa. Da behover kontrollen inte sjalv
# skriva ut ett sparbart konto-id i ett publikt repo.
check_eq "inget inbakat konto-id i kod eller test" "0" \
  "$(grep -rlE '[0-9]{17,19}' --include='*.py' axiomgate_kernel/ tests/ 2>/dev/null | wc -l)"
# Paketet far lagga defaults i sin egen punktkatalog och ingen annans. Att
# namnge den framande katalogen i kontrollen hade fangat just den katalogen --
# och burit dess namn in i ett publikt repo. Varje framande punktkatalog ar felet.
check_eq "ingen framande hemkatalog i paketet" "0" \
  "$(grep -rhoE '~/\.[A-Za-z0-9_-]+|Path\.home\(\) */ *"\.[A-Za-z0-9_-]+"' \
       --include='*.py' axiomgate_kernel/ 2>/dev/null \
     | sed -E 's/.*"(\.[A-Za-z0-9_-]+)".*/\1/; s#^~/##' | sort -u \
     | grep -vx '\.axiomgate-kernel' | wc -l)"
NOOWNER="$("$PY" -c "
import os
os.environ.pop('AXIOMGATE_OWNER_ID', None)
from axiomgate_kernel.approval import ApprovalVerifier
try:
    ApprovalVerifier(public_key_bytes=b'\x01'*32); print('ACCEPTED')
except ValueError:
    print('refused')
")"
check_eq "ApprovalVerifier vagrar utan konfigurerad agare" "refused" "$NOOWNER"

echo "== 4h. Deklarerad skuld halls levande =="
# R1 ar oppen sa lange karnan inte laser principal_context. Kontrollen gar at
# bada hall: dokumentet far inte pasta oppet nar koden ar inkopplad, och
# NOT WIRED far inte forsvinna medan den fortfarande ar frikopplad. Sedan
# 2026-09-10 galler den andra grenen -- och da racker det inte att R1 slutat
# saga OPEN: den ska saga CLOSED med datum, modulen ska ha slutat saga
# NOT WIRED, och flaggan ska fortfarande vara av som standard, eftersom det
# ar avvikelsen R1 sjalv skriver ut.
WIRED="$(grep -rl 'principal_context' axiomgate_kernel/*.py | grep -v 'principal_context.py' | wc -l)"
R1OPEN="$(grep -c '^## R1 .*$' docs/ROADMAP.md)"
check_eq "ROADMAP har R1"                    "1" "$R1OPEN"
if [ "$WIRED" -eq 0 ]; then
  check_eq "R1 oppen medan modulen ar frikopplad" "1" "$(grep -c '^\*\*Status: OPEN\.\*\*' docs/ROADMAP.md)"
  check_eq "modulen sager sjalv NOT WIRED"        "1" "$(grep -c 'NOT WIRED' axiomgate_kernel/principal_context.py)"
else
  check_eq "R1 stangd nar karnan laser modulen"   "0" "$(grep -c '^\*\*Status: OPEN\.\*\*' docs/ROADMAP.md)"
  has_in_section "R1 star CLOSED med datum" "1" "**Status: CLOSED 2026-09-10**" "R1 "
  check_eq "NOT WIRED ar borta ur modulen"        "0" "$(grep -c 'NOT WIRED' axiomgate_kernel/principal_context.py)"
  check_eq "TRACEABILITY har en provenansrad"     "1" "$(grep -c '^| Provenance-bounded authority |' docs/TRACEABILITY.md)"
  # Flaggan ar av som standard. Det ar inte en bekvamlighet utan den deklarerade
  # avvikelsen fran R1 villkor 1; andras defaulten utan att R1 skrivs om ar
  # dokumentet inte langre sant.
  check_eq "require_principal_context ar av som standard" "False" \
    "$("$PY" -c "import inspect;from axiomgate_kernel import Mediator;print(inspect.signature(Mediator.__init__).parameters['require_principal_context'].default)")"
fi

echo "== 4j. R1: provenanstaket ar mutationstestat =="
# Mekanisk verifiering, inte ett omdome: skriptet bar sina egna forvantade
# utfall och failar om en mutation slutar ge det den deklarerar.
if MUT="$("$PY" scripts/mutate_r1.py 2>&1)"; then
  ok "scripts/mutate_r1.py: alla mutationer foll ut som deklarerat"
else
  bad "scripts/mutate_r1.py" "exit 0" "$MUT"
fi
check_eq "tva av tre R1-kontroller har ingen andra barriar" "1" \
  "$(echo "$MUT" | grep -c '2 av 3 har ingen andra barriar')"

echo "== 4k. R2: prefixverifieringen och den ankrade startupen ar mutationstestade =="
if MUT2="$("$PY" scripts/mutate_r2.py 2>&1)"; then
  ok "scripts/mutate_r2.py: alla mutationer foll ut som deklarerat"
else
  bad "scripts/mutate_r2.py" "exit 0" "$MUT2"
fi
check_eq "tva av tre R2-kontroller har ingen andra barriar" "1" \
  "$(echo "$MUT2" | grep -c '2 av 3 har ingen andra barriar')"
# En sanningskalla for lankverifieringen: bade verify_integrity och
# verify_prefix ska ga genom _verify_links, aldrig ha en egen loop.
check_eq "en enda lankloop i audit.py" "1" \
  "$(grep -c 'for index, line in enumerate' axiomgate_kernel/audit.py)"
check_eq "README sager samma sak om andra barriarer" "1" \
  "$(grep -c 'two of the three checks' README.md)"
# Auditposten far inte lasa om den bundna contexten: mellan check_capability och
# skrivningen kor en injicerad provenance-backend, och en backend som byter
# context dar kunde annars fa loggen att beskriva en annan ram an den som gav
# beslutet. Ramen barsas med som CapabilityCheck i stallet.
check_eq "mediator laser inte om contexten vid skrivning" "0" \
  "$(grep -c 'bound_context' axiomgate_kernel/mediator.py)"

echo "== 5. Exemplen kör =="
for ex in examples/0*.py; do
  if "$PY" "$ex" >/dev/null 2>&1; then ok "$ex"; else bad "$ex" "exit 0" "exit $?"; fi
done

echo "== 6. TLC-körningen =="
check_eq "states genererade" "373933" "$(grep -oE '^[0-9]+ states generated' formal/tlc-run-2026-09-08.log | grep -oE '^[0-9]+')"
check_eq "distinkta states"  "345322" "$(grep -oE '[0-9]+ distinct states found' formal/tlc-run-2026-09-08.log | grep -oE '^[0-9]+')"
check_eq "inga fel funna"    "1"      "$(grep -c 'No error has been found' formal/tlc-run-2026-09-08.log)"
check_eq "modellstorlek bunden till 1 authority" "1" "$(grep -c 'Authority = {auth1}' formal/GovernanceMCV6.cfg)"

echo "== 7. Kodmassa (README-siffror) =="
check_eq "kärnfiler (.py)" "25" "$(find axiomgate_kernel -name '*.py' | wc -l)"
check_eq "testfiler"       "19" "$(find tests  -name '*.py' | wc -l)"

echo "== 8. README och docs sager samma sak som facit =="
# Siffran hardkodades tidigare bade har och i README -- tva stallen som kunde
# glida isar. Nu haemtas den ur den faktiska sviten (rad 29) och jamfors.
NTESTS="$(echo "$T" | grep -oE '^[0-9]+ passed' | grep -oE '^[0-9]+')"
check_eq "README: testantalet stammer med sviten" "2" \
  "$(grep -c "$NTESTS tests" README.md)"
check_eq "README: 373 933 states"  "1" "$(grep -c '373 933 states' README.md)"
check_eq "TRACEABILITY: 373 933"   "1" "$(grep -c '373 933' docs/TRACEABILITY.md)"
check_eq "API.md: dump-skriptet finns" "1" "$([ -f scripts/dump_api.py ] && echo 1 || echo 0)"
# Ren-installationen kan inte koras harifran (natverk), men README hanvisar till
# skriptet -- da maste skriptet finnas, annars ar hanvisningen ett tomt lofte.
check_eq "ren-installationsskriptet finns" "1" \
  "$([ -x scripts/verify_clean_install.sh ] && echo 1 || echo 0)"
check_eq "README hanvisar till ren-installationen" "1" \
  "$(grep -c 'scripts/verify_clean_install.sh' README.md)"

echo "== 9. Ankringsnoten (ROADMAP R2) =="
# Dokumentet citerar probens utdata ordagrant. Andras beteendet i audit.py
# ska citaten sluta stamma -- darfor jamfors de rad for rad, inte for hand.
APROBE="$("$PY" scripts/anchor_probe.py 2>&1)"
for line in \
  "kapad, ingen anchor -> (True, 'ok'" \
  "kapad, med anchor -> (False, 'log truncated: 2 entries, anchor expected 4')" \
  "bara count -> (False, 'log truncated: 2 entries, anchor expected 4')" \
  "bara head -> (False, 'head mismatch: log does not end at the anchored entry')" \
  "stale anchor -> (False, 'log longer than anchor: 4 entries, anchor expected 3')" \
  "stale anchor, prefix -> (True, 'prefix ok: 3 anchored entries verified, 1 appended since')" \
  "kapad, prefix -> (False, 'log truncated: 2 entries, anchor expected at least 4')" \
  "utbytt kedja, prefix -> (False, 'prefix mismatch: the entry at the anchored position is not the anchored entry -- the log was replaced, not appended to')" \
  "halvt anchor, prefix -> (False, 'prefix verification needs both halves of the anchor (head and count from a single head() call)')" \
  "noll count med head, prefix -> (False, 'invalid anchor: anchor_count is 0 but anchor_head is set -- there is no entry at position zero for that hash to be')"
do
  if echo "$APROBE" | grep -qF "$line"; then ok "proben: ${line%% ->*}"
  else bad "proben: ${line%% ->*}" "$line" "$(echo "$APROBE" | head -c 120)"; fi
  # Samma meddelande maste sta i dokumentet -- annars citerar det nagot som
  # inte hander. Bara texten mellan citattecknen jamfors: dokumentet visar dem
  # dels som tupler, dels i en tabell utan tupelholjet.
  q="$(echo "$line" | sed -n "s/.*'\\(.*\\)'.*/\\1/p")"
  if grep -qF "${q}" docs/ANCHORING.md; then ok "ANCHORING.md citerar den"
  else bad "ANCHORING.md citerar den" "$q i docs/ANCHORING.md" "saknas"; fi
done
# R2 flyttades till CLOSED 2026-09-10 nar (1) prefixverifiering och (2) ankrad
# startup byggdes och mutationstestades. Punkt (3) -- att karnan sjalv skickar
# ankaret nagonstans -- ar deployment, inte biblioteket, och star kvar som
# deklarerad lucka i noten. Kontrollen binder ihop de tre: star R2 CLOSED maste
# bade koden och noten finnas.
has_in_section "R2 star CLOSED med datum" "1" "**Status: CLOSED 2026-09-10**" "R2 "
check_eq "ankrad konstruktor finns"  "1" \
  "$("$PY" -c "import inspect;from axiomgate_kernel import AuditLog;print(int('anchor' in inspect.signature(AuditLog.__init__).parameters))")"
check_eq "noten sager att karnan inte skickar ankaret" "1" \
  "$(grep -c 'The kernel does not emit the anchor' docs/ANCHORING.md)"
has_in_section "R2 pekar pa noten" "1" "ANCHORING.md" "R2 "
check_eq "README pekar pa noten"      "2" "$(grep -c 'docs/ANCHORING.md' README.md)"

echo "== 10. Marknadssiffrorna ar hamtade, inte omskrivna =="
# Siffrorna stod tidigare som parafraser markta "not independently verified".
# Tva av fem holl inte vid hamtning: 16%-raden gallde en smalare population, och
# prisintervallet gick inte att belagga hos den som det tillskrevs. Citaten star
# nu ordagrant -- och en parafras far inte krypa tillbaka.
for q in \
  "92% are concerned about the use of AI agents across the workforce" \
  "92% of organizations lack full visibility into AI identities" \
  "86% don’t enforce access policies for AI identities" \
  "71% of CISOs say AI has access to core business systems, but only 16% govern that access effectively"
do
  if grep -qF "$q" README.md; then ok "ordagrant: ${q:0:44}…"
  else bad "ordagrant: ${q:0:44}…" "$q" "saknas i README.md"; fi
done
# De tva felen som faktiskt hittades far inte aterkomma som pastaenden.
check_eq "16%-parafrasen ar inte tillbaka som pastaende" "1" \
  "$(grep -c 'used to read \*\*"16% have effective access control."\*\*' README.md)"
check_eq "prisintervallet tillskrivs ingen kalla" "0" \
  "$(grep -c '\$4K–\$15K/month | ' README.md)"
check_eq "kallorna ar daterade" "3" \
  "$(grep -cE '(27 May|21 April|29 January) 2026' README.md)"

echo "== 11. Namnet och paketeringen =="
# Namnbytet 2026-09-10. Det gamla namnet var ett etablerat infosec-ord for en
# hardad jump server och miscuade darmed kategorin. Kontrollen finns for att en
# enda kvarglomd forekomst racker for att gora repot inkonsekvent utat.
# Monstret ar skrivet med teckenklass sa att kontrollen inte traffar sig sjalv.
check_eq "distributionsnamnet" "1" \
  "$(grep -c '^name = "axiomgate-kernel"$' pyproject.toml)"
check_eq "importpaketet finns" "1" "$([ -f axiomgate_kernel/__init__.py ] && echo 1 || echo 0)"
check_eq "packages.find pekar pa det" "1" \
  "$(grep -c 'include = \["axiomgate_kernel\*"\]' pyproject.toml)"
# Sokningen gar over de sparade filerna, inte over arbetskatalogen. README ber
# lasaren skapa en venv har, och en venv bar tredjepartspaketens egna filer --
# de publiceras aldrig och ska inte kunna falla kontrollen.
check_eq "inget spar av det gamla namnet" "0" \
  "$(git ls-files -z | xargs -0 grep -niIE 'bas[t]ion' 2>/dev/null | wc -l)"
# Produkten heter AxiomGate. Det gamla projektnamnet och den kanal agaren
# tidigare godkande genom satt kvar i miljovariabler, ett payload-faltnamn och en
# ContextVar -- osynligt utat, men koden sa en sak och dokumentationen en annan.
# Monstren ar skrivna med teckenklass sa att kontrollen inte traffar sig sjalv.
check_eq "inget spar av det gamla projektnamnet" "0" \
  "$(git ls-files -z | xargs -0 grep -niIE 'aeg[i]s' 2>/dev/null | wc -l)"
check_eq "ingen kanalbunden agaridentitet" "0" \
  "$(git ls-files -z | xargs -0 grep -niIE 'disc[o]rd' 2>/dev/null | wc -l)"
check_eq "clone-URL:en pekar pa robin-svensson" "1" \
  "$(grep -c 'github.com/robin-svensson/axiomgate-kernel.git' README.md)"
# README lovar att en enda importrad ger tre namn. Namnen laeses ur __all__,
# inte ur README, sa raden kan inte ruttna tyst.
check_eq "README:s importrad haller" "3" \
  "$(PYTHONPATH=. $PY -c 'import axiomgate_kernel as k; print(sum(n in k.__all__ for n in ("Mediator","AuditLog","Verdict")))')"
# README pastar ett korberoende och ett utvecklingsberoende. Deklarationen ar
# facit, inte det installerade tradet (cryptography drar in cffi, pytest fyra fler).
check_eq "ett deklarerat korberoende" "1" \
  "$(sed -n '/^dependencies = \[/,/^\]/p' pyproject.toml | grep -c '"')"
check_eq "ett deklarerat dev-beroende" "1" \
  "$(sed -n '/^dev = \[/,/^\]/p' pyproject.toml | grep -c '"')"

echo "== 12. Licensen =="
# Bygget 2026-09-10 gav tva SetuptoolsDeprecationWarning: 'project.license som
# TOML-tabell' (borttagen 2027-02-18) och 'License classifiers are deprecated'
# (PEP 639). Bada ar atgardade; kontrollerna finns for att de inte ska smyga
# tillbaka och gora paketet obyggbart nagon gang efter februari 2027.
check_eq "SPDX-uttryck, inte TOML-tabell" "1" \
  "$(grep -c '^license = "PolyForm-Noncommercial-1.0.0"$' pyproject.toml)"
check_eq "license-files pekar pa LICENSE" "1" \
  "$(grep -c '^license-files = \["LICENSE"\]$' pyproject.toml)"
check_eq "ingen deprecated licensklassificerare" "0" \
  "$(grep -c 'Classifier.*License\|"License ::' pyproject.toml)"
check_eq "LICENSE finns" "1" "$([ -f LICENSE ] && echo 1 || echo 0)"
# Licenstexten ar hamtad ordagrant fran SPDX:s licenslista och far inte
# parafraseras. Radantalet visar bara att texten har ratt langd -- en L6-granskning
# 2026-09-10 papekade att ordagrannheten var obestamd, och ett negativtest bekraftade
# luckan: en omskriven klausul mitt i texten gav 0 FAIL. Darfor hashas de 131
# licensraderna mot SPDX-originalet (PolyForm-Noncommercial-1.0.0.txt, hamtat
# 2026-09-10 fran spdx/license-list-data). En parafras andrar hashen.
check_eq "LICENSE bar hela PolyForm-texten" "149" "$(wc -l < LICENSE)"
check_eq "LICENSE-texten ar ordagrann mot SPDX" \
  "ffcca38841adb694b6f380647e15f17c446a4d1656fed51a1e2041d064c94cc8" \
  "$(tail -131 LICENSE | sha256sum | cut -d' ' -f1)"
check_eq "LICENSE namner ratt licens" "1" \
  "$(grep -c '^# PolyForm Noncommercial License 1.0.0$' LICENSE)"
check_eq "LICENSE bar Required Notice med upphovsman" "1" \
  "$(head -1 LICENSE | grep -c '^Required Notice: Copyright (c) 2026 Robin Svensson$')"
# Det gamla proprietara sprakbruket ar oforenligt med ett publikt repo: GitHubs
# villkor D.4 ger varje besokare ratt att se och forka det, och "CONFIDENTIAL"
# vore sjalvmotsagande i samma sekund repot blir publikt.
# Sparade filer, av samma skal som ovan: en framling som foljde README fick FAIL
# pa "All rights reserved" ur ett beroendes README i sin nyskapade venv.
check_eq "inget kvar av det proprietara sprakbruket" "0" \
  "$(git ls-files -z '*.md' 'LICENSE' \
     | xargs -0 grep -niIE 'CONFIDENTIAL|conveys no right to use|All rights reserved' \
       2>/dev/null | wc -l)"
# En licens som sager "hor av dig for att fa rattigheter" maste ha en adress som
# tar emot post. GitHubs noreply-adresser gor inte det, och far darfor bara stå
# som attribution i pyproject -- aldrig som kontaktvag.
check_eq "LICENSE kontaktadress ar nabar" "1" \
  "$(grep -c '^Contact: robinsvensson493@gmail.com$' LICENSE)"
check_eq "ingen noreply-adress som kontaktvag" "0" \
  "$(grep -c 'Contact:.*noreply' LICENSE)"
check_eq "README namner samma licens som LICENSE" "1" \
  "$(grep -c 'PolyForm Noncommercial License 1.0.0' README.md)"
check_eq "README hanvisar till bada kontaktvagarna" "2" \
  "$(grep -cE 'open an issue|robinsvensson493@gmail.com' README.md)"
check_eq "fortfarande bara ett korberoende" "1" \
  "$(sed -n '/^dependencies = \[/,/^\]/p' pyproject.toml | grep -c 'cryptography')"

echo "== 13. Dokumentens siffror och signaturer =="
# API.md:3 pastar att signaturerna ar extraherade ur det korande paketet.
# Fram till 2026-09-10 kontrollerades bara att dump_api.py *fanns* -- aldrig
# att dokumentet stamde med det paketet exponerar. Tre handskrivna rader hade
# glidit, och en fjarde (set_available) hittades forst nar kontrollen skrevs.
# Exitkoden, inte en radrakning: skriptet rapporterar tre slags fel (GLIDIT,
# OLOSLIGT, OKANT ARGUMENT) och ett fjarde slag kan tillkomma. En grep pa ett
# enda av dem hade tigit om resten.
APIDOC="$("$PY" scripts/check_api_doc.py 2>&1)"; APIRC=$?
check_eq "API.md: alla dokumenterade signaturer stammer" "0" "$APIRC"
# Tystnad far inte rakas som godkant: slutar parsningen traffa ska det falla.
# 43 jamfordes 2026-09-10; gransen ar satt lagre an sa med marginal for att
# dokumentet ska kunna vaxa och krympa utan att kontrollen blir en falsklarmare.
APICOUNT="$(echo "$APIDOC" | grep -oE '^[0-9]+ signaturer' | grep -oE '^[0-9]+')"
check_eq "API.md: signaturer jamfordes overhuvudtaget" "1" \
  "$([ "${APICOUNT:-0}" -ge 40 ] && echo 1 || echo 0)"

# Faltantalet i README ruttnade en gang for att inget rakade om det.
FIELDS="$("$PY" scripts/count_audit_fields.py 2>&1)"
check_eq "audit-posten har 21 falt i skarp korning" "falt=21" \
  "$(echo "$FIELDS" | grep -oE 'falt=[0-9]+')"
check_eq "inget falt maskeras i det flodet" "maskerade=0" \
  "$(echo "$FIELDS" | grep -oE 'maskerade=[0-9]+')"
check_eq "README: samma faltantal som skarp korning" "1" \
  "$(grep -c 'of the 21 fields written in a real decision flow' README.md)"

echo
echo "-------- $PASS PASS / $FAIL FAIL --------"
[ "$FAIL" -eq 0 ] || exit 1
