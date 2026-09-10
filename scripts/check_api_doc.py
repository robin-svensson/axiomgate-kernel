#!/usr/bin/env python3
"""Jämför varje signatur i docs/API.md med den paketet faktiskt exponerar.

Bakgrunden: API.md påstår att signaturerna är extraherade ur det körande
paketet, inte avskrivna för hand. Påståendet saknade täckning. En granskare
körde dump_api.py mot dokumentet 2026-09-10 och hittade tre glidna rader; en
fjärde (`set_available`) föll ut när den här kontrollen skrevs.

Den första versionen av kontrollen var själv otillräcklig, och det är värt att
skriva ner varför, för felet är instruktivt: den matchade bara tabellrader vars
anrop började med en bokstav. Dokumentets genvägsnotation för metoder börjar med
punkt — `.revoke(id, token)` — och sådana rader föll utanför regexen och räknades
inte. En andra granskning hittade att just `.revoke` redan hade glidit: parametern
heter `capability_id`, och det finns ett tredje argument `when` som dokumentet
inte nämner. Signaturerna i kodblock (`Mediator(...)`, `AuditLog(...)`,
`consume_if_valid(...)`) låg också utanför. En kontroll som tiger om det den inte
förstår ger falskt godkännande, och det är sämre än ingen kontroll: den bär ett
löfte den inte håller.

Därför gäller nu: varje backtick-citerat anrop i dokumentet är ett påstående som
ska gå att lösa upp mot paketet. Går det inte att lösa upp faller skriptet — det
räknas som ett fynd, inte som tystnad.

Vad som jämförs är parameternamnen i ordning plus `*`-markören för keyword-only.
Annoteringar och defaultvärden får kortas i dokumentet; det är läsbarhet, inte en
osanning. Ett namn som saknas, tillkommit eller bytt plats är en osanning.

Exit 0 = dokumentet stämmer. Exit 1 = minst ett påstående stämmer inte.
"""
import inspect
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import axiomgate_kernel  # noqa: E402

DOC = ROOT / "docs" / "API.md"

# Ett backtick-citat, och inuti det ett anrop: namn, argument, ev. returtyp.
SPAN = re.compile(r"`([^`\n]+)`")
CALL = re.compile(r"^(\.?[A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s*(?:->.*)?$", re.DOTALL)
HEADING = re.compile(r"^#{1,6}\s+(?:`([A-Za-z_][A-Za-z0-9_]*)`)?")
FENCE = re.compile(r"^```")

# Dokumentet kortar medvetet av dessa argumentlistor; inget påstående görs.
# `...` i en argumentlista säger uttryckligen "detta är inte hela listan" —
# `Mediator(..., require_principal_context=True)` i prosan är en förkortning, inte
# en osanning. Ordningen kan då inte jämföras, men namnen kan: varje namn som ändå
# står där måste finnas i den verkliga signaturen. Att hoppa över raden helt hade
# gjort `...` till ett kryphål som tar bort kontrollen.
ELIDED = {"...", "…"}


def split_top_level(argtext: str) -> list[str]:
    """Dela på kommatecken utanför parenteser och hakar.

    `dict[str, int]` och `tuple[str | None, int] | None = None` får inte
    splittras mitt i.
    """
    parts, depth, current = [], 0, ""
    for ch in argtext:
        if ch in "[({":
            depth += 1
        elif ch in "])}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
    parts.append(current)
    return parts


def documented_params(argtext: str) -> list[str]:
    """Parameternamnen i en dokumenterad argumentlista, i ordning."""
    names = []
    for raw in split_top_level(argtext):
        token = raw.strip()
        if not token:
            continue
        if token == "*":
            names.append("*")
            continue
        # `keys: PrincipalKeyStore = None` -> keys
        names.append(re.split(r"[:=]", token, maxsplit=1)[0].strip())
    return names


def actual_params(obj) -> list[str]:
    """Parameternamnen paketet faktiskt exponerar, i ordning."""
    target = obj.__init__ if inspect.isclass(obj) else obj
    names = []
    for name, param in inspect.signature(target).parameters.items():
        if name == "self":
            continue
        if param.kind is inspect.Parameter.KEYWORD_ONLY and "*" not in names:
            names.append("*")
        if param.kind is inspect.Parameter.VAR_POSITIONAL:
            names.append("*")
            continue
        names.append(name)
    return names


def callables_in(text: str):
    """Varje anrop som citeras i en textbit, som (namn, argumenttext)."""
    for span in SPAN.findall(text):
        call = CALL.match(span.strip())
        if call:
            yield call.group(1), call.group(2)


def fenced_calls(block: str):
    """Anrop i ett kodblock. Blocket kan vara flera rader; slå ihop dem."""
    joined = " ".join(line.strip() for line in block.splitlines() if line.strip())
    call = CALL.match(joined)
    if call:
        yield call.group(1), call.group(2)


def resolve(name: str, owner):
    """Slå upp ett dokumenterat namn i paketet.

    Returnerar (objekt, None) eller (None, förklaring). Ett namn som inte kan
    lösas upp är ett fynd — dokumentet påstår något om ett anrop som paketet
    inte tycks ha.
    """
    if name.startswith("."):
        member = name[1:]
        if owner is None:
            return None, f"metodnotation utan klass i sammanhanget: {name}"
        target = getattr(owner, member, None)
        if not inspect.isfunction(target):
            return None, f"{owner.__name__} har ingen metod {member}"
        return target, None

    if name in axiomgate_kernel.__all__:
        return getattr(axiomgate_kernel, name), None
    if owner is not None:
        target = getattr(owner, name, None)
        if inspect.isfunction(target):
            return target, None
    return None, None  # inget anspråk på paketet — t.ex. ett exempel i prosan


def main() -> int:
    lines = DOC.read_text(encoding="utf-8").splitlines()
    owner = None          # klassen metodnotationen `.x()` hör till
    fence_start = None    # radnummer där ett kodblock började
    fence_body: list[str] = []
    claims = []           # (radnummer, namn, argumenttext, agare)

    for lineno, line in enumerate(lines, 1):
        if FENCE.match(line):
            if fence_start is None:
                fence_start, fence_body = lineno, []
            else:
                for name, argtext in fenced_calls("\n".join(fence_body)):
                    claims.append((fence_start + 1, name, argtext, owner))
                fence_start = None
            continue
        if fence_start is not None:
            fence_body.append(line)
            continue

        heading = HEADING.match(line)
        if heading:
            # Varje rubrik bryter sammanhanget. Bär den ett klassnamn blir den
            # klassen ägare; annars nollställs ägaren, så att en metodrad under
            # en prosarubrik faller i stället för att kontrolleras mot fel klass.
            candidate = getattr(axiomgate_kernel, heading.group(1) or "", None)
            owner = candidate if inspect.isclass(candidate) else None
            continue

        for name, argtext in callables_in(line):
            # En konstruktorrad sätter ägaren för metodraderna under sig:
            # `CapabilityRegistry(...)` följs av `.register(...)`, `.revoke(...)`.
            if not name.startswith("."):
                candidate = getattr(axiomgate_kernel, name, None)
                if inspect.isclass(candidate):
                    owner = candidate
            claims.append((lineno, name, argtext, owner))

    checked = failed = 0
    for lineno, name, argtext, claim_owner in claims:
        obj, problem = resolve(name, claim_owner)
        if problem:
            failed += 1
            print(f"OLOSLIGT  docs/API.md:{lineno}  {name}  — {problem}")
            continue
        if obj is None:
            continue
        if not (inspect.isfunction(obj) or inspect.isclass(obj)):
            continue

        want = actual_params(obj)
        got = documented_params(argtext)
        checked += 1

        if ELIDED & set(got):
            unknown = [g for g in got if g not in want and g not in ELIDED]
            if unknown:
                failed += 1
                print(f"OKANT ARGUMENT  docs/API.md:{lineno}  {name}  — {unknown}")
                print(f"        faktiskt:     {want}")
            continue

        if got != want:
            failed += 1
            print(f"GLIDIT  docs/API.md:{lineno}  {name}")
            print(f"        dokumenterat: {got}")
            print(f"        faktiskt:     {want}")

    if checked == 0:
        # Skulle parsningen sluta hitta något vore tystnaden falskt godkännande.
        print("FEL: inga signaturer kunde jämföras — parsningen träffar inte längre")
        return 1

    print(f"{checked} signaturer jämförda, {failed} fel")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
