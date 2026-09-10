#!/usr/bin/env python3
"""Compare every signature in docs/API.md against what the package actually exposes.

Background: API.md claims the signatures are extracted from the running
package, not copied out by hand. The claim had no coverage. A reviewer ran
dump_api.py against the document on 2026-09-10 and found three drifted lines;
a fourth (`set_available`) fell out when this check was written.

The first version of the check was itself insufficient, and it is worth
writing down why, because the bug is instructive: it only matched table rows
whose call started with a letter. The document's shorthand notation for
methods starts with a dot -- `.revoke(id, token)` -- and such rows fell
outside the regex and were not counted. A second review found that `.revoke`
itself had already drifted: the parameter is named `capability_id`, and
there is a third argument `when` the document does not mention. Signatures
in code blocks (`Mediator(...)`, `AuditLog(...)`, `consume_if_valid(...)`)
also fell outside. A check that stays silent about what it does not
understand grants a false pass, and that is worse than no check at all: it
carries a promise it does not keep.

Therefore the rule now is: every backtick-quoted call in the document is a
claim that must resolve against the package. If it cannot be resolved the
script fails -- that counts as a finding, not as silence.

What is compared is the parameter names in order plus the `*` marker for
keyword-only. Annotations and default values may be shortened in the
document; that is readability, not a falsehood. A name that is missing,
added, or moved is a falsehood.

Exit 0 = the document is correct. Exit 1 = at least one claim does not hold.
"""
import inspect
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import axiomgate_kernel  # noqa: E402

DOC = ROOT / "docs" / "API.md"

# A backtick quote, and inside it a call: name, arguments, optional return type.
SPAN = re.compile(r"`([^`\n]+)`")
CALL = re.compile(r"^(\.?[A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s*(?:->.*)?$", re.DOTALL)
HEADING = re.compile(r"^#{1,6}\s+(?:`([A-Za-z_][A-Za-z0-9_]*)`)?")
FENCE = re.compile(r"^```")

# The document deliberately shortens these argument lists; no claim is made.
# `...` in an argument list explicitly says "this is not the full list" --
# `Mediator(..., require_principal_context=True)` in prose is an abbreviation,
# not a falsehood. The order can then not be compared, but the names can:
# every name that is still there must exist in the real signature. Skipping
# the line entirely would have turned `...` into a loophole that removes the
# check.
ELIDED = {"...", "…"}


def split_top_level(argtext: str) -> list[str]:
    """Split on commas outside parentheses and brackets.

    `dict[str, int]` and `tuple[str | None, int] | None = None` must not be
    split in the middle.
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
    """The parameter names in a documented argument list, in order."""
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
    """The parameter names the package actually exposes, in order."""
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
    """Every call quoted in a piece of text, as (name, argument text)."""
    for span in SPAN.findall(text):
        call = CALL.match(span.strip())
        if call:
            yield call.group(1), call.group(2)


def fenced_calls(block: str):
    """Calls in a code block. The block may span several lines; join them."""
    joined = " ".join(line.strip() for line in block.splitlines() if line.strip())
    call = CALL.match(joined)
    if call:
        yield call.group(1), call.group(2)


def resolve(name: str, owner):
    """Look up a documented name in the package.

    Returns (object, None) or (None, explanation). A name that cannot be
    resolved is a finding -- the document claims something about a call the
    package does not appear to have.
    """
    if name.startswith("."):
        member = name[1:]
        if owner is None:
            return None, f"method notation with no class in context: {name}"
        target = getattr(owner, member, None)
        if not inspect.isfunction(target):
            return None, f"{owner.__name__} has no method {member}"
        return target, None

    if name in axiomgate_kernel.__all__:
        return getattr(axiomgate_kernel, name), None
    if owner is not None:
        target = getattr(owner, name, None)
        if inspect.isfunction(target):
            return target, None
    return None, None  # no claim on the package -- e.g. an example in prose


def main() -> int:
    lines = DOC.read_text(encoding="utf-8").splitlines()
    owner = None          # the class the method notation `.x()` belongs to
    fence_start = None    # line number where a code block started
    fence_body: list[str] = []
    claims = []           # (line number, name, argument text, owner)

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
            # Every heading breaks the context. If it carries a class name it
            # becomes the owner; otherwise the owner is reset, so a method
            # line under a prose heading fails instead of being checked
            # against the wrong class.
            candidate = getattr(axiomgate_kernel, heading.group(1) or "", None)
            owner = candidate if inspect.isclass(candidate) else None
            continue

        for name, argtext in callables_in(line):
            # A constructor line sets the owner for the method lines below it:
            # `CapabilityRegistry(...)` is followed by `.register(...)`, `.revoke(...)`.
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
            print(f"UNRESOLVED  docs/API.md:{lineno}  {name}  -- {problem}")
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
                print(f"UNKNOWN ARGUMENT  docs/API.md:{lineno}  {name}  -- {unknown}")
                print(f"        actual:       {want}")
            continue

        if got != want:
            failed += 1
            print(f"DRIFTED  docs/API.md:{lineno}  {name}")
            print(f"        documented:   {got}")
            print(f"        actual:       {want}")

    if checked == 0:
        # If the parsing stopped matching anything, silence would be a false pass.
        print("ERROR: no signatures could be compared -- the parser no longer matches")
        return 1

    print(f"{checked} signatures compared, {failed} errors")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
