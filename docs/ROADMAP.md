# Roadmap — declared debt

This file exists so that nothing in this repository can be quietly left undone.

Each item is a capability the kernel **states honestly that it did not have**. Every
item has a mechanical check in `scripts/verify_claims.sh` that fails if the item is
silently dropped, or if the code changes without the entry changing with it.
Documenting a gap is not the same as closing it.

**Both items are now CLOSED (2026-09-10) — and neither is closed by default.** R1's
provenance ceiling is enforced only behind `require_principal_context=True`; R2's anchor
check runs only when the integrator passes `anchor=` to `AuditLog`. Those deviations are
written out under each item, with the reason the weaker behavior is the default. Read
them as the remaining gaps, because that is what they are: a deployment that wires
neither flag gets exactly the kernel that existed before these items were closed.

Limits that were never debt -- what formal verification does and does not cover, what
the kernel deliberately leaves to the integrator -- are in the README and in
[TRACEABILITY.md](TRACEABILITY.md), not here.
This file is for debt that was declared and then paid; a closed entry keeps its history
so that the deviation cannot be read out of it later.

---

## R1 — Provenance ceilings, enforced behind an opt-in flag

**Status: CLOSED 2026-09-10** — with one deliberate deviation from the original
terms, written out below rather than absorbed silently.

`axiomgate_kernel/principal_context.py` defines how authority is bounded by *how a call
arose* rather than by what an agent is named:

- `PrincipalContext.provenance` — `direct` / `delegated` / `cron` / `mcp`
- `Mandate`, `MANDATE_SCOPES`, `MANDATE_RISK_CEILING` — bounded scope from the owner
- `propagate_for_subagent` — monotonicity: `child_mandate ⊆ parent_mandate`
- `propagate_for_cron` — a scheduled run has no human in the loop

**What was built.** `Mediator(..., require_principal_context=True)` makes every
verdict read the bound context. `check_capability` then applies, in order: a
missing or invalid context ⇒ DENY (`authz.no_principal_context`); no mandate ⇒
DENY; an unparseable or expired mandate ⇒ DENY; an action outside the mandate's
scope ⇒ DENY; and finally the effective ceiling
`min(capability.risk_ceiling, mandate.risk_ceiling)`, exceeded ⇒ DENY
(`authz.provenance_risk_ceiling`). `authorization.effective_ceiling` is the one
source of truth for that minimum. The audit record carries `provenance`,
`mandate_id` and `effective_risk_ceiling`; each is `None` when there is nothing
to record, never a stand-in value.

**The deviation, stated plainly.** Condition 1 asked for a missing context to
fail closed unconditionally. It fails closed *within the flag*, and the flag is
**off by default**. Turning it on by default would deny every request at every
existing integrator — no context is bound anywhere yet — and would break the
public contract of a security kernel days before release. With the flag off
there is no provenance ceiling at all. That is a declared gap, and
`tests/test_provenance_ceiling.py::test_the_default_mediator_is_unchanged`
holds the default to it so the gap cannot close by accident either.

**How the four conditions were met:**

1. **Effective ceiling as a minimum, missing context failing closed** —
   `authorization.py`, and `tests/test_provenance_ceiling.py` (13 tests) proves
   both directions: the mandate binding below the capability, and the
   capability binding below the mandate.
2. **Provenance and effective ceiling in the audit record** —
   `mediator.py:_audit_record`, with a test that reads the written entry back.
   The first version of this read the bound context *again* at write time. An
   independent review broke it by hand: a `ProvenanceChecker` — an injected
   dependency, called between the check and the write — swapped the context, and
   the log then named a mandate that had not authorised anything, while the
   verdict itself stayed correct. The record now carries the `CapabilityCheck`
   that actually decided, so there is one source of truth per decision.
   `test_a_swapped_context_cannot_rewrite_the_audit_record` fails against the
   old version.
3. **Mutation testing**, on the same terms as the four existing protections —
   `scripts/mutate_r1.py`. Three checks removed in memory, three scenarios
   re-run. Two of the three have **no second barrier**: strike the minimum rule
   and a `propose` mandate permits MEDIUM; widen the mandate scopes and a
   `read-only` mandate permits EXECUTE. The third does have one — the mandate
   block asks for itself whether a context exists, so striking the top gate
   alone still denies. `scripts/verify_claims.sh` runs the probe.
4. **`docs/TRACEABILITY.md` gains a row** — under code concepts with no model
   counterpart, since the TLA+ model has no notion of provenance.

**Corrected after closing** (2026-09-10). `effective_risk_ceiling` in the audit record
was written from `capability.risk_ceiling` at every return that never reached
`effective_ceiling()` — a denial on mandate scope or validity, and the whole unflagged
mode. The record therefore named a bound that had not been applied, in a field whose own
docstring already said it should be `None` when no context was required. The value is now
set by one source, `effective_ceiling()`, and is `None` until that runs. `mandate_id`
stays, so a reader still sees *which* mandate fell short. Same family as the false
traceability this item's frame threading fixed: not fail-open, but a record describing a
frame that did not decide.

**What this still does not do.** The ceiling is read from a `ContextVar`, so it
binds whatever the *calling process* set. It is a constraint on an honest
integrator's own call graph, not a defence against an integrator that lies
about provenance. Nothing signs a `PrincipalContext`.

---

## R2 — The audit chain needs an external anchor to prove its own length

**Status: CLOSED 2026-09-10** — the library half is built and mutation-tested. Getting
the anchor to somewhere external stays the integrator's, and is stated as such below.

Each entry carries its position (`seq`) inside the hashed body, and `AuditLog.head()`
returns `(last_hash, count)`. `verify_chain(expected_head, expected_count)` detects a
truncated tail — **but only when it is given an anchor that was stored somewhere the
attacker cannot reach.**

A self-certifying log cannot prove its own length. Without an externally held anchor,
a chain cut short still verifies as internally consistent, because every remaining
entry does link correctly to the one before it. This is the same reason Certificate
Transparency signs tree heads rather than trusting the log to describe itself.

The kernel cannot close this alone: where the anchor is stored is a deployment
decision.

**The documentation half was delivered first** (2026-09-10):
[docs/ANCHORING.md](ANCHORING.md) covers cadence, where an anchor may be stored, why
both halves of `head()` are needed, and what each check does and does not catch. Every
message it quotes is read back from `scripts/anchor_probe.py`, which
`scripts/verify_claims.sh` runs — so the note cannot drift from the code.

**What was built to close it** (2026-09-10):

1. **Prefix verification.** `verify_prefix(head, count)` answers the weaker question —
   "does this log begin with the chain I anchored, and continue correctly?" — which a
   log that is still being appended to can answer yes to. It catches a removal
   (`log truncated: N entries, anchor expected at least M`) and, unlike a count alone,
   a competing chain of the same length written with the same key
   (`prefix mismatch: ... the log was replaced, not appended to`). It refuses a
   half-anchor rather than reporting on the half it can check, because a partial answer
   here reads as a pass. `verify_chain` keeps its exact semantics; the two answer
   different questions and neither replaces the other.
2. **Startup can be anchored.** `AuditLog(path, key, anchor=(head, count))` runs the
   prefix check as part of construction and raises `AuditError` rather than open a log
   that fails it. The check runs *after* the replay, never before: a partial last line
   is a recovery, but a partial last line that swallowed an anchored entry is a finding,
   and the anchor is what tells them apart.

Both are mutation-tested on the same terms as the four existing protections
(`scripts/mutate_r2.py`): each check removed in memory, the scenario re-run in a forked
subprocess, each case carrying its own declared expected outcome so a deviation in
either direction is a finding. **Two of the three checks have no second barrier.**
Striking `anchor_covers` is the exception — the hash comparison still blocks a truncated
tail, but the message then says *replaced* where *truncated* would be true.

**The deviation, written out.** `anchor=` is **opt-in**, exactly as
`require_principal_context` is in R1: an `AuditLog(path, key)` with no anchor behaves as
it always did, and opens a truncated file without complaint. That is not fail-closed. It
is chosen so that an existing deployment does not start failing on an anchor it never
had, and it means the protection only exists where the integrator wired it.

**What stays open, and is not the library's to close:**

3. **The kernel emits no anchor.** `head()` returns it; shipping it somewhere the
   writing process cannot reach is deployment code. Nothing in the kernel prompts it,
   and no check notices if it never happens. This is stated as a declared gap in
   [docs/ANCHORING.md](ANCHORING.md) rather than tracked as an open item, because no
   amount of library code can close it.
