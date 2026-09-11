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

---

## R3 — The two deviations were invisible from inside a running kernel

**Status: CLOSED 2026-09-11** — the defaults are unchanged, and that is the point.

R1 and R2 each end with a deviation: the protection exists, and it is off unless the
integrator turns it on. Both reasons still hold. What did not hold is what those two
paragraphs left implied — that a deployment could tell which kernel it was running.

It could not. The two flags are set on **two different objects** at two different call
sites (`Mediator(require_principal_context=…)` and `AuditLog(…, anchor=…)`), and nothing
anywhere reported the combination. A deployment with the provenance ceiling on and a
plain `AuditLog` is byte-for-byte indistinguishable, from inside, from one with both:
same audit records, same verdicts, same green suite. Half a fail-closed kernel reads
exactly like a whole one.

That is worse than the gap itself. A documented gap can be checked against; an
*unobservable* gap gets reported as closed by the person running it, in good faith.

**What was built** (`axiomgate_kernel/strict.py`, 13 tests in `tests/test_strict.py`,
12 mechanical checks in `scripts/verify_claims.sh` §6b):

1. **`strict_audit_log(path, key, anchor)`** — `anchor` is positional with no default.
   That is the whole mechanism: `AuditLog(path, key)` is a *valid call* that silently
   accepts a truncated file, and no amount of documentation makes a valid call look
   wrong at the call site. Pass a prior `head()`, or `NEW_LOG` when no chain exists yet.
   `NEW_LOG` is a claim, not an escape hatch — it is refused if a chain is on disk,
   because "first run" and "reopening" are the same call to `AuditLog` and different
   security situations.
2. **`strict_mediator(...)`** — turns the ceiling on, and **refuses to build** on an
   audit log that was not opened with an anchor. Passing `require_principal_context=False`
   raises rather than being ignored: a strict constructor that hands back a weak kernel
   under a name saying otherwise is worse than no constructor, because the name is what
   the integrator quotes in their own documentation.
3. **`strictness_report(mediator)`** — asks a live kernel which protections it has, and
   *names* the missing ones with the flag that turns each on. A bare `False` tells an
   operator nothing about what to wire. Reads state, never changes it; safe to print at
   startup.
4. **`AuditLog.anchored`** — the one behavioral change outside the new module. Nothing
   in the kernel could previously answer "is this log anchored?", so neither the strict
   constructor nor the report could check its own precondition.

**No default changed.** A deployment that never imports `strict` gets exactly the kernel
it got before, and R1's and R2's defaults stay where those entries say they are. This is
a second, narrower door — not a change to the first one.

**What stays open, and is the project owner's call, not the library's:** whether fail-closed should
become the *default* at 1.0. The argument against it in R1 and R2 was that it would break
existing integrators. That argument is currently vacuous — the kernel has never run
outside a development environment and is not on PyPI, so there are no integrators to
break. The window where flipping the default costs nothing is open now and closes with
the first real adopter. Deciding it is a product decision, and it is not made here.

**What this does not do.** `strictness_report` is *self-reporting*, not verification. It
reads `AuditLog.anchored`, which is an ordinary writable attribute: a caller who sets
`log.anchored = True` by hand, or passes any object with that attribute, gets a clean
report. So does `strict_mediator` — it checks the attribute, not the provenance of the
object. That is the right boundary for what this is: R3 closes the gap where an *honest*
integrator cannot tell which kernel they are running. It is not a defence against code
that is deliberately lying to its own audit trail, and no in-process check could be —
such code can also call `Mediator` directly.

One case the `NEW_LOG` path cannot catch: a log file truncated to **zero bytes**.
`_has_entries` reads size, so a complete wipe is indistinguishable from a first run and
is accepted. That is deliberate — a created-but-unwritten file is what a crashed first
run leaves behind, and refusing it would fail the strict path on a situation with nothing
to protect. Detecting a total wipe requires the external anchor, which is exactly what
R2 is for: a reopen that passes `head()` catches it, and one that claims `NEW_LOG` does
not.

## R4 — Three invariants held only by reading the source

**Status: PARTIAL 2026-09-11** — I1, I4 and I6 moved from MODEL-ONLY to PARTIAL. They
are not ENFORCED, and the reason is written out below rather than rounded away.

`docs/TRACEABILITY.md` marked I1, I4 and I6 MODEL-ONLY. Read as three separate entries
that looks like three separate debts. It was one: all three relate `obsLog` to
`enforceLog`, and this implementation had only the second of the two logs.

- **I1** — every enforcement is preceded by an observation
- **I4** — observations are ordered consistently with the enforcements they precede
- **I6** — an observation and its enforcement name the same principal

The kernel already did the right thing. `_gated` authenticates before it dispatches, so
an identity exists before any decision is taken. But that is a property of the *source
text*, provable only by reading it — and an invariant that holds by inspection is not
enforced, it is true until somebody edits the file. Nothing in the suite would have
noticed the edit.

**What was built** (`axiomgate_kernel/observation.py`, 12 tests in `tests/test_observation.py`,
14 mechanical checks in `scripts/verify_claims.sh` §6c):

1. **`ObservationLog`** — append-only. `entries()` returns a copy, records refuse
   `__setattr__`, and `seq` starts at **1**, because `if seq:` on a legitimate zero reads
   as absence.
2. **`Mediator(observations=…)`** — opt-in, like R1 and R2. The observation is taken at
   `mediator.py:169`: after authentication succeeded, before `then(canon, authn)`
   dispatches anything. One site, not several.
3. **`observation_seq`** in every audit record (`mediator.py:757`) — the join between the
   two logs. `None` when there is no observation log, and `None` when the request was
   denied before an identity existed. A missing value is not zero.
4. **`check_invariants(observations, audit_entries)`** (`observation.py:143`) — answers
   in four states, not two: `HOLDS`, `PARTIAL`, `VIOLATED`, `UNOBSERVABLE`. A check that
   cannot say *I don't know* will eventually say *yes* when it means it.

**The vacuous-truth cases are failures here, not passes.** No observation log at all is
`UNOBSERVABLE` and `holds=False` — not a quiet pass over an empty set. A log that exists
but saw nothing while enforcements were recorded is `VIOLATED`, for the same reason. An
audit entry whose `observation_seq` points at no record is `VIOLATED` and never `PARTIAL`:
a dangling reference is a contradiction, not incomplete data.

**Why PARTIAL and not ENFORCED.** Three reasons, all real:

- The log is **opt-in**. A `Mediator` built without `observations=` enforces exactly as
  before and answers `UNOBSERVABLE`. The default kernel is not observed.
- `_observe` **swallows its exceptions on purpose** (`mediator.py:203`). The observation
  is evidence about the run, not part of the decision; a bookkeeping error must not turn
  a legitimate PERMIT into a DENY. The cost is paid honestly — the enforcement is counted
  as unobserved and I1 drops to PARTIAL. The report gets worse, which is correct.
- The log lives **in memory and is not authenticated**. Unlike `AuditLog` there is no MAC
  chain: it proves ordering within one process, not integrity across a restart.

**What stayed open: I5, and it needed a third log.** That log was written the same night;
see **R5** below.

---

## R5 — the execution log, and what a rollback does to it

**Status: PARTIAL 2026-09-11.** I5 says every execution has a matching observation. It was
`MODEL-ONLY` for the same single reason I1, I4 and I6 carried until R4: the invariant
relates two logs and the kernel kept only one of them. Execution in this kernel is the
redemption of a `ReservedGrant` — `ReservedGrantStore.consume_if_valid` is the only way to
redeem one — and that redemption wrote nothing anywhere.

**`consumed` was not a substitute, and `unconsume` is why.** A redemption is rolled back
when downstream audit logging fails, and the flag goes back to `False`. A log that appended
on consume and stopped there would carry an execution that never happened, and would keep
carrying it after the rollback. That is worse than no log: it reports an execution the
kernel deliberately undid. Deleting the entry instead would lose that it was attempted.

**What was built** (`axiomgate_kernel/execution.py`, 16 tests in `tests/test_execution.py`):

1. **`ExecutionLog`** — append-only, three states rather than two: executed, rolled back,
   never happened. `entries()` returns a copy, records refuse `__setattr__`, and `seq`
   starts at **1**, for the same reason it does in `ObservationLog`.
2. **`mark_rolled_back(seq)`** (`execution.py:92`) — marks, never deletes, and raises on a
   sequence number that was never issued. Called from `grant.py:253` inside `unconsume`.
3. **The record is written after every binding check passes** (`grant.py:222`), not at
   entry: a redemption refused for a principal mismatch is not an execution.
4. **`check_execution_invariant(executions, observations)`** (`execution.py:123`) — the same
   four states as R4. A rolled-back record needs no observation; a live one without a
   matching observation is `VIOLATED`.

**An empty execution log is `PARTIAL`, not `HOLDS`** — nothing has been executed, so nothing
has been contradicted, and a green answer over an empty set is exactly the vacuous truth R4
was written to refuse. **So is a log of nothing but rollbacks**, which is the same fact in a
busier shape: zero executions stand, and the entries are there to make the report look
substantiated. The first version answered `HOLDS` to that, and an L6 review found it by
constructing the log rather than by reading the code.

**Why PARTIAL and not ENFORCED.** The same three deviations as R4, plus one of its own:

- The log is **opt-in**: `Mediator(executions=ExecutionLog())`, passed straight through to
  the grant store. A kernel without one reports `UNOBSERVABLE`.
- The recording **swallows its exceptions** (`grant.py:222`), on the same trade as
  `Mediator._observe`: bookkeeping about a redemption must not undo a redemption the policy
  allowed.
- The log lives **in memory and is not authenticated**. No MAC chain, unlike `AuditLog`.
- **A rollback is trusted.** The check believes `rolled_back` because nothing else can know;
  a caller who marks a real execution as rolled back gets a clean report. That is the same
  boundary R3 states for `AuditLog.anchored`, and it is documented rather than defended.
