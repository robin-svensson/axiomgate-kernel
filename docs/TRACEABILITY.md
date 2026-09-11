# Traceability: TLA+ model ↔ Python kernel

**Read this first.** This is a *correspondence table*, not a derivation.

The Python kernel in `axiomgate_kernel/` was **not** generated from the TLA+ model in `formal/`,
and it has **not** been proven to refine it. What follows is an honest mapping of which
model invariants have a running counterpart in code, which are statements about log
sequences that the Python code has no abstraction for, and which have no counterpart at
all. Anything else would be authority referenced but not derived.

Before 2026-09-10 the source code cited invariant numbers (`I-5`, `I-6`, `I-7`, `I-8`)
that did **not** correspond to what the model defines. Those citations were removed
rather than retrofitted. This document replaces them.

---

## What the model run actually proves

From `formal/tlc-run-2026-09-08.log`, read back verbatim:

| | |
|---|---|
| Invariant checked | `GovernanceSecurityBoundary == I1 /\ I2 /\ ... /\ I10` |
| States generated | 373 933 |
| Distinct states | 345 322 |
| Depth of complete state graph | 11 |
| Result | `Model checking completed. No error has been found.` |
| Tool | TLC2 2026.08.21.155922 |

**Scope of the run** (`formal/GovernanceMCV6.cfg`) — this bounds the claim:

```
Authority = {auth1}     Entity    = {ent1}
Actions   = {act1,act2} Resources = {res1,res2}
```

One authority, one entity, two actions, two resources. The model is exhaustively checked
**at that size**. It is not a proof for arbitrary numbers of principals or resources, and
it says nothing about the Python implementation. Anyone citing "373,933 states" without
this paragraph is overstating it.

---

## Invariant map

Status values:

- **ENFORCED** — a running check in Python enforces the same property.
- **PARTIAL** — Python enforces a strictly weaker version.
- **MODEL-ONLY** — the invariant is a statement about `obsLog` / `enforceLog` / `execLog`
  sequences. Python has no such log abstraction, so the invariant is not expressible as a
  runtime assertion without building one.
- **ANALOGY ONLY** — the code enforces something that *resembles* the invariant but is not
  the same statement. Do not cite the model as authority for it.
- **NO COUNTERPART** — the code has a concept the model does not, or vice versa.

| # | TLA+ definition | What it says | Status | Python anchor |
|---|---|---|---|---|
| I1 | `I1_Observability` | Every enforcement has an identity-bound observation | PARTIAL | `mediator.py:153` takes the observation after authentication and before dispatch; `observation.py:143` `check_invariants` reports it. PARTIAL because a decision reached *before* an identity exists — unavailable mediator, uncanonicalizable request, failed authentication — has no observation and cannot have one. Those are counted and their rules named, never excluded. Opt-in: `Mediator(observations=ObservationLog())`, and a kernel without one reports UNOBSERVABLE, not HOLDS. |
| I2 | `I2_Deniability` | Every executed action was authorized for its resource | **ENFORCED** | `authorization.py:91` `check_capability` — no capability, or capability not matching principal/domain/action/risk ⇒ DENY |
| I3 | `I3_Immutability` | After bootstrap, authority policy never changes | **ENFORCED** | `capability.py:167` `seal()` + `provisioning.py` `ProvisioningToken`; a sealed registry rejects further registration |
| I4 | `I4_TemporalOrdering` | Observation precedes enforcement | PARTIAL | `mediator.py:734` writes the observation's sequence number into the audit entry; `observation.py:143` checks those sequences increase strictly in chain order. PARTIAL, and the narrowing is real: this confirms the two logs are *consistent with* observation preceding enforcement — an interleaving that broke the order would show — but nothing reading two logs after the fact can derive the ordering itself. |
| I5 | `I5_Completeness` | Every execution has a matching observation | MODEL-ONLY | — |
| I6 | `I6_Consistency` | `obsLog` and `enforceLog` are identity-bound | PARTIAL | `observation.py:143` compares `bound_principal` in each audit entry against `principal_id` in the observation it cites; a disagreeing pair is VIOLATED. PARTIAL only because it is opt-in and covers the observed entries — the same boundary as I1. |
| I7 | `I7_ExternalAuthority` | `∀ e ∈ Entity, a ∈ Authority: a ≠ e` — the authority is never the entity it judges | **ANALOGY ONLY** | See the note below. `evidence.py:174` / `evidence.py:229` enforce a *related but different* property. |
| I8 | `I8_SemanticCorrectness` | Intent matches policy | PARTIAL | `grant.py:45` binds `policy_hash` into the grant, so an escalate→decide→reenter cycle cannot complete under a different policy. The model's `SemanticallyCorrect` is broader. |
| I9 | `I9_TrustVerification` | Enforcement is done by a trusted authority | **ENFORCED** | `authentication.py:179` `authenticate` — HMAC over the canonical request; `authentication.py:200` constant-time compare |
| I10 | `I10_EnfBeforeExec` | Execution requires a prior `ALLOWED` enforcement record | **ENFORCED** | Mediator returns a `ReservedGrant`; `grant.py:137` `consume_if_valid` is the only way to redeem it, atomically and once |

### Why I7 is not evidence of anything

`I7_ExternalAuthority` states `∀ e ∈ Entity, a ∈ Authority: a ≠ e`. In
`formal/GovernanceMCV6.cfg`, `Authority` and `Entity` are **CONSTANTS** bound to the disjoint
sets `{auth1}` and `{ent1}`. Nothing in the specification moves an element between them.

The invariant is therefore **true by construction in every reachable state**. TLC checked a
tautology. The run demonstrates nothing about external authority, and no Python code can
"implement" it, because there is nothing there to implement.

The producer-separation checks in `evidence.py:174` and `evidence.py:229` are a real, running
property — the principal who produced an evidence record may neither verify nor authorize it.
That is a per-record runtime check on principals. I7 is a static disjointness assumption over
two constant sets. They rhyme; they are not the same statement, and citing I7 as formal backing
for the evidence checks would be exactly the error this document exists to correct.

The producer-separation property stands on its own merit: it is enforced, it is tested, and it
was mutation-tested on 2026-09-09. It needs no invariant number.

### Code concepts with no model counterpart

| Code concept | Where | Note |
|---|---|---|
| `Verdict.ESCALATE` | `domain.py:79` | The model's `enforceLog` decision is `ALLOWED` / not-allowed. A third "blocked pending owner decision" verdict does not exist in the model. |
| `OWNER_MANDATORY_ACTIONS` (COMMIT) | `domain.py:15`, `authorization.py:158` | Owner-only commit gate. Not modelled. **This is a single point of enforcement** — removing the check in `authorization.py:158` yields ALLOW, with no second barrier. Mutation-tested 2026-09-09. |
| Provenance-bounded authority | `principal_context.py`, `authorization.py` | The effective risk ceiling is `min(capability.risk_ceiling, mandate ceiling)`, read from a bound `PrincipalContext`. The model has no notion of *how* a call arose — `Authority` and `Entity` are constants — so there is no invariant to cite. Enforced only when the Mediator is constructed with `require_principal_context=True`; **off by default**, see [ROADMAP.md](ROADMAP.md) R1. Mutation-tested 2026-09-10 (`scripts/mutate_r1.py`): two of its three checks have **no second barrier**. |
| Append-only HMAC audit chain | `audit.py:139`, `audit.py:223` | The model has logs as sequences but does not model tamper-evidence. |
| Externally anchored audit chain | `audit.py:237` (`verify_prefix`), `audit.py:361` (`_verify_links`) | A self-certifying log cannot prove its own length; the anchor is external, which the model has no counterpart for. `verify_chain` asks "is this exactly the log I anchored?", `verify_prefix` the weaker "does it extend the log I anchored?" — both go through the single link loop in `_verify_links`. Anchored startup (`AuditLog(..., anchor=...)`) is **opt-in**, see [ROADMAP.md](ROADMAP.md) R2. Mutation-tested 2026-09-10 (`scripts/mutate_r2.py`): two of its three checks have **no second barrier**. |
| Evidence three-state machine | `evidence.py` `CANDIDATE → VERIFIED → AUTHORIZED` | The role separation (R-IV verifies, R-DEC authorizes) is finer-grained than the model's single `Authority`. |

---

## What would close the gap

Two of the three logs now exist. `observation.py` is the `obsLog`, the audit chain is the
`enforceLog`, and `check_invariants` asserts I1, I4 and I6 over the pair at runtime — which
is why those three rows moved from MODEL-ONLY to PARTIAL on 2026-09-11. Each moved to
PARTIAL and not to ENFORCED, deliberately: the check is opt-in, it cannot cover decisions
made before an identity exists, and I4 confirms consistency with an ordering rather than
deriving it. Claiming ENFORCED for any of them would put this document back in the
business this document exists to correct.

**`execLog` is still missing, and I5 is still MODEL-ONLY.** Execution in this kernel is the
redemption of a `ReservedGrant` (`grant.py:137`), and nothing records that redemption in a
log the invariant could be checked against. Until it does, "every execution has a matching
observation" remains a statement about the model only.

Until that is done, this table is the honest ceiling of the claim:

> The governance model has been exhaustively model-checked at bounded size. The
> implementation enforces the properties in the ENFORCED rows. It has not been proven
> to refine the model.
