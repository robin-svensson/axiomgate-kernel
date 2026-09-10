# AxiomGate Governance Formal Model — V6 Evidence Summary

> **Superseded on 2026-09-10 by [`docs/TRACEABILITY.md`](../docs/TRACEABILITY.md).**
> This file is kept as a dated record of what the V6 run actually reported. Two of
> its judgements no longer stand: it lists `I7_ExternalAuthority` as PASS and as
> partial backing for authority separation, but `I7` is a disjointness assumption
> over two constant sets and is true by construction — TLC checked a tautology, and
> it backs no Python code. Where this file and `TRACEABILITY.md` disagree,
> `TRACEABILITY.md` is the current statement. Cite that document, not this one.

**Date:** 2026-08-22
**Model Version:** V6
**Classification:** ACCEPT WITH BOUNDED CLAIMS
**TLC Version:** 2026.08.21
**Java Version:** OpenJDK 21.0.12.1

---

## 1. STATE-SPACE CONFIGURATION

| Parameter | Value |
|-----------|-------|
| Authorities | 1 (auth1) |
| Entities | 1 (ent1) |
| Actions | 2 (act1, act2) |
| Resources | 2 (res1, res2) |
| UID bound | ≤ 2 |
| Log bound | ≤ 3 entries |
| States generated | 373,933 |
| Distinct states | 345,322 |
| Search depth | 11 |
| Runtime | 12s |
| Deadlock | Expected (bounded state artifact) |

**Scope limitation:** TLC verification establishes correctness only for the instantiated bounded state space. It does not constitute a general proof over arbitrary system sizes.

---

## 2. VERIFIED TRACE SEQUENCE

The following trace demonstrates the governance lifecycle:

```
State 0: Init
  authPolicy = {auth1: {}}
  intent = {auth1: {act1: FALSE, act2: FALSE}}
  entityState = {ent1: idle}
  globalSeq = 0
  bootstrapDone = FALSE

State 1: Bootstrap(auth1, {act2}, {act2: TRUE}, {res1}, {auth1: trusted})
  authPolicy = {auth1: {act2}}
  intent = {auth1: {act2: TRUE}}
  resourcePolicy = {auth1: {res1}}
  trustStatus = {auth1: trusted}
  bootstrapDone = TRUE
  globalSeq = 0

State 2: AttemptAction(ent1, act2, res1)
  entityState = {ent1: attempting}
  uidCounter = 1
  globalSeq = 0

State 3: ObserveAction(ent1, act2, 0, res1)
  obsLog = [{entity: ent1, action: act2, uid: 0, resource: res1, seq: 0}]
  globalSeq = 1
  entityState = {ent1: attempting}

State 4: EnforceAction(ent1, act2, 0, res1, auth1)
  enforceLog = [{action: act2, uid: 0, resource: res1, decision: ALLOWED, seq: 2}]
  execLog = [{entity: ent1, action: act2, uid: 0, resource: res1, seq: 3}]
  entityState = {ent1: executed}
  globalSeq = 3

State 5: ReturnToIdle(ent1)
  entityState = {ent1: idle}
```

**Temporal ordering verification:**
- obs.seq = 0
- enf.seq = 2
- exec.seq = 3
- 0 < 2 < 3 ✓

---

## 3. INVARIANT RESULTS

| Invariant | Description | Result | Evidence |
|-----------|-------------|--------|----------|
| I1_Observability | Enforcement has matching observation | PASS | uid/action/resource match |
| I2_Deniability | Executed actions are authorized | PASS | AuthResource check |
| I3_Immutability | authPolicy = initPolicy after bootstrap | PASS | No mutation transition |
| I4_TemporalOrdering | Observation before enforcement | PASS | globalSeq ordering |
| I5_Completeness | Executed actions have observations | PASS | obsLog match |
| I6_Consistency | Enforcement matches observation | PASS | IdentityBound |
| I7_ExternalAuthority | Authority ≠ entity | PASS | Name-based separation |
| I8_SemanticCorrectness | Policy matches intent | PASS | Boolean consistency |
| I9_TrustVerification | Enforcement requires trusted authority | PASS | trustStatus check |
| I10_EnfBeforeExec | Enforcement before execution | PASS | globalSeq ordering |
| NoUnauthorizedExecution | No unauthorized execution | PASS | AuthResource + Trusted |
| ObservationBeforeEnforcement | Same as I4 | PASS | globalSeq ordering |
| ObservationBeforeExecution | Observation before execution | PASS | globalSeq ordering |

---

## 4. MUTATION TESTING

### 4.1 Detectable Mutations (6/6 detected)

| Mutation | Expected | TLC Result | Invariant Violated |
|----------|----------|------------|-------------------|
| Remove auth check | FAIL | FAIL ✓ | I2, NoAuthExec |
| Remove observation requirement | FAIL | FAIL ✓ | I1, I5 |
| Action mismatch (uid match, action differ) | FAIL | FAIL ✓ | I6 |
| UID substitution | FAIL | FAIL ✓ | I1 |
| Entity substitution | FAIL | FAIL ✓ | I5 |
| Resource substitution | FAIL | FAIL ✓ | I2 |

### 4.2 Threats NOT MODELED (6 additional)

| Threat | Reason Not Modeled |
|--------|-------------------|
| Policy mutation after bootstrap | No ModifyPolicy transition exists |
| Intent mutation after bootstrap | No ModifyIntent transition exists |
| Trust mutation after bootstrap | No ModifyTrust transition exists |
| Semantic mismatch (deeper than boolean) | I8 only checks policy/intent consistency |
| Compromised authority | trustStatus is a parameter, not externally verified |
| TCB compromise | Not represented in transition system |

**Important:** NOT MODELED ≠ PASS. These threats remain unaddressed.

---

## 5. CLAIM MATRIX

| Claim | Formalization | Verification Method | Result | Bound/Gap |
|-------|--------------|---------------------|--------|-----------|
| UID/action/resource binding | I1, I6 (IdentityBound) | TLC model checking | PROVEN | Bounded to stated state space |
| Resource authorization/binding | I2 (AuthResource) | TLC model checking | PROVEN | Bounded to stated state space |
| Observation before enforcement | I4 (ObsBeforeEnf) | TLC model checking | PROVEN | Bounded to stated state space |
| Enforcement before execution | I10 (EnfBeforeExec) | TLC model checking | PROVEN | Bounded to stated state space |
| Observation before execution | ObservationBeforeExecution | TLC model checking | PROVEN | Bounded to stated state space |
| Unauthorized execution prevention | I2 + transition guards | TLC model checking | PROVEN | Bounded to stated state space |
| Policy/intent consistency | I8 | TLC model checking | PROVEN | Boolean policy/intent consistency only; not semantic depth |
| Full identity binding (entity) | Transition guard (obsLog.entity) | Transition analysis | PARTIAL | Not an invariant, transition-based |
| Immutability | I3 (authPolicy = initPolicy) | TLC model checking | PARTIAL | Only authPolicy, no mutation transition |
| Trust verification | I9 (Trusted(a)) | TLC model checking | PARTIAL | Parameter-based, not external verification |
| Semantic correctness | I8 | TLC model checking | PARTIAL | Boolean consistency only, not semantic depth |
| External authority separation | I7 (a # e) | TLC model checking | PARTIAL | Name-based, not role-based |
| Policy mutation attack | N/A | N/A | NOT MODELED | No mutation transition exists |
| External trust establishment | N/A | N/A | NOT MODELED | trustStatus is parameter |
| Deeper semantic correctness | N/A | N/A | NOT MODELED | Actions are symbolic, not semantic |
| Any unrepresentable mutation | N/A | N/A | NOT MODELED | Transition system limitation |

---

## 6. EVIDENCE CLASSIFICATION

### PROVEN (safe for the evidence corpus)

- TLC model checking within stated bounds (1 auth, 1 entity, 2 actions, 2 resources)
- UID/action/resource binding verified
- Resource authorization/binding verified
- Observation before enforcement verified
- Enforcement before execution verified
- Observation before execution verified
- Unauthorized execution prevention verified
- Policy/intent consistency verified

### PARTIAL (use with explicit qualification)

- Full identity binding: entity binding is transition-based, not invariant-based
- Immutability: only authPolicy verified, no mutation transition exists
- Trust verification: parameter-based, not external verification
- Semantic correctness: policy/intent consistency only, not semantic depth
- External authority separation: name-based, not role-based

### NOT MODELED (prohibited from current evidence corpus)

- Policy mutation attack (no transition exists)
- External trust establishment/verification
- Deeper semantic correctness beyond boolean
- Any mutation not representable by current transition system

---

## 7. MUTATION TESTING SUMMARY

```
DETECTABLE MUTATIONS: 6/6 DETECTED
  Remove auth check: DETECTED (I2/NoAuthExec)
  Remove observation: DETECTED (I1/I5)
  Action mismatch: DETECTED (I6)
  UID substitution: DETECTED (I1)
  Entity substitution: DETECTED (I5)
  Resource substitution: DETECTED (I2)

NOT MODELED THREATS: 6
  Policy mutation: NOT MODELED (no transition)
  Intent mutation: NOT MODELED (no transition)
  Trust mutation: NOT MODELED (no transition)
  Semantic mismatch: NOT MODELED (boolean only)
  Compromised authority: NOT MODELED (parameter)
  TCB compromise: NOT MODELED (not in model)
```

---

## 8. BOUNDED LIMITATIONS

TLC verification establishes correctness only for:

- 1 authority
- 1 entity
- 2 actions
- 2 resources
- UID ≤ 2
- Log entries ≤ 3
- 373,933 explored states
- 345,322 distinct states
- Depth 11

The model does NOT prove:

- Correctness for larger state spaces
- Correctness for multiple authorities/entities
- Correctness under policy mutation
- Correctness under trust compromise
- Correctness for semantically complex actions

---

## 9. FINAL EVIDENCE VERDICT

**ACCEPT WITH BOUNDED CLAIMS**

The V6 model is TLC-verified within stated bounds for the specified invariants. Claims must be qualified with the explicit bounds and gaps documented above.

---

## 10. CLAIMS SAFE FOR THE EVIDENCE CORPUS

- TLC verified within stated bounds (1 auth, 1 entity, 2 actions, 2 resources)
- Identity binding (uid/action/resource) verified
- Resource binding verified
- Temporal ordering verified
- Policy/intent consistency verified
- Unauthorized execution prevention verified

---

## 11. CLAIMS PROHIBITED FROM CURRENT EVIDENCE CORPUS

- FULL identity binding (entity = transition-based, not invariant)
- Semantic correctness (I8 = policy/intent consistency only)
- Enforcement-based immutability (transition-based, no mutation transition)
- External trust verification (parameter-based, not external)
- Policy mutation protection (NOT MODELED)
- ANY claim of "formally proven" or "generally secure"
