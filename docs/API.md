# AxiomGate Kernel — public API

Every signature in this document is checked against the running package.
`scripts/check_api_doc.py` resolves each call quoted here — table rows, the shorthand
method rows that begin with a dot, and the signatures in code blocks — and compares its parameter
names, in order, against `inspect.signature`. A call it cannot resolve is a failure,
not a silent pass. Of the 62 calls quoted in this file it checks 59; the other three
are `min` and `frozenset`, which claim nothing about this package. Regenerate the
reference dump with `python scripts/dump_api.py`; `scripts/verify_claims.sh` runs the
comparison and fails on any drift.

That check exists because this document was wrong twice, and the second time is the
reason it is worded this narrowly. On 2026-09-10 a reviewer ran `dump_api.py` against
the document and found three drifted rows: `sign_request` named its parameter `body`
where the code says `request`, `make_capability` was missing three keyword-only
arguments (`transferable`, `delegation_depth`, `revoked_at`) and did not say that all
of them are keyword-only, and `Authenticator` was missing the `nonces` argument
entirely — an undocumented replay defence. The check written to close that gap only
matched rows beginning with a letter, so the shorthand row for
`CapabilityRegistry.revoke` was never compared — and it too had drifted: the row named
the first parameter `id` where the code says `capability_id`, and a third argument,
`when`, was undocumented. The first check reported "0 drifted" while the
document lied. A partial check that reads as a total one is worse than no check: it
carries a promise it does not keep.

Everything in this document is importable from the top-level package:

```python
from axiomgate_kernel import Mediator, Verdict, make_capability, sign_request
```

---

## The one call that matters

```python
decision = mediator.evaluate(signed_request)   # -> Decision
```

`Decision.verdict` is one of exactly three values. There is no fourth, and no
exception path that returns a permission:

| Verdict | Meaning | What the caller must do |
|---|---|---|
| `PERMIT` | Authorized. `decision.grant` carries the reserved grant. | May proceed. |
| `DENY` | Refused. `decision.reason` says why. | Must not proceed. |
| `ESCALATE` | Blocked pending an owner decision. `decision.escalation_id` identifies it. | Must not proceed; may re-enter after `decide_escalation`. |

Anything that goes wrong inside the kernel — an unavailable mediator, a bad
signature, evidence self-verification — resolves to `DENY`, never to a
permission. That is the fail-closed property.

This holds for failures in the **injected dependencies** too. `Authenticator`,
`CapabilityRegistry`, `AuditLog` and `ProvenanceChecker` are supplied by the
integrator, so the kernel cannot assume they behave: an audit backend that raises
`OSError`, or an authenticator that returns something which is not a `Principal`,
still produces a verdict. Even the construction of the audit record is inside the
net — if the decision cannot be described, it is denied.

---

## `Mediator`

The enforcement boundary. Construct once, at startup.

```python
Mediator(authenticator: Authenticator,
         registry: CapabilityRegistry,
         audit: AuditLog,
         provenance: ProvenanceChecker,
         policy: PolicySnapshot | None = None,
         *, available: bool = True,
         policy_token: ProvisioningToken | None = None,
         require_principal_context: bool = False,
         observations: ObservationLog | None = None,
         executions: ExecutionLog | None = None)
```

| Method | Returns | Purpose |
|---|---|---|
| `evaluate(request)` | `Decision` | Authorize an action request. The main entry point. |
| `reenter(request)` | `Decision` | Re-present a request after the owner has decided an escalation. Redeems the reserved grant. |
| `decide_escalation(request)` | `Decision` | Owner records ALLOW/DENY on an open escalation. |
| `create_evidence(request)` | `Decision` | Produce evidence in state `CANDIDATE`. |
| `verify_evidence(request)` | `Decision` | R-IV verifies. **The producer cannot.** |
| `authorize_evidence(request)` | `Decision` | Owner with R-DEC authorizes. **The producer cannot.** |
| `update_policy(request)` | `Decision` | Replace the policy snapshot, if the policy is not sealed. |
| `evidence_state(evidence_id)` | `EvidenceState` | Current state of one evidence record. |
| `evidence_events()` | `list[EvidenceEvent]` | Append-only evidence history. |
| `get_escalation(escalation_id)` | `EscalationRecord` | Look up an escalation. |
| `set_policy(policy, token)` | `None` | Bootstrap-time policy install. Requires the provisioning token. |
| `seal_policy(token)` | `None` | After this, the policy is immutable. |
| `set_available(available: bool)` | `None` | Kill switch. `False` ⇒ every request resolves to `DENY`. |

`require_principal_context=True` makes every verdict read the bound
`PrincipalContext`: the effective risk ceiling becomes
`min(capability.risk_ceiling, mandate ceiling)`, and a missing, unparseable,
expired or out-of-scope mandate is a `DENY`. It defaults to `False` because an
integrator that binds no context would otherwise be denied everything.

`MediatorClient(mediator=None)` wraps the same seven request methods and takes
plain `dict` requests. A client constructed with `None` denies everything —
this is the deliberate behaviour when the kernel is unreachable.

---

## Identity and capability

| Call | Purpose |
|---|---|
| `generate_key() -> bytes` | New HMAC key. |
| `PrincipalKeyStore(bootstrap=None)` | Roster of principal → key. |
| `.register(principal_id, key, token)` | Add a principal. Requires the provisioning token. |
| `.seal(token)` | Close the roster permanently. |
| `Authenticator(keys: PrincipalKeyStore, nonces: NonceTracker | None = None)` | Verifies request signatures. Pass a `NonceTracker` to reject replays; without one, a captured signed request stays valid until its timestamp ages out. |
| `sign_request(request: dict, key: bytes) -> dict` | Sign a request body. |
| `make_capability(*, capability_id, principal_id, role, domains, action_types, risk_ceiling, issued_by, issued_at, expires_at, transferable=False, delegation_depth=1, revoked_at=None)` | Build a frozen `Capability`. Every argument is keyword-only. |
| `CapabilityRegistry(bootstrap=None)` | Holds capabilities. |
| `.register(capability, token)` / `.revoke(capability_id, token, when=None)` / `.seal(token)` | Lifecycle; all token-gated. |
| `.active_for(principal_id, now=None)` | Non-expired, non-revoked capabilities. |

**Sealing is the immutability mechanism.** A sealed store rejects every further
write, and the `ProvisioningToken` that sealed it is single-use. Once the system
is bootstrapped, the roster and the capability set cannot be changed by anything
running inside it.

---

## `AuditLog`

```python
AuditLog(path: str, mac_key: bytes, writer=None,
         anchor: tuple[str | None, int] | None = None)
```

| Method | Returns | Purpose |
|---|---|---|
| `append(record: dict)` | `str` (entry hash) | Append one entry, chained to the previous. |
| `append_approval_event(...)` | `str` | Append a structured owner-approval event. |
| `entries()` | `list[dict]` | Read the log back. |
| `head()` | `(last_hash: str \| None, count: int)` | The anchor for this log. Store it outside the log. |
| `verify_chain(expected_head=None, expected_count=None)` | `(ok: bool, msg: str, last_valid_hash: str \| None)` | Detect any edit, insertion or deletion — and, given an anchor, a truncated tail. |
| `verify_integrity(expected_head=None, expected_count=None)` | `(ok, msg, last_valid_hash, count)` | As above, plus the entry count. |
| `verify_prefix(anchor_head, anchor_count)` | `(ok, msg, last_valid_hash, count)` | Does this log *begin* with the chain I anchored, and continue correctly from it? |

The third return value is the hash of the **last entry that verified**, not the hash of
the entry that failed — the position of the failure is in the message (`mismatch at 2`).
On an empty log it is `None`.

Each entry's position is part of the hashed body, so entries cannot be renumbered.
**Called with no anchor, these methods cannot detect truncation** — a chain cut short
is still internally consistent. Pass an `expected_head` / `expected_count` obtained
earlier from `head()` and held where the writer cannot reach it.

`verify_chain` and `verify_prefix` ask different questions and neither replaces the
other. `verify_chain` is exact — "is this the log I anchored?" — so a log that has been
appended to since fails it, correctly (`log longer than anchor`). `verify_prefix` is the
question you usually want for a live log: it verifies every link, then compares the hash
at the anchored position against the anchored head. It still catches a removal
(`log truncated: N entries, anchor expected at least M`) and the case a count alone
would accept — a competing chain of the same length, internally valid, written with the
same key (`prefix mismatch: ... the log was replaced, not appended to`). It requires
**both** halves of the anchor and refuses a half-anchor rather than reporting on the
half it can check. Entries appended after the anchor remain unanchored either way.

`anchor=(head, count)` runs `verify_prefix` as part of construction and raises
`AuditError` rather than open a log that fails it. The check runs *after* the replay of
an existing file, never before: a partial last line from a process that died mid-append
is dropped as a recovery, but if that line was inside the anchored prefix the anchor
check then fails — which is the finding, not the recovery. Passing no `anchor` keeps the
old behavior exactly, including opening a truncated file without complaint; see
[ROADMAP.md](ROADMAP.md) R2 for why that is the default.

A log written before positions were introduced fails with `legacy chain format`, which
is deliberately distinct from `seq mismatch`: it is a format change, not tampering. It
cannot be migrated in place — renumbering the entries would change the hashes that are
the evidence — so archive the file and start a new chain.

Entries pass through `axiomgate_kernel.redaction.redact_dict` before they are hashed and
written. Two rules apply: fourteen credential **formats** (`sk-AAAA…`), and
sensitive field **names** (`password`, `db_secret`, `authToken`, …), where the
value is masked whatever its type. A secret under an innocuous key in an
unknown shape still passes — see the README for the exact boundary.

---

## `EvidenceJournal`

Three states, and the transitions are one-way: `CANDIDATE → VERIFIED → AUTHORIZED`.

| Method | Who may call it |
|---|---|
| `create_candidate(evidence_id, producer_id, content)` | Anyone. |
| `verify(evidence_id, principal, role, result)` | Role `R_IV`, and **not** the producer. |
| `authorize(evidence_id, principal, role, result)` | Owner with role `R_DEC`, and **not** the producer. |
| `bind_digest(evidence_id, digest, actor)` | Binds a content digest to the record. |
| `events()` | Append-only history. No retraction exists. |

Violations raise `EvidenceError`, which the Mediator maps to `DENY`.

---

## `ReservedGrantStore`

The escalate → decide → re-enter cycle. `consume_if_valid` is the mechanism
with no off-the-shelf equivalent: it redeems a grant **atomically and once**,
and only if the **eleven** bound fields still match.

```python
consume_if_valid(escalation_id, *, principal_id, agent_id, request_id,
                 action, domain, risk_level, payload_hash, capability_id,
                 capability_scope_hash, policy_hash, provenance_identity)
```

Any drift in any of the eleven — a changed payload, a rotated capability, a new
policy — invalidates the grant. Three exceptions are deliberate: if the escalation
was itself caused by a policy or provenance mismatch, that dimension is not
re-compared (it is the thing the owner just ruled on), and neither are
`capability_id` and `capability_scope_hash`, because such a ruling routinely
reissues the capability. Eight bindings remain, and `Mediator.reenter` re-runs the
capability check against the live registry regardless. A grant cannot be replayed.

`ReasonClass` records *why* the escalation happened — five classes:
`owner_mandatory_action`, `owner_mandatory_risk`, `policy`, `provenance`, `other`.

## The strict path

Two protections are off unless an integrator turns them on: the provenance ceiling
(`Mediator(..., require_principal_context=True)`, R1) and truncation detection
(`AuditLog(..., anchor=...)`, R2). They live on different objects and are passed at
different call sites, so a deployment that wired one and believed it had both was
told nothing. These three names are the second, narrower door — they change no
default, and a caller who never imports them gets exactly the kernel they had.

```python
strict_audit_log(path, mac_key, anchor, *, writer=None)
```

`anchor` is positional and has no default: that is the whole mechanism. Pass a prior
`head()` tuple kept **outside** the log file, or the sentinel `NEW_LOG` when no chain
exists yet. `NEW_LOG` is a claim, not a way to skip the anchor — it is refused with
`StrictnessError` if a chain is already on disk. One case it cannot catch is a file
truncated to *zero bytes*, which is indistinguishable from a crashed first run; the
external anchor is what catches that, and does.

```python
strict_mediator(*, authenticator, registry, audit, provenance, policy=None,
                available=True, policy_token=None, require_principal_context=True)
```

Builds a Mediator with both protections on, or refuses to build one. It rejects an
audit log that was not opened strictly, and rejects `require_principal_context=False`
rather than ignoring it — a caller who wants the unbounded kernel wants `Mediator`,
where the call site says so.

```python
strictness_report(mediator)
```

Asks a live kernel which protections it has: `strict`, `provenance_ceiling`,
`audit_anchored`, and `gaps`. `gaps` names each missing protection and the flag that
turns it on, because a bare `False` tells an operator nothing about what to wire.
Reads state, never changes it; safe to call at startup and print.

**The boundary, stated rather than hidden.** All of this is self-reporting.
`AuditLog.anchored` is an ordinary writable attribute, and both functions read it
instead of establishing how the object was built. Set it by hand and the report comes
back clean. What this closes is that an *honest* integrator could not tell which
kernel they were running; code that lies to its own audit trail can call `Mediator`
directly and skip the module entirely.

---

## `ObservationLog`

The record of what was actually looked at. `INSPECT` verdicts are what make I1, I4 and
I6 checkable at runtime rather than model-only: without a log of observations, "a
decision followed an inspection" is a claim about intent.

| Call | Meaning |
|---|---|
| `.record(principal_id, request_id, payload_hash)` | Appends one observation. Returns the `ObservationRecord`. |
| `.for_request(request_id)` | The **latest** observation for that request, or `None`. |
| `.entries()` | A copy of the log, in order. |

A `request_id` of `None` is a missing value, not a key: such observations are stored
but are not retrievable by request. Two observations sharing a `request_id` are both
kept, and `for_request` reports the later one.

```python
check_invariants(observations, audit_entries)
```

Returns a dict keyed `I1`, `I4`, `I6` — one verdict per invariant, each with a
`status` and a `detail` — plus a top-level `holds` that is true only when all three
are `HOLDS`. `status` is one of `HOLDS`, `PARTIAL`, `VIOLATED`, `UNOBSERVABLE`: four,
not two, because a check that cannot say *I do not know* eventually says *yes* when it
means it.

The fourth is the one that matters. With no observation log, or with an audit chain
that recorded no enforcement, every invariant is `UNOBSERVABLE` — nothing was checked,
and vacuous truth is the failure mode these states exist to prevent. Enforcements with
no observation behind them are `VIOLATED`, never a silent pass. `PARTIAL` is reserved
for the enforcements the model's I1 does not range over — a request denied before an
identity existed has no observation to have: they are counted and their rules named
rather than excluded, because excluding them would raise the verdict by narrowing the
question.

---

## `ExecutionLog`

The record of what was actually run, and of what was taken back.

| Call | Meaning |
|---|---|
| `.record(*, request_id, principal_id, escalation_id)` | Appends one execution. Returns the `ExecutionRecord`. |
| `.mark_rolled_back(seq)` | Marks an entry rolled back. Nothing is ever deleted. |
| `.for_request(request_id)` | The latest execution for that request, or `None`. |
| `.entries()` | A copy of the log, in order. |

Passing a log to `Mediator(..., executions=...)` is what moves I5 from model-only to
partial: the mediator records an execution when a grant is redeemed, and marks it
rolled back when it is unconsumed.

Marking rather than deleting is the entire design reason. `unconsume` exists, so an
execution can be taken back — and a log that forgot the withdrawn entry would report
the same history as one where it never happened.

```python
check_execution_invariant(executions, observations)
```

Every execution that stands must have an observation behind it. One verdict, not three:
a flat dict of `status`, `holds`, `detail`, and the `matched`, `unmatched` and
`rolled_back` entries behind it. The four statuses are the same as above, and so is the
rule about vacuous truth, with one addition learnt from review: a log containing
**nothing but rollbacks** is `PARTIAL`, not `HOLDS`. Zero confirmed executions is
evidence of nothing whether the log is empty or merely busy.

---

---

## Domain values

| Type | Values |
|---|---|
| `Verdict` | `PERMIT`, `DENY`, `ESCALATE` |
| `ActionType` | `INSPECT`, `PROPOSE`, `EXECUTE`, `VERIFY`, `COMMIT` |
| `RiskLevel` | `LOW`, `MEDIUM`, `HIGH` |
| `Role` | `R-ENG`, `R-IV`, `R-DEC` (Python members `R_ENG` etc.) |
| `EvidenceState` | `CANDIDATE`, `VERIFIED`, `AUTHORIZED` |
| `EscalationStatus` | `pending`, `decided`, `resolved` |
| `CapabilityDecision` | `ALLOW`, `DENY`, `OWNER_MANDATORY` |
| `ReasonClass` | `owner_mandatory_action`, `owner_mandatory_risk`, `policy`, `provenance`, `other` |
| `OWNER_MANDATORY_ACTIONS` | `frozenset({"COMMIT"})` — always requires the owner |

---

## What the kernel does not do

- **It does not execute.** `Decision` carries no execution flag and the kernel
  invokes nothing. Acting on a `PERMIT` is the caller's job, and so is the
  discipline of not acting without one.
- **It does not persist by itself.** `axiomgate_kernel.persistence` provides SQLite
  serialization; wiring it up is the integrator's choice.
- **It does not decide policy.** `PolicySnapshot` is data you supply.
- **It does not bound authority by provenance unless asked to.**
  `Mediator(..., require_principal_context=True)` makes every verdict read the bound
  `PrincipalContext` and apply `min(capability.risk_ceiling, mandate ceiling)`; a
  missing context is a `DENY`. The flag defaults to `False`, and with it off no
  verdict consults provenance at all. See [ROADMAP.md](ROADMAP.md) item R1 for the
  terms, and for what a `ContextVar`-carried ceiling cannot defend against.
- **It does not authenticate provenance.** Nothing signs a `PrincipalContext`. The
  ceiling constrains an honest integrator's own call graph; it is not a defence
  against one that misstates how a call arose.
