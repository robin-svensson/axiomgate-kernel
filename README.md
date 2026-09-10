# AxiomGate Kernel

**Your AI agents can act. This decides whether they may.**

AxiomGate Kernel is a deterministic, fail-closed authorization and audit kernel for AI agents.
An agent does not call the tool — it asks the kernel, and the kernel answers `PERMIT`,
`DENY` or `ESCALATE`. Every answer is signed into an append-only, tamper-evident
chain. Nothing that goes wrong inside the kernel can produce a permission — not a
failing audit backend, and not an injected dependency that misbehaves.

```python
decision = mediator.evaluate(signed_request)

if decision.verdict is not Verdict.PERMIT:
    return refuse(decision.reason)     # DENY, or ESCALATE pending the owner
proceed(decision.grant)
```

---

## The four protections

| | What it means | Where |
|---|---|---|
| **Capability control** | An agent can only do what it holds an explicit, unexpired, scoped capability for — principal, domain, action type and risk ceiling all have to match. | `authorization.py` |
| **Audit chain** | Every decision is appended to an HMAC-chained log. The chain does not prevent an edit; it makes an edit impossible to hide. Each entry carries its position inside the hashed body, so a cut-short tail is detectable against an external anchor. Secrets are redacted at the write point, before hashing — by credential *format* and by field *name*. | `audit.py` |
| **Producer separation** | Whoever produces evidence cannot verify it, and cannot be its final authority. Roles are enforced, not advisory. | `evidence.py` |
| **Commit gate** | Actions in `OWNER_MANDATORY_ACTIONS` (today: `COMMIT`) always escalate to the owner, regardless of capability. | `authorization.py`, `domain.py` |

Plus two mechanisms that are not reconstructable from off-the-shelf parts:

- **Atomic grant consumption** — `grant.py:consume_if_valid` redeems an
  escalate→decide→re-enter cycle exactly once, and only if **eleven** bound fields
  still match: principal, agent, request, action, domain, risk, payload hash,
  capability id, capability scope hash, policy hash and provenance identity. When
  the escalation was itself *caused* by a policy or provenance mismatch, **three**
  of the eleven are skipped — that dimension plus the two capability bindings,
  since the owner's ruling routinely comes with a reissued capability — leaving
  **eight**. Re-entry still re-runs the live capability check and requires ALLOW,
  so the exception drops the binding to one specific capability, never the
  requirement to hold a valid one. A grant cannot be replayed and cannot survive an
  unrelated policy change.
- **Three-state evidence machine** — `CANDIDATE → VERIFIED → AUTHORIZED`, one-way,
  with enforced R-IV / R-DEC roles and no retraction path.

**All four protections have been mutation-tested** (2026-09-09): each check was
removed in memory and the scenario re-run. Three of the four have no second
barrier — see [docs/TRACEABILITY.md](docs/TRACEABILITY.md) for exactly which.

Two later mechanisms were mutation-tested on the same terms: the provenance-bounded
risk ceiling (`scripts/mutate_r1.py`) and the externally anchored audit chain
(`scripts/mutate_r2.py`). Both are **opt-in** — `require_principal_context=True` and
`AuditLog(..., anchor=...)` respectively — and two of three checks in each have no
second barrier. What that means, and why the default is the weaker one, is written out
in [docs/ROADMAP.md](docs/ROADMAP.md) R1 and R2.

---

## Quick start

```bash
git clone https://github.com/robin-svensson/axiomgate-kernel.git
cd axiomgate-kernel
pip install -e ".[dev]"
pytest -q                       # 299 tests
python examples/01_permit.py    # a request that is allowed
python examples/02_deny.py      # three that are refused, three different ways
python examples/03_audit_trail.py   # tampering with the log, and being caught
bash scripts/verify_claims.sh   # every number in this README, checked mechanically
```

The distribution is `axiomgate-kernel`; the import is `axiomgate_kernel`:

```python
from axiomgate_kernel import Mediator, AuditLog, Verdict
```

One runtime dependency (`cryptography`) and one for development (`pytest`). The
suite runs in a fresh virtual environment containing nothing else — 299 passed,
with no `PYTHONPATH` and no editable install of anything but this package — so a
green suite here is not an artefact of a pre-populated environment. Reproduce it
with `bash scripts/verify_clean_install.sh`, which builds the empty environment,
installs only this package, and runs the suite with `env -i`. It is kept out of
`verify_claims.sh` because it needs the network; a review pointed out that this
paragraph was the one claim here that asked to be believed.

`verify_claims.sh` is the point. Nothing in this repository asks to be believed.

### How redaction works, and where it stops

`axiomgate_kernel/redaction.py` applies two independent rules at the write point, before the
entry is hashed:

```python
audit.append({"key": "sk-AAAA…"})      # format rule  -> [REDACTED_SECRET:openai-***AA]
audit.append({"password": "hunter2"})  # name rule    -> [REDACTED_SECRET:field-name]
audit.append({"api_key": 1234567890})  # name rule    -> masked even though it is an int
```

- **By format** — fourteen credential shapes (`sk-`, `sk-ant-`, `ghp_`, `github_pat_`,
  `AKIA…`, `AIza…`, `hf_`, Stripe, Slack, private-key headers, and `password = "…"`
  style assignments).
- **By field name** — any key whose normalised name contains `password`, `passwd`,
  `secret`, `token`, `apikey`, `authorization`, `credential`, `privatekey`,
  `passphrase`, `sessionkey` or `accesskey`. Matching ignores case and separators, so
  `db_secret`, `authToken` and `X-Api-Key` are all caught, and the value is masked
  whatever its type.

The name rule is deliberately blunt. In an append-only, HMAC-chained log a leak cannot
be cleaned up afterwards — editing the entry breaks the chain that is the evidence — so
masking a harmless field is the cheaper error. Verified against the kernel's own audit
entries: of the 21 fields written in a real decision flow, none are masked —
counted by `scripts/count_audit_fields.py`, which runs a real `PERMIT` through the
mediator, and checked by `scripts/verify_claims.sh`. It said 17 until 2026-09-10:
the number was true when written and rotted when provenance and mandates added four
fields to the entry. A documented number that nothing re-counts only records when it
was last read.

**Where it still stops:** a secret under an innocuous key, in a shape no pattern knows —
`{"note": "the door code is 4711"}` — is written verbatim. Nothing infers meaning from
free text. Keep credentials out of payloads.

### What the log can and cannot prove about itself

Every entry carries its position (`seq`) inside the hashed body, and `AuditLog.head()`
returns `(last_hash, count)`. Pass those back to `verify_chain(expected_head,
expected_count)` and a truncated tail is caught.

Without that anchor it is not, and cannot be. A chain cut short still verifies as
internally consistent — every entry that remains does link correctly to the one before
it. **A self-certifying log cannot prove its own length.** Store the head somewhere the
writer cannot reach; this is the same reason Certificate Transparency signs tree heads
instead of trusting a log to describe itself. How often to anchor, where to put it, and
what an anchor still cannot prove are in [docs/ANCHORING.md](docs/ANCHORING.md).

### Bounding authority by how a call arose

An agent's name is not its authority. `axiomgate_kernel/principal_context.py` carries the
*mandate* a call is running under — a `direct`, `delegated`, `cron` or `mcp` origin,
mandate scopes, and monotonic propagation to subagents (`child_mandate ⊆
parent_mandate`). Since 2026-09-10 verdicts read it:

```python
mediator = Mediator(..., require_principal_context=True)

with principal_context_scope(ctx):        # ctx.mandate = "propose"
    mediator.evaluate(req)                # MEDIUM risk -> DENY
```

The effective risk ceiling is `min(capability.risk_ceiling, mandate ceiling)`, so a
capability good for MEDIUM does not reach MEDIUM under a mandate that only reaches
LOW. A missing or invalid context is a `DENY`, never a fallback to the most
permissive value, and the audit record says which bound applied — `provenance`,
`mandate_id` and `effective_risk_ceiling`, each `None` when there is nothing to
record. Mutation-tested 2026-09-10 (`scripts/mutate_r1.py`): two of the three checks
have no second barrier.

**The flag is off by default, and with it off there is no provenance ceiling at
all.** Turning it on for an integrator that binds no context would deny everything.
That is a declared gap, held in place by a test, and its exact terms — including
what a `ContextVar` ceiling cannot defend against — are in
[docs/ROADMAP.md](docs/ROADMAP.md) R1.

## Formal verification — and its exact limits

The governance model in `formal/` is written in TLA+ and exhaustively
model-checked with TLC:

```
INVARIANT GovernanceSecurityBoundary == I1 /\ I2 /\ ... /\ I10
373 933 states generated, 345 322 distinct, depth 11
Model checking completed. No error has been found.
```

**What that does not mean.** The run is bounded to one authority, one entity,
two actions and two resources (`formal/GovernanceMCV6.cfg`). The Python kernel
was not generated from the model and has not been proven to refine it.

Until 2026-09-10 the source code cited invariant numbers that did not match what
the model defines. Those citations were removed rather than quietly corrected,
and replaced with a declared correspondence table stating, per invariant,
whether Python enforces it (`ENFORCED`), enforces something weaker (`PARTIAL`),
or cannot express it at all (`MODEL-ONLY`).

Read [docs/TRACEABILITY.md](docs/TRACEABILITY.md) before citing the formal work
anywhere. Authority that is referenced but not derived is worse than no
authority at all — and being able to say precisely where the proof stops is the
part competitors cannot copy.

---

## Why this exists

Regulation now assumes something like this exists. EU AI Act **Art. 12(1)** requires
high-risk systems to "technically allow for the automatic recording of events (logs)
over the lifetime of the system"; **Art. 14(1)** requires that they "can be effectively
overseen by natural persons"; **Art. 19(1)** and **Art. 26(6)** require provider and
deployer to keep those logs "of at least six months". An agent that calls tools with
no enforced permission boundary and no tamper-evident record has no story to tell an
auditor.

Two corrections to what this README used to say, because getting them wrong is the
same error as citing an invariant the model does not define:

- **The penalty tier for a missing audit trail is Art. 99(4) — €15M or 3% of worldwide
  turnover.** The €35M / 7% headline is **Art. 99(3)**, and it applies to Article 5
  prohibited practices, not to logging or oversight failures.
- **The deadline is no longer 2 August 2026.** Regulation (EU) 2026/1744 deferred the
  high-risk obligations to **2 December 2027** (Annex III) and **2 August 2028**
  (Annex I). Prohibited practices, GPAI duties and Art. 50 transparency are unaffected
  and already in force.

The deferral happened partly because the harmonised standards were not ready, and they
still are not: **no AI Act standard has been cited in the Official Journal**, so there
is no presumption of conformity under Art. 40 to rely on — and CEN-CENELEC names
logging as one of the areas still in development. An organisation picking a mechanism
today picks it without that cover, and has to defend it on its merits.

Every article quoted above, the evidence status of the deferral, and what could not be
verified are in [docs/REGULATORY.md](docs/REGULATORY.md). The Official Journal text of
2026/1744 was **not** read directly — EUR-Lex refused automated retrieval — so that
one rests on convergent secondary sources and is labelled as such.

Third-party figures, **retrieved from the publisher and quoted verbatim** on
2026-09-10. Earlier versions of this table paraphrased them; two of the five were
wrong, and both corrections are noted below.

| Figure, as the source states it | Source |
|---|---|
| "92% are concerned about the use of AI agents across the workforce and their impact on security" | *State of AI Cybersecurity Report 2026*, survey by Darktrace, published by the Cloud Security Alliance, 27 May 2026 |
| "92% of organizations lack full visibility into AI identities, and 95% doubt they could detect misuse if it happened" | *2026 CISO AI Risk Report*, Saviynt with Cybersecurity Insiders, 21 April 2026 (n > 200 CISOs and security leaders) |
| "86% don’t enforce access policies for AI identities. Only 17% govern even half of their AI identities like human users, and just 5% feel confident they could contain a compromised agent" | *ibid.* |
| "71% of CISOs say AI has access to core business systems, but only 16% govern that access effectively" | *ibid.* |
| AI-native applications are the fastest-growing spend category, "up 393% year over year in organizations with more than 10,000 employees and up 108% overall" | Zylo, *2026 SaaS Management Index*, 29 January 2026 |

Two corrections, on the same terms as the legal ones above:

- The table used to read **"16% have effective access control."** The source says 16%
  govern *access to core business systems* effectively — a narrower claim about a
  specific population, not a statement about access control in general.
- The table used to attribute **"Governance platforms: $4K–$15K/month" to Zylo Research
  2026.** That figure does not appear in Zylo's 2026 index or its related material;
  the attribution could not be substantiated and the row is removed rather than
  re-sourced. AxiomGate Kernel's own pricing is not set here, and no competitor price is quoted
  in this repository.

Adjacent work: KLA (runtime control plane), Odock (EU gateway, MCP tool
permissions), ServiceNow AI Control Tower, Microsoft Agent Governance Toolkit.
None of them ships a model-checked governance specification.

---

## Documentation

| | |
|---|---|
| [docs/API.md](docs/API.md) | Public API, extracted from the running package |
| [docs/TRACEABILITY.md](docs/TRACEABILITY.md) | TLA+ ↔ Python, per invariant, with honest status |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Declared debt: both items closed 2026-09-10, each with the deviation that keeps its protection opt-in written out |
| [docs/REGULATORY.md](docs/REGULATORY.md) | The AI Act articles quoted verbatim, with dates, sources, and what could not be verified |
| [docs/ANCHORING.md](docs/ANCHORING.md) | Integration note: how to anchor the audit chain, at what cadence, and what an anchor still cannot prove |
| `examples/` | Three runnable examples: permit, refuse, trace |
| `formal/` | TLA+ specification, model config and the TLC run log |
| `scripts/verify_claims.sh` | Mechanical check of every claim above |

## Status and licence

Version 0.9.0. The code is mature — 299 tests, mutation-tested protections — but
has never run outside a development environment. Treat it as beta.

**Two protections are off until you turn them on.** The provenance ceiling requires
`Mediator(..., require_principal_context=True)`, and the audit chain is only checked
against an external anchor if you pass `anchor=` to `AuditLog` and hold that anchor
somewhere the writing process cannot reach. Neither default is fail-closed, and the
reason each was chosen is in [docs/ROADMAP.md](docs/ROADMAP.md). A deployment that
wires neither gets the kernel as it was before those items were closed — which is
still the four protections above, but not the two the roadmap describes.

## The linter, for what happens before runtime

The kernel enforces attenuation at the moment a call is made. It cannot tell you
that your codebase is full of delegation that will hit it. That is a static
question, and it has its own tool:
[**axiomgate-lint**](https://github.com/robin-svensson/axiomgate-lint) — a
dependency-free AST linter that finds unattenuated agent delegation in source,
with a GitHub Action. It is MIT, it is genuinely separate, and it is useful
without this kernel.

## Licence and contact

**Source-available, not open source.** AxiomGate Kernel is licensed under the
[PolyForm Noncommercial License 1.0.0](LICENSE). Any noncommercial purpose is
permitted — read it, run it, test it against your own agents, study how the
authorization and audit paths are built. Commercial use of any kind requires a
separate written agreement with the copyright holder.

That split is deliberate. A kernel that decides what an agent may do is worth
nothing to you if you cannot read it, so it is here to be read and tested. What
it is not is free to build a product on.

- **Technical questions, bugs, findings** — open an issue. Preferably with the
  command you ran and what came back; the repo's own claims are checked that way
  too (`scripts/verify_claims.sh`).
- **Commercial use, integration, or a licence** — write to the address below.
  GitHub has no private messaging, and a commercial enquiry does not belong in a
  public issue thread.

Robin Svensson · robinsvensson493@gmail.com
