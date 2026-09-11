# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions below 1.0.0 are beta: the API may change between minor versions, and
each such change is listed here.

## [Unreleased]

### Added
- `.github/workflows/ci.yml` — the suite on Python 3.10–3.13, `verify_claims.sh`,
  a clean-environment install, and a build that runs the suite against the built
  wheel rather than the working tree.
- `.github/workflows/release.yml` — tag-triggered publication to PyPI via Trusted
  Publishing, gated on the suite, the claim verifier, a tag/version match and the
  wheel run. Documented in [RELEASING.md](RELEASING.md).
- `SECURITY.md` — a private channel for reporting a fail-open decision,
  an authentication bypass, capability escalation or audit tampering.
- `.github/dependabot.yml` — weekly updates for the pinned GitHub Actions.
- `axiomgate_kernel/observation.py` — `ObservationLog`, `ObservationRecord`,
  `ObservationError` and `check_invariants`. `docs/TRACEABILITY.md` marked I1, I4
  and I6 `MODEL-ONLY`, which read as three debts and was one: all three relate the
  model's observation log to its enforcement log, and this kernel had only the
  second. The kernel already authenticated before dispatching — but that was a
  property of the source text, provable only by reading it, and nothing in the
  suite would have noticed an edit. `check_invariants` answers in four states
  (`HOLDS`, `PARTIAL`, `VIOLATED`, `UNOBSERVABLE`), because a check that cannot say
  *I don't know* will eventually say *yes* when it means it: no log at all is
  `UNOBSERVABLE`, a log that saw nothing while enforcements were recorded is
  `VIOLATED`, and a dangling `observation_seq` is `VIOLATED` and never `PARTIAL`.
  See [docs/ROADMAP.md](docs/ROADMAP.md) R4.
- `Mediator(observations=…)` — opt-in, like the other two protections. The
  observation is taken at one site: after authentication succeeded, before anything
  is dispatched. A failure to record is swallowed deliberately — evidence about a
  run must not turn a legitimate PERMIT into a DENY — and the enforcement then counts
  as unobserved, dropping I1 to `PARTIAL`.
- `observation_seq` in every audit record, joining an enforcement to the observation
  that preceded it. `None` when there is no observation log and when the request was
  denied before an identity existed. The audit record now has 22 fields, was 21.
- `tests/test_observation.py` (12 tests) and §6c of `scripts/verify_claims.sh`
  (14 checks that run a real `Mediator` against real signed requests).
- A check that the `check_invariants` call shown in README.md is the call the
  function actually accepts. The first draft of that example passed `obs.entries()`
  where the log belongs; README code is code nobody runs.

- `axiomgate_kernel/execution.py` — `ExecutionLog`, `ExecutionRecord`,
  `ExecutionError` and `check_execution_invariant`. I5 — every execution has a
  matching observation — was `MODEL-ONLY` for the same single reason as I1, I4 and
  I6: the invariant relates two logs and the kernel kept one. Execution here is the
  redemption of a `ReservedGrant`, and that redemption wrote nothing. The `consumed`
  flag was not a substitute, and `unconsume` is why: a redemption is rolled back when
  downstream audit logging fails, so a log that only appended would keep reporting an
  execution the kernel deliberately took back. The log marks rather than deletes, and
  the check reads three states — executed, rolled back, never happened. An empty
  execution log is `PARTIAL`, never `HOLDS`, and so is a log of nothing but rollbacks. See [docs/ROADMAP.md](docs/ROADMAP.md) R5.
- `Mediator(executions=…)` and `ReservedGrantStore(executions=…)` — opt-in, passed
  straight through: the store is what redeems a grant. The record is written after
  every binding check has passed, not on entry, because a redemption refused for a
  principal mismatch is not an execution.
- `tests/test_execution.py` (16 tests), the last of which runs the only path that
  reaches an execution — `evaluate` → `decide_escalation` → `reenter` → redemption —
  through a real `Mediator`. The unit tests above it build both logs by hand, which
  proves the check and not the wiring: without the end-to-end test the kernel could
  pass every one of them and never call `ExecutionLog.record`.

- `axiomgate_kernel/strict.py` — `strict_audit_log`, `strict_mediator`,
  `strictness_report` and the `NEW_LOG` sentinel. The two fail-closed protections
  (R1's provenance ceiling, R2's audit anchor) are opt-in on two different objects,
  and nothing reported the combination: a kernel with one of them wired was
  indistinguishable from a kernel with both — same records, same verdicts, same
  green suite. `strict_audit_log` has no default for its anchor argument;
  `strict_mediator` refuses to build on an unanchored log or to have the ceiling
  declined; `strictness_report` asks a live kernel which protections it has and
  names each missing one with the flag that turns it on. See
  [docs/ROADMAP.md](docs/ROADMAP.md) R3.
- `AuditLog.anchored` — whether the log was opened against an anchor. Nothing in
  the kernel could answer that before, so neither the strict constructor nor the
  report could check its own precondition.
- `tests/test_strict.py` (13 tests) and §6b of `scripts/verify_claims.sh`
  (12 checks that run the real constructors, because a strict kernel that can be
  talked into the weak configuration is worth nothing and only a run can tell).
- A check that no internal nickname or company name appears in any tracked file.
  One reached `docs/ROADMAP.md` and was found by eye in review; this repo is
  public, and a check a reviewer performs twice by reading belongs in a script.

### Changed
- Every GitHub Action is pinned to a commit SHA rather than a moving major tag.
- `empty_parameter_set_mark = "fail_at_collect"` in `pyproject.toml`. A
  parametrised test whose parameter set came out empty was skipped by default,
  and a skip reads as green — so `tests/test_no_embedded_identity.py`, pointed at
  a tree without the source directory, examined nothing at all and still passed.
  Anything with nothing left to check now fails at collection instead.
- The suite is 346 tests, up from 299. `README.md`, `docs/TRACEABILITY.md` and the
  line anchors in `scripts/verify_claims.sh` were corrected to match — the claim
  verifier caught all four drifted `audit.py` line numbers and both file counts,
  which is what it is for, and caught seven more after the observation work.
- `docs/TRACEABILITY.md`: I1, I4, I5 and I6 moved from `MODEL-ONLY` to `PARTIAL`, each
  with the file and line that carries it. Not `ENFORCED` — the observation log is
  opt-in, lives in memory without a MAC chain, and records on a best-effort basis.
  Claiming `ENFORCED` would put the document back in the practice it exists to correct.

### Limits, stated rather than defended
- `strictness_report` is **self-reporting, not verification**. `AuditLog.anchored`
  is an ordinary writable attribute, so a caller who sets it by hand — or passes
  any object carrying it — gets a clean report. What R3 closes is that an *honest*
  integrator could not tell which kernel they were running. Code lying to its own
  audit trail is not addressable in-process; it can call `Mediator` directly.
- The observation log proves **ordering within one process**, not integrity across a
  restart. Unlike `AuditLog` it has no MAC chain and is never written to disk.
- **I5 stays `MODEL-ONLY`.** It relates enforcement to execution, execution here is
  grant redemption at `grant.py:137`, and that is unlogged. Same single reason
  I1/I4/I6 had: the kernel does the right thing and cannot show it.
- A log truncated to **zero bytes** is indistinguishable from a first run, so the
  `NEW_LOG` path accepts it. Deliberate: a created-but-unwritten file is what a
  crashed first run leaves behind. Detecting a total wipe needs the external
  anchor — a reopen passing `head()` catches it. Both limits are characterisation
  tests, so a change that claims to close either has to delete an assertion.

### Unchanged, deliberately
- **No default moved.** A deployment that does not import `strict` gets exactly the
  kernel it got before. Whether fail-closed should become the default at 1.0 is a
  product decision and is recorded as open in [docs/ROADMAP.md](docs/ROADMAP.md) R3.

## [0.9.0] — 2026-09-10 (not tagged)

The kernel became its own repository, extracted from the scanner it grew up
inside, and was pushed public on 2026-09-10.

It has never been tagged or released. `git tag -l` is empty, there are no
releases, and nothing has been published to PyPI — `version = "0.9.0"` in
`pyproject.toml` is the only place this number exists. The date above is the
date the code went public, not the date of a release.

### Added
- Four enforced protections: capability attenuation, fail-closed authorization,
  hash-chained audit, and redaction by credential format and by field name.
- `principal_context.py` — authority bounded by how a call arose
  (`direct` / `delegated` / `cron` / `mcp`), with monotonic mandate propagation
  to subagents. Enforced behind `Mediator(..., require_principal_context=True)`.
- External anchoring for the audit chain, checked when `anchor=` is passed to
  `AuditLog`. See [docs/ANCHORING.md](docs/ANCHORING.md).
- `formal/` — the TLA+ specification, its model configuration and the TLC run log.
- `docs/TRACEABILITY.md` — TLA+ ↔ Python per invariant, with each correspondence
  marked ENFORCED / PARTIAL / MODEL-ONLY / ANALOGY ONLY rather than implied.
- `scripts/verify_claims.sh` — 130 mechanical checks binding every documented
  number to a run.

### Notes
- Licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE):
  source-available, not open source.
