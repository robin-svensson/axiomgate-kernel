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
- The suite is 314 tests, up from 299. `README.md`, `docs/TRACEABILITY.md` and the
  line anchors in `scripts/verify_claims.sh` were corrected to match — the claim
  verifier caught all four drifted `audit.py` line numbers and both file counts,
  which is what it is for.

### Limits, stated rather than defended
- `strictness_report` is **self-reporting, not verification**. `AuditLog.anchored`
  is an ordinary writable attribute, so a caller who sets it by hand — or passes
  any object carrying it — gets a clean report. What R3 closes is that an *honest*
  integrator could not tell which kernel they were running. Code lying to its own
  audit trail is not addressable in-process; it can call `Mediator` directly.
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
