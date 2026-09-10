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

### Changed
- Every GitHub Action is pinned to a commit SHA rather than a moving major tag.
- `empty_parameter_set_mark = "fail_at_collect"` in `pyproject.toml`. A
  parametrised test whose parameter set came out empty was skipped by default,
  and a skip reads as green — so `tests/test_no_embedded_identity.py`, pointed at
  a tree without the source directory, examined nothing at all and still passed.
  Anything with nothing left to check now fails at collection instead.

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
