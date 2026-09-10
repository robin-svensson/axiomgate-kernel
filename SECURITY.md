# Security policy

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on
[this repository](https://github.com/robin-svensson/axiomgate-kernel/security/advisories/new).
That keeps the report private until there's a fix.

Please don't open a public issue for a vulnerability.

You'll get a first reply within 72 hours. This is maintained by one person, so
a fix may take longer than that, but you won't be left wondering whether the
report was seen.

`robinsvensson493@gmail.com` is the address for licensing and contractual
matters. Use the private advisory for security, not that address — an advisory
carries the report, the fix and the disclosure in one place.

## What counts as a vulnerability here

This package decides whether an agent may act, and writes the record of what
was decided. Both halves are in scope.

- **A decision that fails open.** The kernel is fail-closed by construction:
  anything unproven is a denial. Any input, ordering or error path that turns
  an absent, malformed or unverifiable authorization into a permit is the most
  serious thing you can report.
- **Authentication bypass.** Forging or replaying a request past the HMAC over
  the canonical request in `authentication.py`, or any way to make two
  different requests canonicalize to the same bytes.
- **Capability escalation.** Obtaining authority beyond what a grant carries —
  crossing a principal, domain, action or risk boundary in `authorization.py`
  or `capability.py`, registering against a sealed registry, or redeeming a
  `ReservedGrant` more than once through `grant.consume_if_valid`.
- **Audit records that can be altered, dropped or reordered** after the fact,
  or a decision that executes without leaving one.
- **Secrets surviving redaction.** A credential that reaches an audit entry in
  the clear, by format or by field name, past `redaction.py`.
- **Producer-verified evidence.** Any path where the party that produced a
  piece of evidence can also mark it verified.

## What doesn't

- **An invariant marked MODEL-ONLY or ANALOGY ONLY in `docs/TRACEABILITY.md`
  not holding at runtime.** Those are stated there precisely because the code
  does not enforce them. That document is the boundary of what the formal model
  is evidence for; it is not a list of promises. A place where the *code*
  contradicts what that table says about it is a real report.
- The TLA+ specification in `formal/` proving something narrower than you
  expected. Bring it as an issue — that's a modelling discussion, in the open.
- A missing feature, or hardening the roadmap already names.
- Anything requiring an attacker who already runs code as the process holding
  the keys.

## Scope

This policy covers `axiomgate-kernel` only. Version 0.9.0 is the supported
version; there is no earlier release to patch.
