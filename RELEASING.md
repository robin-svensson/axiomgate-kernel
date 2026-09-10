# Releasing

`axiomgate-kernel` publishes to PyPI from `.github/workflows/release.yml`, which
runs only on a tag matching `v*`. Nothing publishes from a branch push, and
nothing publishes at all until the one-time PyPI setup below has been done.

## Decide before you publish, not after

The kernel is licensed **PolyForm Noncommercial 1.0.0**. Putting it on PyPI does
not change that licence, but it does change who can get it: anyone can
`pip install axiomgate-kernel`, and commercial use still requires a separate
licence they have to ask for. That is a distribution decision, not a technical
one, and it cannot be undone — PyPI never releases a version number for reuse,
even after a deletion.

The linter (`axiomgate-lint`, MIT) is the piece meant to be picked up freely.
Publishing the kernel is a separate call.

## Trusted Publishing — no API token

PyPI verifies the workflow's OIDC identity instead of a stored token. There is
no secret in this repository and nothing to rotate.

### One-time setup (manual, PyPI account owner only)

1. Sign in at <https://pypi.org> and go to
   **Your projects → Publishing → Add a new pending publisher**.
   `axiomgate-kernel` is not registered on PyPI, so it has to be added as a
   *pending* publisher; the project is created by the first successful run.
2. Fill in (PyPI's own labels may read slightly differently; these are the
   values, in the order the form asks for them):
   - PyPI Project Name: `axiomgate-kernel`
   - Owner: `robin-svensson`
   - Repository name: `axiomgate-kernel`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. Save. Nothing is published by this step.

The environment name must match `environment: pypi` in the publish job. If they
differ, PyPI rejects the upload with an OIDC error.

### The GitHub side is already configured

The `pypi` environment exists in this repository with two protection rules set
2026-09-11, so the workflow does not publish unattended:

- **Required reviewer: `robin-svensson`.** The `publish` job waits for an
  explicit approval in the Actions tab before it uploads anything. This is the
  last reversible moment — after it, the version number is spent forever.
- **Deployments only from tags matching `v*`.** A branch cannot deploy to this
  environment at all.

Neither rule is set by the workflow file; both live in the repository settings
under Settings → Environments → pypi. If the environment is ever deleted, GitHub
recreates it on the next run **without** these rules, and the release then
publishes with no human gate.

## Releasing a version

1. Bump `version` in `pyproject.toml` and add the CHANGELOG entry.
2. Commit and push to `main`; let CI go green.
3. `git tag v0.9.1 && git push origin v0.9.1`

**The tag must be spelled the way the version is.** The workflow compares the tag,
minus its leading `v`, against the version of the wheel it just built, and Python
normalises versions — `0.3.0rc1`, never `0.3.0-rc1`. So a pre-release is tagged
`v0.3.0rc1`. A hyphen there fails the check rather than publishing the wrong
thing, which is the right outcome, but it fails after the tag is already pushed.

The workflow runs the suite on Python 3.10–3.13, runs `scripts/verify_claims.sh`
so no documented number ships stale, builds, runs `twine check --strict`,
refuses to continue if the tag disagrees with the built version, runs the suite
against the built wheel from a directory where the source tree cannot shadow it,
and only then publishes.
