# Working in this repository

A governance kernel: it decides whether an agent's action is allowed, and leaves
a record that can be checked afterwards. Every number this repo states about
itself is mechanically verified, and that is the habit to work inside.

## Before you change anything

```bash
pip install -e ".[dev]"
bash scripts/verify_claims.sh    # expect the summary line to end: 0 FAIL
python3 -m pytest -q             # expect: no failures
```

Read the counts off the run, not off this file. The totals move with every
change, and a number written here would be one more claim nobody verifies —
which is the exact failure this repository exists to talk about.

If either is red before your change, stop and say so. Do not fix it as a side
quest — a red baseline means the thing you are about to measure is unmeasurable.

Run both again when you are done. `verify_claims.sh` is the source of truth for
every claim in `README.md` and `docs/TRACEABILITY.md`; it is what catches a
documented line number that drifted, a test count that no longer holds, a
version range stated in prose that the workflows do not run.

## How code is written here

- **The test is written first and must fail.** A test that passes on the
  unfixed code proves nothing about the fix.
- **The test's docstring carries the bug, not the function.** Describe what was
  wrong and why it mattered, so the next reader learns the failure, not the API.
- **Comments explain why.** What the code does is visible; why it was allowed to
  be this way is not.
- **One source of truth per calculation.** A second way to compute the same
  value is a second place to be wrong — this repo has been bitten by exactly
  that, twice, both times in a check rather than in the kernel.
- **A missing value is not zero.** Write `None`.
- **Run the whole suite, never part of it.**

## Claims, numbers and documentation

Any number this repo asserts about itself belongs in `scripts/verify_claims.sh`
with a known command and a known expected value — never in prose alone, and
never decided by a model. If you state a new figure, add the check in the same
change.

`docs/TRACEABILITY.md` grades each invariant `ENFORCED`, `PARTIAL`,
`MODEL-ONLY` or `ANALOGY ONLY`. **Never move a grade upward without a run
behind it.** The document exists to correct the practice of claiming derivation
that was never performed; overstating it there is the one change that damages
this project more than a bug would.

Change something `README.md`, `docs/API.md` or `CHANGELOG.md` asserts, and
change those files in the same commit. The docs are part of the unit of work.

## Review before it is called done

The author does not approve their own change. `scripts/l6-review.sh` runs that
review, and it is the last step, not the first:

```bash
L6_AUTHOR_VENDOR=<who wrote this> bash scripts/l6-review.sh
```

It runs `verify_claims.sh` and the suite first and refuses to wake a model while
either is red — a model should never be paid to find what a script already
found. What it sends is the diff, not the repository, and the brief is *find
faults; if you find none, you have not looked hard enough.*

`L6_AUTHOR_VENDOR` is required, and names the vendor whose model wrote the
change — or `human` if a person did. Git records a human author, not a model, so
nothing else can know this. The script lists the names it accepts when it
rejects one; that list is not repeated here, because a second copy of it is a
second copy to drift.

It is required rather than defaulted because the default that suggests itself —
skip nobody when nothing was said — is the answer that lets a model approve its
own work under a command that looks like a review. Saying `human` takes a
moment; discovering afterwards that the reviewer was the author does not. Reviewers from that vendor are then
skipped: a model family reviewing its own output carries the same blind spots
that produced the change. If it cannot name a reviewer's vendor, it skips that
reviewer too — not knowing whether a review is independent is not the same as
knowing it is.

Exit codes are the contract:

| | |
|---|---|
| `0` | reviewed, nothing found |
| `1` | a blocker was found |
| `4` | findings, none blocking |
| `2` | a gate was red; no reviewer ran |
| `3` | no usable review: none ran, or the answer could not be read |
| `5` | a reviewer answered in prose and nothing parsed it — a human reads it |

`2` and `5` are deliberately different. A red gate is fixed by fixing the code;
prose is fixed by someone reading it. Only `0` means reviewed and clean, and
`3` never does — not reviewed is not the same as reviewed and quiet. An empty
diff is `3` for that reason: it is the usual symptom of a wrong base ref, and
reporting it as clean would be the script's own worst failure.

## Honesty about what ran

Report what actually happened, including failures and skipped steps. Never write
that a command was run, a test passed, or a value was observed unless it was.
An unverified claim in a repository about verification is the worst kind of bug
it can have.

## Scope

Source-available under PolyForm Noncommercial 1.0.0. Feature pull requests
cannot be accepted from outside the maintainer — see `CONTRIBUTING.md`. Security
issues go to a private advisory, never a public issue.
