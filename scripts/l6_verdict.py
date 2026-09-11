"""Print an L6 reviewer's answer, and exit non-zero if it found a blocker.

Exit codes: 0 clean, 1 a blocker was found, 4 findings but none blocking,
3 the answer could not be read.

Reads agy's JSON on stdin. The verdict is taken from ``structured_output`` only,
never from ``response``: the same answer comes back in both, but ``response`` is
free text the model formatted, while ``structured_output`` is what the schema
actually validated. Parsing the prose would be a second way to compute the same
thing. ``response`` is printed -- never parsed -- in one place: when
``structured_output`` is missing, so a human can see what the model did say.
"""

import json
import sys

RANK = {"blocker": 0, "major": 1, "minor": 2}


def main() -> int:
    raw = sys.stdin.read()
    try:
        answer = json.loads(raw)
    except json.JSONDecodeError:
        print("The reviewer did not answer in JSON. Raw head:")
        print(raw[:2000])
        return 3

    report = answer.get("structured_output")
    if not isinstance(report, dict):
        print("The reviewer answered, but not in the shape the schema asked for.")
        print((answer.get("response") or "")[:2000])
        return 3

    usage = answer.get("usage") or {}

    # An absent findings list is not an empty one. Treating it as empty would
    # turn a malformed answer into a clean review, which is the single worst
    # thing this file can do.
    findings = report.get("findings")
    if not isinstance(findings, list):
        print("The reviewer's answer has no findings list, so it is not a review.")
        return 3
    findings.sort(key=lambda f: RANK.get(f.get("severity"), 9))

    print()
    print(f"verdict: {report.get('verdict')}  ({len(findings)} findings)")
    # Same rule as the duration below: a count that was not reported is not a
    # count of zero, and it must not print as a number either.
    def _count(key):
        value = usage.get(key)
        return "not reported" if value is None else value

    print(
        "tokens:  in={} out={} total={}".format(
            _count("input_tokens"), _count("output_tokens"), _count("total_tokens")
        )
    )
    # A missing duration is not a duration of zero -- say so rather than
    # printing a number the reviewer never reported.
    seconds = answer.get("duration_seconds")
    print(f"seconds: {round(seconds, 1) if seconds is not None else 'not reported'}")
    print()

    for f in findings:
        # `or`, not a get() default: a present key holding null returns the
        # null, and the concatenation below then fails with a TypeError that
        # Python exits 1 for -- the code this contract reserves for "a blocker
        # was found". A crash that reads as a finding is worse than a crash.
        where = f.get("file") or "?"
        if f.get("line"):
            where += f":{f['line']}"
        print(f"[{str(f.get('severity', '?')).upper()}] {where}")
        print(f"  claim:  {f.get('claim', '?')}")
        print(f"  wrong:  {f.get('why_wrong', '?')}")
        print(f"  verify: {f.get('how_to_verify', '?')}")
        print()

    # The verdict field and the findings list are two ways to say the same
    # thing, so they are two places to be wrong. They are cross-checked rather
    # than one being trusted: an incoherent answer is not a clean one.
    verdict = report.get("verdict")
    # Checked against the allowed set first. The coherence test below compares
    # `verdict == "CLEAN"` to `not findings`, and for any other string -- a
    # missing field, "APPROVED", a typo -- both sides are False, the comparison
    # is satisfied, and an answer nobody validated is read as a valid one. A
    # test that passes hardest on input it does not understand is not a test.
    if verdict not in ("CLEAN", "FINDINGS"):
        print(f"The reviewer's verdict is {verdict!r}, which is not a verdict "
              "this schema allows, so the answer was not validated against it.")
        return 3
    if (verdict == "CLEAN") != (not findings):
        print(
            f"The reviewer answered {verdict!r} alongside {len(findings)} findings. "
            "Those contradict each other, so neither is trusted."
        )
        return 3

    # Three answers, not two. A blocker stops the change. Findings without a
    # blocker are neither a pass nor a stop, and collapsing them into either one
    # decides the caller's policy for them -- silently, which is how a review
    # that found something ends up recorded as a review that found nothing.
    if any(f.get("severity") == "blocker" for f in findings):
        return 1
    return 4 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
