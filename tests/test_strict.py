"""The two fail-closed protections are opt-in separately, and silence is the default.

R1 gives a provenance ceiling only under Mediator(require_principal_context=True).
R2 gives truncation detection only under AuditLog(..., anchor=...). Neither is on
by default, both are set on different objects, and nothing anywhere reports which
of them a given deployment actually has. An integrator who set one and believed
they had both would be told nothing -- by the constructor, by the audit record, or
by any check in the suite.

That is the gap these tests describe: not that the protections are missing, but
that having them is unverifiable from inside the kernel, so "we run AxiomGate"
says nothing about which kernel is running.

Every test here fails against a kernel where strict.py does not exist.
"""

import os
import tempfile

import pytest

from axiomgate_kernel import (
    AuditError,
    AuditLog,
    generate_key,
)
from axiomgate_kernel.strict import (
    NEW_LOG,
    StrictnessError,
    strict_audit_log,
    strict_mediator,
    strictness_report,
)


def _tmp_path(name="audit.log"):
    return os.path.join(tempfile.mkdtemp(prefix="axiomgate-kernel-strict-"), name)


# --- the audit half ---------------------------------------------------------

def test_opening_a_strict_log_without_saying_which_case_it_is_refuses():
    """AuditLog(path, key) opens both a fresh log and a pre-existing one, and
    those are different security situations. Omitting the anchor is how the
    truncation gap gets in, so the strict constructor has no default for it."""
    path = _tmp_path()
    with pytest.raises(TypeError):
        strict_audit_log(path, generate_key())


def test_claiming_a_new_log_when_one_already_exists_is_refused():
    """NEW_LOG means 'there is no earlier chain to anchor against'. If a chain
    is already on disk that claim is false, and accepting it would open exactly
    the unanchored log the strict path exists to prevent."""
    path = _tmp_path()
    log = AuditLog(path, generate_key())
    log.append({"marker": "first"})

    with pytest.raises(StrictnessError) as exc:
        strict_audit_log(path, generate_key(), NEW_LOG)
    assert "already exists" in str(exc.value)


def test_a_new_log_is_accepted_when_the_file_really_is_new():
    """The honest case still has to work, or the strict path is unusable for a
    first run and nobody adopts it."""
    path = _tmp_path()
    log = strict_audit_log(path, generate_key(), NEW_LOG)
    log.append({"marker": "a"})
    head, count = log.head()
    assert count == 1
    assert head is not None


def test_an_anchored_reopen_still_detects_a_cut_tail():
    """The strict wrapper must not weaken what R2 already built. A log cut back
    to its anchor point plus nothing has to be refused on open, not on first
    write, because a deployment that never writes again would never find out."""
    path = _tmp_path()
    key = generate_key()
    log = strict_audit_log(path, key, NEW_LOG)
    for i in range(4):
        log.append({"n": i})
    anchor = log.head()
    for i in range(4, 7):
        log.append({"n": i})

    lines = open(path, encoding="utf-8").read().splitlines(True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(lines[:2]))

    with pytest.raises(AuditError):
        strict_audit_log(path, key, anchor)


def test_a_strictly_opened_log_says_so_and_a_plain_one_does_not():
    """Nothing in the kernel could previously answer 'is this log anchored?'.
    Without that, strict_mediator cannot check its own precondition and the
    report below cannot be written honestly."""
    path = _tmp_path()
    plain = AuditLog(path, generate_key())
    assert plain.anchored is False

    strict_path = _tmp_path()
    strict = strict_audit_log(strict_path, generate_key(), NEW_LOG)
    assert strict.anchored is True


# --- the mediator half ------------------------------------------------------

def test_strict_mediator_refuses_a_log_that_was_not_opened_strictly(
    auth_system, registry_system, fixed_provenance
):
    """Half a fail-closed kernel reads as a whole one. A Mediator with the
    provenance ceiling on, writing to a log that opens truncated files without
    complaint, is precisely the deployment that believes it is protected."""
    from axiomgate_kernel import Authenticator

    plain = AuditLog(_tmp_path(), generate_key())
    with pytest.raises(StrictnessError) as exc:
        strict_mediator(
            authenticator=Authenticator(auth_system),
            registry=registry_system,
            audit=plain,
            provenance=fixed_provenance,
        )
    assert "anchor" in str(exc.value).lower()


def test_strict_mediator_turns_the_provenance_ceiling_on(
    auth_system, registry_system, fixed_provenance
):
    """The whole point of the strict path is that the caller does not have to
    remember the flag. If it were merely passed through, a caller who forgot it
    would get the weak kernel from the strict constructor."""
    from axiomgate_kernel import Authenticator

    audit = strict_audit_log(_tmp_path(), generate_key(), NEW_LOG)
    mediator = strict_mediator(
        authenticator=Authenticator(auth_system),
        registry=registry_system,
        audit=audit,
        provenance=fixed_provenance,
    )
    assert mediator.require_principal_context is True


def test_strict_mediator_refuses_to_be_talked_out_of_the_ceiling(
    auth_system, registry_system, fixed_provenance
):
    """A strict constructor that accepts require_principal_context=False hands
    back a weak kernel under a name that says otherwise. The name is what the
    integrator will quote in their own documentation."""
    from axiomgate_kernel import Authenticator

    audit = strict_audit_log(_tmp_path(), generate_key(), NEW_LOG)
    with pytest.raises(StrictnessError):
        strict_mediator(
            authenticator=Authenticator(auth_system),
            registry=registry_system,
            audit=audit,
            provenance=fixed_provenance,
            require_principal_context=False,
        )


# --- the report -------------------------------------------------------------

def test_the_report_names_the_default_kernel_as_not_strict(
    auth_system, registry_system, fixed_provenance
):
    """A deployment cannot today answer 'which protections are live here?'
    except by reading the source of its own wiring. That answer belongs to the
    kernel, which is the only thing that knows."""
    from axiomgate_kernel import Authenticator, Mediator

    audit = AuditLog(_tmp_path(), generate_key())
    mediator = Mediator(
        authenticator=Authenticator(auth_system),
        registry=registry_system,
        audit=audit,
        provenance=fixed_provenance,
    )
    report = strictness_report(mediator)
    assert report["strict"] is False
    assert report["provenance_ceiling"] is False
    assert report["audit_anchored"] is False
    # The gaps have to be named, not merely counted: a boolean False tells an
    # operator nothing about what to wire.
    assert any("require_principal_context" in gap for gap in report["gaps"])
    assert any("anchor" in gap for gap in report["gaps"])


def test_the_report_is_clean_for_a_strict_kernel(
    auth_system, registry_system, fixed_provenance
):
    """If the report cannot come back empty it is not a check, it is a warning
    banner, and operators learn to ignore it."""
    from axiomgate_kernel import Authenticator

    audit = strict_audit_log(_tmp_path(), generate_key(), NEW_LOG)
    mediator = strict_mediator(
        authenticator=Authenticator(auth_system),
        registry=registry_system,
        audit=audit,
        provenance=fixed_provenance,
    )
    report = strictness_report(mediator)
    assert report["strict"] is True
    assert report["gaps"] == []


def test_the_report_catches_the_half_wired_case(
    auth_system, registry_system, fixed_provenance
):
    """This is the case the whole file is about: the ceiling on, the audit log
    unanchored. Both halves report themselves correctly, and only the combined
    answer is false -- which is why it has to be asked as one question."""
    from axiomgate_kernel import Authenticator, Mediator

    audit = AuditLog(_tmp_path(), generate_key())
    mediator = Mediator(
        authenticator=Authenticator(auth_system),
        registry=registry_system,
        audit=audit,
        provenance=fixed_provenance,
        require_principal_context=True,
    )
    report = strictness_report(mediator)
    assert report["provenance_ceiling"] is True
    assert report["audit_anchored"] is False
    assert report["strict"] is False
    assert len(report["gaps"]) == 1
    assert "anchor" in report["gaps"][0]


# --- the boundary ------------------------------------------------------------
#
# The two tests below are characterisation tests, not regression tests: they
# passed the moment they were written, because they describe what the module
# already does. They exist because an L6 review read "impossible to half-wire"
# and correctly found it stronger than the code. Writing the limit down in prose
# only puts it where nobody re-reads it; writing it as a test means a future
# change that claims to close either gap has to delete an assertion to do it.

def test_the_report_is_self_reporting_and_can_be_told_anything(
    auth_system, registry_system, fixed_provenance
):
    """`anchored` is an ordinary writable attribute, so a caller who sets it by
    hand gets a clean report from a log that was never anchored. That is the
    boundary of what an in-process check can do -- the same caller can call
    Mediator directly -- and it is documented rather than defended."""
    from axiomgate_kernel import Authenticator

    plain = AuditLog(_tmp_path(), generate_key())
    assert plain.anchored is False
    plain.anchored = True  # the lie

    mediator = strict_mediator(
        authenticator=Authenticator(auth_system),
        registry=registry_system,
        audit=plain,
        provenance=fixed_provenance,
    )
    assert strictness_report(mediator)["strict"] is True


def test_a_log_wiped_to_zero_bytes_reads_as_a_first_run():
    """_has_entries reads size, so a total wipe is indistinguishable from a
    first run and NEW_LOG accepts it. Deliberate: a created-but-unwritten file
    is what a crashed first run leaves behind. Catching a wipe needs the
    external anchor, which is what R2 is for."""
    path = _tmp_path()
    key = generate_key()
    log = strict_audit_log(path, key, NEW_LOG)
    for i in range(5):
        log.append({"n": i})
    anchor = log.head()
    assert os.path.getsize(path) > 0

    open(path, "w", encoding="utf-8").close()

    # The claim goes through, because there is nothing left to contradict it.
    reopened = strict_audit_log(path, key, NEW_LOG)
    assert reopened.anchored is True

    # The anchor is what catches it, and it does.
    with pytest.raises(AuditError):
        strict_audit_log(path, key, anchor)
