"""One way to get both fail-closed protections, and one way to ask which you have.

The kernel has two protections that are off unless the integrator turns them on:

- **R1**, the provenance ceiling, under ``Mediator(require_principal_context=True)``
- **R2**, truncation detection, under ``AuditLog(..., anchor=(head, count))``

Both defaults are deliberate and documented in ``docs/ROADMAP.md``: turning either
on unconditionally would deny every request, or refuse every log, at a deployment
that never wired it. That reasoning has not changed.

What this module addresses is a different problem, and it is not a documentation
problem. The two flags live on two different objects, are passed at two different
call sites, and **nothing reports which of them a running kernel actually has**.
A deployment that set the ceiling and opened a plain ``AuditLog`` is indistinguishable,
from inside, from one that set both. Its audit records look identical. Its tests pass
identically. The gap is real but invisible, and an invisible gap is the kind that gets
reported as closed.

So there are two things here, and only two:

``strict_audit_log`` / ``strict_mediator``
    Constructors that cannot produce the half-wired kernel. They take the same
    arguments as the plain ones, minus the ability to leave a protection off.

``strictness_report``
    Asks a live ``Mediator`` which protections it has, and names the missing ones.
    An operator can call it at startup and print the result.

Nothing here changes the behavior of ``Mediator`` or ``AuditLog``. A deployment that
does not import this module gets exactly what it got before, and the defaults stay
where ``docs/ROADMAP.md`` says they are. This is a second, narrower door -- not a
change to the first one.

**The boundary, stated so nobody has to discover it.** All of this is self-reporting.
``AuditLog.anchored`` is an ordinary writable attribute, and both ``strict_mediator``
and ``strictness_report`` read it rather than establishing how the object was built.
Set it by hand, or pass any object carrying it, and the report comes back clean. That
is the correct boundary rather than a hole to plug: what this module fixes is that an
*honest* integrator could not tell which kernel they were running. Code that lies to
its own audit trail is not addressable from inside that same process -- it can call
``Mediator`` directly and skip this module entirely.
"""

from typing import Any, Dict, Optional, Tuple

from .audit import AuditError, AuditLog
from .mediator import Mediator

__all__ = [
    "NEW_LOG",
    "StrictnessError",
    "strict_audit_log",
    "strict_mediator",
    "strictness_report",
]


class StrictnessError(Exception):
    """A strict constructor was asked to produce a kernel that is not strict.

    Separate from ``AuditError`` on purpose: an ``AuditError`` means the chain
    on disk is wrong, which is a finding about data. This means the *wiring* is
    wrong, which is a finding about code, and the two get handled by different
    people at different times.
    """


class _NewLog:
    """The sentinel type. Named so that a repr in a traceback reads as English."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return "NEW_LOG"


NEW_LOG = _NewLog()
"""Passed as the anchor when there is genuinely no earlier chain to anchor to.

This is not a way to skip the anchor. It is a claim -- "no chain exists yet" --
and :func:`strict_audit_log` refuses it if a chain is on disk. The distinction
matters because "first run" and "reopening" are the same call to ``AuditLog`` and
different security situations, and the ambiguity is where the truncation gap
lives.
"""


def strict_audit_log(
    path: str,
    mac_key: bytes,
    anchor: Any,
    *,
    writer: Optional[Any] = None,
) -> AuditLog:
    """Open an audit log, having stated which situation this is.

    ``anchor`` is positional and has no default. That is the whole mechanism:
    ``AuditLog(path, key)`` is a valid call that silently accepts a truncated
    file, and no amount of documentation makes a valid call look wrong at the
    call site.

    Pass either a prior ``head()`` tuple kept outside the log file, or
    :data:`NEW_LOG` if no chain exists yet.

    One case ``NEW_LOG`` cannot catch: a file truncated to **zero bytes**. See
    :func:`_has_entries` -- a complete wipe is indistinguishable from a first run.
    Catching that needs the external anchor, which is what it is for: a reopen passing
    ``head()`` detects it, a reopen claiming ``NEW_LOG`` does not.

    Raises:
        StrictnessError: ``NEW_LOG`` was claimed but a chain is already on disk.
        AuditError: the log on disk does not match the anchor (raised by
            ``AuditLog`` itself; the message is its own).
    """
    if anchor is NEW_LOG:
        # An empty file is not a chain: a created-but-unwritten file is what a
        # crashed first run leaves behind, and refusing it would make the strict
        # path fail on a situation with nothing to protect.
        if _has_entries(path):
            raise StrictnessError(
                f"NEW_LOG was passed for {path!r}, but a chain already exists there. "
                "Either this is a reopen and needs the anchor that was kept outside "
                "the log, or this path is not the one that was meant. Opening it "
                "unanchored is the case a truncated tail is never caught in."
            )
        log = AuditLog(path, mac_key, writer=writer)
        # A log that starts empty has nothing behind it to be cut away, so it
        # satisfies what the anchor is for. Recording that here rather than
        # inferring it later keeps strictness_report from having to guess.
        log.anchored = True
        return log

    if not isinstance(anchor, tuple) or len(anchor) != 2:
        raise StrictnessError(
            "anchor must be a (head, count) tuple from a prior AuditLog.head(), "
            f"or NEW_LOG. Got {anchor!r}."
        )

    return AuditLog(path, mac_key, writer=writer, anchor=anchor)


def strict_mediator(
    *,
    authenticator: Any,
    registry: Any,
    audit: AuditLog,
    provenance: Any,
    policy: Any = None,
    available: bool = True,
    policy_token: Any = None,
    require_principal_context: bool = True,
) -> Mediator:
    """Build a Mediator with both protections on, or refuse to build one.

    ``require_principal_context`` is accepted only so that passing ``False``
    fails loudly instead of being silently ignored. A caller who wants it off
    wants ``Mediator``, and should say so at the call site where a reader of
    the code will see it.

    Raises:
        StrictnessError: the audit log was not opened through
            :func:`strict_audit_log`, or the ceiling was declined.
    """
    if require_principal_context is not True:
        raise StrictnessError(
            "strict_mediator cannot turn the provenance ceiling off -- that is the "
            "protection it exists to guarantee. Use Mediator(...) directly if the "
            "deployment genuinely needs the unbounded kernel; the call site is then "
            "honest about it."
        )

    if not getattr(audit, "anchored", False):
        raise StrictnessError(
            "the audit log was opened without an anchor, so a truncated tail would "
            "be replayed without complaint and this kernel is only half fail-closed. "
            "Open it with strict_audit_log(path, key, anchor) -- passing NEW_LOG if "
            "no chain exists yet. See docs/ROADMAP.md R2."
        )

    return Mediator(
        authenticator,
        registry,
        audit,
        provenance,
        policy,
        available=available,
        policy_token=policy_token,
        require_principal_context=True,
    )


def strictness_report(mediator: Mediator) -> Dict[str, Any]:
    """Ask a live kernel which of the two opt-in protections it actually has.

    Returns a dict with ``strict``, ``provenance_ceiling``, ``audit_anchored``
    and ``gaps``. ``gaps`` names each missing protection and the flag that turns
    it on, because a bare ``False`` tells an operator nothing about what to wire.

    This reads state; it never changes it. Safe to call at startup and print.

    Self-reporting, not verification: it reads ``anchored`` off whatever object the
    mediator holds. See the module docstring for why that is the boundary and not a
    defect.
    """
    ceiling = bool(getattr(mediator, "require_principal_context", False))
    anchored = bool(getattr(getattr(mediator, "_audit", None), "anchored", False))

    gaps = []
    if not ceiling:
        gaps.append(
            "no provenance ceiling: Mediator(require_principal_context=True) is off, "
            "so no verdict is bounded by how the call arose (docs/ROADMAP.md R1)"
        )
    if not anchored:
        gaps.append(
            "audit log has no anchor: a truncated tail replays as a valid chain, "
            "because a truncated chain is internally consistent (docs/ROADMAP.md R2)"
        )

    return {
        "strict": ceiling and anchored,
        "provenance_ceiling": ceiling,
        "audit_anchored": anchored,
        "gaps": gaps,
    }


def _has_entries(path: str) -> bool:
    """True if a chain exists at path. Size, not existence: an empty file has
    nothing to truncate and treating it as a chain would block a legitimate
    first run after a crash."""
    import os

    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False
