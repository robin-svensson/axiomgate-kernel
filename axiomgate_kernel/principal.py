"""AxiomGate Kernel — Principal Model

Minimal, immutable principal identity.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    """An identified entity in the governance system.

    The principal_id is the unique identifier for this principal.
    It is bound during authentication and cannot change.
    """

    principal_id: str
