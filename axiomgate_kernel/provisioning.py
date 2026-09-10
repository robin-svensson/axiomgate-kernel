"""AxiomGate Kernel — Provisioning Tokens

One-shot bootstrap authorization for system setup.
"""

from dataclasses import dataclass, field
from typing import Optional
from uuid import uuid4


class ProvisioningError(Exception):
    """Raised when provisioning token is invalid."""
    pass


@dataclass
class ProvisioningToken:
    """One-shot token for bootstrap operations.

    Tokens are consumed on use. After consumption,
    the token cannot be used again.

    After seal, no more provisioning operations are allowed.
    """

    token_id: str = field(default_factory=lambda: uuid4().hex[:16])
    _consumed: bool = field(default=False, repr=False)

    def _consume(self) -> None:
        """Mark token as consumed. Internal use only."""
        if self._consumed:
            raise ProvisioningError("Token already consumed")
        self._consumed = True

    @property
    def consumed(self) -> bool:
        return self._consumed


def require_token(token: ProvisioningToken, sealed: bool) -> None:
    """Validate that a provisioning token is usable.

    Raises ProvisioningError if:
    - Token is None
    - Token has been consumed
    - System is already sealed
    """
    if token is None:
        raise ProvisioningError("Provisioning token required")
    if token.consumed:
        raise ProvisioningError("Token already consumed")
    if sealed:
        raise ProvisioningError("System is sealed")


def bind_token(bound_id: Optional[str], token: ProvisioningToken) -> str:
    """Bind a token to a store, returning the token ID.

    If a token is already bound, verify it matches.
    Does NOT consume the token — only seal should consume.
    """
    if bound_id is not None and bound_id != token.token_id:
        raise ProvisioningError("Token mismatch")
    return token.token_id
