"""AxiomGate Kernel — Policy Snapshot

Placeholder/missing/corrupt/unbound blocks PERMIT.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from .canonical import canonical_bytes, canonical_json
from .crypto import sha256_hex

PLACEHOLDER_HASH = "sha256:" + ("0" * 64)


def _all_zero_digest(value: str) -> bool:
    """Check if a hash is all zeros."""
    if not isinstance(value, str) or not value.strip():
        return True
    hexpart = value.split(":")[-1].strip().lower()
    if not hexpart:
        return True
    return set(hexpart) <= set("0")


@dataclass(frozen=True)
class PolicySnapshot:
    """Immutable policy snapshot with hash integrity."""
    version: str
    body: Mapping[str, Any]
    hash: str
    readable: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.body, MappingProxyType):
            object.__setattr__(self, "body", MappingProxyType(dict(self.body)))

    @classmethod
    def from_body(cls, version: str, body: dict) -> "PolicySnapshot":
        """Create a policy snapshot from a body dict."""
        copied = dict(body)
        digest = "sha256:" + sha256_hex(canonical_bytes(copied))
        return cls(version=version, body=MappingProxyType(copied), hash=digest, readable=True)

    @classmethod
    def placeholder(cls) -> "PolicySnapshot":
        """Create a placeholder policy that blocks PERMIT."""
        return cls(version="unset", body=MappingProxyType({}), hash=PLACEHOLDER_HASH, readable=True)

    @classmethod
    def corrupt(cls) -> "PolicySnapshot":
        """Create a corrupt policy that blocks PERMIT."""
        return cls(version="corrupt", body=MappingProxyType({}), hash="", readable=False)

    def is_placeholder(self) -> bool:
        """Check if this is a placeholder policy."""
        return _all_zero_digest(self.hash) or self.hash == PLACEHOLDER_HASH

    def identity(self) -> str:
        """Return policy identity string."""
        return f"{self.version}:{self.hash}"

    def blocks_permit(self) -> bool:
        """Check if this policy blocks PERMIT.

        Blocks if: unreadable, empty hash, placeholder, or body hash mismatch.
        """
        if not self.readable:
            return True
        if not self.hash or not str(self.hash).strip():
            return True
        if self.is_placeholder():
            return True
        try:
            actual = "sha256:" + sha256_hex(canonical_bytes(dict(self.body)))
        except Exception:
            return True
        if actual != self.hash:
            return True
        return False
