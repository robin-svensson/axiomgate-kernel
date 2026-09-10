"""AxiomGate Kernel — Canonical Request Snapshot

Freezes incoming requests into immutable canonical form.
Prevents split-view TOCTOU attacks.
"""

from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional

from .canonical import canonical_bytes, canonical_json
from .crypto import sha256_hex

# Fields excluded from payload hash (they change per-message)
_PAYLOAD_HASH_EXCLUDE = frozenset({"nonce", "timestamp", "mac", "escalation_id"})


class CanonicalError(Exception):
    """Raised when request canonicalization fails."""
    pass


class CanonicalRequest:
    """Immutable snapshot of a request.

    All authorization decisions read from this object.
    The mapping is re-parsed from canonical text to prevent
    split-view attacks where a hostile mapping returns
    different values on successive .get() calls.
    """

    __slots__ = ("_data", "_canonical_text")

    def __init__(self, data: Mapping[str, Any], canonical_text: str) -> None:
        # Always derive the mapping from canonical_text so a hostile Mapping
        # passed to the constructor cannot split-view later .get() calls.
        import json

        parsed = json.loads(canonical_text)
        object.__setattr__(self, "_data", MappingProxyType(parsed))
        object.__setattr__(self, "_canonical_text", canonical_text)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from the canonical request."""
        return self._data.get(key, default)

    def as_dict(self) -> Dict[str, Any]:
        """Return a plain dict copy of the canonical request."""
        return dict(self._data)

    def mac_material(self) -> bytes:
        """Compute the material that the MAC covers.

        Includes all fields except 'mac' itself.
        """
        body = {k: v for k, v in self._data.items() if k != "mac"}
        return canonical_bytes(body)

    def full_payload_hash(self) -> str:
        """Compute hash of the full payload for binding.

        Excludes nonce, timestamp, and mac (which change per-message).
        Binds: principal_id, agent_id, action_type, domain, risk_level,
        request_id, and all body fields.
        """
        body = {
            k: v
            for k, v in self._data.items()
            if k not in _PAYLOAD_HASH_EXCLUDE
        }
        return sha256_hex(canonical_bytes(body))

    def __repr__(self) -> str:
        return f"CanonicalRequest({dict(self._data)})"


def snapshot_request(request: Mapping[str, Any]) -> CanonicalRequest:
    """Freeze a request into canonical form.

    This is the ONLY way to create a CanonicalRequest.
    The request is serialized to canonical JSON, then re-parsed
    to ensure immutability and prevent split-view attacks.
    """
    from .canonical import canonical_json

    if not isinstance(request, Mapping):
        raise CanonicalError(f"Request must be a Mapping, got {type(request).__name__}")

    try:
        # Reject non-finite constants in the request
        _reject_json_constant(request)
        canonical_text = canonical_json(request)
        return CanonicalRequest(request, canonical_text)
    except CanonicalError:
        raise
    except (ValueError, TypeError) as exc:
        raise CanonicalError(f"Canonicalization failed: {exc}") from exc
    except Exception as exc:
        raise CanonicalError(f"Unexpected canonicalization error: {exc}") from exc


def _reject_json_constant(obj: object) -> None:
    """Recursively reject non-finite float constants."""
    if isinstance(obj, float):
        if obj != obj:  # NaN
            raise ValueError("NaN is not allowed in requests")
        if obj == float("inf") or obj == float("-inf"):
            raise ValueError("Infinity is not allowed in requests")
    elif isinstance(obj, dict):
        for v in obj.values():
            _reject_json_constant(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_json_constant(v)
