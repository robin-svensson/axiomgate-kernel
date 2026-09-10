"""AxiomGate Kernel — Authentication Gate

Bind a Principal from a CanonicalRequest via HMAC verification.
"""

import collections
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from .canonical_request import CanonicalRequest
from .crypto import hmac_equal, hmac_sha256_hex
from .principal import Principal
from .provisioning import ProvisioningError, ProvisioningToken, bind_token, require_token
from .domain import OWNER_PRINCIPAL_ID


@dataclass
class AuthnResult:
    """Authentication outcome."""
    ok: bool
    principal: Optional[Principal]
    reason: str
    rule: str


class NonceTracker:
    """Replay protection via per-principal nonce tracking.

    Each principal has a bounded set of recent nonces.
    Nonces expire after TTL. Capacity is enforced per principal.
    Fail-closed on capacity exhaustion.
    """

    def __init__(self, max_per_principal: int = 10000, max_ttl_seconds: int = 300) -> None:
        self._seen_by_principal: Dict[str, collections.OrderedDict] = {}
        self._max_per_principal = max_per_principal
        self._max_ttl = timedelta(seconds=max_ttl_seconds)
        # The check and the write must happen atomically: without a lock, two
        # threads could both pass the same "nonce in seen" check and both got
        # True. Reproduced with 16 threads and a lowered switch interval -- the
        # replay guard is the only control against replaying a signed approval.
        self._lock = threading.Lock()

    def consume(self, principal_id: str, nonce: str, timestamp_str: str) -> bool:
        """Attempt to consume a nonce. Returns True if successful.

        Fails if:
        - principal_id, nonce, or timestamp is invalid
        - timestamp is outside TTL window
        - nonce has been seen before
        - capacity is exhausted (fail-closed)
        """
        if self._max_per_principal <= 0:
            return False
        if not principal_id or not isinstance(principal_id, str):
            return False
        if not nonce or not isinstance(nonce, str):
            return False
        if not timestamp_str or not isinstance(timestamp_str, str):
            return False

        try:
            ts = datetime.fromisoformat(timestamp_str)
        except ValueError:
            return False

        if ts.tzinfo is None:
            return False  # Reject naive timestamps (Fail-Closed)

        now = datetime.now(timezone.utc)

        # Strict TTL: Reject past expirations
        if now - ts > self._max_ttl:
            return False

        # Strict TTL: Reject future-dated timestamps (allowing 5s clock skew)
        if ts > now + timedelta(seconds=5):
            return False

        with self._lock:
            if principal_id not in self._seen_by_principal:
                self._seen_by_principal[principal_id] = collections.OrderedDict()

            seen = self._seen_by_principal[principal_id]
            if nonce in seen:
                return False

            # Evict expired entries if we're at capacity
            while len(seen) >= self._max_per_principal:
                oldest_nonce, oldest_ts = next(iter(seen.items()))
                if now - oldest_ts > self._max_ttl:
                    seen.popitem(last=False)
                else:
                    return False  # Capacity reached with valid nonces, fail-closed

            seen[nonce] = ts
            return True


class PrincipalKeyStore:
    """Mediator-held per-principal HMAC keys.

    Register requires provisioning token.
    Keys are not exposed externally.
    """

    def __init__(self, bootstrap: Optional[ProvisioningToken] = None) -> None:
        self._keys: Dict[str, bytes] = {}
        self._sealed = False
        self._bound_id = bootstrap.token_id if bootstrap is not None else None

    def register(self, principal_id: str, key: bytes, token: ProvisioningToken) -> None:
        """Register a principal's HMAC key. Requires provisioning token."""
        require_token(token, self._sealed)
        self._bound_id = bind_token(self._bound_id, token)
        if not principal_id or not isinstance(principal_id, str):
            raise ValueError("principal_id required")
        if not key:
            raise ValueError("key required")
        if principal_id == OWNER_PRINCIPAL_ID and principal_id in self._keys:
            raise ProvisioningError("Owner credentials cannot be replaced")
        self._keys[principal_id] = key

    def seal(self, token: ProvisioningToken) -> None:
        """Seal the key store. No more registrations after seal."""
        require_token(token, self._sealed)
        self._bound_id = bind_token(self._bound_id, token)
        self._sealed = True
        token._consume()

    def _get_key(self, principal_id: str) -> Optional[bytes]:
        """Internal key lookup for Authenticator use only.

        NOT a public API. External code must not call this.
        """
        return self._keys.get(principal_id)

    def has_principal(self, principal_id: str) -> bool:
        """Check whether a principal is registered. Does not expose key material."""
        return principal_id in self._keys

    @property
    def sealed(self) -> bool:
        return self._sealed


def sign_canonical(canon: CanonicalRequest, key: bytes) -> str:
    """Compute HMAC signature for a canonical request."""
    return hmac_sha256_hex(key, canon.mac_material())


def sign_request(request: dict, key: bytes) -> dict:
    """Helper for tests: snapshot, sign, attach mac to a new plain dict."""
    from .canonical_request import snapshot_request

    canon = snapshot_request(request)
    mac = sign_canonical(canon, key)
    out = canon.as_dict()
    out["mac"] = mac
    return out


class Authenticator:
    """HMAC-based authentication gate.

    Verifies:
    1. MAC is present and valid
    2. Principal is known
    3. Nonce is fresh (replay protection)
    4. Agent ID matches principal
    """

    def __init__(self, keys: PrincipalKeyStore, nonces: Optional[NonceTracker] = None) -> None:
        self._keys = keys
        self._nonces = nonces or NonceTracker()

    def authenticate(self, canon: CanonicalRequest) -> AuthnResult:
        """Authenticate a canonical request.

        Returns AuthnResult with ok=True only if all checks pass.
        All failure paths return ok=False with specific rule.
        """
        mac = canon.get("mac")
        if mac is None or mac == "":
            return AuthnResult(False, None, "required MAC missing", "authn.mac_missing")
        if not isinstance(mac, str):
            return AuthnResult(False, None, "invalid MAC", "authn.mac_invalid")

        principal_id = canon.get("principal_id")
        if not isinstance(principal_id, str) or not principal_id.strip():
            return AuthnResult(False, None, "principal_id missing", "authn.principal_missing")

        key = self._keys._get_key(principal_id)
        if key is None:
            return AuthnResult(False, None, "unknown principal", "authn.unknown_principal")

        expected = sign_canonical(canon, key)
        if not hmac_equal(expected, mac):
            return AuthnResult(False, None, "invalid MAC", "authn.mac_invalid")

        nonce = canon.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            return AuthnResult(False, None, "nonce missing", "authn.nonce_missing")
        timestamp = canon.get("timestamp")
        if not self._nonces.consume(principal_id, nonce, timestamp):
            return AuthnResult(False, None, "nonce replay or expired", "authn.replay")

        claim = canon.get("agent_id")
        if not isinstance(claim, str) or not claim:
            return AuthnResult(False, None, "agent_id claim missing", "authn.claim_missing")
        if claim != principal_id:
            return AuthnResult(
                False,
                Principal(principal_id),
                "agent_id claim does not match bound principal",
                "authn.claim_mismatch",
            )

        return AuthnResult(True, Principal(principal_id), "authenticated", "authn.ok")
