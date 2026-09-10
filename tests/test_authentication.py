"""AxiomGate Kernel — Authentication Property Tests

Tests for authentication security properties.
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from axiomgate_kernel import (
    ActionType, Authenticator, NonceTracker, PrincipalKeyStore,
    RiskLevel, Role, Verdict, generate_key, sign_request, snapshot_request,
)
from axiomgate_kernel.authentication import sign_canonical
from axiomgate_kernel.crypto import hmac_equal


class TestHMACProperties:
    """Test HMAC cryptographic properties."""

    def test_constant_time_comparison_used(self):
        """Verify hmac_equal uses constant-time comparison."""
        # This is a code inspection property - hmac.compare_digest is constant-time
        import inspect
        from axiomgate_kernel.crypto import hmac_equal
        source = inspect.getsource(hmac_equal)
        assert "compare_digest" in source, "hmac_equal must use hmac.compare_digest"

    def test_hmac_deterministic(self):
        """Same key + data produces same HMAC."""
        key = generate_key()
        data = b"test data"
        mac1 = __import__("axiomgate_kernel.crypto", fromlist=["hmac_sha256_hex"]).hmac_sha256_hex(key, data)
        mac2 = __import__("axiomgate_kernel.crypto", fromlist=["hmac_sha256_hex"]).hmac_sha256_hex(key, data)
        assert mac1 == mac2

    def test_hmac_different_keys_differ(self):
        """Different keys produce different HMACs."""
        from axiomgate_kernel.crypto import hmac_sha256_hex
        key1 = generate_key()
        key2 = generate_key()
        data = b"test data"
        mac1 = hmac_sha256_hex(key1, data)
        mac2 = hmac_sha256_hex(key2, data)
        assert mac1 != mac2

    def test_hmac_different_data_differ(self):
        """Different data produces different HMACs."""
        from axiomgate_kernel.crypto import hmac_sha256_hex
        key = generate_key()
        mac1 = hmac_sha256_hex(key, b"data1")
        mac2 = hmac_sha256_hex(key, b"data2")
        assert mac1 != mac2

    def test_hmac_empty_key_raises(self):
        """Empty key raises ValueError."""
        from axiomgate_kernel.crypto import hmac_sha256_hex
        with pytest.raises(ValueError):
            hmac_sha256_hex(b"", b"data")


class TestNonceReplay:
    """Test nonce replay protection properties."""

    def test_nonce_replay_denied(self):
        """Same nonce cannot be used twice."""
        nt = NonceTracker(max_per_principal=100)
        now = datetime.now(timezone.utc).isoformat()
        assert nt.consume("agent-a", "nonce-1", now) is True
        assert nt.consume("agent-a", "nonce-1", now) is False

    def test_different_nonces_accepted(self):
        """Different nonces are accepted."""
        nt = NonceTracker(max_per_principal=100)
        now = datetime.now(timezone.utc).isoformat()
        assert nt.consume("agent-a", "nonce-1", now) is True
        assert nt.consume("agent-a", "nonce-2", now) is True

    def test_stale_nonce_denied(self):
        """Nonce with old timestamp is denied."""
        nt = NonceTracker(max_per_principal=100, max_ttl_seconds=300)
        old_time = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()
        assert nt.consume("agent-a", "nonce-1", old_time) is False

    def test_future_nonce_denied(self):
        """Nonce with future timestamp (beyond clock skew) is denied."""
        nt = NonceTracker(max_per_principal=100)
        future_time = (datetime.now(timezone.utc) + timedelta(seconds=10)).isoformat()
        assert nt.consume("agent-a", "nonce-1", future_time) is False

    def test_naive_timestamp_denied(self):
        """Naive timestamp (no timezone) is denied."""
        nt = NonceTracker(max_per_principal=100)
        naive_time = "2026-01-01T00:00:00"
        assert nt.consume("agent-a", "nonce-1", naive_time) is False

    def test_capacity_exhaustion_fail_closed(self):
        """Capacity exhaustion is fail-closed."""
        nt = NonceTracker(max_per_principal=3)
        now = datetime.now(timezone.utc).isoformat()
        for i in range(3):
            assert nt.consume("agent-a", f"nonce-{i}", now) is True
        # Fourth nonce should fail (capacity reached)
        assert nt.consume("agent-a", "nonce-3", now) is False

    def test_cross_principal_independence(self):
        """Nonce tracking is per-principal."""
        nt = NonceTracker(max_per_principal=2)
        now = datetime.now(timezone.utc).isoformat()
        assert nt.consume("agent-a", "nonce-1", now) is True
        assert nt.consume("agent-a", "nonce-2", now) is True
        # agent-a at capacity
        assert nt.consume("agent-a", "nonce-3", now) is False
        # agent-b can still use nonces
        assert nt.consume("agent-b", "nonce-1", now) is True


class TestIdentityBinding:
    """Test identity binding properties."""

    def test_unknown_principal_denied(self, auth_system):
        """Unknown principal is denied."""
        auth = Authenticator(auth_system)
        from uuid import uuid4
        key = generate_key()
        request = sign_request({
            "principal_id": "unknown-agent",
            "agent_id": "unknown-agent",
            "action_type": "EXECUTE",
            "domain": "code",
            "risk_level": "MEDIUM",
            "nonce": uuid4().hex,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": "req-001",
        }, key)
        canon = snapshot_request(request)
        result = auth.authenticate(canon)
        assert result.ok is False
        assert "unknown_principal" in result.rule

    def test_agent_id_mismatch_denied(self, auth_system, agent_key):
        """agent_id not matching principal_id is denied."""
        auth = Authenticator(auth_system)
        from uuid import uuid4
        request = sign_request({
            "principal_id": "agent-a",
            "agent_id": "different-agent",
            "action_type": "EXECUTE",
            "domain": "code",
            "risk_level": "MEDIUM",
            "nonce": uuid4().hex,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": "req-001",
        }, agent_key)
        canon = snapshot_request(request)
        result = auth.authenticate(canon)
        assert result.ok is False
        assert "claim_mismatch" in result.rule

    def test_invalid_mac_denied(self, auth_system):
        """Invalid MAC is denied."""
        auth = Authenticator(auth_system)
        request = {
            "principal_id": "agent-a",
            "agent_id": "agent-a",
            "action_type": "EXECUTE",
            "domain": "code",
            "risk_level": "MEDIUM",
            "nonce": uuid4().hex,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": "req-001",
            "mac": "invalid_mac_value",
        }
        canon = snapshot_request(request)
        result = auth.authenticate(canon)
        assert result.ok is False
        assert "mac_invalid" in result.rule

    def test_missing_mac_denied(self, auth_system):
        """Missing MAC is denied."""
        auth = Authenticator(auth_system)
        request = {
            "principal_id": "agent-a",
            "agent_id": "agent-a",
            "action_type": "EXECUTE",
            "domain": "code",
            "risk_level": "MEDIUM",
            "nonce": uuid4().hex,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": "req-001",
        }
        canon = snapshot_request(request)
        result = auth.authenticate(canon)
        assert result.ok is False
        assert "mac_missing" in result.rule

    def test_valid_request_authenticated(self, auth_system, agent_key):
        """Valid signed request is authenticated."""
        auth = Authenticator(auth_system)
        request = sign_request({
            "principal_id": "agent-a",
            "agent_id": "agent-a",
            "action_type": "EXECUTE",
            "domain": "code",
            "risk_level": "MEDIUM",
            "nonce": uuid4().hex,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": "req-001",
        }, agent_key)
        canon = snapshot_request(request)
        result = auth.authenticate(canon)
        assert result.ok is True
        assert result.principal.principal_id == "agent-a"


class TestNonceTrackerThreadSafety:
    """consume() reads and writes _seen_by_principal without a lock.

    Between `if nonce in seen` and `seen[nonce] = ts` there is a window where
    a second thread can slip past the same check. Two concurrent calls with
    the same nonce can then both return True -- the replay guard is the only
    control against replaying a signed approval.
    """

    def test_concurrent_calls_with_the_same_nonce_yield_exactly_one_true(self):
        import sys
        import threading
        from concurrent.futures import ThreadPoolExecutor

        # The window between check and write is a few bytecodes; with the
        # default switchinterval it is almost never hit. Force the thread switch.
        old_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            self._run_the_race()
        finally:
            sys.setswitchinterval(old_interval)

    def _run_the_race(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        for _ in range(200):
            nt = NonceTracker(max_per_principal=1000)
            ts = datetime.now(timezone.utc).isoformat()
            start = threading.Barrier(16)

            def attempt():
                start.wait()
                return nt.consume("p-1", "nonce-shared", ts)

            with ThreadPoolExecutor(max_workers=16) as pool:
                outcomes = list(pool.map(lambda _: attempt(), range(16)))

            assert sum(outcomes) == 1, (
                f"{sum(outcomes)} threads consumed the same nonce concurrently"
            )
