"""AxiomGate Kernel — Cryptographic Operations

HMAC-SHA256 and SHA-256 primitives. All comparison is constant-time.
"""

import hashlib
import hmac
import os


def generate_key() -> bytes:
    """Generate a 256-bit random key for HMAC operations."""
    return os.urandom(32)


def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    """Compute HMAC-SHA256 and return hex digest.

    Raises ValueError if key is empty.
    """
    if not key:
        raise ValueError("HMAC key is not initialized")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_equal(expected_hex: str, actual_hex: str) -> bool:
    """Constant-time comparison of two hex digests.

    Uses hmac.compare_digest to prevent timing attacks.
    Returns False on type mismatch rather than raising.
    """
    if not isinstance(expected_hex, str) or not isinstance(actual_hex, str):
        return False
    if len(expected_hex) != len(actual_hex):
        return False
    return hmac.compare_digest(expected_hex, actual_hex)


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return hex digest."""
    return hashlib.sha256(data).hexdigest()
