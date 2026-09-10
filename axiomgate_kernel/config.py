"""AxiomGate Kernel — Governance Configuration & Key Management

Isolates cryptographic keys:
- Verifiers receive ONLY public keys.
- Private signing keys are isolated to Gateway/Owner context only.
- Agent environments are sanitized to prevent private key leakage.
"""

from __future__ import annotations

import os
from typing import Optional, Tuple

from .approval import generate_approval_keypair

# See approval.py: no built-in owner identity may ship with the package.

# Process-level key cache
_cached_public_key: Optional[bytes] = None
_cached_private_key: Optional[bytes] = None
_is_agent_context: bool = False


def _reset_context_for_testing() -> None:
    """Reset key cache and agent context flag for unit test isolation."""
    global _cached_public_key, _cached_private_key, _is_agent_context
    _cached_public_key = None
    _cached_private_key = None
    _is_agent_context = False


def get_home() -> Path:
    """Return the directory AxiomGate Kernel keeps approval keys in.

    Defaults to ~/.axiomgate-kernel. It used to point into a private tooling
    environment, which put a customer's keys in a directory named after
    someone else's system.
    """
    from pathlib import Path
    env_home = os.environ.get("AXIOMGATE_KERNEL_HOME")
    if env_home:
        return Path(env_home).resolve()
    return (Path.home() / ".axiomgate-kernel").resolve()


def get_public_key_path() -> Path:
    """Path to the persisted Ed25519 public key file."""
    return get_home() / "approval_ed25519.pub"


def get_private_key_path() -> Path:
    """Path to the isolated Ed25519 private key file (Gateway only)."""
    return get_home() / ".approval_ed25519.key"


def get_owner_id() -> Optional[str]:
    """Return the configured Owner id, or None if none is configured.

    A missing value is None, never a substituted identity.
    """
    return os.environ.get("AXIOMGATE_OWNER_ID") or None


def set_approval_public_key(public_key_bytes: bytes) -> None:
    """Set the public key for approval verification in this process."""
    global _cached_public_key
    if not public_key_bytes or len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes")
    _cached_public_key = bytes(public_key_bytes)


def get_approval_public_key() -> Optional[bytes]:
    """Get the public key for approval verification.

    Checks:
    1. Process cache
    2. AXIOMGATE_APPROVAL_PUBLIC_KEY env var (hex)
    3. Public key file on disk (~/.axiomgate-kernel/approval_ed25519.pub)
    """
    global _cached_public_key
    if _cached_public_key is not None:
        return _cached_public_key

    pub_hex = os.environ.get("AXIOMGATE_APPROVAL_PUBLIC_KEY")
    if pub_hex:
        try:
            b = bytes.fromhex(pub_hex.strip())
            if len(b) == 32:
                _cached_public_key = b
                return b
        except ValueError:
            pass

    # Check public key file
    pub_file = get_public_key_path()
    if pub_file.exists():
        try:
            content = pub_file.read_text(encoding="utf-8").strip()
            b = bytes.fromhex(content)
            if len(b) == 32:
                _cached_public_key = b
                return b
        except Exception:
            pass

    return None


def set_approval_private_key(private_key_bytes: bytes) -> None:
    """Set the private signing key (GATEWAY ONLY)."""
    global _cached_private_key, _cached_public_key, _is_agent_context
    if _is_agent_context:
        raise PermissionError("Agent context cannot set or access private signing key")
    if not private_key_bytes or len(private_key_bytes) != 32:
        raise ValueError("Ed25519 private key must be exactly 32 bytes")
    _cached_private_key = bytes(private_key_bytes)
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(_cached_private_key)
    _cached_public_key = priv.public_key().public_bytes_raw()


def get_approval_private_key() -> Optional[bytes]:
    """Get the private signing key for Gateway.

    Accessible ONLY if set in process cache or AXIOMGATE_APPROVAL_PRIVATE_KEY env var
    or private key file in Gateway context.
    NEVER accessible from agent context once sanitize_agent_environment() is called.
    """
    global _cached_private_key, _is_agent_context
    if _is_agent_context:
        return None

    if _cached_private_key is not None:
        return _cached_private_key

    priv_hex = os.environ.get("AXIOMGATE_APPROVAL_PRIVATE_KEY") or os.environ.get("AXIOMGATE_APPROVAL_SIGNING_KEY")
    if priv_hex:
        try:
            b = bytes.fromhex(priv_hex.strip())
            if len(b) == 32:
                _cached_private_key = b
                return b
        except ValueError:
            pass

    # Check private key file on disk (Gateway context only)
    priv_file = get_private_key_path()
    if priv_file.exists():
        try:
            content = priv_file.read_text(encoding="utf-8").strip()
            b = bytes.fromhex(content)
            if len(b) == 32:
                _cached_private_key = b
                return b
        except Exception:
            pass

    return None


def sanitize_agent_environment() -> None:
    """Purge signing secrets from environment variables and process memory.

    MUST be called at agent process / task initialization so that:
    1. Agent Python environment cannot read private key from os.environ
    2. In-memory private key cache is wiped immediately
    3. Agent context flag prevents any subsequent private key retrieval
    4. Subprocesses spawned by the agent do not inherit signing secrets
    """
    global _cached_private_key, _is_agent_context
    _is_agent_context = True
    _cached_private_key = None

    for key in (
        "AXIOMGATE_APPROVAL_PRIVATE_KEY",
        "AXIOMGATE_APPROVAL_SIGNING_KEY",
        "AXIOMGATE_SIGNING_KEY",
        "AXIOMGATE_OWNER_PRIVATE_KEY",
    ):
        os.environ.pop(key, None)


def ensure_gateway_approval_keys() -> Tuple[bytes, bytes]:
    """Ensure keypair is available in Gateway context. Returns (private_key, public_key).

    If no keys exist, generates a fresh pair and persists:
    - Public key to ~/.axiomgate-kernel/approval_ed25519.pub (mode 0644)
    - Private key to ~/.axiomgate-kernel/.approval_ed25519.key (mode 0600)
    """
    global _cached_private_key, _cached_public_key, _is_agent_context
    if _is_agent_context:
        raise PermissionError("Agent context cannot initialize or access Gateway signing keys")

    priv = get_approval_private_key()
    pub = get_approval_public_key()
    if priv is not None and pub is not None:
        return priv, pub

    if priv is not None and pub is None:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        p_obj = ed25519.Ed25519PrivateKey.from_private_bytes(priv)
        pub = p_obj.public_key().public_bytes_raw()
        _cached_public_key = pub

    if priv is None:
        priv, pub = generate_approval_keypair()
        _cached_private_key = priv
        _cached_public_key = pub

        try:
            home = get_home()
            home.mkdir(parents=True, exist_ok=True)

            priv_file = get_private_key_path()
            fd = os.open(str(priv_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(priv.hex())

            pub_file = get_public_key_path()
            pub_file.write_text(pub.hex(), encoding="utf-8")
        except Exception:
            pass

    return priv, pub


def ensure_approval_keys() -> Tuple[Optional[bytes], bytes]:
    """Backward-compatible helper.

    In agent context: returns (None, public_key) and NEVER generates a private key.
    In gateway context: calls ensure_gateway_approval_keys().
    """
    global _is_agent_context
    if _is_agent_context:
        pub = get_approval_public_key()
        return None, pub or b""

    return ensure_gateway_approval_keys()
