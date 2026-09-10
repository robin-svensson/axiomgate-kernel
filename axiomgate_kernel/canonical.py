"""AxiomGate Kernel — Canonical Encoding

Deterministic encoding for cryptographic operations.
"""

import json


def canonical_bytes(obj: object) -> bytes:
    """Encode an object as canonical bytes for hashing.

    Uses sorted JSON with no whitespace for determinism.
    Rejects non-finite floats (NaN, Infinity).
    """
    return canonical_json(obj).encode("utf-8")


def canonical_json(obj: object) -> str:
    """Encode an object as canonical JSON string.

    Uses sorted keys, no whitespace, and rejects non-finite floats.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
