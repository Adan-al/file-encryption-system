"""HMAC-based integrity verification for encrypted files."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod


def compute_hmac(hmac_key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 over data."""
    return hmac_mod.new(hmac_key, data, hashlib.sha256).digest()


def verify_hmac(hmac_key: bytes, data: bytes, expected_hmac: bytes) -> bool:
    """Verify HMAC-SHA256 in constant time."""
    computed = hmac_mod.new(hmac_key, data, hashlib.sha256).digest()
    return hmac_mod.compare_digest(computed, expected_hmac)
