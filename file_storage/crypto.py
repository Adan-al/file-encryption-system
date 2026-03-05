"""AES-256-GCM encryption/decryption primitives and HMAC key derivation."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from file_storage.constants import AES_KEY_BITS, HMAC_HKDF_INFO, NONCE_SIZE
from file_storage.errors import DecryptionError


def generate_key() -> bytes:
    """Generate a new AES-256 key (32 bytes)."""
    return AESGCM.generate_key(bit_length=AES_KEY_BITS)


def generate_nonce() -> bytes:
    """Generate a random 12-byte nonce for AES-GCM."""
    return os.urandom(NONCE_SIZE)


def encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Encrypt plaintext with AES-256-GCM.

    Returns ciphertext with 16-byte auth tag appended.
    """
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, aad)


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext_with_tag: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Decrypt AES-256-GCM ciphertext.

    Raises DecryptionError if authentication fails.
    """
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
    except Exception as e:
        raise DecryptionError(
            "Decryption failed: data may be tampered or key is incorrect"
        ) from e


def derive_hmac_key(encryption_key: bytes) -> bytes:
    """Derive an HMAC key from the encryption key via HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HMAC_HKDF_INFO,
    ).derive(encryption_key)
