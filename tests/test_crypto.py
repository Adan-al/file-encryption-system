"""Tests for AES-256-GCM encryption/decryption primitives."""

import pytest

from file_storage.crypto import (
    decrypt,
    derive_hmac_key,
    encrypt,
    generate_key,
    generate_nonce,
)
from file_storage.errors import DecryptionError


class TestKeyGeneration:
    def test_generate_key_length(self):
        key = generate_key()
        assert len(key) == 32

    def test_generate_key_is_bytes(self):
        key = generate_key()
        assert isinstance(key, bytes)

    def test_generate_key_randomness(self):
        key1 = generate_key()
        key2 = generate_key()
        assert key1 != key2


class TestNonceGeneration:
    def test_generate_nonce_length(self):
        nonce = generate_nonce()
        assert len(nonce) == 12

    def test_generate_nonce_is_bytes(self):
        nonce = generate_nonce()
        assert isinstance(nonce, bytes)


class TestEncryptDecrypt:
    def test_encrypt_decrypt_roundtrip(self):
        key = generate_key()
        nonce = generate_nonce()
        plaintext = b"Hello, World!"
        ciphertext = encrypt(key, nonce, plaintext)
        result = decrypt(key, nonce, ciphertext)
        assert result == plaintext

    def test_encrypt_produces_ciphertext_plus_tag(self):
        key = generate_key()
        nonce = generate_nonce()
        plaintext = b"test data"
        ciphertext = encrypt(key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext) + 16

    def test_decrypt_with_wrong_key_fails(self):
        key = generate_key()
        wrong_key = generate_key()
        nonce = generate_nonce()
        ciphertext = encrypt(key, nonce, b"secret")
        with pytest.raises(DecryptionError):
            decrypt(wrong_key, nonce, ciphertext)

    def test_decrypt_with_wrong_nonce_fails(self):
        key = generate_key()
        nonce = generate_nonce()
        wrong_nonce = generate_nonce()
        ciphertext = encrypt(key, nonce, b"secret")
        with pytest.raises(DecryptionError):
            decrypt(key, wrong_nonce, ciphertext)

    def test_decrypt_tampered_ciphertext(self):
        key = generate_key()
        nonce = generate_nonce()
        ciphertext = encrypt(key, nonce, b"secret")
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt(key, nonce, bytes(tampered))

    def test_encrypt_with_aad_roundtrip(self):
        key = generate_key()
        nonce = generate_nonce()
        plaintext = b"Hello, World!"
        aad = b"header-data"
        ciphertext = encrypt(key, nonce, plaintext, aad=aad)
        result = decrypt(key, nonce, ciphertext, aad=aad)
        assert result == plaintext

    def test_decrypt_with_wrong_aad_fails(self):
        key = generate_key()
        nonce = generate_nonce()
        plaintext = b"Hello, World!"
        aad = b"header-data"
        ciphertext = encrypt(key, nonce, plaintext, aad=aad)
        with pytest.raises(DecryptionError):
            decrypt(key, nonce, ciphertext, aad=b"wrong-header")

    def test_encrypt_empty_plaintext(self):
        key = generate_key()
        nonce = generate_nonce()
        ciphertext = encrypt(key, nonce, b"")
        assert len(ciphertext) == 16  # tag only
        result = decrypt(key, nonce, ciphertext)
        assert result == b""


class TestHmacKeyDerivation:
    def test_derive_hmac_key_deterministic(self):
        key = generate_key()
        hmac1 = derive_hmac_key(key)
        hmac2 = derive_hmac_key(key)
        assert hmac1 == hmac2

    def test_derive_hmac_key_differs_from_enc_key(self):
        key = generate_key()
        hmac_key = derive_hmac_key(key)
        assert hmac_key != key

    def test_derive_hmac_key_length(self):
        key = generate_key()
        hmac_key = derive_hmac_key(key)
        assert len(hmac_key) == 32
