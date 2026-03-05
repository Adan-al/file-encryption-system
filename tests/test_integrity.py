"""Tests for HMAC-based integrity verification."""

import os

from file_storage.integrity import compute_hmac, verify_hmac


class TestComputeHmac:
    def test_compute_hmac_deterministic(self):
        key = os.urandom(32)
        data = b"test data"
        h1 = compute_hmac(key, data)
        h2 = compute_hmac(key, data)
        assert h1 == h2

    def test_compute_hmac_length(self):
        key = os.urandom(32)
        h = compute_hmac(key, b"data")
        assert len(h) == 32

    def test_compute_hmac_different_data(self):
        key = os.urandom(32)
        h1 = compute_hmac(key, b"data1")
        h2 = compute_hmac(key, b"data2")
        assert h1 != h2


class TestVerifyHmac:
    def test_verify_hmac_valid(self):
        key = os.urandom(32)
        data = b"test data"
        h = compute_hmac(key, data)
        assert verify_hmac(key, data, h) is True

    def test_verify_hmac_tampered_data(self):
        key = os.urandom(32)
        data = b"test data"
        h = compute_hmac(key, data)
        assert verify_hmac(key, b"tampered data", h) is False

    def test_verify_hmac_wrong_key(self):
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        data = b"test data"
        h = compute_hmac(key, data)
        assert verify_hmac(wrong_key, data, h) is False

    def test_verify_hmac_tampered_hmac(self):
        key = os.urandom(32)
        data = b"test data"
        h = compute_hmac(key, data)
        tampered_h = bytearray(h)
        tampered_h[0] ^= 0xFF
        assert verify_hmac(key, data, bytes(tampered_h)) is False
