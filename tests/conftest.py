"""Shared pytest fixtures."""

from __future__ import annotations

import os

import pytest

from file_storage.access_control import AccessController
from file_storage.key_manager import KeyManager
from file_storage.key_store import KeyStore
from file_storage.role_store import RoleStore
from file_storage.user_store import UserStore


@pytest.fixture
def tmp_keystore(tmp_path):
    """Provide a temporary key store directory."""
    ks = tmp_path / "keys"
    ks.mkdir()
    return ks


@pytest.fixture
def key_manager(tmp_keystore):
    """Provide a KeyManager with a temporary store."""
    store = KeyStore(tmp_keystore)
    return KeyManager(store)


@pytest.fixture
def sample_file(tmp_path):
    """Create a sample plaintext file."""
    f = tmp_path / "sample.txt"
    f.write_text("Hello, World! This is test content for encryption.")
    return f


@pytest.fixture
def empty_file(tmp_path):
    """Create an empty file."""
    f = tmp_path / "empty.txt"
    f.write_bytes(b"")
    return f


@pytest.fixture
def large_file(tmp_path):
    """Create a 10MB file."""
    f = tmp_path / "large.bin"
    f.write_bytes(os.urandom(10 * 1024 * 1024))
    return f


@pytest.fixture
def binary_file(tmp_path):
    """Create a binary file with non-text content."""
    f = tmp_path / "data.bin"
    f.write_bytes(bytes(range(256)) * 100)
    return f
