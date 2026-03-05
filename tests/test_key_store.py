"""Tests for key store disk I/O."""

import json
import os
import stat

import pytest

from file_storage.errors import KeyNotFoundError, KeyStoreCorruptionError
from file_storage.key_store import KeyRecord, KeyStore, PreviousKeyVersion


def make_record(**kwargs) -> KeyRecord:
    defaults = {
        "key_id": "test-key-001",
        "version": 1,
        "created_at": "2026-03-04T12:00:00+00:00",
        "expires_at": None,
        "revoked": False,
        "revoked_at": None,
        "algorithm": "AES-256-GCM",
        "key_material_b64": "dGVzdGtleW1hdGVyaWFs",
        "previous_versions": [],
        "associated_files": [],
        "description": "",
    }
    defaults.update(kwargs)
    return KeyRecord(**defaults)


class TestSaveAndLoad:
    def test_save_and_load_roundtrip(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        record = make_record()
        store.save_key(record)
        loaded = store.load_key("test-key-001")
        assert loaded.key_id == record.key_id
        assert loaded.version == record.version
        assert loaded.key_material_b64 == record.key_material_b64
        assert loaded.expires_at == record.expires_at
        assert loaded.revoked == record.revoked

    def test_save_with_previous_versions(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        prev = PreviousKeyVersion(
            version=0,
            key_material_b64="b2xka2V5",
            created_at="2026-03-01T10:00:00+00:00",
            retired_at="2026-03-04T12:00:00+00:00",
        )
        record = make_record(version=2, previous_versions=[prev])
        store.save_key(record)
        loaded = store.load_key("test-key-001")
        assert len(loaded.previous_versions) == 1
        assert loaded.previous_versions[0].version == 0

    def test_save_with_associated_files(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        record = make_record(associated_files=["/tmp/file1.enc", "/tmp/file2.enc"])
        store.save_key(record)
        loaded = store.load_key("test-key-001")
        assert loaded.associated_files == ["/tmp/file1.enc", "/tmp/file2.enc"]

    def test_save_overwrites_existing(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        record = make_record(description="original")
        store.save_key(record)
        record.description = "updated"
        store.save_key(record)
        loaded = store.load_key("test-key-001")
        assert loaded.description == "updated"


class TestLoadErrors:
    def test_load_nonexistent_key_raises(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        with pytest.raises(KeyNotFoundError, match="nonexistent"):
            store.load_key("nonexistent")

    def test_corrupt_json_raises(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        key_path = store.base_dir / "corrupt-key.json"
        key_path.write_text("{invalid json")
        with pytest.raises(KeyStoreCorruptionError, match="corrupted"):
            store.load_key("corrupt-key")

    def test_missing_fields_raises(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        key_path = store.base_dir / "incomplete-key.json"
        key_path.write_text('{"key_id": "incomplete-key"}')
        with pytest.raises(KeyStoreCorruptionError, match="missing fields"):
            store.load_key("incomplete-key")


class TestFilePermissions:
    def test_save_sets_file_permissions(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        record = make_record()
        store.save_key(record)
        key_path = store.base_dir / "test-key-001.json"
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        assert mode == 0o600


class TestListAndExists:
    def test_list_keys_empty(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        assert store.list_keys() == []

    def test_list_keys_multiple(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        store.save_key(make_record(key_id="key-1"))
        store.save_key(make_record(key_id="key-2"))
        store.save_key(make_record(key_id="key-3"))
        keys = store.list_keys()
        ids = {k.key_id for k in keys}
        assert ids == {"key-1", "key-2", "key-3"}

    def test_list_keys_skips_corrupt(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        store.save_key(make_record(key_id="good-key"))
        corrupt_path = store.base_dir / "bad-key.json"
        corrupt_path.write_text("{bad json")
        keys = store.list_keys()
        assert len(keys) == 1
        assert keys[0].key_id == "good-key"

    def test_key_exists_true(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        store.save_key(make_record())
        assert store.key_exists("test-key-001") is True

    def test_key_exists_false(self, tmp_path):
        store = KeyStore(tmp_path / "keys")
        assert store.key_exists("nonexistent") is False


class TestDirectoryCreation:
    def test_creates_base_dir_if_missing(self, tmp_path):
        store_dir = tmp_path / "nested" / "keys"
        assert not store_dir.exists()
        store = KeyStore(store_dir)
        assert store_dir.exists()
