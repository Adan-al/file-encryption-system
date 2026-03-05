"""Tests for key lifecycle management."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from file_storage.errors import KeyExpiredError, KeyNotFoundError, KeyRevokedError
from file_storage.key_manager import KeyManager
from file_storage.key_store import KeyStore


@pytest.fixture
def key_manager(tmp_path):
    store = KeyStore(tmp_path / "keys")
    return KeyManager(store)


class TestCreateKey:
    def test_create_key_generates_valid_record(self, key_manager):
        record = key_manager.create_key()
        assert record.key_id is not None
        assert record.version == 1
        assert record.algorithm == "AES-256-GCM"
        assert record.revoked is False
        assert record.expires_at is None
        assert record.key_material_b64 is not None
        # Verify key material is valid base64 encoding of 32 bytes
        raw = base64.b64decode(record.key_material_b64)
        assert len(raw) == 32

    def test_create_key_unique_ids(self, key_manager):
        r1 = key_manager.create_key()
        r2 = key_manager.create_key()
        assert r1.key_id != r2.key_id

    def test_create_key_with_description(self, key_manager):
        record = key_manager.create_key(description="test key")
        assert record.description == "test key"

    def test_create_key_persisted(self, key_manager):
        record = key_manager.create_key()
        loaded = key_manager.get_key(record.key_id)
        assert loaded.key_id == record.key_id


class TestGetKey:
    def test_get_key_by_id(self, key_manager):
        record = key_manager.create_key()
        loaded = key_manager.get_key(record.key_id)
        assert loaded.key_id == record.key_id
        assert loaded.key_material_b64 == record.key_material_b64

    def test_get_key_not_found(self, key_manager):
        with pytest.raises(KeyNotFoundError):
            key_manager.get_key("nonexistent-key-id")


class TestValidateKey:
    def test_validate_active_key(self, key_manager):
        record = key_manager.create_key()
        # Should not raise
        key_manager.validate_key_for_use(record)

    def test_validate_expired_key_raises(self, key_manager):
        record = key_manager.create_key()
        # Set expiry in the past
        record.expires_at = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat()
        with pytest.raises(KeyExpiredError):
            key_manager.validate_key_for_use(record)

    def test_validate_revoked_key_raises(self, key_manager):
        record = key_manager.create_key()
        record.revoked = True
        record.revoked_at = datetime.now(timezone.utc).isoformat()
        with pytest.raises(KeyRevokedError):
            key_manager.validate_key_for_use(record)

    def test_validate_key_with_future_expiry(self, key_manager):
        record = key_manager.create_key()
        record.expires_at = (
            datetime.now(timezone.utc) + timedelta(days=30)
        ).isoformat()
        # Should not raise
        key_manager.validate_key_for_use(record)


class TestRevokeKey:
    def test_revoke_key_sets_fields(self, key_manager):
        record = key_manager.create_key()
        revoked = key_manager.revoke_key(record.key_id)
        assert revoked.revoked is True
        assert revoked.revoked_at is not None

    def test_revoke_key_idempotent(self, key_manager):
        record = key_manager.create_key()
        r1 = key_manager.revoke_key(record.key_id)
        r2 = key_manager.revoke_key(record.key_id)
        assert r1.revoked_at == r2.revoked_at

    def test_revoke_key_persisted(self, key_manager):
        record = key_manager.create_key()
        key_manager.revoke_key(record.key_id)
        loaded = key_manager.get_key(record.key_id)
        assert loaded.revoked is True


class TestSetExpiry:
    def test_set_expiry_future(self, key_manager):
        record = key_manager.create_key()
        future = datetime.now(timezone.utc) + timedelta(days=7)
        updated = key_manager.set_expiry(record.key_id, future)
        assert updated.expires_at is not None

    def test_set_expiry_past_raises(self, key_manager):
        record = key_manager.create_key()
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        with pytest.raises(ValueError, match="future"):
            key_manager.set_expiry(record.key_id, past)

    def test_set_expiry_persisted(self, key_manager):
        record = key_manager.create_key()
        future = datetime.now(timezone.utc) + timedelta(days=7)
        key_manager.set_expiry(record.key_id, future)
        loaded = key_manager.get_key(record.key_id)
        assert loaded.expires_at is not None


class TestRotateKey:
    def test_rotate_key_increments_version(self, key_manager):
        record = key_manager.create_key()
        rotated = key_manager.rotate_key(record.key_id)
        assert rotated.version == 2

    def test_rotate_key_preserves_history(self, key_manager):
        record = key_manager.create_key()
        old_material = record.key_material_b64
        rotated = key_manager.rotate_key(record.key_id)
        assert len(rotated.previous_versions) == 1
        assert rotated.previous_versions[0].version == 1
        assert rotated.previous_versions[0].key_material_b64 == old_material

    def test_rotate_key_generates_new_material(self, key_manager):
        record = key_manager.create_key()
        old_material = record.key_material_b64
        rotated = key_manager.rotate_key(record.key_id)
        assert rotated.key_material_b64 != old_material

    def test_rotate_revoked_key_raises(self, key_manager):
        record = key_manager.create_key()
        key_manager.revoke_key(record.key_id)
        with pytest.raises(KeyRevokedError):
            key_manager.rotate_key(record.key_id)

    def test_rotate_key_clears_expiry(self, key_manager):
        record = key_manager.create_key()
        future = datetime.now(timezone.utc) + timedelta(days=1)
        key_manager.set_expiry(record.key_id, future)
        rotated = key_manager.rotate_key(record.key_id)
        assert rotated.expires_at is None

    def test_double_rotate_preserves_all_history(self, key_manager):
        record = key_manager.create_key()
        key_manager.rotate_key(record.key_id)
        rotated = key_manager.rotate_key(record.key_id)
        assert rotated.version == 3
        assert len(rotated.previous_versions) == 2
        assert rotated.previous_versions[0].version == 1
        assert rotated.previous_versions[1].version == 2


class TestKeyMaterial:
    def test_get_key_material(self, key_manager):
        record = key_manager.create_key()
        material = key_manager.get_key_material(record)
        assert isinstance(material, bytes)
        assert len(material) == 32

    def test_get_key_material_for_current_version(self, key_manager):
        record = key_manager.create_key()
        material = key_manager.get_key_material_for_version(record, record.version)
        assert material == key_manager.get_key_material(record)

    def test_get_key_material_for_old_version(self, key_manager):
        record = key_manager.create_key()
        old_material = key_manager.get_key_material(record)
        rotated = key_manager.rotate_key(record.key_id)
        loaded = key_manager.get_key(record.key_id)
        historical = key_manager.get_key_material_for_version(loaded, 1)
        assert historical == old_material

    def test_get_key_material_for_missing_version(self, key_manager):
        record = key_manager.create_key()
        with pytest.raises(KeyNotFoundError, match="version"):
            key_manager.get_key_material_for_version(record, 99)


class TestListKeys:
    def test_list_keys_empty(self, key_manager):
        assert key_manager.list_keys() == []

    def test_list_keys_multiple(self, key_manager):
        key_manager.create_key()
        key_manager.create_key()
        key_manager.create_key()
        keys = key_manager.list_keys()
        assert len(keys) == 3


class TestFileAssociations:
    def test_add_file_association(self, key_manager, tmp_path):
        record = key_manager.create_key()
        test_file = str(tmp_path / "test.enc")
        key_manager.add_file_association(record.key_id, test_file)
        loaded = key_manager.get_key(record.key_id)
        assert len(loaded.associated_files) == 1

    def test_add_duplicate_file_association(self, key_manager, tmp_path):
        record = key_manager.create_key()
        test_file = str(tmp_path / "test.enc")
        key_manager.add_file_association(record.key_id, test_file)
        key_manager.add_file_association(record.key_id, test_file)
        loaded = key_manager.get_key(record.key_id)
        assert len(loaded.associated_files) == 1

    def test_remove_file_association(self, key_manager, tmp_path):
        record = key_manager.create_key()
        test_file = str(tmp_path / "test.enc")
        key_manager.add_file_association(record.key_id, test_file)
        key_manager.remove_file_association(record.key_id, test_file)
        loaded = key_manager.get_key(record.key_id)
        assert len(loaded.associated_files) == 0


class TestGetKeyStatus:
    def test_status_active(self, key_manager):
        record = key_manager.create_key()
        assert key_manager.get_key_status(record) == "active"

    def test_status_revoked(self, key_manager):
        record = key_manager.create_key()
        revoked = key_manager.revoke_key(record.key_id)
        assert key_manager.get_key_status(revoked) == "revoked"

    def test_status_expired(self, key_manager):
        record = key_manager.create_key()
        record.expires_at = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat()
        assert key_manager.get_key_status(record) == "expired"
