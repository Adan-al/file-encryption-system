"""Tests for user store disk I/O and password hashing."""

import json
import os
import stat

import pytest

from file_storage.errors import UserNotFoundError, StoreCorruptionError
from file_storage.user_store import (
    UserRecord,
    UserStore,
    hash_password,
    verify_password,
)


def make_user(**kwargs) -> UserRecord:
    defaults = {
        "user_id": "test-user-001",
        "username": "alice",
        "password_hash": hash_password("password123"),
        "role_ids": ["role-1"],
        "created_at": "2026-03-04T12:00:00+00:00",
        "is_active": True,
        "access_expires_at": None,
        "deactivated_at": None,
    }
    defaults.update(kwargs)
    return UserRecord(**defaults)


class TestPasswordHashing:
    def test_hash_password_produces_valid_format(self):
        h = hash_password("test")
        assert h.startswith("pbkdf2:sha256:")
        parts = h.split("$")
        assert len(parts) == 3

    def test_verify_password_correct(self):
        h = hash_password("mypassword")
        assert verify_password("mypassword", h) is True

    def test_verify_password_wrong(self):
        h = hash_password("mypassword")
        assert verify_password("wrongpassword", h) is False

    def test_hash_password_unique_salts(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # Different salts produce different hashes

    def test_verify_with_invalid_hash_format(self):
        assert verify_password("test", "not-a-valid-hash") is False

    def test_verify_both_hashes_valid(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert verify_password("same", h1) is True
        assert verify_password("same", h2) is True


class TestUserSaveAndLoad:
    def test_save_and_load_roundtrip(self, tmp_path):
        store = UserStore(tmp_path / "users")
        record = make_user()
        store.save_user(record)
        loaded = store.load_user("test-user-001")
        assert loaded.user_id == record.user_id
        assert loaded.username == record.username
        assert loaded.role_ids == record.role_ids
        assert loaded.is_active == record.is_active

    def test_save_with_all_fields(self, tmp_path):
        store = UserStore(tmp_path / "users")
        record = make_user(
            access_expires_at="2026-12-31T23:59:59+00:00",
            deactivated_at="2026-06-01T00:00:00+00:00",
            is_active=False,
        )
        store.save_user(record)
        loaded = store.load_user("test-user-001")
        assert loaded.access_expires_at == "2026-12-31T23:59:59+00:00"
        assert loaded.deactivated_at == "2026-06-01T00:00:00+00:00"
        assert loaded.is_active is False

    def test_save_overwrites_existing(self, tmp_path):
        store = UserStore(tmp_path / "users")
        record = make_user(is_active=True)
        store.save_user(record)
        record.is_active = False
        store.save_user(record)
        loaded = store.load_user("test-user-001")
        assert loaded.is_active is False

    def test_load_nonexistent_user_raises(self, tmp_path):
        store = UserStore(tmp_path / "users")
        with pytest.raises(UserNotFoundError, match="nonexistent"):
            store.load_user("nonexistent")

    def test_corrupt_json_raises(self, tmp_path):
        store = UserStore(tmp_path / "users")
        path = store.base_dir / "corrupt.json"
        path.write_text("{invalid json")
        with pytest.raises(StoreCorruptionError, match="corrupted"):
            store.load_user("corrupt")

    def test_missing_fields_raises(self, tmp_path):
        store = UserStore(tmp_path / "users")
        path = store.base_dir / "incomplete.json"
        path.write_text('{"user_id": "incomplete"}')
        with pytest.raises(StoreCorruptionError, match="missing fields"):
            store.load_user("incomplete")


class TestUserLookupByUsername:
    def test_load_user_by_username_found(self, tmp_path):
        store = UserStore(tmp_path / "users")
        store.save_user(make_user(user_id="u1", username="alice"))
        store.save_user(make_user(user_id="u2", username="bob"))
        loaded = store.load_user_by_username("bob")
        assert loaded.user_id == "u2"
        assert loaded.username == "bob"

    def test_load_user_by_username_not_found(self, tmp_path):
        store = UserStore(tmp_path / "users")
        store.save_user(make_user(user_id="u1", username="alice"))
        with pytest.raises(UserNotFoundError, match="charlie"):
            store.load_user_by_username("charlie")

    def test_username_exists_true(self, tmp_path):
        store = UserStore(tmp_path / "users")
        store.save_user(make_user(user_id="u1", username="alice"))
        assert store.username_exists("alice") is True

    def test_username_exists_false(self, tmp_path):
        store = UserStore(tmp_path / "users")
        assert store.username_exists("nobody") is False

    def test_username_index_rebuilt_on_missing(self, tmp_path):
        store = UserStore(tmp_path / "users")
        store.save_user(make_user(user_id="u1", username="alice"))
        # Delete the index file
        idx_path = store.base_dir / "_username_index.json"
        if idx_path.exists():
            idx_path.unlink()
        # Should still find via scan
        loaded = store.load_user_by_username("alice")
        assert loaded.username == "alice"
        # Index should be rebuilt
        assert idx_path.exists()


class TestUserList:
    def test_list_users_empty(self, tmp_path):
        store = UserStore(tmp_path / "users")
        assert store.list_users() == []

    def test_list_users_multiple(self, tmp_path):
        store = UserStore(tmp_path / "users")
        store.save_user(make_user(user_id="u1", username="alice"))
        store.save_user(make_user(user_id="u2", username="bob"))
        store.save_user(make_user(user_id="u3", username="charlie"))
        users = store.list_users()
        names = {u.username for u in users}
        assert names == {"alice", "bob", "charlie"}

    def test_list_users_skips_corrupt(self, tmp_path):
        store = UserStore(tmp_path / "users")
        store.save_user(make_user(user_id="good", username="good"))
        corrupt = store.base_dir / "bad.json"
        corrupt.write_text("{bad json")
        users = store.list_users()
        assert len(users) == 1
        assert users[0].username == "good"

    def test_list_users_skips_index_file(self, tmp_path):
        store = UserStore(tmp_path / "users")
        store.save_user(make_user(user_id="u1", username="alice"))
        users = store.list_users()
        # Should only return 1 user, not the index file
        assert len(users) == 1


class TestUserFilePermissions:
    def test_save_sets_0o600_permissions(self, tmp_path):
        store = UserStore(tmp_path / "users")
        store.save_user(make_user())
        path = store.base_dir / "test-user-001.json"
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600


class TestUserDirectoryCreation:
    def test_creates_base_dir_if_missing(self, tmp_path):
        store_dir = tmp_path / "nested" / "users"
        assert not store_dir.exists()
        UserStore(store_dir)
        assert store_dir.exists()


class TestUserExists:
    def test_user_exists_true(self, tmp_path):
        store = UserStore(tmp_path / "users")
        store.save_user(make_user())
        assert store.user_exists("test-user-001") is True

    def test_user_exists_false(self, tmp_path):
        store = UserStore(tmp_path / "users")
        assert store.user_exists("nonexistent") is False
