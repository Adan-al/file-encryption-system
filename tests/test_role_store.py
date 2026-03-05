"""Tests for role store disk I/O."""

import json
import os
import stat

import pytest

from file_storage.errors import RoleNotFoundError, StoreCorruptionError
from file_storage.role_store import RoleRecord, RoleStore


def make_role(**kwargs) -> RoleRecord:
    defaults = {
        "role_id": "test-role-001",
        "name": "testrole",
        "permissions": ["file:encrypt", "file:decrypt"],
        "description": "A test role",
        "created_at": "2026-03-04T12:00:00+00:00",
    }
    defaults.update(kwargs)
    return RoleRecord(**defaults)


class TestRoleSaveAndLoad:
    def test_save_and_load_roundtrip(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        record = make_role()
        store.save_role(record)
        loaded = store.load_role("test-role-001")
        assert loaded.role_id == record.role_id
        assert loaded.name == record.name
        assert loaded.permissions == record.permissions
        assert loaded.description == record.description

    def test_save_with_permissions(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        perms = ["file:encrypt", "key:create", "key:list"]
        record = make_role(permissions=perms)
        store.save_role(record)
        loaded = store.load_role("test-role-001")
        assert loaded.permissions == perms

    def test_save_overwrites_existing(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        record = make_role(description="original")
        store.save_role(record)
        record.description = "updated"
        store.save_role(record)
        loaded = store.load_role("test-role-001")
        assert loaded.description == "updated"

    def test_load_nonexistent_role_raises(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        with pytest.raises(RoleNotFoundError, match="nonexistent"):
            store.load_role("nonexistent")

    def test_corrupt_json_raises(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        path = store.base_dir / "corrupt.json"
        path.write_text("{invalid json")
        with pytest.raises(StoreCorruptionError, match="corrupted"):
            store.load_role("corrupt")

    def test_missing_fields_raises(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        path = store.base_dir / "incomplete.json"
        path.write_text('{"role_id": "incomplete"}')
        with pytest.raises(StoreCorruptionError, match="missing fields"):
            store.load_role("incomplete")


class TestRoleLookupByName:
    def test_load_role_by_name_found(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        store.save_role(make_role(role_id="r1", name="admin"))
        store.save_role(make_role(role_id="r2", name="viewer"))
        loaded = store.load_role_by_name("viewer")
        assert loaded.role_id == "r2"
        assert loaded.name == "viewer"

    def test_load_role_by_name_not_found(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        store.save_role(make_role(role_id="r1", name="admin"))
        with pytest.raises(RoleNotFoundError, match="nonexistent"):
            store.load_role_by_name("nonexistent")


class TestRoleList:
    def test_list_roles_empty(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        assert store.list_roles() == []

    def test_list_roles_multiple(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        store.save_role(make_role(role_id="r1", name="admin"))
        store.save_role(make_role(role_id="r2", name="viewer"))
        store.save_role(make_role(role_id="r3", name="encryptor"))
        roles = store.list_roles()
        names = {r.name for r in roles}
        assert names == {"admin", "viewer", "encryptor"}

    def test_list_roles_skips_corrupt(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        store.save_role(make_role(role_id="good", name="good"))
        corrupt = store.base_dir / "bad.json"
        corrupt.write_text("{bad json")
        roles = store.list_roles()
        assert len(roles) == 1
        assert roles[0].name == "good"


class TestRoleFilePermissions:
    def test_save_sets_0o600_permissions(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        store.save_role(make_role())
        path = store.base_dir / "test-role-001.json"
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600


class TestRoleDirectoryCreation:
    def test_creates_base_dir_if_missing(self, tmp_path):
        store_dir = tmp_path / "nested" / "roles"
        assert not store_dir.exists()
        RoleStore(store_dir)
        assert store_dir.exists()


class TestRoleExists:
    def test_role_exists_true(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        store.save_role(make_role())
        assert store.role_exists("test-role-001") is True

    def test_role_exists_false(self, tmp_path):
        store = RoleStore(tmp_path / "roles")
        assert store.role_exists("nonexistent") is False
