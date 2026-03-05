"""Tests for RBAC access control engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from file_storage.access_control import AccessController
from file_storage.errors import (
    AccessDeniedError,
    AuthenticationError,
    FileStorageError,
    RoleNotFoundError,
    UserAccessExpiredError,
    UserInactiveError,
    UserNotFoundError,
)
from file_storage.permissions import (
    ALL_PERMISSIONS,
    PERM_DECRYPT,
    PERM_DECRYPT_ANY,
    PERM_ENCRYPT,
    PERM_KEY_CREATE,
    PERM_KEY_INFO,
    PERM_KEY_INFO_ANY,
    PERM_KEY_LIST,
    PERM_KEY_REVOKE,
    PERM_KEY_REVOKE_ANY,
    PERM_KEY_ROTATE,
    PERM_KEY_ROTATE_ANY,
    PERM_ROLE_LIST,
    PERM_USER_CREATE,
    PERM_USER_DEACTIVATE,
    PERM_USER_LIST,
    PERM_USER_INFO,
)
from file_storage.role_store import RoleStore
from file_storage.user_store import UserStore


@pytest.fixture
def stores(tmp_path):
    user_store = UserStore(tmp_path / "users")
    role_store = RoleStore(tmp_path / "roles")
    return user_store, role_store


@pytest.fixture
def ac(stores):
    return AccessController(*stores)


@pytest.fixture
def initialized(ac):
    """An initialized system with admin user."""
    admin = ac.initialize("admin", "admin_pass")
    return {"ac": ac, "admin": admin}


def _create_user_with_role(ac, admin, username, role_name, password="pass123"):
    """Helper to create a user with a named role."""
    return ac.create_user(admin, username, password, role_name)


class TestInitialization:
    def test_is_initialized_false_when_empty(self, ac):
        assert ac.is_initialized() is False

    def test_is_initialized_true_after_init(self, ac):
        ac.initialize("admin", "password")
        assert ac.is_initialized() is True

    def test_initialize_creates_default_roles(self, ac):
        ac.initialize("admin", "password")
        roles = ac.role_store.list_roles()
        role_names = {r.name for r in roles}
        assert role_names == {"admin", "key_manager", "encryptor", "viewer", "auditor"}

    def test_initialize_creates_admin_user(self, ac):
        admin = ac.initialize("myadmin", "password")
        assert admin.username == "myadmin"
        assert admin.is_active is True
        assert len(admin.role_ids) == 1

    def test_initialize_admin_has_admin_role(self, ac):
        admin = ac.initialize("admin", "password")
        perms = ac.get_user_permissions(admin)
        assert perms == set(ALL_PERMISSIONS)

    def test_initialize_twice_raises(self, ac):
        ac.initialize("admin", "password")
        with pytest.raises(FileStorageError, match="already initialized"):
            ac.initialize("admin2", "password2")


class TestUserResolution:
    def test_resolve_user_found_and_active(self, initialized):
        ac = initialized["ac"]
        user = ac.resolve_user("admin")
        assert user.username == "admin"

    def test_resolve_user_not_found(self, initialized):
        ac = initialized["ac"]
        with pytest.raises(UserNotFoundError):
            ac.resolve_user("nobody")

    def test_resolve_inactive_user_raises(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        bob = _create_user_with_role(ac, admin, "bob", "encryptor")
        ac.deactivate_user(admin, "bob")
        with pytest.raises(UserInactiveError, match="deactivated"):
            ac.resolve_user("bob")

    def test_resolve_expired_user_raises(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        bob = _create_user_with_role(ac, admin, "bob", "encryptor")
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        ac.set_user_expiry(admin, "bob", past)
        with pytest.raises(UserAccessExpiredError, match="expired"):
            ac.resolve_user("bob")

    def test_resolve_user_with_future_expiry_succeeds(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        bob = _create_user_with_role(ac, admin, "bob", "encryptor")
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        ac.set_user_expiry(admin, "bob", future)
        user = ac.resolve_user("bob")
        assert user.username == "bob"


class TestAuthentication:
    def test_authenticate_correct_password(self, initialized):
        ac = initialized["ac"]
        user = ac.authenticate_user("admin", "admin_pass")
        assert user.username == "admin"

    def test_authenticate_wrong_password(self, initialized):
        ac = initialized["ac"]
        with pytest.raises(AuthenticationError, match="Invalid password"):
            ac.authenticate_user("admin", "wrong_pass")

    def test_authenticate_inactive_user(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        bob = _create_user_with_role(ac, admin, "bob", "encryptor", password="bobpass")
        ac.deactivate_user(admin, "bob")
        with pytest.raises(UserInactiveError):
            ac.authenticate_user("bob", "bobpass")

    def test_authenticate_expired_user(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        bob = _create_user_with_role(ac, admin, "bob", "encryptor", password="bobpass")
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        ac.set_user_expiry(admin, "bob", past)
        with pytest.raises(UserAccessExpiredError):
            ac.authenticate_user("bob", "bobpass")


class TestPermissionChecks:
    def test_admin_has_all_permissions(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        for perm in ALL_PERMISSIONS:
            assert ac.has_permission(admin, perm) is True

    def test_encryptor_can_encrypt(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        assert ac.has_permission(enc, PERM_ENCRYPT) is True

    def test_encryptor_cannot_create_users(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        assert ac.has_permission(enc, PERM_USER_CREATE) is False

    def test_viewer_cannot_encrypt(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        viewer = _create_user_with_role(ac, admin, "viewer1", "viewer")
        assert ac.has_permission(viewer, PERM_ENCRYPT) is False

    def test_viewer_can_list_keys(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        viewer = _create_user_with_role(ac, admin, "viewer1", "viewer")
        assert ac.has_permission(viewer, PERM_KEY_LIST) is True

    def test_auditor_can_list_users(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        auditor = _create_user_with_role(ac, admin, "auditor1", "auditor")
        assert ac.has_permission(auditor, PERM_USER_LIST) is True

    def test_auditor_cannot_encrypt(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        auditor = _create_user_with_role(ac, admin, "auditor1", "auditor")
        assert ac.has_permission(auditor, PERM_ENCRYPT) is False

    def test_check_permission_raises_access_denied(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        viewer = _create_user_with_role(ac, admin, "viewer1", "viewer")
        with pytest.raises(AccessDeniedError, match="lacks permission"):
            ac.check_permission(viewer, PERM_ENCRYPT)

    def test_deny_by_default_unknown_permission(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        assert ac.has_permission(enc, "nonexistent:permission") is False

    def test_key_manager_can_decrypt_any(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        km = _create_user_with_role(ac, admin, "km1", "key_manager")
        assert ac.has_permission(km, PERM_DECRYPT_ANY) is True

    def test_encryptor_cannot_decrypt_any(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        assert ac.has_permission(enc, PERM_DECRYPT_ANY) is False


class TestOwnershipChecks:
    def test_owner_can_rotate_own_key(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        # Encryptor has key:rotate -- should not raise for own key
        ac.check_key_access(enc, PERM_KEY_ROTATE, PERM_KEY_ROTATE_ANY, enc.user_id)

    def test_owner_cannot_rotate_other_key_without_any(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        with pytest.raises(AccessDeniedError):
            ac.check_key_access(enc, PERM_KEY_ROTATE, PERM_KEY_ROTATE_ANY, "other-user-id")

    def test_admin_can_revoke_any_key(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        # Admin has revoke_any
        ac.check_key_access(admin, PERM_KEY_REVOKE, PERM_KEY_REVOKE_ANY, "other-user-id")

    def test_key_manager_can_revoke_any_key(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        km = _create_user_with_role(ac, admin, "km1", "key_manager")
        ac.check_key_access(km, PERM_KEY_REVOKE, PERM_KEY_REVOKE_ANY, "other-user-id")

    def test_legacy_key_no_owner_requires_any_permission(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        # Legacy key (owner_id=None) -- encryptor doesn't have _any
        with pytest.raises(AccessDeniedError):
            ac.check_key_access(enc, PERM_KEY_REVOKE, PERM_KEY_REVOKE_ANY, None)

    def test_admin_can_access_legacy_key(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        # Admin has _any, so can access legacy keys
        ac.check_key_access(admin, PERM_KEY_REVOKE, PERM_KEY_REVOKE_ANY, None)

    def test_owner_can_decrypt_own_file(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        ac.check_key_access(enc, PERM_DECRYPT, PERM_DECRYPT_ANY, enc.user_id)

    def test_cannot_decrypt_others_file_without_any(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        with pytest.raises(AccessDeniedError):
            ac.check_key_access(enc, PERM_DECRYPT, PERM_DECRYPT_ANY, "other-user-id")

    def test_admin_can_decrypt_any_file(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        ac.check_key_access(admin, PERM_DECRYPT, PERM_DECRYPT_ANY, "other-user-id")


class TestUserManagement:
    def test_admin_can_create_user(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        user = _create_user_with_role(ac, admin, "newuser", "encryptor")
        assert user.username == "newuser"
        assert user.is_active is True

    def test_encryptor_cannot_create_user(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        with pytest.raises(AccessDeniedError, match="lacks permission"):
            ac.create_user(enc, "unauthorized", "pass", "viewer")

    def test_create_user_duplicate_username_raises(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        _create_user_with_role(ac, admin, "alice", "encryptor")
        with pytest.raises(FileStorageError, match="already exists"):
            ac.create_user(admin, "alice", "pass", "viewer")

    def test_create_user_unknown_role_raises(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        with pytest.raises(RoleNotFoundError):
            ac.create_user(admin, "newuser", "pass", "nonexistent_role")

    def test_deactivate_user(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        bob = _create_user_with_role(ac, admin, "bob", "encryptor")
        result = ac.deactivate_user(admin, "bob")
        assert result.is_active is False
        assert result.deactivated_at is not None

    def test_cannot_deactivate_self(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        with pytest.raises(AccessDeniedError, match="Cannot deactivate yourself"):
            ac.deactivate_user(admin, "admin")

    def test_set_user_expiry(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        bob = _create_user_with_role(ac, admin, "bob", "encryptor")
        future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        result = ac.set_user_expiry(admin, "bob", future)
        assert result.access_expires_at == future

    def test_list_users_requires_permission(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        with pytest.raises(AccessDeniedError):
            ac.list_users(enc)

    def test_admin_can_list_users(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        _create_user_with_role(ac, admin, "bob", "encryptor")
        users = ac.list_users(admin)
        usernames = {u.username for u in users}
        assert "admin" in usernames
        assert "bob" in usernames

    def test_get_user_info_requires_permission(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        enc = _create_user_with_role(ac, admin, "enc", "encryptor")
        with pytest.raises(AccessDeniedError):
            ac.get_user_info(enc, "admin")

    def test_admin_can_get_user_info(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        _create_user_with_role(ac, admin, "bob", "encryptor")
        info = ac.get_user_info(admin, "bob")
        assert info.username == "bob"


class TestTimeBased:
    def test_user_access_expires_at_past_is_rejected(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        bob = _create_user_with_role(ac, admin, "bob", "encryptor")
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        ac.set_user_expiry(admin, "bob", past)
        with pytest.raises(UserAccessExpiredError):
            ac.resolve_user("bob")

    def test_user_access_expires_at_future_is_accepted(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        bob = _create_user_with_role(ac, admin, "bob", "encryptor")
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        ac.set_user_expiry(admin, "bob", future)
        user = ac.resolve_user("bob")
        assert user.username == "bob"

    def test_user_access_expires_at_none_never_expires(self, initialized):
        ac = initialized["ac"]
        admin = initialized["admin"]
        bob = _create_user_with_role(ac, admin, "bob", "encryptor")
        # access_expires_at is None by default -- should not expire
        user = ac.resolve_user("bob")
        assert user.username == "bob"
