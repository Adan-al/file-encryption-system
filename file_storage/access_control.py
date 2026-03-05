"""RBAC access control engine."""

from __future__ import annotations

import logging

from file_storage.errors import (
    AccessDeniedError,
    AuthenticationError,
    FileStorageError,
    RoleNotFoundError,
    UserAccessExpiredError,
    UserInactiveError,
)
from file_storage.permissions import DEFAULT_ROLES
from file_storage.role_store import RoleRecord, RoleStore
from file_storage.user_store import (
    UserRecord,
    UserStore,
    hash_password,
    verify_password,
)
from file_storage.utils import generate_uuid, is_expired, utc_now_iso

logger = logging.getLogger("file_storage.access_control")


class AccessController:
    """Enforces RBAC policies for all file_storage operations.

    Called by CLI handlers before KeyManager methods. The KeyManager
    interface remains unchanged; RBAC is an opt-in governance layer.
    """

    def __init__(self, user_store: UserStore, role_store: RoleStore):
        self._user_store = user_store
        self._role_store = role_store

    @property
    def user_store(self) -> UserStore:
        return self._user_store

    @property
    def role_store(self) -> RoleStore:
        return self._role_store

    # --- System initialization ---

    def is_initialized(self) -> bool:
        """Check if the RBAC system has been initialized (any roles exist)."""
        return len(self._role_store.list_roles()) > 0

    def initialize(self, admin_username: str, admin_password: str) -> UserRecord:
        """Bootstrap the RBAC system: seed default roles, create admin user.

        Can only be called once.
        """
        if self.is_initialized():
            raise FileStorageError("System is already initialized")

        # Seed all default roles
        role_id_map: dict[str, str] = {}
        for role_name, role_def in DEFAULT_ROLES.items():
            role_id = generate_uuid()
            role = RoleRecord(
                role_id=role_id,
                name=role_name,
                permissions=role_def["permissions"],
                description=role_def["description"],
                created_at=utc_now_iso(),
            )
            self._role_store.save_role(role)
            role_id_map[role_name] = role_id

        # Create admin user
        user = UserRecord(
            user_id=generate_uuid(),
            username=admin_username,
            password_hash=hash_password(admin_password),
            role_ids=[role_id_map["admin"]],
            created_at=utc_now_iso(),
            is_active=True,
            access_expires_at=None,
            deactivated_at=None,
        )
        self._user_store.save_user(user)
        logger.info("System initialized, admin user created: %s", admin_username)
        return user

    # --- User validation ---

    def authenticate_user(self, username: str, password: str) -> UserRecord:
        """Authenticate a user by username and password."""
        user = self._user_store.load_user_by_username(username)
        if not verify_password(password, user.password_hash):
            logger.warning("Authentication failed for user: %s", username)
            raise AuthenticationError("Invalid password")
        self._validate_user_active(user)
        logger.info("User authenticated: %s", username)
        return user

    def resolve_user(self, username: str) -> UserRecord:
        """Look up a user by username and validate they are active."""
        user = self._user_store.load_user_by_username(username)
        self._validate_user_active(user)
        return user

    def _validate_user_active(self, user: UserRecord) -> None:
        """Check that a user is active and not expired."""
        if not user.is_active:
            raise UserInactiveError(
                f"User '{user.username}' has been deactivated"
            )
        if is_expired(user.access_expires_at):
            raise UserAccessExpiredError(
                f"User '{user.username}' access expired at {user.access_expires_at}"
            )

    # --- Permission resolution ---

    def get_user_permissions(self, user: UserRecord) -> set[str]:
        """Resolve the complete set of permissions for a user across all roles."""
        permissions: set[str] = set()
        for role_id in user.role_ids:
            try:
                role = self._role_store.load_role(role_id)
                permissions.update(role.permissions)
            except RoleNotFoundError:
                continue
        return permissions

    def has_permission(self, user: UserRecord, permission: str) -> bool:
        """Check if a user has a specific permission."""
        return permission in self.get_user_permissions(user)

    # --- Access enforcement ---

    def check_permission(self, user: UserRecord, permission: str) -> None:
        """Assert that a user has a permission. Raises AccessDeniedError if not."""
        if not self.has_permission(user, permission):
            logger.warning(
                "Access denied: user '%s' lacks permission '%s'",
                user.username,
                permission,
            )
            raise AccessDeniedError(
                f"User '{user.username}' lacks permission '{permission}'"
            )

    def check_key_access(
        self,
        user: UserRecord,
        permission: str,
        any_permission: str,
        key_owner_id: str | None,
    ) -> None:
        """Check permission for a key operation, considering ownership.

        - If user has any_permission, access is granted (can operate on any key).
        - If user has permission AND user.user_id == key_owner_id, access is granted.
        - If key_owner_id is None (legacy pre-RBAC key), only any_permission grants access.
        - Otherwise, raise AccessDeniedError.
        """
        perms = self.get_user_permissions(user)

        if any_permission in perms:
            return

        if permission in perms and key_owner_id == user.user_id:
            return

        logger.warning(
            "Key access denied: user '%s' for key owned by '%s'",
            user.username,
            key_owner_id or "unknown",
        )
        raise AccessDeniedError(
            f"User '{user.username}' lacks permission to perform this operation "
            f"on key owned by '{key_owner_id or 'unknown'}'"
        )

    # --- User management operations ---

    def create_user(
        self,
        acting_user: UserRecord,
        username: str,
        password: str,
        role_name: str,
    ) -> UserRecord:
        """Create a new user. Requires user:create permission."""
        self.check_permission(acting_user, "user:create")

        if self._user_store.username_exists(username):
            raise FileStorageError(f"Username '{username}' already exists")

        role = self._role_store.load_role_by_name(role_name)

        user = UserRecord(
            user_id=generate_uuid(),
            username=username,
            password_hash=hash_password(password),
            role_ids=[role.role_id],
            created_at=utc_now_iso(),
            is_active=True,
            access_expires_at=None,
            deactivated_at=None,
        )
        self._user_store.save_user(user)
        logger.info(
            "User created: '%s' with role '%s' (by '%s')",
            username,
            role_name,
            acting_user.username,
        )
        return user

    def deactivate_user(
        self,
        acting_user: UserRecord,
        target_username: str,
    ) -> UserRecord:
        """Deactivate a user. Requires user:deactivate permission."""
        self.check_permission(acting_user, "user:deactivate")
        target = self._user_store.load_user_by_username(target_username)

        if target.user_id == acting_user.user_id:
            raise AccessDeniedError("Cannot deactivate yourself")

        target.is_active = False
        target.deactivated_at = utc_now_iso()
        self._user_store.save_user(target)
        logger.info(
            "User deactivated: '%s' (by '%s')",
            target_username,
            acting_user.username,
        )
        return target

    def set_user_expiry(
        self,
        acting_user: UserRecord,
        target_username: str,
        expires_at: str,
    ) -> UserRecord:
        """Set access expiry on a user. Requires user:set_expiry permission."""
        self.check_permission(acting_user, "user:set_expiry")
        target = self._user_store.load_user_by_username(target_username)
        target.access_expires_at = expires_at
        self._user_store.save_user(target)
        logger.info(
            "User expiry set: '%s' -> %s (by '%s')",
            target_username,
            expires_at,
            acting_user.username,
        )
        return target

    def list_users(self, acting_user: UserRecord) -> list[UserRecord]:
        """List all users. Requires user:list permission."""
        self.check_permission(acting_user, "user:list")
        return self._user_store.list_users()

    def get_user_info(
        self, acting_user: UserRecord, target_username: str
    ) -> UserRecord:
        """Get user details. Requires user:info permission."""
        self.check_permission(acting_user, "user:info")
        return self._user_store.load_user_by_username(target_username)
