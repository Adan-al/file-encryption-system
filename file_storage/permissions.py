"""Permission constants and default role definitions for RBAC."""

from __future__ import annotations

# --- Permission constants ---
# Each permission is a colon-separated string: "resource:action"

# File operations
PERM_ENCRYPT: str = "file:encrypt"
PERM_DECRYPT: str = "file:decrypt"
PERM_DECRYPT_ANY: str = "file:decrypt_any"

# Key operations
PERM_KEY_CREATE: str = "key:create"
PERM_KEY_LIST: str = "key:list"
PERM_KEY_INFO: str = "key:info"
PERM_KEY_INFO_ANY: str = "key:info_any"
PERM_KEY_REVOKE: str = "key:revoke"
PERM_KEY_REVOKE_ANY: str = "key:revoke_any"
PERM_KEY_ROTATE: str = "key:rotate"
PERM_KEY_ROTATE_ANY: str = "key:rotate_any"
PERM_KEY_SET_EXPIRY: str = "key:set_expiry"
PERM_KEY_SET_EXPIRY_ANY: str = "key:set_expiry_any"

# User management
PERM_USER_CREATE: str = "user:create"
PERM_USER_LIST: str = "user:list"
PERM_USER_INFO: str = "user:info"
PERM_USER_DEACTIVATE: str = "user:deactivate"
PERM_USER_SET_EXPIRY: str = "user:set_expiry"

# Role operations
PERM_ROLE_LIST: str = "role:list"
PERM_ROLE_INFO: str = "role:info"

# Complete enumeration for validation
ALL_PERMISSIONS: frozenset[str] = frozenset([
    PERM_ENCRYPT, PERM_DECRYPT, PERM_DECRYPT_ANY,
    PERM_KEY_CREATE, PERM_KEY_LIST, PERM_KEY_INFO, PERM_KEY_INFO_ANY,
    PERM_KEY_REVOKE, PERM_KEY_REVOKE_ANY,
    PERM_KEY_ROTATE, PERM_KEY_ROTATE_ANY,
    PERM_KEY_SET_EXPIRY, PERM_KEY_SET_EXPIRY_ANY,
    PERM_USER_CREATE, PERM_USER_LIST, PERM_USER_INFO,
    PERM_USER_DEACTIVATE, PERM_USER_SET_EXPIRY,
    PERM_ROLE_LIST, PERM_ROLE_INFO,
])

# --- Default role definitions ---
# Seeded during `file_storage init`

DEFAULT_ROLES: dict[str, dict] = {
    "admin": {
        "description": "Full system administrator with all permissions",
        "permissions": sorted(ALL_PERMISSIONS),
    },
    "key_manager": {
        "description": "Can create, rotate, revoke, and manage all keys",
        "permissions": sorted([
            PERM_ENCRYPT, PERM_DECRYPT, PERM_DECRYPT_ANY,
            PERM_KEY_CREATE, PERM_KEY_LIST, PERM_KEY_INFO, PERM_KEY_INFO_ANY,
            PERM_KEY_REVOKE, PERM_KEY_REVOKE_ANY,
            PERM_KEY_ROTATE, PERM_KEY_ROTATE_ANY,
            PERM_KEY_SET_EXPIRY, PERM_KEY_SET_EXPIRY_ANY,
            PERM_ROLE_LIST, PERM_ROLE_INFO,
        ]),
    },
    "encryptor": {
        "description": "Can encrypt files and manage own keys",
        "permissions": sorted([
            PERM_ENCRYPT, PERM_DECRYPT,
            PERM_KEY_CREATE, PERM_KEY_LIST, PERM_KEY_INFO,
            PERM_KEY_ROTATE, PERM_KEY_SET_EXPIRY,
            PERM_ROLE_LIST,
        ]),
    },
    "viewer": {
        "description": "Read-only access to key listings and info",
        "permissions": sorted([
            PERM_KEY_LIST, PERM_KEY_INFO,
            PERM_ROLE_LIST, PERM_ROLE_INFO,
        ]),
    },
    "auditor": {
        "description": "Can view all keys and users for audit purposes",
        "permissions": sorted([
            PERM_KEY_LIST, PERM_KEY_INFO, PERM_KEY_INFO_ANY,
            PERM_USER_LIST, PERM_USER_INFO,
            PERM_ROLE_LIST, PERM_ROLE_INFO,
        ]),
    },
}
