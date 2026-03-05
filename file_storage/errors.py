"""Custom exception hierarchy for file_storage."""


class FileStorageError(Exception):
    """Base exception for all File_storage errors."""


class KeyNotFoundError(FileStorageError):
    """Raised when a key ID is not found in the key store."""


class KeyExpiredError(FileStorageError):
    """Raised when attempting to use an expired key."""


class KeyRevokedError(FileStorageError):
    """Raised when attempting to use a revoked key."""


class KeyStoreCorruptionError(FileStorageError):
    """Raised when a key file is malformed or unreadable."""


class StoreCorruptionError(FileStorageError):
    """Raised when any store file (user, role) is malformed or unreadable."""


class InvalidFileFormatError(FileStorageError):
    """Raised when a file does not have valid File_storage headers."""


class UnsupportedVersionError(FileStorageError):
    """Raised when the file format version is not supported."""


class IntegrityError(FileStorageError):
    """Raised when HMAC verification fails (file tampered)."""


class DecryptionError(FileStorageError):
    """Raised when AES-GCM decryption fails (wrong key or corruption)."""


class FileOperationError(FileStorageError):
    """Raised on OS-level file I/O errors."""


class AccessDeniedError(FileStorageError):
    """Raised when a user lacks permission for an operation."""


class UserNotFoundError(FileStorageError):
    """Raised when a user ID or username is not found."""


class UserInactiveError(FileStorageError):
    """Raised when an inactive or deactivated user attempts an operation."""


class UserAccessExpiredError(FileStorageError):
    """Raised when a user's time-based access has expired."""


class RoleNotFoundError(FileStorageError):
    """Raised when a role ID or name is not found."""


class AuthenticationError(FileStorageError):
    """Raised when password verification fails."""


class SystemNotInitializedError(FileStorageError):
    """Raised when RBAC operations are attempted before init has been run."""
