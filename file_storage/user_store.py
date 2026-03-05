"""Disk I/O for user JSON files with atomic writes and password hashing."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from file_storage.errors import UserNotFoundError, StoreCorruptionError

_PBKDF2_ITERATIONS: int = 600_000


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-SHA256.

    Returns a self-contained string: 'pbkdf2:sha256:<iterations>$<salt_hex>$<hash_hex>'
    """
    salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    )
    return f"pbkdf2:sha256:{_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a stored hash. Constant-time comparison."""
    parts = password_hash.split("$")
    if len(parts) != 3:
        return False
    header = parts[0]
    salt_hex = parts[1]
    expected_hex = parts[2]
    try:
        iterations = int(header.split(":")[2])
        salt = bytes.fromhex(salt_hex)
    except (IndexError, ValueError):
        return False
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac_mod.compare_digest(dk.hex(), expected_hex)


@dataclass
class UserRecord:
    """Complete user record."""

    user_id: str
    username: str
    password_hash: str
    role_ids: list[str] = field(default_factory=list)
    created_at: str = ""
    is_active: bool = True
    access_expires_at: str | None = None
    deactivated_at: str | None = None


def _user_record_from_dict(data: dict) -> UserRecord:
    """Deserialize a dict into a UserRecord."""
    return UserRecord(
        user_id=data["user_id"],
        username=data["username"],
        password_hash=data["password_hash"],
        role_ids=data.get("role_ids", []),
        created_at=data.get("created_at", ""),
        is_active=data.get("is_active", True),
        access_expires_at=data.get("access_expires_at"),
        deactivated_at=data.get("deactivated_at"),
    )


class UserStore:
    """Handles reading and writing user JSON files to disk."""

    def __init__(self, base_dir: Path):
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def _user_path(self, user_id: str) -> Path:
        return self._base_dir / f"{user_id}.json"

    def _index_path(self) -> Path:
        return self._base_dir / "_username_index.json"

    def save_user(self, record: UserRecord) -> None:
        """Atomically write a UserRecord to disk with 0o600 permissions.

        Also updates the username index.
        """
        data = asdict(record)
        path = self._user_path(record.user_id)

        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._base_dir), suffix=".tmp", prefix=".user_"
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, str(path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        self._update_index(record.username, record.user_id)

    def _update_index(self, username: str, user_id: str) -> None:
        """Update the username -> user_id index file."""
        index = self._load_index()
        index[username] = user_id
        self._save_index(index)

    def _load_index(self) -> dict[str, str]:
        """Load the username index, or return empty dict if missing."""
        path = self._index_path()
        if not path.exists():
            return {}
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_index(self, index: dict[str, str]) -> None:
        """Atomically save the username index."""
        path = self._index_path()
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._base_dir), suffix=".tmp", prefix=".idx_"
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(index, f, indent=2)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, str(path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def load_user(self, user_id: str) -> UserRecord:
        """Load a UserRecord by its UUID."""
        path = self._user_path(user_id)
        if not path.exists():
            raise UserNotFoundError(f"User not found: {user_id}")

        try:
            with open(path) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise StoreCorruptionError(
                f"User file corrupted: {user_id}.json"
            ) from e

        try:
            return _user_record_from_dict(data)
        except (KeyError, TypeError) as e:
            raise StoreCorruptionError(
                f"User file has missing fields: {user_id}.json"
            ) from e

    def load_user_by_username(self, username: str) -> UserRecord:
        """Load a UserRecord by username using the index, falling back to scan."""
        index = self._load_index()
        user_id = index.get(username)
        if user_id:
            try:
                record = self.load_user(user_id)
                if record.username == username:
                    return record
            except (UserNotFoundError, StoreCorruptionError):
                pass

        # Fallback: scan all user files
        for path in self._base_dir.glob("*.json"):
            if path.name.startswith("_"):
                continue
            try:
                with open(path) as f:
                    data = json.load(f)
                record = _user_record_from_dict(data)
                if record.username == username:
                    # Repair index
                    self._update_index(username, record.user_id)
                    return record
            except (json.JSONDecodeError, KeyError, TypeError):
                continue

        raise UserNotFoundError(f"User not found: {username}")

    def list_users(self) -> list[UserRecord]:
        """Return all UserRecords from the store directory."""
        records = []
        for path in sorted(self._base_dir.glob("*.json")):
            if path.name.startswith("_"):
                continue
            try:
                with open(path) as f:
                    data = json.load(f)
                records.append(_user_record_from_dict(data))
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        return records

    def user_exists(self, user_id: str) -> bool:
        """Check if a user file exists on disk."""
        return self._user_path(user_id).exists()

    def username_exists(self, username: str) -> bool:
        """Check if a username is already taken."""
        try:
            self.load_user_by_username(username)
            return True
        except UserNotFoundError:
            return False

    def delete_user(self, user_id: str) -> None:
        """Delete a user file from disk (for testing only)."""
        path = self._user_path(user_id)
        if path.exists():
            path.unlink()
