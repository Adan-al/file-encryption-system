"""Key lifecycle management: create, validate, revoke, expire, rotate."""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from pathlib import Path

from file_storage.crypto import (
    decrypt as aes_decrypt,
    derive_hmac_key,
    encrypt as aes_encrypt,
    generate_key,
    generate_nonce,
)
from file_storage.errors import (
    FileOperationError,
    KeyExpiredError,
    KeyNotFoundError,
    KeyRevokedError,
)
from file_storage.file_format import FileHeader, pack_header, unpack_header
from file_storage.integrity import compute_hmac
from file_storage.key_store import KeyRecord, KeyStore, PreviousKeyVersion
from file_storage.utils import generate_uuid, is_expired, utc_now_iso
from file_storage.constants import HMAC_SIZE

logger = logging.getLogger("file_storage.key_manager")


class KeyManager:
    """Manages key lifecycle operations."""

    def __init__(self, store: KeyStore):
        self._store = store

    @property
    def store(self) -> KeyStore:
        return self._store

    def create_key(self, description: str = "", owner_id: str | None = None) -> KeyRecord:
        """Generate a new AES-256 key and persist it."""
        raw_key = generate_key()
        record = KeyRecord(
            key_id=generate_uuid(),
            version=1,
            created_at=utc_now_iso(),
            expires_at=None,
            revoked=False,
            revoked_at=None,
            algorithm="AES-256-GCM",
            key_material_b64=base64.b64encode(raw_key).decode("ascii"),
            previous_versions=[],
            associated_files=[],
            description=description,
            owner_id=owner_id,
        )
        self._store.save_key(record)
        logger.info("Key created: %s (owner=%s)", record.key_id, owner_id)
        return record

    def get_key(self, key_id: str) -> KeyRecord:
        """Retrieve a key record by ID."""
        return self._store.load_key(key_id)

    def get_key_material(self, record: KeyRecord) -> bytes:
        """Decode the current key material from a record."""
        return base64.b64decode(record.key_material_b64)

    def get_key_material_for_version(
        self, record: KeyRecord, version: int
    ) -> bytes:
        """Get key material for a specific version (current or historical)."""
        if version == record.version:
            return self.get_key_material(record)

        for prev in record.previous_versions:
            if prev.version == version:
                return base64.b64decode(prev.key_material_b64)

        raise KeyNotFoundError(
            f"Key version {version} not found for key {record.key_id}"
        )

    def validate_key_for_use(self, record: KeyRecord) -> None:
        """Check that a key is neither expired nor revoked."""
        if record.revoked:
            raise KeyRevokedError(
                f"Key {record.key_id} was revoked at {record.revoked_at}"
            )
        if is_expired(record.expires_at):
            raise KeyExpiredError(
                f"Key {record.key_id} expired at {record.expires_at}"
            )

    def revoke_key(self, key_id: str) -> KeyRecord:
        """Mark a key as revoked. Idempotent."""
        record = self._store.load_key(key_id)
        if not record.revoked:
            record.revoked = True
            record.revoked_at = utc_now_iso()
            self._store.save_key(record)
            logger.info("Key revoked: %s", key_id)
        return record

    def set_expiry(self, key_id: str, expires_at: datetime) -> KeyRecord:
        """Set or update the expiry timestamp on a key."""
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= datetime.now(timezone.utc):
            raise ValueError("Expiry time must be in the future")

        record = self._store.load_key(key_id)
        record.expires_at = expires_at.isoformat()
        self._store.save_key(record)
        logger.info("Key expiry set: %s -> %s", key_id, record.expires_at)
        return record

    def rotate_key(self, key_id: str) -> KeyRecord:
        """Create a new version of the key and re-encrypt associated files.

        Revoked keys cannot be rotated. Expired keys CAN be rotated.
        """
        record = self._store.load_key(key_id)

        if record.revoked:
            raise KeyRevokedError(
                f"Cannot rotate revoked key {record.key_id}"
            )

        now = utc_now_iso()

        # Move current key to history
        record.previous_versions.append(
            PreviousKeyVersion(
                version=record.version,
                key_material_b64=record.key_material_b64,
                created_at=record.created_at,
                retired_at=now,
            )
        )

        # Generate new key material
        old_key = base64.b64decode(record.key_material_b64)
        new_key = generate_key()
        record.key_material_b64 = base64.b64encode(new_key).decode("ascii")
        record.version += 1

        # Clear expiry on rotation (new key version starts fresh)
        record.expires_at = None

        # Re-encrypt associated files
        updated_files = []
        for file_path in record.associated_files:
            try:
                self._reencrypt_file(file_path, old_key, new_key, record)
                updated_files.append(file_path)
            except FileNotFoundError:
                logger.warning(
                    "File not found during rotation, removing association: %s",
                    file_path,
                )
            except Exception as exc:
                logger.error(
                    "Failed to re-encrypt file during rotation: %s: %s",
                    file_path,
                    exc,
                )
                updated_files.append(file_path)

        record.associated_files = updated_files
        self._store.save_key(record)
        logger.info(
            "Key rotated: %s -> version %d (%d files re-encrypted)",
            key_id,
            record.version,
            len(updated_files),
        )
        return record

    def _reencrypt_file(
        self,
        file_path: str,
        old_key: bytes,
        new_key: bytes,
        record: KeyRecord,
    ) -> None:
        """Re-encrypt a file with a new key version."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        data = path.read_bytes()
        if len(data) < HMAC_SIZE:
            raise FileOperationError(f"File too small: {file_path}")

        # Strip HMAC, parse header, decrypt with old key
        file_data = data[:-HMAC_SIZE]
        header, offset = unpack_header(file_data)
        ciphertext_tag = file_data[offset:]

        header_bytes = file_data[:offset]
        plaintext = aes_decrypt(old_key, header.nonce, ciphertext_tag, aad=header_bytes)

        # Re-encrypt with new key
        nonce = generate_nonce()
        new_header = FileHeader(
            key_id=header.key_id,
            key_version=record.version,
            nonce=nonce,
            original_filename=header.original_filename,
        )
        new_header_bytes = pack_header(new_header)
        new_ciphertext = aes_encrypt(new_key, nonce, plaintext, aad=new_header_bytes)

        # Compute new HMAC
        hmac_key = derive_hmac_key(new_key)
        file_content = new_header_bytes + new_ciphertext
        hmac_digest = compute_hmac(hmac_key, file_content)

        # Atomic write
        import tempfile, os
        fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(file_content + hmac_digest)
            os.replace(tmp_path, str(path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def list_keys(self) -> list[KeyRecord]:
        """Return all keys with their current status."""
        return self._store.list_keys()

    def add_file_association(self, key_id: str, file_path: str) -> None:
        """Record that a file was encrypted with this key."""
        record = self._store.load_key(key_id)
        abs_path = str(Path(file_path).resolve())
        if abs_path not in record.associated_files:
            record.associated_files.append(abs_path)
            self._store.save_key(record)

    def remove_file_association(self, key_id: str, file_path: str) -> None:
        """Remove a file association."""
        record = self._store.load_key(key_id)
        abs_path = str(Path(file_path).resolve())
        if abs_path in record.associated_files:
            record.associated_files.remove(abs_path)
            self._store.save_key(record)

    def get_key_status(self, record: KeyRecord) -> str:
        """Return human-readable status: active, expired, or revoked."""
        if record.revoked:
            return "revoked"
        if is_expired(record.expires_at):
            return "expired"
        return "active"
