"""Disk I/O for key JSON files with atomic writes."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from file_storage.errors import KeyNotFoundError, KeyStoreCorruptionError


@dataclass
class PreviousKeyVersion:
    """Historical key version retained for audit/recovery."""

    version: int
    key_material_b64: str
    created_at: str
    retired_at: str


@dataclass
class KeyRecord:
    """Complete key record with metadata and material."""

    key_id: str
    version: int
    created_at: str
    expires_at: str | None
    revoked: bool
    revoked_at: str | None
    algorithm: str
    key_material_b64: str
    previous_versions: list[PreviousKeyVersion] = field(default_factory=list)
    associated_files: list[str] = field(default_factory=list)
    description: str = ""
    owner_id: str | None = None


def _key_record_from_dict(data: dict) -> KeyRecord:
    """Deserialize a dict into a KeyRecord."""
    prev = [PreviousKeyVersion(**pv) for pv in data.get("previous_versions", [])]
    return KeyRecord(
        key_id=data["key_id"],
        version=data["version"],
        created_at=data["created_at"],
        expires_at=data.get("expires_at"),
        revoked=data["revoked"],
        revoked_at=data.get("revoked_at"),
        algorithm=data["algorithm"],
        key_material_b64=data["key_material_b64"],
        previous_versions=prev,
        associated_files=data.get("associated_files", []),
        description=data.get("description", ""),
        owner_id=data.get("owner_id"),
    )


def _key_record_to_dict(record: KeyRecord) -> dict:
    """Serialize a KeyRecord to a dict."""
    return asdict(record)


class KeyStore:
    """Handles reading and writing key JSON files to disk."""

    def __init__(self, base_dir: Path):
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def _key_path(self, key_id: str) -> Path:
        return self._base_dir / f"{key_id}.json"

    def save_key(self, record: KeyRecord) -> None:
        """Atomically write a KeyRecord to disk.

        Uses write-to-temp-then-rename for atomicity.
        Sets file permissions to 0o600 (owner read/write only).
        """
        data = _key_record_to_dict(record)
        path = self._key_path(record.key_id)

        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._base_dir), suffix=".tmp", prefix=".key_"
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, str(path))
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def load_key(self, key_id: str) -> KeyRecord:
        """Load a KeyRecord by its UUID."""
        path = self._key_path(key_id)
        if not path.exists():
            raise KeyNotFoundError(f"Key not found: {key_id}")

        try:
            with open(path) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise KeyStoreCorruptionError(
                f"Key file corrupted: {key_id}.json"
            ) from e

        try:
            return _key_record_from_dict(data)
        except (KeyError, TypeError) as e:
            raise KeyStoreCorruptionError(
                f"Key file has missing fields: {key_id}.json"
            ) from e

    def list_keys(self) -> list[KeyRecord]:
        """Return all KeyRecords from the store directory."""
        records = []
        for path in sorted(self._base_dir.glob("*.json")):
            try:
                with open(path) as f:
                    data = json.load(f)
                records.append(_key_record_from_dict(data))
            except (json.JSONDecodeError, KeyError, TypeError):
                continue  # skip corrupted files
        return records

    def key_exists(self, key_id: str) -> bool:
        """Check if a key file exists on disk."""
        return self._key_path(key_id).exists()

    def delete_key(self, key_id: str) -> None:
        """Delete a key file from disk (for testing only)."""
        path = self._key_path(key_id)
        if path.exists():
            path.unlink()
