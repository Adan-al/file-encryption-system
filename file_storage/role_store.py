"""Disk I/O for role JSON files with atomic writes."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from file_storage.errors import RoleNotFoundError, StoreCorruptionError


@dataclass
class RoleRecord:
    """A role definition with its associated permissions."""

    role_id: str
    name: str
    permissions: list[str] = field(default_factory=list)
    description: str = ""
    created_at: str = ""


def _role_record_from_dict(data: dict) -> RoleRecord:
    """Deserialize a dict into a RoleRecord."""
    return RoleRecord(
        role_id=data["role_id"],
        name=data["name"],
        permissions=data.get("permissions", []),
        description=data.get("description", ""),
        created_at=data.get("created_at", ""),
    )


class RoleStore:
    """Handles reading and writing role JSON files to disk."""

    def __init__(self, base_dir: Path):
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def _role_path(self, role_id: str) -> Path:
        return self._base_dir / f"{role_id}.json"

    def save_role(self, record: RoleRecord) -> None:
        """Atomically write a RoleRecord to disk with 0o600 permissions."""
        data = asdict(record)
        path = self._role_path(record.role_id)

        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._base_dir), suffix=".tmp", prefix=".role_"
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

    def load_role(self, role_id: str) -> RoleRecord:
        """Load a RoleRecord by its UUID."""
        path = self._role_path(role_id)
        if not path.exists():
            raise RoleNotFoundError(f"Role not found: {role_id}")

        try:
            with open(path) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise StoreCorruptionError(
                f"Role file corrupted: {role_id}.json"
            ) from e

        try:
            return _role_record_from_dict(data)
        except (KeyError, TypeError) as e:
            raise StoreCorruptionError(
                f"Role file has missing fields: {role_id}.json"
            ) from e

    def load_role_by_name(self, name: str) -> RoleRecord:
        """Load a RoleRecord by its human-readable name."""
        for path in self._base_dir.glob("*.json"):
            try:
                with open(path) as f:
                    data = json.load(f)
                record = _role_record_from_dict(data)
                if record.name == name:
                    return record
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        raise RoleNotFoundError(f"Role not found: {name}")

    def list_roles(self) -> list[RoleRecord]:
        """Return all RoleRecords from the store directory."""
        records = []
        for path in sorted(self._base_dir.glob("*.json")):
            try:
                with open(path) as f:
                    data = json.load(f)
                records.append(_role_record_from_dict(data))
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        return records

    def role_exists(self, role_id: str) -> bool:
        """Check if a role file exists on disk."""
        return self._role_path(role_id).exists()

    def delete_role(self, role_id: str) -> None:
        """Delete a role file from disk (for testing only)."""
        path = self._role_path(role_id)
        if path.exists():
            path.unlink()
