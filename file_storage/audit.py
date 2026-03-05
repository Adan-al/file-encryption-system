"""Audit logging for file_storage operations.

Provides structured audit trail for all security-relevant actions including
encryption, decryption, key management, user management, and access control.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from file_storage.utils import generate_uuid, utc_now_iso

logger = logging.getLogger("file_storage.audit")

# Audit event types
EVENT_ENCRYPT = "file:encrypt"
EVENT_DECRYPT = "file:decrypt"
EVENT_KEY_CREATE = "key:create"
EVENT_KEY_REVOKE = "key:revoke"
EVENT_KEY_ROTATE = "key:rotate"
EVENT_KEY_EXPIRE = "key:set_expiry"
EVENT_KEY_LIST = "key:list"
EVENT_KEY_INFO = "key:info"
EVENT_SYSTEM_INIT = "system:init"
EVENT_USER_CREATE = "user:create"
EVENT_USER_DEACTIVATE = "user:deactivate"
EVENT_USER_SET_EXPIRY = "user:set_expiry"
EVENT_USER_LIST = "user:list"
EVENT_USER_INFO = "user:info"
EVENT_ROLE_LIST = "role:list"
EVENT_ROLE_INFO = "role:info"
EVENT_AUTH_SUCCESS = "auth:success"
EVENT_AUTH_FAILURE = "auth:failure"
EVENT_ACCESS_DENIED = "access:denied"


@dataclass
class AuditEvent:
    """Represents a single audit log entry."""

    event_id: str
    timestamp: str
    event_type: str
    success: bool
    user_id: str | None = None
    username: str | None = None
    detail: dict = field(default_factory=dict)
    error: str | None = None


class AuditLogger:
    """Writes structured audit events to a JSON-lines log file.

    Each line in the log file is a self-contained JSON object representing
    one audit event. The log file is append-only.
    """

    def __init__(self, log_dir: Path):
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self._log_dir / "audit.jsonl"

    @property
    def log_path(self) -> Path:
        return self._log_path

    def log(
        self,
        event_type: str,
        success: bool,
        user_id: str | None = None,
        username: str | None = None,
        detail: dict | None = None,
        error: str | None = None,
    ) -> AuditEvent:
        """Record an audit event.

        Args:
            event_type: The type of event (use EVENT_* constants).
            success: Whether the operation succeeded.
            user_id: ID of the user who performed the action.
            username: Username of the user who performed the action.
            detail: Additional context about the event.
            error: Error message if the operation failed.

        Returns:
            The recorded AuditEvent.
        """
        event = AuditEvent(
            event_id=generate_uuid(),
            timestamp=utc_now_iso(),
            event_type=event_type,
            success=success,
            user_id=user_id,
            username=username,
            detail=detail or {},
            error=error,
        )
        self._write_event(event)
        logger.info(
            "audit event: %s success=%s user=%s",
            event_type,
            success,
            username or user_id or "anonymous",
        )
        return event

    def _write_event(self, event: AuditEvent) -> None:
        """Append an event to the audit log file."""
        line = json.dumps(asdict(event), separators=(",", ":"))
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._log_dir), suffix=".tmp", prefix=".audit_"
        )
        try:
            os.close(fd)
            with open(self._log_path, "a") as f:
                f.write(line + "\n")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def read_events(self) -> list[AuditEvent]:
        """Read all audit events from the log file."""
        if not self._log_path.exists():
            return []
        events = []
        with open(self._log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    events.append(AuditEvent(**data))
                except (json.JSONDecodeError, TypeError):
                    continue
        return events
