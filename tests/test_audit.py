"""Tests for audit logging."""

import json

import pytest

from file_storage.audit import (
    AuditEvent,
    AuditLogger,
    EVENT_ENCRYPT,
    EVENT_DECRYPT,
    EVENT_KEY_CREATE,
    EVENT_KEY_REVOKE,
    EVENT_USER_CREATE,
    EVENT_ACCESS_DENIED,
    EVENT_AUTH_FAILURE,
)


class TestAuditLogger:
    def test_log_creates_event(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit")
        event = logger.log(
            event_type=EVENT_ENCRYPT,
            success=True,
            username="alice",
            detail={"file": "test.txt"},
        )
        assert event.event_type == EVENT_ENCRYPT
        assert event.success is True
        assert event.username == "alice"
        assert event.detail == {"file": "test.txt"}
        assert event.error is None
        assert event.event_id is not None
        assert event.timestamp is not None

    def test_log_writes_to_file(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit")
        logger.log(event_type=EVENT_ENCRYPT, success=True, username="alice")
        assert logger.log_path.exists()
        content = logger.log_path.read_text()
        assert content.strip() != ""
        data = json.loads(content.strip())
        assert data["event_type"] == EVENT_ENCRYPT

    def test_log_appends_multiple_events(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit")
        logger.log(event_type=EVENT_ENCRYPT, success=True, username="alice")
        logger.log(event_type=EVENT_DECRYPT, success=True, username="bob")
        logger.log(event_type=EVENT_KEY_CREATE, success=False, error="test error")
        lines = logger.log_path.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_log_failure_event(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit")
        event = logger.log(
            event_type=EVENT_ACCESS_DENIED,
            success=False,
            username="eve",
            error="permission denied",
        )
        assert event.success is False
        assert event.error == "permission denied"

    def test_log_with_user_id(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit")
        event = logger.log(
            event_type=EVENT_USER_CREATE,
            success=True,
            user_id="user-123",
            username="admin",
            detail={"target_username": "newuser"},
        )
        assert event.user_id == "user-123"
        assert event.username == "admin"

    def test_log_without_optional_fields(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit")
        event = logger.log(event_type=EVENT_AUTH_FAILURE, success=False)
        assert event.user_id is None
        assert event.username is None
        assert event.detail == {}
        assert event.error is None


class TestAuditLoggerReadEvents:
    def test_read_events_empty(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit")
        events = logger.read_events()
        assert events == []

    def test_read_events_returns_all(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit")
        logger.log(event_type=EVENT_ENCRYPT, success=True, username="alice")
        logger.log(event_type=EVENT_DECRYPT, success=True, username="bob")
        events = logger.read_events()
        assert len(events) == 2
        assert events[0].event_type == EVENT_ENCRYPT
        assert events[1].event_type == EVENT_DECRYPT

    def test_read_events_skips_corrupt_lines(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit")
        logger.log(event_type=EVENT_ENCRYPT, success=True, username="alice")
        # Append corrupt line
        with open(logger.log_path, "a") as f:
            f.write("{not valid json\n")
        logger.log(event_type=EVENT_DECRYPT, success=True, username="bob")
        events = logger.read_events()
        assert len(events) == 2

    def test_read_events_preserves_detail(self, tmp_path):
        logger = AuditLogger(tmp_path / "audit")
        logger.log(
            event_type=EVENT_KEY_REVOKE,
            success=True,
            username="admin",
            detail={"key_id": "key-abc"},
        )
        events = logger.read_events()
        assert events[0].detail == {"key_id": "key-abc"}


class TestAuditLoggerDirectoryCreation:
    def test_creates_audit_dir(self, tmp_path):
        audit_dir = tmp_path / "nested" / "audit"
        assert not audit_dir.exists()
        AuditLogger(audit_dir)
        assert audit_dir.exists()


class TestAuditEventDataclass:
    def test_event_fields(self):
        event = AuditEvent(
            event_id="evt-1",
            timestamp="2026-03-04T12:00:00+00:00",
            event_type=EVENT_ENCRYPT,
            success=True,
            user_id="u1",
            username="alice",
            detail={"file": "test.txt"},
            error=None,
        )
        assert event.event_id == "evt-1"
        assert event.event_type == EVENT_ENCRYPT
        assert event.success is True
        assert event.detail == {"file": "test.txt"}
