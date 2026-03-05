"""Utility functions for file_storage."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone


def generate_uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


def utc_now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def parse_datetime(s: str) -> datetime:
    """Parse an ISO 8601 datetime string into a timezone-aware datetime."""
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def is_expired(expires_at: str | None) -> bool:
    """Check if an expiry timestamp is in the past."""
    if expires_at is None:
        return False
    expiry = parse_datetime(expires_at)
    return datetime.now(timezone.utc) >= expiry
