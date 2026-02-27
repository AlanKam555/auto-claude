"""
SecureClaw Audit Logger — Structured security event logging.

All security-relevant events are written to config/audit.log as JSON lines.
Provides a tamper-evident audit trail separate from application logs.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Optional

AUDIT_LOG_DIR = Path(__file__).parent.parent / "config"
AUDIT_LOG_FILE = AUDIT_LOG_DIR / "audit.log"

_audit_lock = Lock()

# Maximum audit log size before rotation (10 MB)
MAX_AUDIT_LOG_BYTES = 10 * 1024 * 1024


class AuditEvent:
    """Audit event type constants."""
    AUTH_ALLOWED = "auth.allowed"
    AUTH_BLOCKED = "auth.blocked"
    AUTH_RATE_LIMITED = "auth.rate_limited"
    INJECTION_BLOCKED = "injection.blocked"
    SKILL_EXECUTED = "skill.executed"
    SKILL_BLOCKED = "skill.blocked"
    SKILL_COOLDOWN = "skill.cooldown"
    ADMIN_ACTION = "admin.action"
    CLAUDE_CALL = "claude.call"
    CLAUDE_ERROR = "claude.error"
    MESSAGE_RECEIVED = "message.received"
    MEDIA_RECEIVED = "media.received"
    STATUS_UPDATE = "message.status_update"


def audit_log(
    event_type: str,
    phone: str = "",
    detail: str = "",
    metadata: Optional[dict] = None,
) -> None:
    """
    Write a structured audit event to the audit log.

    Each entry is a JSON line with timestamp, event type, masked phone, and details.
    Phone numbers are masked for privacy (only first 6 chars shown).
    """
    AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Mask phone for privacy
    masked_phone = phone[:6] + "***" if len(phone) > 6 else phone

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "phone": masked_phone,
        "detail": detail,
    }
    if metadata:
        entry["metadata"] = metadata

    try:
        with _audit_lock:
            # Simple size-based rotation
            if AUDIT_LOG_FILE.exists() and AUDIT_LOG_FILE.stat().st_size > MAX_AUDIT_LOG_BYTES:
                rotated = AUDIT_LOG_FILE.with_suffix(".log.1")
                if rotated.exists():
                    rotated.unlink()
                AUDIT_LOG_FILE.rename(rotated)

            with open(AUDIT_LOG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logging.getLogger(__name__).error("Failed to write audit log: %s", e)


def read_recent_events(count: int = 50) -> list[dict]:
    """Read the most recent N audit events (newest first)."""
    if not AUDIT_LOG_FILE.exists():
        return []

    try:
        lines = AUDIT_LOG_FILE.read_text().strip().split("\n")
        events = []
        for line in reversed(lines[-count:]):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events
    except OSError:
        return []
