"""
SecureClaw Authentication & Authorization.

Manages phone number whitelisting, admin privileges, RBAC permissions,
optional PIN system, and per-number rate limiting.
Whitelist is stored in config/whitelist.json. Admin phone comes from ADMIN_PHONE env var.
"""

import json
import logging
import os
import time
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).parent.parent / "config"
WHITELIST_FILE = CONFIG_DIR / "whitelist.json"

# Rate limit defaults
DEFAULT_MAX_MESSAGES = 30
DEFAULT_WINDOW_SECONDS = 3600  # 1 hour


class Permission(str, Enum):
    """Capability-based permission system. New skills must map to existing permissions."""
    CHAT = "chat"                       # Basic conversation
    WEB_SEARCH = "web_search"           # Internet search
    URL_FETCH = "url_fetch"             # Fetch and summarize URLs
    REMINDERS = "reminders"             # Set reminders
    WEATHER = "weather"                 # Weather lookups
    ADMIN = "admin"                     # Admin commands (add/remove users, manage skills)
    VAULT_READ = "vault_read"           # Read secrets from vault
    VAULT_WRITE = "vault_write"         # Write secrets to vault
    SKILL_MANAGE = "skill_manage"       # Enable/disable skills


# Default role permission sets
ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "user": {Permission.CHAT},
    "power_user": {
        Permission.CHAT,
        Permission.WEB_SEARCH,
        Permission.URL_FETCH,
        Permission.REMINDERS,
        Permission.WEATHER,
    },
    "admin": set(Permission),  # All permissions
}


@dataclass
class UserRecord:
    """Record for a whitelisted user."""
    phone: str
    role: str = "user"
    pin_hash: Optional[str] = None
    added_at: float = field(default_factory=time.time)


@dataclass
class RateLimitEntry:
    """Tracks message timestamps for a single phone number."""
    timestamps: list[float] = field(default_factory=list)


class AuthManager:
    """
    Phone number authentication, whitelisting, RBAC, PIN, and rate limiting.

    Whitelist file format (config/whitelist.json):
    {
        "numbers": {
            "+6512345678": {"role": "admin", "pin_hash": null},
            "+6598765432": {"role": "power_user", "pin_hash": null}
        },
        "open_access": false
    }

    If open_access is true, all numbers are allowed (useful for testing).
    If the whitelist file doesn't exist, only the admin phone is allowed.
    """

    def __init__(self) -> None:
        self._admin_phone = os.environ.get("ADMIN_PHONE", "").strip()
        self._users: dict[str, UserRecord] = {}
        self._open_access = False
        self._rate_limits: dict[str, RateLimitEntry] = {}
        self._lock = Lock()

        self._max_messages = int(os.environ.get("RATE_LIMIT_MAX", str(DEFAULT_MAX_MESSAGES)))
        self._window_seconds = int(os.environ.get("RATE_LIMIT_WINDOW", str(DEFAULT_WINDOW_SECONDS)))

        self._load_whitelist()

        if self._admin_phone:
            normalized = self._normalize(self._admin_phone)
            if normalized not in self._users:
                self._users[normalized] = UserRecord(phone=normalized, role="admin")
            logger.info("Admin phone configured: %s***", self._admin_phone[:6])

    def _normalize(self, phone: str) -> str:
        """Normalize phone number to E.164 — strip spaces, ensure + prefix."""
        phone = phone.strip().replace(" ", "").replace("-", "")
        if not phone.startswith("+"):
            phone = "+" + phone
        return phone

    def _load_whitelist(self) -> None:
        """Load whitelist from config/whitelist.json."""
        if not WHITELIST_FILE.exists():
            logger.info("No whitelist file found at %s — admin-only mode", WHITELIST_FILE)
            return

        try:
            data = json.loads(WHITELIST_FILE.read_text())
            self._open_access = data.get("open_access", False)
            numbers = data.get("numbers", {})

            if isinstance(numbers, list):
                # Legacy format: list of phone strings
                for n in numbers:
                    norm = self._normalize(n)
                    self._users[norm] = UserRecord(phone=norm, role="user")
            elif isinstance(numbers, dict):
                for phone, info in numbers.items():
                    norm = self._normalize(phone)
                    if isinstance(info, dict):
                        self._users[norm] = UserRecord(
                            phone=norm,
                            role=info.get("role", "user"),
                            pin_hash=info.get("pin_hash"),
                        )
                    else:
                        self._users[norm] = UserRecord(phone=norm, role="user")

            logger.info(
                "Whitelist loaded: %d users, open_access=%s",
                len(self._users),
                self._open_access,
            )
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load whitelist: %s", e)

    def save_whitelist(self) -> None:
        """Persist the current whitelist to disk."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        numbers = {}
        for phone, record in sorted(self._users.items()):
            numbers[phone] = {
                "role": record.role,
                "pin_hash": record.pin_hash,
            }
        data = {
            "numbers": numbers,
            "open_access": self._open_access,
        }
        WHITELIST_FILE.write_text(json.dumps(data, indent=2) + "\n")

    def is_allowed(self, phone: str) -> bool:
        """Check if a phone number is authorized to use the service."""
        if self._open_access:
            return True
        return self._normalize(phone) in self._users

    def is_admin(self, phone: str) -> bool:
        """Check if a phone number has admin role."""
        normalized = self._normalize(phone)
        record = self._users.get(normalized)
        if not record:
            return False
        return record.role == "admin"

    def has_permission(self, phone: str, permission: Permission) -> bool:
        """Check if a phone number has a specific permission via its role."""
        if self._open_access and permission == Permission.CHAT:
            return True

        normalized = self._normalize(phone)
        record = self._users.get(normalized)
        if not record:
            return False

        role_perms = ROLE_PERMISSIONS.get(record.role, set())
        return permission in role_perms

    def get_role(self, phone: str) -> Optional[str]:
        """Get the role assigned to a phone number."""
        normalized = self._normalize(phone)
        record = self._users.get(normalized)
        return record.role if record else None

    def set_role(self, phone: str, role: str) -> None:
        """Set the role for a phone number."""
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"Unknown role: {role}. Valid roles: {list(ROLE_PERMISSIONS.keys())}")
        normalized = self._normalize(phone)
        if normalized in self._users:
            self._users[normalized].role = role
        else:
            self._users[normalized] = UserRecord(phone=normalized, role=role)
        self.save_whitelist()

    def add_number(self, phone: str, role: str = "user") -> None:
        """Add a phone number to the whitelist."""
        normalized = self._normalize(phone)
        self._users[normalized] = UserRecord(phone=normalized, role=role)
        self.save_whitelist()

    def remove_number(self, phone: str) -> None:
        """Remove a phone number from the whitelist."""
        normalized = self._normalize(phone)
        self._users.pop(normalized, None)
        self.save_whitelist()

    def list_numbers(self) -> list[dict]:
        """Return all whitelisted numbers with their roles."""
        return [
            {"phone": r.phone, "role": r.role}
            for r in sorted(self._users.values(), key=lambda r: r.phone)
        ]

    def check_rate_limit(self, phone: str) -> bool:
        """
        Check if a phone number is within rate limits.
        Returns True if allowed, False if rate limited.
        """
        normalized = self._normalize(phone)
        now = time.time()
        cutoff = now - self._window_seconds

        with self._lock:
            entry = self._rate_limits.setdefault(normalized, RateLimitEntry())
            entry.timestamps = [t for t in entry.timestamps if t > cutoff]

            if len(entry.timestamps) >= self._max_messages:
                return False

            entry.timestamps.append(now)
            return True

    def get_rate_limit_remaining(self, phone: str) -> int:
        """Get the number of messages remaining in the current window."""
        normalized = self._normalize(phone)
        now = time.time()
        cutoff = now - self._window_seconds

        with self._lock:
            entry = self._rate_limits.get(normalized)
            if not entry:
                return self._max_messages
            current = len([t for t in entry.timestamps if t > cutoff])
            return max(0, self._max_messages - current)

    def set_open_access(self, enabled: bool) -> None:
        """Enable or disable open access mode."""
        self._open_access = enabled
        self.save_whitelist()

    def set_pin(self, phone: str, pin_hash: str) -> None:
        """Set a PIN hash for a user."""
        normalized = self._normalize(phone)
        if normalized in self._users:
            self._users[normalized].pin_hash = pin_hash
            self.save_whitelist()

    def verify_pin(self, phone: str, pin_hash: str) -> bool:
        """Verify a PIN hash for a user. Uses constant-time comparison."""
        import hmac
        normalized = self._normalize(phone)
        record = self._users.get(normalized)
        if not record or not record.pin_hash:
            return False
        return hmac.compare_digest(record.pin_hash, pin_hash)
