"""
SecureClaw Vault — Encrypted credential storage.

Stores API keys and secrets using Fernet symmetric encryption.
The encryption key is derived from VAULT_ENCRYPTION_KEY env var,
or auto-generated on first run and saved to config/vault.key.

Falls back to base64 obfuscation if the cryptography library is unavailable
(not production-safe — install cryptography for real encryption).
"""

import base64
import hashlib
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).parent.parent / "config"
VAULT_FILE = CONFIG_DIR / "vault.enc"
VAULT_KEY_FILE = CONFIG_DIR / "vault.key"

# Try to import Fernet; fall back gracefully
HAS_FERNET = False

def _check_cryptography_available() -> bool:
    """Check if cryptography's Rust bindings work before importing."""
    import subprocess
    try:
        result = subprocess.run(
            [sys.executable, "-c", "from cryptography.fernet import Fernet"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False

import sys
if _check_cryptography_available():
    try:
        from cryptography.fernet import Fernet, InvalidToken
        HAS_FERNET = True
    except Exception:
        pass

if not HAS_FERNET:
    logger.warning(
        "cryptography library not available — vault will use base64 fallback. "
        "Install cryptography for production: pip install cryptography"
    )


class _FallbackFernet:
    """
    Minimal fallback when cryptography is not installed.
    Uses base64 encoding with a key-derived XOR — NOT cryptographically secure.
    Only for development/testing. Install cryptography for production.
    """

    def __init__(self, key: bytes) -> None:
        self._key = key

    @staticmethod
    def generate_key() -> bytes:
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data: bytes) -> bytes:
        # Simple XOR with key bytes, then base64
        key_bytes = base64.urlsafe_b64decode(self._key)
        xored = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
        return base64.urlsafe_b64encode(xored)

    def decrypt(self, token: bytes) -> bytes:
        # Reverse the XOR
        key_bytes = base64.urlsafe_b64decode(self._key)
        xored = base64.urlsafe_b64decode(token)
        return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(xored))


class VaultManager:
    """
    Encrypted key-value store for secrets and credentials.

    Usage:
        vault = VaultManager()
        vault.set("tavily_api_key", "tvly-xxxxx")
        key = vault.get("tavily_api_key")
    """

    def __init__(self) -> None:
        self._fernet = None
        self._data: dict[str, str] = {}
        self._initialize()

    def _initialize(self) -> None:
        """Initialize encryption and load existing vault data."""
        key = self._get_or_create_key()
        if HAS_FERNET:
            self._fernet = Fernet(key)
        else:
            self._fernet = _FallbackFernet(key)
        self._load()

    def _get_or_create_key(self) -> bytes:
        """
        Get the encryption key from env var or file, or generate a new one.
        """
        # Check environment variable first
        env_key = os.environ.get("VAULT_ENCRYPTION_KEY", "").strip()
        if env_key:
            # Derive a proper Fernet key from the user-provided key
            derived = hashlib.sha256(env_key.encode()).digest()
            return base64.urlsafe_b64encode(derived)

        # Check for saved key file
        if VAULT_KEY_FILE.exists():
            key = VAULT_KEY_FILE.read_bytes().strip()
            if len(key) >= 32:
                return key

        # Generate a new key
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if HAS_FERNET:
            key = Fernet.generate_key()
        else:
            key = _FallbackFernet.generate_key()
        VAULT_KEY_FILE.write_bytes(key)
        # Restrict permissions
        try:
            os.chmod(VAULT_KEY_FILE, 0o600)
        except OSError:
            pass  # Windows doesn't support chmod the same way

        logger.info("Generated new vault encryption key at %s", VAULT_KEY_FILE)
        return key

    def _load(self) -> None:
        """Load and decrypt vault data from disk."""
        if not VAULT_FILE.exists():
            self._data = {}
            return

        try:
            encrypted = VAULT_FILE.read_bytes()
            decrypted = self._fernet.decrypt(encrypted)
            self._data = json.loads(decrypted.decode("utf-8"))
            logger.info("Vault loaded: %d entries", len(self._data))
        except Exception as e:
            logger.error("Failed to load vault: %s", e)
            self._data = {}

    def _save(self) -> None:
        """Encrypt and save vault data to disk."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        plaintext = json.dumps(self._data, indent=2).encode("utf-8")
        encrypted = self._fernet.encrypt(plaintext)
        VAULT_FILE.write_bytes(encrypted)
        try:
            os.chmod(VAULT_FILE, 0o600)
        except OSError:
            pass

    def get(self, key: str) -> Optional[str]:
        """Retrieve a secret by key. Returns None if not found."""
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        """Store a secret. Persists to disk immediately."""
        self._data[key] = value
        self._save()
        logger.info("Vault entry stored: %s", key)

    def delete(self, key: str) -> bool:
        """Delete a secret. Returns True if it existed."""
        if key in self._data:
            del self._data[key]
            self._save()
            return True
        return False

    def has(self, key: str) -> bool:
        """Check if a key exists in the vault."""
        return key in self._data

    def list_keys(self) -> list[str]:
        """List all stored keys (not values)."""
        return sorted(self._data.keys())

    def clear(self) -> None:
        """Delete all vault entries."""
        self._data.clear()
        self._save()
        logger.warning("Vault cleared")
