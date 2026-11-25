"""Independent validation, password generation, KDF settings, and buffer cleanup.

This module has no dependency on the menus, sessions, clipboard, or database.
"""

import secrets
import string

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


KDF_ITERATIONS = 3
KDF_LANES = 4
KDF_MEMORY_COST = 64 * 1024  # KiB: 64 MiB of memory per derivation
ENTRY_NOT_FOUND = "Entry not found in your vault."
INVALID_ACCOUNT_METADATA = "Invalid account metadata."


def wipe_buffer(buffer: bytearray):
    """Overwrite this buffer only; immutable and library-owned copies may remain."""
    buffer[:] = b"\x00" * len(buffer)


def validate_account_username(username: str):
    """Reject empty, oversized, or unsafe account names."""
    if not isinstance(username, str) or not username.strip() or len(username) > 64 or not username.isprintable():
        raise ValueError("Username must contain 1 to 64 printable characters.")


def validate_password(password: str, label: str, minimum: int = 1):
    """Apply the same password type and length rules at every boundary."""
    if not isinstance(password, str) or not minimum <= len(password) <= 1024:
        raise ValueError(f"{label} must contain {minimum} to 1024 characters.")
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{label} contains invalid Unicode.") from None


def validate_master_password(password: str):
    """Reject a new master password outside the allowed length range."""
    validate_password(password, "Master password", minimum=12)


def validate_entry_id(entry_id: str):
    if not isinstance(entry_id, str) or len(entry_id) != 32 or any(
        character not in "0123456789abcdef" for character in entry_id
    ):
        raise ValueError(ENTRY_NOT_FOUND)


def validate_owner_id(owner_id: int):
    if type(owner_id) is not int or not 1 <= owner_id <= 2**63 - 1:
        raise ValueError(INVALID_ACCOUNT_METADATA)


def unique_json_fields(pairs):
    """Reject ambiguous JSON objects instead of silently keeping the last field."""
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON field.")
        result[name] = value
    return result


def password_kdf(salt: bytes) -> Argon2id:
    """Build a fresh Argon2id object using the application's fixed settings."""
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise ValueError(INVALID_ACCOUNT_METADATA)
    return Argon2id(
        salt=salt,
        length=32,
        iterations=KDF_ITERATIONS,
        lanes=KDF_LANES,
        memory_cost=KDF_MEMORY_COST,
    )


def validate_entry_field(value: str, label: str):
    """Check a displayed field's length and reject terminal control characters."""
    if not isinstance(value, str) or not value.strip() or len(value) > 256 or not value.isprintable():
        raise ValueError(f"{label} must contain 1 to 256 printable characters.")


def generate_password() -> str:
    """Generate a 20-character password using secure randomness."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+?"
    return "".join(secrets.choice(alphabet) for _ in range(20))
