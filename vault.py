"""Account authentication and encrypted, owner-scoped vault storage."""

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import uuid

from cryptography.exceptions import InvalidKey
from cryptography.fernet import Fernet, InvalidToken

import audit
import security
import session as sessions


DATABASE = Path(__file__).resolve().parent / "data" / "passwords.db"
MAX_PAYLOAD_BYTES = 64 * 1024


def open_database(path: Path = DATABASE) -> sqlite3.Connection:
    """Open a private SQLite file and create any missing account/vault tables."""
    descriptor = audit.open_private_file(path, os.O_RDWR)
    os.close(descriptor)

    database = sqlite3.connect(path)
    database.row_factory = sqlite3.Row
    try:
        # Reject entries whose owner account does not exist.
        # SQLite requires this setting on each connection.
        database.execute("PRAGMA foreign_keys = ON")
        with database:
            database.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    verification_salt BLOB NOT NULL,
                    verifier BLOB NOT NULL,
                    key_salt BLOB NOT NULL,
                    iterations INTEGER NOT NULL,
                    lanes INTEGER NOT NULL,
                    memory_cost INTEGER NOT NULL
                )
            """)
            database.execute("""
                CREATE TABLE IF NOT EXISTS entries (
                    id TEXT PRIMARY KEY,
                    owner_id INTEGER NOT NULL REFERENCES users(id),
                    payload BLOB NOT NULL
                )
            """)
    except sqlite3.Error:
        database.close()
        raise
    return database


def register_account(database: sqlite3.Connection, username: str, password: str):
    """Save an account's password verifier, independent salts, and KDF settings."""
    security.validate_account_username(username)
    security.validate_master_password(password)

    verification_salt = os.urandom(16)
    # The encryption key will use its own salt, separate from password checking.
    key_salt = os.urandom(16)
    password_bytes = bytearray(password, "utf-8")
    password = None
    try:
        verifier = security.password_kdf(verification_salt).derive(password_bytes)
    finally:
        security.wipe_buffer(password_bytes)

    try:
        # Commit the complete account on success, or roll back if saving fails.
        with database:
            result = database.execute(
                """INSERT INTO users
                   (username, verification_salt, verifier, key_salt,
                    iterations, lanes, memory_cost) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (username, verification_salt, verifier, key_salt,
                 security.KDF_ITERATIONS, security.KDF_LANES, security.KDF_MEMORY_COST),
            )
    except sqlite3.IntegrityError:
        raise ValueError("Username is already taken.") from None
    audit.log_event("account_created", user_id=result.lastrowid)


def login_account(database: sqlite3.Connection, username: str, password: str) -> sessions.Session:
    """Verify credentials before deriving the account's vault encryption key."""
    failure = "Invalid username or master password."
    try:
        security.validate_account_username(username)
        security.validate_password(password, "Master password")
    except ValueError:
        audit.log_event("login_failed")
        raise ValueError(failure) from None

    user = database.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user is None:
        audit.log_event("login_failed")
        raise ValueError(failure)

    # Treat the database as untrusted: do not accept arbitrary Argon2 costs.
    settings = (user["iterations"], user["lanes"], user["memory_cost"])
    if any(type(value) is not int for value in settings) or settings != (security.KDF_ITERATIONS, security.KDF_LANES, security.KDF_MEMORY_COST):
        audit.log_event("login_failed")
        raise ValueError("Unsupported account key-derivation settings.")
    if not isinstance(user["verifier"], bytes) or len(user["verifier"]) != 32:
        audit.log_event("login_failed")
        raise ValueError(security.INVALID_ACCOUNT_METADATA)

    try:
        security.validate_owner_id(user["id"])
        for salt in (user["verification_salt"], user["key_salt"]):
            if not isinstance(salt, bytes) or len(salt) != 16:
                raise ValueError(security.INVALID_ACCOUNT_METADATA)
    except ValueError:
        audit.log_event("login_failed")
        raise

    password_bytes = bytearray(password, "utf-8")
    password = None
    key = None
    try:
        try:
            security.password_kdf(user["verification_salt"]).verify(password_bytes, user["verifier"])
        except InvalidKey:
            audit.log_event("login_failed")
            raise ValueError(failure) from None

        # Reuse the same input buffer; the returned key and Fernet internals are immutable.
        key = security.password_kdf(user["key_salt"]).derive(password_bytes)
        session = sessions.Session(user["id"], Fernet(base64.urlsafe_b64encode(key)), username)
    finally:
        security.wipe_buffer(password_bytes)
        key = None

    audit.log_event("login_succeeded", user_id=user["id"])
    return session


def add_entry(
    database: sqlite3.Connection, session: sessions.Session,
    service: str, username: str, password: str,
) -> str:
    """Encrypt a new credential for the session's owner and return its ID."""
    session.require_unlocked()
    security.validate_entry_field(service, "Service")
    security.validate_entry_field(username, "Entry username")
    security.validate_password(password, "Entry password")

    entry_id = uuid.uuid4().hex
    entry = {
        "id": entry_id,
        "owner_id": session.owner_id,
        "service": service,
        "username": username,
        "password": password,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    # Encrypt all credential fields together. Only ciphertext reaches SQLite.
    # Encrypted IDs will let us detect payloads moved to another record on read.
    try:
        payload = session.cipher.encrypt(json.dumps(entry).encode("utf-8"))
    finally:
        # Release plaintext field references before database I/O, even on failure.
        entry.clear()
        password = None
    with database:
        database.execute(
            "INSERT INTO entries (id, owner_id, payload) VALUES (?, ?, ?)",
            (entry_id, session.owner_id, payload),
        )
    audit.log_event("entry_created", user_id=session.owner_id)
    return entry_id


def decrypt_entry(session: sessions.Session, row: sqlite3.Row) -> dict:
    """Shared integrity checks for listing and password retrieval."""
    session.require_unlocked()
    entry = None
    try:
        security.validate_entry_id(row["id"])
        payload = row["payload"]
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_PAYLOAD_BYTES:
            raise ValueError
        entry = json.loads(session.cipher.decrypt(payload), object_pairs_hook=security.unique_json_fields)
        if not isinstance(entry, dict):
            raise ValueError
        # A valid encrypted payload must belong to this exact row and user.
        if entry["id"] != row["id"] or entry["owner_id"] != session.owner_id:
            raise ValueError
        security.validate_entry_id(entry["id"])
        security.validate_owner_id(entry["owner_id"])
        security.validate_entry_field(entry["service"], "Service")
        security.validate_entry_field(entry["username"], "Entry username")
        security.validate_password(entry["password"], "Entry password")
        # Older entries have no timestamp; do not invent an update time.
        updated_at = None
        if "updated_at" in entry:
            updated_at = datetime.fromisoformat(entry["updated_at"])
            if updated_at.tzinfo is None:
                raise ValueError
            updated_at = updated_at.astimezone(timezone.utc)
        entry["updated_at"] = updated_at
    except (InvalidToken, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        if isinstance(entry, dict):
            entry.clear()
        audit.log_event("integrity_check_failed", user_id=session.owner_id)
        raise ValueError("Entry integrity check failed. Vault data may be damaged.") from None
    return entry


def load_entry(database: sqlite3.Connection, session: sessions.Session, entry_id: str) -> dict:
    """Load and verify one owned record; callers must keep plaintext short-lived."""
    session.require_unlocked()
    security.validate_entry_id(entry_id)
    row = database.execute(
        "SELECT id, payload FROM entries WHERE id = ? AND owner_id = ?",
        (entry_id, session.owner_id),
    ).fetchone()
    if row is None:
        raise ValueError(security.ENTRY_NOT_FOUND)
    return decrypt_entry(session, row)


def copy_entry_password(database: sqlite3.Connection, session: sessions.Session, entry_id: str):
    """Re-read an owned entry and copy its password without printing."""
    entry = load_entry(database, session, entry_id)
    try:
        session.clipboard.copy(entry["password"])
    finally:
        entry.clear()
    audit.log_event("password_copied", user_id=session.owner_id)


def update_entry(database: sqlite3.Connection, session: sessions.Session, entry_id: str,
                 service: str, username: str, password: str | None = None):
    """Update an owned entry; None preserves the existing password."""
    session.require_unlocked()
    security.validate_entry_field(service, "Service")
    security.validate_entry_field(username, "Entry username")
    if password is not None:
        security.validate_password(password, "Entry password")
    entry = load_entry(database, session, entry_id)
    if password is not None:
        entry["password"] = password
    entry["service"] = service
    entry["username"] = username
    entry["updated_at"] = datetime.now(timezone.utc).isoformat()
    try:
        payload = session.cipher.encrypt(json.dumps(entry).encode("utf-8"))
    finally:
        # Release plaintext field references before database I/O, even on failure.
        entry.clear()
        password = None
    session.require_unlocked()
    with database:
        result = database.execute(
            "UPDATE entries SET payload = ? WHERE id = ? AND owner_id = ?",
            (payload, entry_id, session.owner_id),
        )
        if result.rowcount != 1:
            raise ValueError(security.ENTRY_NOT_FOUND)

    audit.log_event("entry_updated", user_id=session.owner_id)


def delete_entry(database: sqlite3.Connection, session: sessions.Session, entry_id: str):
    """Delete only the authenticated user's selected record."""
    session.require_unlocked()
    security.validate_entry_id(entry_id)
    with database:
        result = database.execute(
            "DELETE FROM entries WHERE id = ? AND owner_id = ?",
            (entry_id, session.owner_id),
        )
        if result.rowcount != 1:
            raise ValueError(security.ENTRY_NOT_FOUND)

    audit.log_event("entry_deleted", user_id=session.owner_id)


def list_entries(database: sqlite3.Connection, session: sessions.Session) -> list[dict]:
    """Return verified display fields, newest first, without plaintext passwords."""
    session.require_unlocked()
    rows = database.execute(
        "SELECT id, payload FROM entries WHERE owner_id = ? ORDER BY rowid",
        (session.owner_id,),
    ).fetchall()
    summaries = []
    for row in rows:
        entry = decrypt_entry(session, row)

        try:
            # Return only display data so the interface never receives the password.
            summaries.append({
                "id": row["id"],
                "service": entry["service"],
                "username": entry["username"],
                "updated_at": entry["updated_at"],
            })
        finally:
            entry.clear()
    # Entries without a known time appear last. Equal times retain their order.
    oldest = datetime.min.replace(tzinfo=timezone.utc)
    return sorted(summaries, key=lambda entry: entry["updated_at"] or oldest, reverse=True)
