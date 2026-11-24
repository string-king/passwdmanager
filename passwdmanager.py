import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import getpass
import hashlib
import json
import logging
import os
from pathlib import Path
import sqlite3
import stat
import signal
import subprocess
import sys
import threading
import termios
import time
import uuid
import warnings

from cryptography.exceptions import InvalidKey, UnsupportedAlgorithm
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


DATABASE = Path(__file__).resolve().parent / "data" / "passwords.db"
KDF_ITERATIONS = 3
KDF_LANES = 4
KDF_MEMORY_COST = 64 * 1024  # KiB: 64 MiB of memory per derivation
PAGE_SIZE = 10
CLIPBOARD_SECONDS = 20
IDLE_SECONDS = 5 * 60
MAX_PAYLOAD_BYTES = 64 * 1024
ENTRY_NOT_FOUND = "Entry not found in your vault."
INVALID_ACCOUNT_METADATA = "Invalid account metadata."
INACTIVITY_MESSAGE = "Vault locked after five minutes of inactivity."
LOG_FILE = Path(__file__).resolve().parent / "logs" / "events.jsonl"
LOGGER = logging.getLogger("passwdmanager.events")
LOGGER.addHandler(logging.NullHandler())
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


class EventLogHandler(logging.StreamHandler):
    def handleError(self, record):
        # Never print logging internals or the original exception to the terminal.
        print("Could not write the security log. Check permissions and disk space.", file=sys.stderr)


def private_directory(path: Path):
    """Reject symlinked application directories before changing permissions."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise OSError("Unsafe application directory.")
    path.chmod(0o700)


def open_private_file(path: Path, flags: int) -> int:
    """Open a regular private file; nonblocking mode prevents FIFO hangs."""
    private_directory(path.parent)
    descriptor = os.open(path, flags | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("Expected a regular file.")
        os.fchmod(descriptor, 0o600)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def configure_logging(path: Path = LOG_FILE):
    """Open one private append-only JSON Lines file for this process."""
    descriptor = open_private_file(path, os.O_APPEND | os.O_WRONLY)
    try:
        stream = os.fdopen(descriptor, "a", encoding="utf-8")
    except BaseException:
        os.close(descriptor)
        raise
    handler = EventLogHandler(stream)
    LOGGER.addHandler(handler)
    return handler


def log_event(event: str, *, user_id: int | None = None,
              operation: str | None = None, reason: str | None = None):
    """Accept only explicit audit fields; callers never pass credential contents."""
    level = logging.WARNING if event in ("login_failed", "integrity_check_failed", "operation_failed") else logging.INFO
    record = {"timestamp": datetime.now(timezone.utc).isoformat(),
              "severity": logging.getLevelName(level), "event": event}
    if user_id is not None:
        record["user_id"] = user_id
    if operation is not None:
        record["operation"] = operation
    if reason is not None:
        record["reason"] = reason
    LOGGER.log(level, json.dumps(record))


def wipe_buffer(buffer: bytearray):
    """Overwrite this buffer only; immutable and library-owned copies may remain."""
    buffer[:] = b"\x00" * len(buffer)


class SessionExpired(Exception):
    """Interrupt an idle vault, including a blocked terminal prompt."""


class Clipboard:
    """Track our last copy without retaining another plaintext password."""

    def __init__(self, owner_id: int | None = None):
        """Initialize clipboard tracking and synchronization for the timer."""
        self.owner_id = owner_id
        self.digest = None
        self.timer = None
        # Copy may call clear while holding the lock; timers still serialize here.
        self.mutex = threading.RLock()
        self.warning = ""
        self.generation = 0

    def copy(self, password: str):
        """Copy a password to macOS and schedule conditional clearing."""
        data = bytearray(password, "utf-8")
        password = None
        try:
            with self.mutex:
                # Finish tracking any previous copy before replacing its fingerprint.
                if self.digest is not None:
                    self.clear()
                    if self.digest is not None:
                        raise ValueError("Could not clear the previous password. Clear the clipboard manually and try again.")
                self.digest = hashlib.sha256(data).digest()
                self.warning = ""
                self.generation += 1
                self.timer = threading.Timer(CLIPBOARD_SECONDS, self.clear, args=(self.generation,))
                self.timer.daemon = True
                self.timer.start()
                try:
                    subprocess.run(
                        ["/usr/bin/pbcopy"], input=data, capture_output=True,
                        env={**os.environ, "LC_ALL": "en_US.UTF-8"},
                        check=True, timeout=3,
                    )
                except (OSError, subprocess.SubprocessError):
                    log_event("operation_failed", user_id=self.owner_id, operation="clipboard_copy")
                    # pbcopy may have written the password before reporting failure.
                    self.clear()
                    raise ValueError("Could not copy the password. Clear the clipboard manually if needed.") from None

        finally:
            wipe_buffer(data)

    def clear(self, generation=None):
        """Clear our copied password if unchanged, ignoring outdated timers."""
        # Serialize copying and clearing so an old timer cannot clear a new copy.
        with self.mutex:
            if generation is not None and generation != self.generation:
                return
            self.generation += 1
            if self.timer is not None:
                self.timer.cancel()
                self.timer = None
            if self.digest is None:
                return
            try:
                current = subprocess.run(
                    ["/usr/bin/pbpaste", "-Prefer", "txt"], capture_output=True,
                    env={**os.environ, "LC_ALL": "en_US.UTF-8"},
                    check=True, timeout=3,
                ).stdout
                if hashlib.sha256(current).digest() == self.digest:
                    subprocess.run(
                        ["/usr/bin/pbcopy"], input=b"", capture_output=True,
                        check=True, timeout=3,
                    )
            except (OSError, subprocess.SubprocessError):
                log_event("operation_failed", user_id=self.owner_id, operation="clipboard_clear")
                self.warning = "Could not clear the clipboard. Clear it manually."
                return
            self.digest = None
            self.warning = ""


class Session:
    """Keep the authenticated account and its temporary encryption object."""

    def __init__(self, owner_id: int, cipher: Fernet):
        """Start an unlocked session with its own clipboard tracker."""
        validate_owner_id(owner_id)
        self.owner_id = owner_id
        self.cipher = cipher
        self.clipboard = Clipboard(owner_id)
        self.deadline = time.monotonic() + IDLE_SECONDS

    def require_unlocked(self):
        """Reject expired sessions even when called outside the terminal menu."""
        if self.cipher is None:
            raise ValueError("Vault is locked. Log in again.")
        if time.monotonic() >= self.deadline:
            self.lock(reason="inactivity")
            raise SessionExpired(INACTIVITY_MESSAGE)

    def read_input(self, prompt: str, *, hidden=False) -> str:
        """Interrupt only terminal input; never interrupt a vault write or copy."""
        self.require_unlocked()

        def expire(signum, frame):
            raise SessionExpired(INACTIVITY_MESSAGE)

        previous_handler = signal.getsignal(signal.SIGALRM)
        if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
            raise RuntimeError("An existing process alarm prevents safe vault timing.")
        signal.signal(signal.SIGALRM, expire)
        try:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise SessionExpired(INACTIVITY_MESSAGE)
            signal.setitimer(signal.ITIMER_REAL, remaining)
            value = read_password(prompt) if hidden else input(prompt)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)

        self.require_unlocked()
        self.deadline = time.monotonic() + IDLE_SECONDS
        return value

    def lock(self, reason: str = "logout"):
        """Drop the encryption object and attempt to clear our clipboard copy."""
        # Release the encryption object; this does not guarantee memory erasure.
        was_unlocked = self.cipher is not None
        self.cipher = None
        self.clipboard.clear()
        if was_unlocked:
            log_event("vault_locked", user_id=self.owner_id, reason=reason)


def open_database(path: Path = DATABASE) -> sqlite3.Connection:
    """Open a private SQLite file and create any missing account/vault tables."""
    descriptor = open_private_file(path, os.O_RDWR)
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


def read_password(prompt: str) -> str:
    """Read hidden input, failing if the terminal cannot suppress echo."""
    # Refuse getpass's fallback to visible input if the terminal cannot hide it.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt)


def clear_console():
    """Clear the visible screen when output goes to a terminal."""
    if sys.stdout.isatty():
        # Clear the visible terminal screen and move the cursor to the top.
        print("\033[2J\033[H", end="", flush=True)


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


def register_account(database: sqlite3.Connection, username: str, password: str):
    """Save an account's password verifier, independent salts, and KDF settings."""
    validate_account_username(username)
    validate_master_password(password)

    verification_salt = os.urandom(16)
    # The encryption key will use its own salt, separate from password checking.
    key_salt = os.urandom(16)
    password_bytes = bytearray(password, "utf-8")
    password = None
    try:
        verifier = password_kdf(verification_salt).derive(password_bytes)
    finally:
        wipe_buffer(password_bytes)

    try:
        # Commit the complete account on success, or roll back if saving fails.
        with database:
            result = database.execute(
                """INSERT INTO users
                   (username, verification_salt, verifier, key_salt,
                    iterations, lanes, memory_cost) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (username, verification_salt, verifier, key_salt,
                 KDF_ITERATIONS, KDF_LANES, KDF_MEMORY_COST),
            )
    except sqlite3.IntegrityError:
        raise ValueError("Username is already taken.") from None
    log_event("account_created", user_id=result.lastrowid)


def login_account(database: sqlite3.Connection, username: str, password: str) -> Session:
    """Verify credentials before deriving the account's vault encryption key."""
    failure = "Invalid username or master password."
    try:
        validate_account_username(username)
        validate_password(password, "Master password")
    except ValueError:
        log_event("login_failed")
        raise ValueError(failure) from None

    user = database.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user is None:
        log_event("login_failed")
        raise ValueError(failure)

    # Treat the database as untrusted: do not accept arbitrary Argon2 costs.
    settings = (user["iterations"], user["lanes"], user["memory_cost"])
    if any(type(value) is not int for value in settings) or settings != (KDF_ITERATIONS, KDF_LANES, KDF_MEMORY_COST):
        log_event("login_failed")
        raise ValueError("Unsupported account key-derivation settings.")
    if not isinstance(user["verifier"], bytes) or len(user["verifier"]) != 32:
        log_event("login_failed")
        raise ValueError(INVALID_ACCOUNT_METADATA)

    try:
        validate_owner_id(user["id"])
        for salt in (user["verification_salt"], user["key_salt"]):
            if not isinstance(salt, bytes) or len(salt) != 16:
                raise ValueError(INVALID_ACCOUNT_METADATA)
    except ValueError:
        log_event("login_failed")
        raise

    password_bytes = bytearray(password, "utf-8")
    password = None
    key = None
    try:
        try:
            password_kdf(user["verification_salt"]).verify(password_bytes, user["verifier"])
        except InvalidKey:
            log_event("login_failed")
            raise ValueError(failure) from None

        # Reuse the same input buffer; the returned key and Fernet internals are immutable.
        key = password_kdf(user["key_salt"]).derive(password_bytes)
        session = Session(user["id"], Fernet(base64.urlsafe_b64encode(key)))
    finally:
        wipe_buffer(password_bytes)
        key = None

    log_event("login_succeeded", user_id=user["id"])
    return session


def validate_entry_field(value: str, label: str):
    """Check a displayed field's length and reject terminal control characters."""
    if not isinstance(value, str) or not value.strip() or len(value) > 256 or not value.isprintable():
        raise ValueError(f"{label} must contain 1 to 256 printable characters.")


def add_entry(
    database: sqlite3.Connection, session: Session,
    service: str, username: str, password: str,
) -> str:
    """Encrypt a new credential for the session's owner and return its ID."""
    session.require_unlocked()
    validate_entry_field(service, "Service")
    validate_entry_field(username, "Entry username")
    validate_password(password, "Entry password")

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
    log_event("entry_created", user_id=session.owner_id)
    return entry_id


def decrypt_entry(session: Session, row: sqlite3.Row) -> dict:
    """Shared integrity checks for listing and password retrieval."""
    session.require_unlocked()
    entry = None
    try:
        validate_entry_id(row["id"])
        payload = row["payload"]
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_PAYLOAD_BYTES:
            raise ValueError
        entry = json.loads(session.cipher.decrypt(payload), object_pairs_hook=unique_json_fields)
        if not isinstance(entry, dict):
            raise ValueError
        # A valid encrypted payload must belong to this exact row and user.
        if entry["id"] != row["id"] or entry["owner_id"] != session.owner_id:
            raise ValueError
        validate_entry_id(entry["id"])
        validate_owner_id(entry["owner_id"])
        validate_entry_field(entry["service"], "Service")
        validate_entry_field(entry["username"], "Entry username")
        validate_password(entry["password"], "Entry password")
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
        log_event("integrity_check_failed", user_id=session.owner_id)
        raise ValueError("Entry integrity check failed. Vault data may be damaged.") from None
    return entry


def load_entry(database: sqlite3.Connection, session: Session, entry_id: str) -> dict:
    """Load and verify one owned record; callers must keep plaintext short-lived."""
    session.require_unlocked()
    validate_entry_id(entry_id)
    row = database.execute(
        "SELECT id, payload FROM entries WHERE id = ? AND owner_id = ?",
        (entry_id, session.owner_id),
    ).fetchone()
    if row is None:
        raise ValueError(ENTRY_NOT_FOUND)
    return decrypt_entry(session, row)


def copy_entry_password(database: sqlite3.Connection, session: Session, entry_id: str):
    """Re-read an owned entry and copy its password without printing."""
    entry = load_entry(database, session, entry_id)
    try:
        session.clipboard.copy(entry["password"])
    finally:
        entry.clear()
    log_event("password_copied", user_id=session.owner_id)


def update_entry(database: sqlite3.Connection, session: Session, entry_id: str,
                 service: str, username: str, password: str | None = None):
    """Update an owned entry; None preserves the existing password."""
    session.require_unlocked()
    validate_entry_field(service, "Service")
    validate_entry_field(username, "Entry username")
    if password is not None:
        validate_password(password, "Entry password")
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
            raise ValueError(ENTRY_NOT_FOUND)

    log_event("entry_updated", user_id=session.owner_id)


def delete_entry(database: sqlite3.Connection, session: Session, entry_id: str):
    """Delete only the authenticated user's selected record."""
    session.require_unlocked()
    validate_entry_id(entry_id)
    with database:
        result = database.execute(
            "DELETE FROM entries WHERE id = ? AND owner_id = ?",
            (entry_id, session.owner_id),
        )
        if result.rowcount != 1:
            raise ValueError(ENTRY_NOT_FOUND)

    log_event("entry_deleted", user_id=session.owner_id)


def list_entries(database: sqlite3.Connection, session: Session) -> list[dict]:
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


def print_entries(entries: list[dict]):
    """Print one page as a numbered table with local update times."""
    if not entries:
        print("Vault is empty.")
        return

    headers = ["#", "Service", "Username/email", "Last updated"]
    rows = []
    for number, entry in enumerate(entries, start=1):
        updated_at = entry["updated_at"]
        time_text = updated_at.astimezone().strftime("%Y-%m-%d %H:%M") if updated_at else "Unknown"
        # Keep long fields from making the table excessively wide.
        service = entry["service"]
        username = entry["username"]
        if len(service) > 24:
            service = service[:21] + "..."
        if len(username) > 22:
            username = username[:19] + "..."
        rows.append([str(number), service, username, time_text])

    # Start with header widths, then widen each column to fit its values.
    widths = [len(header) for header in headers]
    for row in rows:
        for column, value in enumerate(row):
            widths[column] = max(widths[column], len(value))
    print(" | ".join(value.ljust(width) for value, width in zip(headers, widths)))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(" | ".join(value.ljust(width) for value, width in zip(row, widths)))


def print_entry_page(entries: list[dict], page: int, page_count: int,
                     message: str, clipboard_warning: str):
    """Render one page and its status messages without changing navigation."""
    start = page * PAGE_SIZE
    end = min(start + PAGE_SIZE, len(entries))
    clear_console()
    print(f"Page {page + 1} of {page_count} | {len(entries)} entries")
    if entries:
        print(f"Showing {start + 1}-{end}, newest first.\n")
    print_entries(entries[start:end])
    if message:
        print(f"\n{message}")
    if clipboard_warning:
        print(clipboard_warning)
    print("\n[N] Next  [P] Previous  [B] Back")
    print("Enter a row number for entry actions.")


def browse_entries(database: sqlite3.Connection, session: Session, entries: list[dict]):
    """Browse display fields and open actions for the selected row."""
    page = 0
    message = ""
    while True:
        page_count = max(1, (len(entries) + PAGE_SIZE - 1) // PAGE_SIZE)
        page = min(page, page_count - 1)
        start = page * PAGE_SIZE
        page_entries = entries[start:start + PAGE_SIZE]
        row_numbers = [str(number) for number in range(1, len(page_entries) + 1)]
        print_entry_page(entries, page, page_count, message, session.clipboard.warning)
        choice = session.read_input("Choice: ").strip().lower()
        message = ""
        try:
            if choice == "n":
                message = "Already on the last page." if page + 1 == page_count else ""
                page = min(page + 1, page_count - 1)
            elif choice == "p":
                message = "Already on the first page." if page == 0 else ""
                page = max(page - 1, 0)
            elif choice == "b":
                clear_console()
                return
            elif choice in row_numbers:
                selected_entry = page_entries[int(choice) - 1]
                message = entry_actions(database, session, selected_entry)
                entries = list_entries(database, session)
            else:
                message = "Choose a row number shown on this page, N, P, or B."
        except ValueError as error:
            message = str(error)


def entry_actions(database: sqlite3.Connection, session: Session, entry: dict) -> str:
    """Offer actions using display data only; never retain a decrypted password."""
    while True:
        clear_console()
        print(f"Service: {entry['service']}\nUsername/email: {entry['username']}")
        print("\n1. Copy password\n2. Edit entry\n3. Delete entry\n4. Back")
        choice = session.read_input("Choice: ").strip()
        if choice == "1":
            copy_entry_password(database, session, entry["id"])
            return f"Password copied. Clipboard clears after {CLIPBOARD_SECONDS} seconds if unchanged."
        if choice == "2":
            prompt_edit_entry(database, session, entry)
            return "Entry updated."
        if choice == "3":
            confirmation = session.read_input("Delete this entry? Type DELETE to confirm: ")
            if confirmation != "DELETE":
                return "Deletion cancelled."
            delete_entry(database, session, entry["id"])
            return "Entry deleted."
        if choice == "4":
            return ""
        print("Choose 1, 2, 3, or 4.")


def prompt_edit_entry(database: sqlite3.Connection, session: Session, entry: dict):
    """Keep blank display fields and replace passwords only by explicit choice."""
    service = session.read_input("Service (Enter to keep): ") or entry["service"]
    validate_entry_field(service, "Service")
    username = session.read_input("Username/email (Enter to keep): ") or entry["username"]
    validate_entry_field(username, "Entry username")
    replace = session.read_input("Replace password? [y/N]: ").strip().lower()
    if replace not in ("", "n", "y"):
        raise ValueError("Choose Y or N. Entry was not changed.")
    password = session.read_input("New entry password: ", hidden=True) if replace == "y" else None
    try:
        update_entry(database, session, entry["id"], service, username, password)
    finally:
        password = None


# Keep plaintext input local to these short prompt functions. Returning releases
# their local references; Python cannot guarantee erasing every memory copy.
def prompt_registration(database: sqlite3.Connection):
    """Collect and confirm a new master password, then register the account."""
    username = input("Username: ")
    print("Master password must contain 12 to 1024 characters.")
    password = read_password("Master password: ")
    confirmation = None
    try:
        validate_master_password(password)
        confirmation = read_password("Confirm master password: ")
        if password != confirmation:
            raise ValueError("Passwords do not match.")
        confirmation = None
        register_account(database, username, password)
    finally:
        password = None
        confirmation = None


def prompt_login(database: sqlite3.Connection) -> Session:
    """Collect hidden login credentials and return the authenticated session."""
    username = input("Username: ")
    password = read_password("Master password: ")
    try:
        return login_account(database, username, password)
    finally:
        password = None


def prompt_add_entry(database: sqlite3.Connection, session: Session):
    """Validate each field as it is entered, then encrypt and save the entry."""
    service = session.read_input("Service: ")
    validate_entry_field(service, "Service")
    username = session.read_input("Username/email: ")
    validate_entry_field(username, "Entry username")
    password = session.read_input("Entry password: ", hidden=True)
    try:
        add_entry(database, session, service, username, password)
    finally:
        password = None


def run_vault(database: sqlite3.Connection, session: Session) -> bool:
    """Run the vault menu; return True to exit or False to log out. Always lock."""
    lock_reason = "error"
    try:
        clear_console()
        print("Vault unlocked.")
        while True:
            if session.clipboard.warning:
                print(session.clipboard.warning)
            print("\n1. Add entry")
            print("2. List entries")
            print("3. Lock / log out")
            print("4. Exit")
            choice = session.read_input("Choice: ")
            clear_console()
            try:
                if choice == "1":
                    prompt_add_entry(database, session)
                    clear_console()
                    print("Entry saved.")
                elif choice == "2":
                    entries = list_entries(database, session)
                    browse_entries(database, session, entries)
                elif choice == "3":
                    lock_reason = "logout"
                    return False
                elif choice == "4":
                    lock_reason = "exit"
                    return True
                else:
                    print("Choose 1, 2, 3, or 4.")
            except ValueError as error:
                clear_console()
                print(error)
    except SessionExpired as error:
        lock_reason = "inactivity"
        clear_console()
        print(error)
        return False
    except (OSError, sqlite3.Error):
        log_event("operation_failed", user_id=session.owner_id, operation="database")
        print("Unable to access the vault database. Check permissions and disk space.")
        return False
    except (EOFError, KeyboardInterrupt):
        lock_reason = "interrupted"
        raise
    finally:
        # Also lock when Ctrl-C, EOF, or an unexpected error interrupts the menu.
        session.lock(reason=lock_reason)
        if session.clipboard.warning:
            print(session.clipboard.warning)
        print("Vault locked.")


def run(database: sqlite3.Connection):
    """Run the start menu and hand successful logins to the vault menu."""
    clear_console()
    while True:
        print("\nPassword manager")
        print("1. Register")
        print("2. Log in")
        print("3. Exit")
        choice = input("Choice: ")
        clear_console()

        if choice == "1":
            try:
                prompt_registration(database)
                clear_console()
                print("Account created. Log in to unlock your vault.")
            except ValueError as error:
                clear_console()
                print(error)
        elif choice == "2":
            try:
                session = prompt_login(database)
            except ValueError as error:
                clear_console()
                print(error)
                continue
            if run_vault(database, session):
                return
        elif choice == "3":
            return
        else:
            print("Choose 1, 2, or 3.")


def interrupt_exit(signum, frame):
    """Use orderly exit for terminal quit and suspension requests."""
    raise KeyboardInterrupt


@contextmanager
def terminal_mode():
    """Disable flow control and restore terminal settings and handlers on exit."""
    descriptor = sys.stdin.fileno()
    original = termios.tcgetattr(descriptor)
    settings = original[:]
    settings[0] &= ~(termios.IXON | termios.IXOFF)
    previous_handlers = {}
    try:
        for signum in (signal.SIGTSTP, signal.SIGQUIT):
            previous_handlers[signum] = signal.signal(signum, interrupt_exit)
        termios.tcsetattr(descriptor, termios.TCSANOW, settings)
        yield
    finally:
        try:
            # Discard unfinished input and restore echo even after interrupted getpass.
            termios.tcsetattr(descriptor, termios.TCSAFLUSH, original)
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)


def main() -> int:
    """Check terminal support, manage the database lifetime, and report failures."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Run this application in an interactive terminal.")
        return 1

    try:
        with terminal_mode():
            return run_application()
    except termios.error:
        print("Unable to configure or restore terminal settings.", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
        return 0


def run_application() -> int:
    """Manage logging and database resources inside the terminal context."""
    try:
        log_handler = configure_logging()
    except OSError:
        print("Unable to open the security log. Check permissions and disk space.")
        return 1

    database = None
    try:
        database = open_database()
        run(database)
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
    except (OSError, sqlite3.Error):
        log_event("operation_failed", operation="database")
        print("Unable to access the vault database. Check permissions and disk space.")
        return 1
    except getpass.GetPassWarning:
        print("Hidden password input is unavailable. Exiting.")
        return 1
    except UnsupportedAlgorithm:
        print("This cryptography installation does not support Argon2id.")
        return 1
    finally:
        if database is not None:
            database.close()
        LOGGER.removeHandler(log_handler)
        log_handler.stream.close()
        log_handler.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
