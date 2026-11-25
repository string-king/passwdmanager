import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import sqlite3
import signal
import sys
import termios
import time
import uuid
import warnings

from cryptography.exceptions import InvalidKey, UnsupportedAlgorithm
from cryptography.fernet import Fernet, InvalidToken

import audit
import clipboard
import security


DATABASE = Path(__file__).resolve().parent / "data" / "passwords.db"
PAGE_SIZE = 10
IDLE_SECONDS = 5 * 60
MAX_PAYLOAD_BYTES = 64 * 1024
INACTIVITY_MESSAGE = "Vault locked after five minutes of inactivity."


class SessionExpired(Exception):
    """Interrupt an idle vault, including a blocked terminal prompt."""


class Session:
    """Keep the authenticated account and its temporary encryption object."""

    def __init__(self, owner_id: int, cipher: Fernet):
        """Start an unlocked session with its own clipboard tracker."""
        security.validate_owner_id(owner_id)
        self.owner_id = owner_id
        self.cipher = cipher
        self.clipboard = clipboard.Clipboard(owner_id)
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

        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise SessionExpired(INACTIVITY_MESSAGE)
        try:
            # terminal_mode owns the signal handler; only input arms the timer.
            signal.setitimer(signal.ITIMER_REAL, remaining)
            value = read_password(prompt) if hidden else input(prompt)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

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
            audit.log_event("vault_locked", user_id=self.owner_id, reason=reason)


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


def login_account(database: sqlite3.Connection, username: str, password: str) -> Session:
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
        session = Session(user["id"], Fernet(base64.urlsafe_b64encode(key)))
    finally:
        security.wipe_buffer(password_bytes)
        key = None

    audit.log_event("login_succeeded", user_id=user["id"])
    return session


def add_entry(
    database: sqlite3.Connection, session: Session,
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


def decrypt_entry(session: Session, row: sqlite3.Row) -> dict:
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


def load_entry(database: sqlite3.Connection, session: Session, entry_id: str) -> dict:
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


def copy_entry_password(database: sqlite3.Connection, session: Session, entry_id: str):
    """Re-read an owned entry and copy its password without printing."""
    entry = load_entry(database, session, entry_id)
    try:
        session.clipboard.copy(entry["password"])
    finally:
        entry.clear()
    audit.log_event("password_copied", user_id=session.owner_id)


def update_entry(database: sqlite3.Connection, session: Session, entry_id: str,
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


def delete_entry(database: sqlite3.Connection, session: Session, entry_id: str):
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
            return f"Password copied. Clipboard clears after {clipboard.CLIPBOARD_SECONDS} seconds if unchanged."
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


def prompt_entry_password(session: Session, prompt: str = "Entry password: ") -> str:
    """Generate a password or read one without displaying it."""
    choice = session.read_input("Generate a 20-character password? [y/N]: ").strip().lower()
    if choice == "y":
        return security.generate_password()
    if choice in ("", "n"):
        return session.read_input(prompt, hidden=True)
    raise ValueError("Choose Y or N.")


def prompt_edit_entry(database: sqlite3.Connection, session: Session, entry: dict):
    """Keep blank display fields and replace passwords only by explicit choice."""
    service = session.read_input("Service (Enter to keep): ") or entry["service"]
    security.validate_entry_field(service, "Service")
    username = session.read_input("Username/email (Enter to keep): ") or entry["username"]
    security.validate_entry_field(username, "Entry username")
    replace = session.read_input("Replace password? [y/N]: ").strip().lower()
    if replace not in ("", "n", "y"):
        raise ValueError("Choose Y or N. Entry was not changed.")
    password = prompt_entry_password(session, "New entry password: ") if replace == "y" else None
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
        security.validate_master_password(password)
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
    security.validate_entry_field(service, "Service")
    username = session.read_input("Username/email: ")
    security.validate_entry_field(username, "Entry username")
    password = prompt_entry_password(session)
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
        audit.log_event("operation_failed", user_id=session.owner_id, operation="database")
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
    """Unwind input so normal finally blocks restore the terminal and lock."""
    if signum == signal.SIGALRM:
        raise SessionExpired(INACTIVITY_MESSAGE)
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
        for signum in (signal.SIGTSTP, signal.SIGQUIT, signal.SIGALRM):
            previous_handlers[signum] = signal.signal(signum, interrupt_exit)
        termios.tcsetattr(descriptor, termios.TCSANOW, settings)
        yield
    finally:
        try:
            # Discard unfinished input and restore echo even after interrupted getpass.
            signal.setitimer(signal.ITIMER_REAL, 0)
            termios.tcsetattr(descriptor, termios.TCSAFLUSH, original)
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)


def main() -> int:
    """Open resources, run the terminal interface, and always close resources."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Run this application in an interactive terminal.")
        return 1

    database = None
    log_handler = None
    try:
        with terminal_mode():
            log_handler = audit.configure_logging()
            database = open_database()
            run(database)
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
    except termios.error:
        print("Unable to configure or restore terminal settings.", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error):
        audit.log_event("operation_failed", operation="application_files")
        print("Unable to access application files. Check permissions and disk space.")
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
        if log_handler is not None:
            audit.LOGGER.removeHandler(log_handler)
            log_handler.stream.close()
            log_handler.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
