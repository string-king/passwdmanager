import base64
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
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


class Clipboard:
    """Track our last copy without retaining another plaintext password."""

    def __init__(self):
        """Initialize clipboard tracking and synchronization for the timer."""
        self.digest = None
        self.timer = None
        self.mutex = threading.Lock()
        self.warning = ""
        self.generation = 0

    def copy(self, password: str):
        """Copy a password to macOS and schedule conditional clearing."""
        data = password.encode("utf-8")
        with self.mutex:
            try:
                subprocess.run(
                    ["/usr/bin/pbcopy"], input=data, capture_output=True,
                    env={**os.environ, "LC_ALL": "en_US.UTF-8"},
                    check=True, timeout=3,
                )
            except (OSError, subprocess.SubprocessError):
                raise ValueError("Could not copy the password. Clear the clipboard manually if needed.") from None
            if self.timer is not None:
                self.timer.cancel()
            self.digest = hashlib.sha256(data).digest()
            self.warning = ""
            self.generation += 1
            self.timer = threading.Timer(CLIPBOARD_SECONDS, self.clear, args=(self.generation,))
            self.timer.daemon = True
            self.timer.start()

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
                self.warning = "Could not clear the clipboard. Clear it manually."
                return
            self.digest = None
            self.warning = ""


class Session:
    """Keep the authenticated account and its temporary encryption object."""

    def __init__(self, owner_id: int, cipher: Fernet):
        """Start an unlocked session with its own clipboard tracker."""
        self.owner_id = owner_id
        self.cipher = cipher
        self.clipboard = Clipboard()

    def lock(self):
        """Drop the encryption object and attempt to clear our clipboard copy."""
        # Release the encryption object; this does not guarantee memory erasure.
        self.cipher = None
        self.clipboard.clear()


def open_database(path: Path = DATABASE) -> sqlite3.Connection:
    """Open a private SQLite file and create any missing account/vault tables."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Create the file privately before SQLite writes anything to it.
    # Reject symbolic links so we cannot change permissions on another file.
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
    finally:
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


def validate_master_password(password: str):
    """Reject a new master password outside the allowed length range."""
    if not 12 <= len(password) <= 1024:
        raise ValueError("Master password must contain 12 to 1024 characters.")


def password_kdf(salt: bytes) -> Argon2id:
    """Build a fresh Argon2id object using the application's fixed settings."""
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise ValueError("Invalid account metadata.")
    return Argon2id(
        salt=salt,
        length=32,
        iterations=KDF_ITERATIONS,
        lanes=KDF_LANES,
        memory_cost=KDF_MEMORY_COST,
    )


def register_account(database: sqlite3.Connection, username: str, password: str):
    """Save an account's password verifier, independent salts, and KDF settings."""
    if not username.strip() or len(username) > 64 or not username.isprintable():
        raise ValueError("Username must contain 1 to 64 printable characters.")
    validate_master_password(password)

    verification_salt = os.urandom(16)
    # The encryption key will use its own salt, separate from password checking.
    key_salt = os.urandom(16)
    verifier = password_kdf(verification_salt).derive(password.encode("utf-8"))

    try:
        # Commit the complete account on success, or roll back if saving fails.
        with database:
            database.execute(
                """INSERT INTO users
                   (username, verification_salt, verifier, key_salt,
                    iterations, lanes, memory_cost) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (username, verification_salt, verifier, key_salt,
                 KDF_ITERATIONS, KDF_LANES, KDF_MEMORY_COST),
            )
    except sqlite3.IntegrityError:
        raise ValueError("Username is already taken.") from None


def login_account(database: sqlite3.Connection, username: str, password: str) -> Session:
    """Verify credentials before deriving the account's vault encryption key."""
    failure = "Invalid username or master password."
    if not username.strip() or len(username) > 64 or not username.isprintable():
        raise ValueError(failure)
    if not 1 <= len(password) <= 1024:
        raise ValueError(failure)

    user = database.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user is None:
        raise ValueError(failure)

    # Treat the database as untrusted: do not accept arbitrary Argon2 costs.
    settings = (user["iterations"], user["lanes"], user["memory_cost"])
    if settings != (KDF_ITERATIONS, KDF_LANES, KDF_MEMORY_COST):
        raise ValueError("Unsupported account key-derivation settings.")
    if not isinstance(user["verifier"], bytes) or len(user["verifier"]) != 32:
        raise ValueError("Invalid account metadata.")

    try:
        password_kdf(user["verification_salt"]).verify(
            password.encode("utf-8"), user["verifier"]
        )
    except InvalidKey:
        raise ValueError(failure) from None

    # Derive the vault key only after verification, using the independent salt.
    key = password_kdf(user["key_salt"]).derive(password.encode("utf-8"))
    return Session(user["id"], Fernet(base64.urlsafe_b64encode(key)))


def validate_entry_field(value: str, label: str):
    """Check a displayed field's length and reject terminal control characters."""
    if not isinstance(value, str) or not value.strip() or len(value) > 256 or not value.isprintable():
        raise ValueError(f"{label} must contain 1 to 256 printable characters.")


def add_entry(
    database: sqlite3.Connection, session: Session,
    service: str, username: str, password: str,
) -> str:
    """Encrypt a new credential for the session's owner and return its ID."""
    if session.cipher is None:
        raise ValueError("Vault is locked. Log in again.")
    validate_entry_field(service, "Service")
    validate_entry_field(username, "Entry username")
    if not 1 <= len(password) <= 1024:
        raise ValueError("Entry password must contain 1 to 1024 characters.")

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
    payload = session.cipher.encrypt(json.dumps(entry).encode("utf-8"))
    with database:
        database.execute(
            "INSERT INTO entries (id, owner_id, payload) VALUES (?, ?, ?)",
            (entry_id, session.owner_id, payload),
        )
    return entry_id


def decrypt_entry(session: Session, row: sqlite3.Row) -> dict:
    """Shared integrity checks for listing and password retrieval."""
    if session.cipher is None:
        raise ValueError("Vault is locked. Log in again.")
    try:
        entry = json.loads(session.cipher.decrypt(row["payload"]))
        if not isinstance(entry, dict):
            raise ValueError
        # A valid encrypted payload must belong to this exact row and user.
        if entry["id"] != row["id"] or entry["owner_id"] != session.owner_id:
            raise ValueError
        validate_entry_field(entry["id"], "Entry ID")
        validate_entry_field(entry["service"], "Service")
        validate_entry_field(entry["username"], "Entry username")
        if not isinstance(entry["password"], str) or not 1 <= len(entry["password"]) <= 1024:
            raise ValueError
        # Older entries have no timestamp; do not invent an update time.
        updated_at = None
        if "updated_at" in entry:
            updated_at = datetime.fromisoformat(entry["updated_at"])
            if updated_at.tzinfo is None:
                raise ValueError
            updated_at = updated_at.astimezone(timezone.utc)
        entry["updated_at"] = updated_at
    except (InvalidToken, ValueError, TypeError, KeyError, OverflowError):
        raise ValueError("Entry integrity check failed. Vault data may be damaged.") from None
    return entry


def copy_entry_password(database: sqlite3.Connection, session: Session, entry_id: str):
    """Re-read an owned entry, verify it, and copy its password without printing."""
    if session.cipher is None:
        raise ValueError("Vault is locked. Log in again.")
    row = database.execute(
        "SELECT id, payload FROM entries WHERE id = ? AND owner_id = ?",
        (entry_id, session.owner_id),
    ).fetchone()
    if row is None:
        raise ValueError("Entry not found in your vault.")
    entry = decrypt_entry(session, row)
    session.clipboard.copy(entry["password"])


def list_entries(database: sqlite3.Connection, session: Session) -> list[dict]:
    """Return verified display fields, newest first, without plaintext passwords."""
    if session.cipher is None:
        raise ValueError("Vault is locked. Log in again.")
    rows = database.execute(
        "SELECT id, payload FROM entries WHERE owner_id = ? ORDER BY rowid",
        (session.owner_id,),
    ).fetchall()
    summaries = []
    for row in rows:
        entry = decrypt_entry(session, row)

        # Return only display data so the interface never receives the password.
        summaries.append({
            "id": row["id"],
            "service": entry["service"],
            "username": entry["username"],
            "updated_at": entry["updated_at"],
        })
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


def browse_entries(database: sqlite3.Connection, session: Session, entries: list[dict]):
    """Page through display fields and copy passwords by the visible row number."""
    page = 0
    page_count = max(1, (len(entries) + PAGE_SIZE - 1) // PAGE_SIZE)
    message = ""
    while True:
        clear_console()
        start = page * PAGE_SIZE
        end = min(start + PAGE_SIZE, len(entries))
        page_entries = entries[start:end]
        row_numbers = [str(number) for number in range(1, len(page_entries) + 1)]
        print(f"Page {page + 1} of {page_count} | {len(entries)} entries")
        if entries:
            print(f"Showing {start + 1}-{end}, newest first.\n")
        print_entries(page_entries)
        if message:
            print(f"\n{message}")
        if session.clipboard.warning:
            print(session.clipboard.warning)

        print("\n[N] Next  [P] Previous  [B] Back")
        print("Enter a row number to copy its password.")
        choice = input("Choice: ").strip().lower()
        message = ""
        if choice == "n":
            if page + 1 < page_count:
                page += 1
            else:
                message = "Already on the last page."
        elif choice == "p":
            if page > 0:
                page -= 1
            else:
                message = "Already on the first page."
        elif choice == "b":
            clear_console()
            return
        elif choice in row_numbers:
            selected_entry = page_entries[int(choice) - 1]
            try:
                copy_entry_password(database, session, selected_entry["id"])
                message = f"Password copied. Clipboard clears after {CLIPBOARD_SECONDS} seconds if unchanged."
            except ValueError as error:
                message = str(error)
        else:
            message = "Choose a row number shown on this page, N, P, or B."


# Keep plaintext input local to these short prompt functions. Returning releases
# their local references; Python cannot guarantee erasing every memory copy.
def prompt_registration(database: sqlite3.Connection):
    """Collect and confirm a new master password, then register the account."""
    username = input("Username: ")
    print("Master password must contain 12 to 1024 characters.")
    password = read_password("Master password: ")
    validate_master_password(password)
    confirmation = read_password("Confirm master password: ")
    if password != confirmation:
        raise ValueError("Passwords do not match.")
    register_account(database, username, password)


def prompt_login(database: sqlite3.Connection) -> Session:
    """Collect hidden login credentials and return the authenticated session."""
    username = input("Username: ")
    password = read_password("Master password: ")
    return login_account(database, username, password)


def prompt_add_entry(database: sqlite3.Connection, session: Session):
    """Validate each field as it is entered, then encrypt and save the entry."""
    service = input("Service: ")
    validate_entry_field(service, "Service")
    username = input("Username/email: ")
    validate_entry_field(username, "Entry username")
    password = read_password("Entry password: ")
    add_entry(database, session, service, username, password)


def run_vault(database: sqlite3.Connection, session: Session) -> bool:
    """Run the vault menu; return True to exit or False to log out. Always lock."""
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
            choice = input("Choice: ")
            clear_console()
            if choice == "1":
                try:
                    prompt_add_entry(database, session)
                    clear_console()
                    print("Entry saved.")
                except ValueError as error:
                    clear_console()
                    print(error)
            elif choice == "2":
                try:
                    entries = list_entries(database, session)
                    browse_entries(database, session, entries)
                except ValueError as error:
                    print(error)
            elif choice == "3":
                return False
            elif choice == "4":
                return True
            else:
                print("Choose 1, 2, 3, or 4.")
    finally:
        # Also lock when Ctrl-C, EOF, or an unexpected error interrupts the menu.
        session.lock()
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


def main() -> int:
    """Check terminal support, manage the database lifetime, and report failures."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Run this application in an interactive terminal.")
        return 1

    database = None
    try:
        database = open_database()
        run(database)
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
    except (OSError, sqlite3.Error):
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
