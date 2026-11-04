import base64
import getpass
import json
import os
from pathlib import Path
import sqlite3
import sys
import uuid
import warnings

from cryptography.exceptions import InvalidKey, UnsupportedAlgorithm
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


DATABASE = Path(__file__).resolve().parent / "data" / "passwords.db"
KDF_ITERATIONS = 3
KDF_LANES = 4
KDF_MEMORY_COST = 64 * 1024  # KiB: 64 MiB of memory per derivation


class Session:
    def __init__(self, owner_id: int, cipher: Fernet):
        self.owner_id = owner_id
        self.cipher = cipher

    def lock(self):
        # Release the encryption object; this does not guarantee memory erasure.
        self.cipher = None


def open_database(path: Path = DATABASE) -> sqlite3.Connection:
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
    # Refuse getpass's fallback to visible input if the terminal cannot hide it.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt)


def clear_console():
    if sys.stdout.isatty():
        # Clear the visible terminal screen and move the cursor to the top.
        print("\033[2J\033[H", end="", flush=True)


def validate_master_password(password: str):
    if not 12 <= len(password) <= 1024:
        raise ValueError("Master password must contain 12 to 1024 characters.")


def password_kdf(salt: bytes) -> Argon2id:
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
    if not value.strip() or len(value) > 256 or not value.isprintable():
        raise ValueError(f"{label} must contain 1 to 256 printable characters.")


def add_entry(
    database: sqlite3.Connection, session: Session,
    service: str, username: str, password: str,
) -> str:
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


def run_vault(database: sqlite3.Connection, session: Session) -> bool:
    """Return True to exit the application, or False to return to login."""
    try:
        clear_console()
        print("Vault unlocked.")
        while True:
            print("\n1. Add entry")
            print("2. Lock / log out")
            print("3. Exit")
            choice = input("Choice: ")
            clear_console()
            if choice == "1":
                try:
                    service = input("Service: ")
                    validate_entry_field(service, "Service")
                    username = input("Username/email: ")
                    validate_entry_field(username, "Entry username")
                    password = read_password("Entry password: ")
                    try:
                        add_entry(database, session, service, username, password)
                    finally:
                        del password
                    clear_console()
                    print("Entry saved.")
                except ValueError as error:
                    clear_console()
                    print(error)
            elif choice == "2":
                return False
            elif choice == "3":
                return True
            else:
                print("Choose 1, 2, or 3.")
    finally:
        # Also lock when Ctrl-C, EOF, or an unexpected error interrupts the menu.
        session.lock()
        print("Vault locked.")


def run(database: sqlite3.Connection):
    clear_console()
    while True:
        print("\nPassword manager")
        print("1. Register")
        print("2. Log in")
        print("3. Exit")
        choice = input("Choice: ")
        clear_console()

        if choice == "1":
            username = input("Username: ")
            print("Master password must contain 12 to 1024 characters.")
            password = read_password("Master password: ")
            try:
                validate_master_password(password)
                confirmation = read_password("Confirm master password: ")
                try:
                    if password != confirmation:
                        raise ValueError("Passwords do not match.")
                    register_account(database, username, password)
                    clear_console()
                    print("Account created. Log in to unlock your vault.")
                finally:
                    del confirmation
            except ValueError as error:
                clear_console()
                print(error)
            finally:
                # Drop references; Python cannot guarantee wiping every copy.
                del password
        elif choice == "2":
            username = input("Username: ")
            password = read_password("Master password: ")
            try:
                session = login_account(database, username, password)
            except ValueError as error:
                clear_console()
                print(error)
                continue
            finally:
                del password
            if run_vault(database, session):
                return
        elif choice == "3":
            return
        else:
            print("Choose 1, 2, or 3.")


def main() -> int:
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
