import getpass
import os
from pathlib import Path
import sqlite3
import sys
import warnings

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


DATABASE = Path(__file__).resolve().parent / "data" / "passwords.db"
KDF_ITERATIONS = 3
KDF_LANES = 4
KDF_MEMORY_COST = 64 * 1024  # KiB: 64 MiB of memory per derivation


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


def register_account(database: sqlite3.Connection, username: str, password: str):
    if not username.strip() or len(username) > 64 or not username.isprintable():
        raise ValueError("Username must contain 1 to 64 printable characters.")
    if not 12 <= len(password) <= 1024:
        raise ValueError("Master password must contain 12 to 1024 characters.")

    verification_salt = os.urandom(16)
    # The encryption key will use its own salt, separate from password checking.
    key_salt = os.urandom(16)
    kdf = Argon2id(
        salt=verification_salt,
        length=32,
        iterations=KDF_ITERATIONS,
        lanes=KDF_LANES,
        memory_cost=KDF_MEMORY_COST,
    )
    verifier = kdf.derive(password.encode("utf-8"))

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


def run(database: sqlite3.Connection):
    while True:
        print("\nPassword manager")
        print("1. Register")
        print("2. Log in")
        print("3. Exit")
        choice = input("Choice: ")

        if choice == "1":
            username = input("Username: ")
            password = read_password("Master password: ")
            try:
                confirmation = read_password("Confirm master password: ")
                try:
                    if password != confirmation:
                        raise ValueError("Passwords do not match.")
                    register_account(database, username, password)
                    print("Account created. Login is not implemented yet.")
                finally:
                    del confirmation
            except ValueError as error:
                print(error)
            finally:
                # Drop references; Python cannot guarantee wiping every copy.
                del password
        elif choice == "2":
            print("Login is not implemented yet.")
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
