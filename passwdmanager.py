from getpass import GetPassWarning
from termios import error as TerminalError
import sqlite3
import sys

from cryptography.exceptions import UnsupportedAlgorithm

import audit
import clipboard
import security
import session as sessions
import vault


PAGE_SIZE = 10


def clear_console():
    """Clear the visible screen when output goes to a terminal."""
    if sys.stdout.isatty():
        # Clear the visible terminal screen and move the cursor to the top.
        print("\033[2J\033[H", end="", flush=True)


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


def browse_entries(database: sqlite3.Connection, session: sessions.Session, entries: list[dict]):
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
                entries = vault.list_entries(database, session)
            else:
                message = "Choose a row number shown on this page, N, P, or B."
        except ValueError as error:
            message = str(error)


def entry_actions(database: sqlite3.Connection, session: sessions.Session, entry: dict) -> str:
    """Offer actions using display data only; never retain a decrypted password."""
    while True:
        clear_console()
        print(f"Service: {entry['service']}\nUsername/email: {entry['username']}")
        print("\n1. Copy password\n2. Edit entry\n3. Delete entry\n4. Back")
        choice = session.read_input("Choice: ").strip()
        if choice == "1":
            vault.copy_entry_password(database, session, entry["id"])
            return f"Password copied. Clipboard clears after {clipboard.CLIPBOARD_SECONDS} seconds if unchanged."
        if choice == "2":
            prompt_edit_entry(database, session, entry)
            return "Entry updated."
        if choice == "3":
            confirmation = session.read_input("Delete this entry? Type DELETE to confirm: ")
            if confirmation != "DELETE":
                return "Deletion cancelled."
            vault.delete_entry(database, session, entry["id"])
            return "Entry deleted."
        if choice == "4":
            return ""
        print("Choose 1, 2, 3, or 4.")


def prompt_entry_password(session: sessions.Session, prompt: str = "Entry password: ") -> str:
    """Generate a password or read one without displaying it."""
    choice = session.read_input("Generate a 20-character password? [y/N]: ").strip().lower()
    if choice == "y":
        return security.generate_password()
    if choice in ("", "n"):
        return session.read_input(prompt, hidden=True)
    raise ValueError("Choose Y or N.")


def prompt_edit_entry(database: sqlite3.Connection, session: sessions.Session, entry: dict):
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
        vault.update_entry(database, session, entry["id"], service, username, password)
    finally:
        password = None


# Keep plaintext input local to these short prompt functions. Returning releases
# their local references; Python cannot guarantee erasing every memory copy.
def prompt_registration(database: sqlite3.Connection):
    """Collect and confirm a new master password, then register the account."""
    username = input("Username: ")
    print("Master password must contain 12 to 1024 characters.")
    password = sessions.read_password("Master password: ")
    confirmation = None
    try:
        security.validate_master_password(password)
        confirmation = sessions.read_password("Confirm master password: ")
        if password != confirmation:
            raise ValueError("Passwords do not match.")
        confirmation = None
        vault.register_account(database, username, password)
    finally:
        password = None
        confirmation = None


def prompt_login(database: sqlite3.Connection) -> sessions.Session:
    """Collect hidden login credentials and return the authenticated session."""
    username = input("Username: ")
    password = sessions.read_password("Master password: ")
    try:
        return vault.login_account(database, username, password)
    finally:
        password = None


def prompt_add_entry(database: sqlite3.Connection, session: sessions.Session):
    """Validate each field as it is entered, then encrypt and save the entry."""
    service = session.read_input("Service: ")
    security.validate_entry_field(service, "Service")
    username = session.read_input("Username/email: ")
    security.validate_entry_field(username, "Entry username")
    password = prompt_entry_password(session)
    try:
        vault.add_entry(database, session, service, username, password)
    finally:
        password = None


def run_vault(database: sqlite3.Connection, session: sessions.Session) -> bool:
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
                    entries = vault.list_entries(database, session)
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
    except sessions.SessionExpired as error:
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


def main() -> int:
    """Open resources, run the terminal interface, and always close resources."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Run this application in an interactive terminal.")
        return 1

    database = None
    log_handler = None
    try:
        with sessions.terminal_mode():
            log_handler = audit.configure_logging()
            database = vault.open_database()
            run(database)
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
    except TerminalError:
        print("Unable to configure or restore terminal settings.", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error):
        audit.log_event("operation_failed", operation="application_files")
        print("Unable to access application files. Check permissions and disk space.")
        return 1
    except GetPassWarning:
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
