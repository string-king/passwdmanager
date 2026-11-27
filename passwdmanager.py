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
CHOICE_PROMPT = "Choice: "


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
        time_text = "Unknown"
        if updated_at:
            try:
                time_text = updated_at.astimezone().strftime("%Y-%m-%d %H:%M")
            except (OverflowError, ValueError):
                time_text = "Invalid date"
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
                     message: str, clipboard_warning: str, filter_text: str = ""):
    """Render one page and its status messages without changing navigation."""
    start = page * PAGE_SIZE
    end = min(start + PAGE_SIZE, len(entries))
    clear_console()
    print(f"Page {page + 1} of {page_count} | {len(entries)} entries")
    if entries:
        print(f"Showing {start + 1}-{end}, newest first.\n")
    if filter_text:
        print(f"Filter: {filter_text} (service name or username/email)")
    if filter_text and not entries:
        print("No matching entries. Change or clear the filter to see more entries.")
    else:
        print_entries(entries[start:end])
    if message:
        print(f"\n{message}")
    if clipboard_warning:
        print(clipboard_warning)
    print("\n[N] Next  [P] Previous  [F] Filter  [C] Clear filter  [B] Back")
    print("Enter a row number for entry actions.")


def browse_entries(database: sqlite3.Connection, session: sessions.Session, entries: list[dict]):
    """Browse display fields and open actions for the selected row."""
    page = 0
    message = ""
    filter_text = ""
    while True:
        matching = [entry for entry in entries if
                    filter_text.casefold() in entry["service"].casefold() or
                    filter_text.casefold() in entry["username"].casefold()]
        page_count = max(1, (len(matching) + PAGE_SIZE - 1) // PAGE_SIZE)
        page = min(page, page_count - 1)
        start = page * PAGE_SIZE
        page_entries = matching[start:start + PAGE_SIZE]
        row_numbers = [str(number) for number in range(1, len(page_entries) + 1)]
        print_entry_page(matching, page, page_count, message, session.clipboard.warning, filter_text)
        choice = session.read_input(CHOICE_PROMPT).strip().lower()
        message = ""
        try:
            match choice:
                case "n":
                    message = "Already on the last page." if page + 1 == page_count else ""
                    page = min(page + 1, page_count - 1)
                case "p":
                    message = "Already on the first page." if page == 0 else ""
                    page = max(page - 1, 0)
                case "f":
                    value = session.read_input("Filter service name or username/email (partial text; Enter clears): ").strip()
                    if value:
                        security.validate_entry_field(value, "Filter")
                    filter_text = value
                    page = 0
                case "c":
                    filter_text = ""
                    page = 0
                case "b":
                    clear_console()
                    return
                case _ if choice in row_numbers:
                    selected_entry = page_entries[int(choice) - 1]
                    message = entry_actions(database, session, selected_entry)
                    entries = vault.list_entries(database, session)
                case _:
                    message = "Choose a row number shown on this page, N, P, F, C, or B."
        except ValueError as error:
            message = str(error)


def entry_actions(database: sqlite3.Connection, session: sessions.Session, entry: dict) -> str:
    """Offer actions using display data only; never retain a decrypted password."""
    while True:
        clear_console()
        print(f"Service: {entry['service']}\nUsername/email: {entry['username']}")
        print("\n1. Copy password\n2. Edit entry\n3. Delete entry\n4. Back")
        choice = session.read_input(CHOICE_PROMPT).strip()
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


def prompt_yes_no(session: sessions.Session, prompt: str) -> bool:
    """Retry a yes/no choice; Enter means no."""
    while True:
        choice = session.read_input(prompt).strip().lower()
        if choice in ("y", "n", ""):
            return choice == "y"
        print("Please enter Y for yes or N for no (Enter also means no).")


def prompt_entry_field(session: sessions.Session, label: str, example: str,
                       current: str | None = None) -> str:
    """Retry one display field while retaining earlier valid answers."""
    hint = f"e.g. {example}; 1–256 printable characters"
    if current is not None:
        print(f"Current {label.lower()}: {current}")
        hint += "; Enter to keep current value"
    while True:
        value = session.read_input(f"{label} ({hint}): ")
        if value == "" and current is not None:
            return current
        try:
            security.validate_entry_field(value, label)
            return value
        except ValueError:
            if not value.strip():
                print(f"{label} cannot be empty or only spaces. Please try again.")
            elif len(value) > 256:
                print(f"{label} must be at most 256 characters. Please try again.")
            else:
                print(f"{label} cannot contain control or non-printable characters. Please try again.")


def prompt_entry_password(session: sessions.Session,
                          prompt: str = "Entry password (1–1024 characters; hidden): ") -> str:
    """Generate a password or retry hidden manual input until valid."""
    if prompt_yes_no(session, "Generate a 20-character password? [y/N]: "):
        return security.generate_password()
    while True:
        password = session.read_input(prompt, hidden=True)
        try:
            security.validate_password(password, "Entry password")
            return password
        except ValueError as error:
            print(f"{error} Please try again.")
        finally:
            password = None


def prompt_edit_entry(database: sqlite3.Connection, session: sessions.Session, entry: dict):
    """Retry invalid fields and replace passwords only by explicit choice."""
    print("Edit entry — Enter keeps the current service name or username/email.")
    service = prompt_entry_field(session, "Service name", "GitHub", entry["service"])
    username = prompt_entry_field(session, "Username or email", "alice@example.com", entry["username"])
    replace = prompt_yes_no(session, "Replace password? [y/N]: ")
    password = prompt_entry_password(session, "New entry password (1–1024 characters; hidden): ") if replace else None
    try:
        vault.update_entry(database, session, entry["id"], service, username, password)
    finally:
        password = None


# Keep plaintext input local to these short prompt functions. Returning releases
# their local references; Python cannot guarantee erasing every memory copy.
def prompt_registration(database: sqlite3.Connection):
    """Retry invalid registration fields without exposing password contents."""
    print("Create an account — choose a username and a master password for your vault.")
    print("Username: 1–64 printable characters, not only spaces.")
    print("Master password: 12–1024 characters. Input is hidden.")
    while True:
        username = input("Choose your username: ")
        try:
            security.validate_account_username(username)
        except ValueError as error:
            print(f"{error} Please try again.")
            continue
        password = None
        confirmation = None
        try:
            while True:
                password = sessions.read_password("Choose your master password (hidden): ")
                try:
                    security.validate_master_password(password)
                    break
                except ValueError as error:
                    password = None
                    print(f"{error} Please try again.")
            while True:
                confirmation = sessions.read_password("Repeat your master password (hidden): ")
                if password == confirmation:
                    confirmation = None
                    break
                confirmation = None
                print("Passwords do not match. Repeat the master password you just chose.")
            try:
                vault.register_account(database, username, password)
                return
            except ValueError as error:
                print(f"{error} Please choose a username and password again.")
        finally:
            password = None
            confirmation = None


def prompt_login(database: sqlite3.Connection,
                 cooldown: sessions.LoginCooldown) -> sessions.Session | None:
    """Offer another login attempt or return without revealing account existence."""
    print("Log in — enter your account username and master password to unlock your vault.")
    print("Your master password is hidden while you type.")
    while True:
        remaining = cooldown.remaining_seconds()
        if remaining:
            clear_console()
            print(f"Too many failed login attempts. Try again in {remaining} seconds.")
            return None
        username = input("Account username: ")
        password = sessions.read_password("Master password (hidden): ")
        try:
            session = vault.login_account(database, username, password)
            cooldown.reset()
            return session
        except ValueError:
            cooldown.record_failure()
            print("Unable to log in. Check your username and master password.")
        finally:
            password = None
        if cooldown.failures == sessions.LOGIN_ATTEMPTS:
            continue
        while True:
            choice = input("1. Try logging in again  2. Return to the welcome menu: ").strip()
            if choice == "1":
                break
            if choice == "2":
                clear_console()
                return None
            print("Choose 1 to retry or 2 to return to the welcome menu.")


def prompt_add_entry(database: sqlite3.Connection, session: sessions.Session):
    """Validate each field as it is entered, then encrypt and save the entry."""
    print("Add entry — enter the service, username/email, and a password.")
    service = prompt_entry_field(session, "Service name", "GitHub")
    username = prompt_entry_field(session, "Username or email", "alice@example.com")
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
        print("Login successful. Your vault is unlocked.")
        while True:
            if session.clipboard.warning:
                print(session.clipboard.warning)
            print(f"\nLogged in as {session.username}")
            print("Your vault locks after five minutes without input.")
            print("1. Add entry — save credentials for a service")
            print("2. Browse entries — copy, edit, or delete saved credentials")
            print("3. Lock / log out — return to the welcome menu")
            print("4. Exit password manager — lock your vault and quit")
            choice = session.read_input(CHOICE_PROMPT)
            clear_console()
            try:
                match choice:
                    case "1":
                        prompt_add_entry(database, session)
                        clear_console()
                        print("Entry saved.")
                    case "2":
                        entries = vault.list_entries(database, session)
                        browse_entries(database, session, entries)
                    case "3":
                        lock_reason = "logout"
                        return False
                    case "4":
                        lock_reason = "exit"
                        return True
                    case _:
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
        if lock_reason in ("logout", "inactivity"):
            print("Vault locked. Returning to the welcome menu.")
        else:
            print("Vault locked.")


def run(database: sqlite3.Connection):
    """Run the start menu and hand successful logins to the vault menu."""
    cooldown = sessions.LoginCooldown()
    clear_console()
    while True:
        print("\nWelcome to Password Manager")
        print("Store credentials in your own encrypted vault. Passwords are never displayed.")
        print("1. Register — create an account and master password")
        print("2. Log in — unlock your existing vault")
        print("3. Exit password manager")
        choice = input(CHOICE_PROMPT)
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
            session = prompt_login(database, cooldown)
            if session is None:
                continue
            if run_vault(database, session):
                print("Exiting password manager. Goodbye.")
                return
        elif choice == "3":
            print("Exiting password manager. Goodbye.")
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
        print("\nInput interrupted. Exiting password manager. Goodbye.")
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
