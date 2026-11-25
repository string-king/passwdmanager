# Password manager

A terminal password manager for the ICS0022 Secure Programming project.
Each account has its own encrypted vault. You can save, browse, edit, delete,
and copy credentials without displaying passwords.

## Setup and run

Use macOS with Python 3.15. The application uses the macOS clipboard commands
`pbcopy` and `pbpaste`. Run these commands from the project directory:

```sh
python3.15 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python passwdmanager.py
```

Run it in an interactive terminal. The only external runtime package is
`cryptography`; SQLite is included with Python.

For later runs, activate the environment and start the application:

```sh
source .venv/bin/activate
python passwdmanager.py
```

## Register and log in

Choose **1. Register** from the welcome menu. Enter a username containing
1 to 64 printable characters and a master password containing 12 to 1024
characters. Usernames cannot be empty or only spaces. Repeat the password to
confirm it. Invalid input is retried in place.

Choose **2. Log in** to unlock your vault. Password input is hidden, so nothing
appears while you type. If login fails, you can retry or return to the welcome
menu. There is no master-password recovery or reset feature.

## Add an entry

Choose **1. Add entry** after logging in. Enter the service name, such as GitHub,
and the username or email used for that service. Each field accepts 1 to 256
printable characters and cannot be empty or only spaces.

You can generate a 20-character password or enter one yourself. Generated
passwords use letters, digits, and symbols. Manual passwords accept 1 to 1024
characters and remain hidden. At a Y/N prompt, Enter means no.

If a field is invalid, correct it at the same prompt. Earlier valid answers are
kept. The entry is saved after all fields are valid.

An account cannot save two entries with exactly the same service name and
username/email, even if their passwords differ. Matching is case-sensitive.
Edit the existing entry to change its password. Other accounts can use the
same service and username/email.

## Browse and search

Choose **2. Browse entries** to see service names, usernames/emails, and update
times. Entries appear newest first, with 10 per page. Passwords are not listed.

| Input | Action |
| --- | --- |
| N / P | Go to the next / previous page. |
| F | Filter by part of a service name or username/email, ignoring case. |
| C | Clear the filter and show all entries. |
| B | Return to the vault menu. |
| Row number | Open actions for that entry. |

At the filter prompt, pressing Enter without typing also clears the filter. Changing or clearing
the filter returns to page one. The filter stays active after entry actions.
Row numbers restart on each page.

## Copy, edit, or delete

Select an entry's row number to open its actions:

- **Copy password:** copy it to the clipboard, then paste it where needed.
  The application attempts to clear it after 20 seconds, provided the clipboard
  still contains that password. Unrelated clipboard contents are left alone.
- **Edit entry:** enter new service or username/email values, or press Enter to
  keep them. The password stays unchanged unless you choose to replace it.
- **Delete entry:** type `DELETE` to confirm. Any other response cancels deletion.
- **Back:** return to browsing.

If clipboard copying or clearing fails, follow the message and clear the
clipboard manually if needed.

## Lock and exit

Choose **3. Lock / log out** to lock the vault and return to the welcome menu.
Choose **4. Exit password manager** to lock it and quit. From the welcome menu,
choose **3. Exit password manager**.

The vault locks if you leave a prompt unanswered for five minutes. Locking also
attempts to clear any tracked password from
the clipboard. Ctrl-C, Ctrl-Z, and Ctrl-Backslash exit through the normal cleanup
path. Ctrl-Z exits rather than suspending the application.

## Data and limitations

The application creates these files beside the source code:

- `data/passwords.db`: account metadata and encrypted entries.
- `logs/events.jsonl`: security events, one JSON object per line, without passwords
  or entry contents.

Keep the database to retain your accounts and entries. To back it up, close the
application and copy `data/passwords.db` to a safe location. Use one running
instance at a time, since the application checks for duplicates before saving.

Entries are encrypted with Fernet. Argon2id verifies the master password and
separately derives the encryption key. Account usernames, record ownership,
entry counts, and Fernet timestamps remain visible in the database.

Python cannot guarantee erasing every password or key copy from memory. The
application overwrites mutable buffers where possible and releases sensitive
references after use. Clipboard history can retain copied passwords, and a crash
or forced termination can prevent clipboard cleanup. An unlocked vault also
cannot protect against malware running on your machine.

## Troubleshooting

If the application requests an interactive terminal, run it directly in Terminal
or another terminal emulator with the environment activated. It exits if it
cannot hide password input.

For file-access errors, check permissions and available disk space. For clipboard
errors, clear the clipboard manually before copying another password.

## Run the tests

Tests use temporary databases and mock clipboard commands, leaving your vault
and clipboard untouched.

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -q
```

To generate coverage reports:

```sh
python -m coverage run -m unittest discover -s tests -q
python -m coverage report
python -m coverage html
python -m coverage xml
```

Open `htmlcov/index.html` for the detailed report. The XML report is
`coverage.xml`.
