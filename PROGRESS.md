# Checkpoint 2 progress

The application now supports registration, master-password login, adding encrypted
credentials, listing entries, and copying passwords to the clipboard. Entries
are stored in SQLite using Argon2id and Fernet. Passwords are never printed,
and each account can access only its own entries.

The README includes setup and run instructions for Python 3.15 on macOS.
