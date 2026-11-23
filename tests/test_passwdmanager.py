"""Security regression tests; never use the real vault or system clipboard."""

import contextlib
import io
import json
from pathlib import Path
import sqlite3
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import passwdmanager as pm


class VaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use the real KDF and production costs, but derive accounts only once.
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.seed = pm.open_database(Path(cls.directory.name) / "seed.db")
        cls.addClassCleanup(cls.seed.close)
        pm.register_account(cls.seed, "alice", "alice master password")
        pm.register_account(cls.seed, "bob", "bob master password")
        cls.alice_cipher = pm.login_account(cls.seed, "alice", "alice master password").cipher
        cls.bob_cipher = pm.login_account(cls.seed, "bob", "bob master password").cipher

    def setUp(self):
        self.database = sqlite3.connect(":memory:")
        self.addCleanup(self.database.close)
        self.seed.backup(self.database)
        self.database.row_factory = sqlite3.Row
        self.database.execute("PRAGMA foreign_keys = ON")
        self.alice = pm.Session(1, self.alice_cipher)
        self.bob = pm.Session(2, self.bob_cipher)
        self.alice.clipboard = Mock()
        self.bob.clipboard = Mock()

    def add_entry(self, session=None, service="Example", username="alice@example.test", password="stored secret"):
        return pm.add_entry(self.database, session or self.alice, service, username, password)

    def test_login_accepts_correct_password(self):
        session = pm.login_account(self.database, "alice", "alice master password")
        self.assertEqual(session.owner_id, 1)
        entry_id = self.add_entry()
        row = self.database.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        self.assertEqual(pm.decrypt_entry(session, row)["password"], "stored secret")
        session.lock()

    def test_login_errors_do_not_disclose_account_existence(self):
        errors = []
        for username, password in [("alice", "wrong password"), ("missing", "wrong password")]:
            with self.assertRaises(ValueError) as caught:
                pm.login_account(self.database, username, password)
            errors.append(str(caught.exception))
        self.assertEqual(errors, ["Invalid username or master password."] * 2)

    def test_duplicate_registration_preserves_existing_account(self):
        with self.assertRaisesRegex(ValueError, "already taken"):
            pm.register_account(self.database, "alice", "different master password")
        self.assertEqual(self.database.execute("SELECT COUNT(*) FROM users").fetchone()[0], 2)
        pm.login_account(self.database, "alice", "alice master password")

    def test_registration_uses_independent_salts_and_no_plaintext(self):
        row = self.database.execute("SELECT * FROM users WHERE username = 'alice'").fetchone()
        self.assertEqual(len(row["verification_salt"]), 16)
        self.assertEqual(len(row["key_salt"]), 16)
        self.assertNotEqual(row["verification_salt"], row["key_salt"])
        self.assertNotIn("alice master password", repr(tuple(row)))

    def test_rejects_untrusted_kdf_costs_and_metadata(self):
        for column, value in [("memory_cost", 2**30), ("verifier", b"invalid"), ("key_salt", b"short")]:
            with self.subTest(column=column):
                with self.database:
                    self.database.execute(f"UPDATE users SET {column} = ? WHERE id = 1", (value,))
                with self.assertRaises(ValueError):
                    pm.login_account(self.database, "alice", "alice master password")
                self.seed.backup(self.database)

    def test_encrypted_storage_survives_database_reopen(self):
        entry_id = self.add_entry()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.db"
            saved = pm.open_database(path)
            self.database.backup(saved)
            saved.close()
            raw = path.read_bytes()
            for secret in [b"stored secret", b"alice@example.test", b"Example"]:
                self.assertNotIn(secret, raw)
            reopened = pm.open_database(path)
            try:
                pm.copy_entry_password(reopened, self.alice, entry_id)
                self.alice.clipboard.copy.assert_called_once_with("stored secret")
            finally:
                reopened.close()

    def test_listing_and_display_do_not_expose_passwords(self):
        self.add_entry()
        entries = pm.list_entries(self.database, self.alice)
        self.assertNotIn("password", entries[0])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pm.print_entries(entries)
        self.assertIn("Example", output.getvalue())
        self.assertNotIn("stored secret", output.getvalue())

    def test_account_isolation_and_missing_record(self):
        entry_id = self.add_entry()
        self.assertEqual(pm.list_entries(self.database, self.bob), [])
        for identifier in [entry_id, "missing", "' OR 1=1 --"]:
            with self.subTest(identifier=identifier):
                with self.assertRaisesRegex(ValueError, "not found"):
                    pm.copy_entry_password(self.database, self.bob, identifier)
        self.bob.clipboard.copy.assert_not_called()

    def test_sql_input_is_stored_as_data(self):
        username = "alice' OR 1=1 --"
        self.add_entry(service="'; DROP TABLE users; --", username=username)
        self.assertEqual(pm.list_entries(self.database, self.alice)[0]["username"], username)
        self.assertEqual(self.database.execute("SELECT COUNT(*) FROM users").fetchone()[0], 2)

    def test_tampered_ciphertext_is_rejected_without_copying(self):
        entry_id = self.add_entry()
        self.database.execute("UPDATE entries SET payload = ? WHERE id = ?", (b"damaged token", entry_id))
        for operation in [lambda: pm.list_entries(self.database, self.alice),
                          lambda: pm.copy_entry_password(self.database, self.alice, entry_id)]:
            with self.assertRaisesRegex(ValueError, "integrity check failed"):
                operation()
        self.alice.clipboard.copy.assert_not_called()

    def test_swapped_records_and_owner_changes_are_rejected(self):
        first = self.add_entry()
        second = self.add_entry(service="Other")
        payload = self.database.execute("SELECT payload FROM entries WHERE id = ?", (first,)).fetchone()[0]
        self.database.execute("UPDATE entries SET payload = ? WHERE id = ?", (payload, second))
        with self.assertRaisesRegex(ValueError, "integrity check failed"):
            pm.copy_entry_password(self.database, self.alice, second)
        self.database.execute("UPDATE entries SET owner_id = 2 WHERE id = ?", (first,))
        with self.assertRaisesRegex(ValueError, "integrity check failed"):
            pm.copy_entry_password(self.database, self.bob, first)

    def test_authenticated_but_invalid_payloads_are_rejected(self):
        entry_id = self.add_entry()
        base = dict(id=entry_id, owner_id=1, service="Example", username="alice", password="secret")
        payloads = [[], {}, {**base, "service": "\x1b[2J"}, {**base, "password": 12},
                    {**base, "updated_at": "2026-01-01T00:00:00"}]
        for entry in payloads:
            with self.subTest(entry=entry):
                payload = self.alice.cipher.encrypt(json.dumps(entry).encode())
                self.database.execute("UPDATE entries SET payload = ? WHERE id = ?", (payload, entry_id))
                with self.assertRaisesRegex(ValueError, "integrity check failed"):
                    pm.copy_entry_password(self.database, self.alice, entry_id)
        self.alice.clipboard.copy.assert_not_called()

    def test_entry_validation_rejects_invalid_fields_without_saving(self):
        for field in ["service", "username"]:
            for value in ["", "   ", "x" * 257, "line\nbreak", "\x1b[2J", None]:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        self.add_entry(**{field: value})
        for password in ["", "x" * 1025]:
            with self.assertRaises(ValueError):
                self.add_entry(password=password)
        self.assertEqual(pm.list_entries(self.database, self.alice), [])

    def test_entry_validation_accepts_boundaries_and_unicode(self):
        for length in [1, 256]:
            self.add_entry(service="õ" * length, username="界" * length, password="🔐" * (1024 if length == 256 else 1))
        self.assertEqual(len(pm.list_entries(self.database, self.alice)), 2)

    def test_account_validation_boundaries(self):
        for password in ["", "x" * 11, "x" * 1025]:
            with self.subTest(length=len(password)), self.assertRaises(ValueError):
                pm.validate_master_password(password)
        for password in ["x" * 12, "õ" * 1024]:
            pm.validate_master_password(password)
        for username in ["", "   ", "x" * 65, "a\nb", "\x1b[2J"]:
            with self.subTest(username=username), self.assertRaises(ValueError):
                pm.register_account(self.database, username, "valid master password")

    def test_lock_drops_cipher_clears_clipboard_and_blocks_operations(self):
        entry_id = self.add_entry()
        self.alice.lock()
        self.assertIsNone(self.alice.cipher)
        self.alice.clipboard.clear.assert_called_once_with()
        for operation in [lambda: self.add_entry(), lambda: pm.list_entries(self.database, self.alice),
                          lambda: pm.copy_entry_password(self.database, self.alice, entry_id)]:
            with self.assertRaisesRegex(ValueError, "locked"):
                operation()

    def test_clipboard_copy_finishes_tracking_before_expired_session_cleanup(self):
        entry_id = self.add_entry()
        self.alice.clipboard = pm.Clipboard()
        contents = b""

        def clipboard_command(command, **kwargs):
            nonlocal contents
            self.assertEqual(pm.signal.getitimer(pm.signal.ITIMER_REAL), (0.0, 0.0))
            if command[0] == "/usr/bin/pbcopy":
                contents = kwargs["input"]
                # Simulate crossing the idle deadline while pbcopy is running.
                self.alice.deadline = pm.time.monotonic() - 1
            return subprocess.CompletedProcess(command, 0, stdout=contents, stderr=b"")

        def copy_selected_entry(database, session, entries):
            pm.copy_entry_password(database, session, entry_id)
            self.assertEqual(contents, b"stored secret")
            self.assertIsNotNone(session.clipboard.digest)

        with patch("builtins.input", return_value="2"), patch("builtins.print"), \
                patch.object(pm, "clear_console"), \
                patch.object(pm, "browse_entries", side_effect=copy_selected_entry), \
                patch.object(pm.subprocess, "run", side_effect=clipboard_command), \
                patch.object(pm.threading, "Timer"):
            self.assertFalse(pm.run_vault(self.database, self.alice))
        self.assertEqual(contents, b"")
        self.assertIsNone(self.alice.cipher)
        self.assertIsNone(self.alice.clipboard.digest)

    def test_invalid_account_and_password_types_are_rejected(self):
        for value in [None, 12, b"password", []]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    pm.register_account(self.database, value, "valid master password")
                with self.assertRaisesRegex(ValueError, "Invalid username or master password"):
                    pm.login_account(self.database, value, "valid master password")
                with self.assertRaises(ValueError):
                    pm.validate_master_password(value)
                with self.assertRaisesRegex(ValueError, "Invalid username or master password"):
                    pm.login_account(self.database, "alice", value)
                with self.assertRaises(ValueError):
                    self.add_entry(password=value)

    def test_interrupted_vault_menu_always_locks(self):
        for error in [KeyboardInterrupt, EOFError, RuntimeError]:
            session = pm.Session(1, self.alice_cipher)
            session.clipboard = Mock(warning="")
            with patch("builtins.input", side_effect=error), patch("builtins.print"), patch.object(pm, "clear_console"):
                with self.assertRaises(error):
                    pm.run_vault(self.database, session)
            self.assertIsNone(session.cipher)
            session.clipboard.clear.assert_called_once_with()


class DatabaseTests(unittest.TestCase):
    def test_private_permissions_and_foreign_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data" / "vault.db"
            database = pm.open_database(path)
            try:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                with self.assertRaises(sqlite3.IntegrityError):
                    with database:
                        database.execute("INSERT INTO entries VALUES (?, ?, ?)", ("id", 999, b"token"))
            finally:
                database.close()

    def test_symlink_database_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("leave untouched")
            link = Path(directory) / "vault.db"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                pm.open_database(link)
            self.assertEqual(target.read_text(), "leave untouched")


class ClipboardTests(unittest.TestCase):
    def setUp(self):
        self.contents = b""
        self.process = patch.object(pm.subprocess, "run", side_effect=self.run_clipboard).start()
        self.addCleanup(patch.stopall)
        self.timer_factory = patch.object(pm.threading, "Timer").start()
        self.clipboard = pm.Clipboard()

    def run_clipboard(self, command, **kwargs):
        if command[0] == "/usr/bin/pbcopy":
            self.contents = kwargs["input"]
        return subprocess.CompletedProcess(command, 0, stdout=self.contents, stderr=b"")

    def test_copy_schedules_clear_and_keeps_no_plaintext_attribute(self):
        self.clipboard.copy("secret")
        self.assertEqual(self.contents, b"secret")
        self.assertNotIn("secret", vars(self.clipboard).values())
        self.assertNotIn(b"secret", vars(self.clipboard).values())
        self.timer_factory.assert_called_once_with(pm.CLIPBOARD_SECONDS, self.clipboard.clear, args=(1,))
        self.timer_factory.return_value.start.assert_called_once_with()
        self.clipboard.clear()
        self.assertEqual(self.contents, b"")
        self.assertIsNone(self.clipboard.digest)
        self.assertIsNone(self.clipboard.timer)

    def test_clear_preserves_replacement_clipboard_content(self):
        self.clipboard.copy("secret")
        self.contents = b"new user content"
        self.clipboard.clear()
        self.assertEqual(self.contents, b"new user content")
        self.assertIsNone(self.clipboard.digest)

    def test_outdated_timer_cannot_clear_new_copy(self):
        self.clipboard.copy("first")
        old_generation = self.clipboard.generation
        self.clipboard.copy("second")
        self.clipboard.clear(old_generation)
        self.assertEqual(self.contents, b"second")
        self.clipboard.clear(self.clipboard.generation)
        self.assertEqual(self.contents, b"")

    def test_copy_failure_uses_safe_error(self):
        self.process.side_effect = OSError("sensitive diagnostic")
        with self.assertRaises(ValueError) as caught:
            self.clipboard.copy("secret")
        self.assertNotIn("sensitive diagnostic", str(caught.exception))
        self.timer_factory.assert_not_called()

    def test_clear_failure_warns_and_can_be_retried(self):
        self.clipboard.copy("secret")
        self.process.side_effect = subprocess.TimeoutExpired("pbpaste", 3)
        self.clipboard.clear()
        self.assertIn("Clear it manually", self.clipboard.warning)
        self.assertIsNotNone(self.clipboard.digest)
        self.process.side_effect = self.run_clipboard
        self.clipboard.clear()
        self.assertEqual(self.contents, b"")
        self.assertEqual(self.clipboard.warning, "")


class InactivityTests(unittest.TestCase):
    def make_session(self):
        session = pm.Session(1, pm.Fernet(pm.Fernet.generate_key()))
        session.clipboard = Mock(warning="")
        return session

    def test_exact_deadline_locks_before_record_access(self):
        for operation in [lambda s: pm.add_entry(None, s, "site", "user", "secret"),
                          lambda s: pm.list_entries(None, s),
                          lambda s: pm.copy_entry_password(None, s, "id"),
                          lambda s: pm.decrypt_entry(s, {})]:
            session = self.make_session()
            with patch.object(pm.time, "monotonic", return_value=session.deadline):
                with self.assertRaises(pm.SessionExpired):
                    operation(session)
            self.assertIsNone(session.cipher)
            session.clipboard.clear.assert_called_once_with()

    def test_completed_input_renews_deadline(self):
        session = self.make_session()
        now = session.deadline - 1
        with patch.object(pm.time, "monotonic", return_value=now), patch("builtins.input", return_value="2"):
            self.assertEqual(session.read_input("Choice: "), "2")
        self.assertEqual(session.deadline, now + pm.IDLE_SECONDS)

    def test_input_arriving_at_deadline_cannot_revive_session(self):
        session = self.make_session()
        with patch.object(pm.time, "monotonic", side_effect=[session.deadline - 1, session.deadline - 1, session.deadline]), \
                patch("builtins.input", return_value="1"):
            with self.assertRaises(pm.SessionExpired):
                session.read_input("Choice: ")
        self.assertIsNone(session.cipher)

    def test_menu_timeout_returns_to_login_and_restores_alarm(self):
        session = self.make_session()
        handler = pm.signal.getsignal(pm.signal.SIGALRM)
        with patch("builtins.input", side_effect=pm.SessionExpired("Timed out")), \
                patch("builtins.print"), patch.object(pm, "clear_console"):
            self.assertFalse(pm.run_vault(None, session))
        self.assertIsNone(session.cipher)
        session.clipboard.clear.assert_called_once_with()
        self.assertEqual(pm.signal.getsignal(pm.signal.SIGALRM), handler)
        self.assertEqual(pm.signal.getitimer(pm.signal.ITIMER_REAL), (0.0, 0.0))

    def test_alarm_is_active_only_during_input(self):
        session = self.make_session()
        def receive_input(prompt):
            self.assertGreater(pm.signal.getitimer(pm.signal.ITIMER_REAL)[0], 0)
            return "x"
        with patch("builtins.input", side_effect=receive_input):
            self.assertEqual(session.read_input("Choice: "), "x")
        self.assertEqual(pm.signal.getitimer(pm.signal.ITIMER_REAL), (0.0, 0.0))

    def test_failed_input_restores_alarm_handler(self):
        session = self.make_session()
        handler = pm.signal.getsignal(pm.signal.SIGALRM)
        with patch("builtins.input", side_effect=EOFError):
            with self.assertRaises(EOFError):
                session.read_input("Choice: ")
        self.assertEqual(pm.signal.getsignal(pm.signal.SIGALRM), handler)
        self.assertEqual(pm.signal.getitimer(pm.signal.ITIMER_REAL), (0.0, 0.0))


if __name__ == "__main__":
    unittest.main()
