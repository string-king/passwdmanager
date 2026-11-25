"""Requirement-focused tests using a real, disposable vault database."""

import contextlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

import audit
import passwdmanager as pm


class VaultTests(unittest.TestCase):
    def setUp(self):
        # Each test starts with one account and an empty temporary database.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name)
        self.database = pm.open_database(self.folder / "data" / "vault.db")
        self.addCleanup(self.database.close)
        pm.register_account(self.database, "alice", "alice master password")
        self.session = pm.login_account(self.database, "alice", "alice master password")
        # Tests never read or change the real macOS clipboard.
        self.session.clipboard = Mock(warning="")
        self.addCleanup(self.session.lock)

    def add_entry(self):
        return pm.add_entry(self.database, self.session, "Example", "alice@example.test", "entry secret")

    def test_correct_login_opens_the_account_vault(self):
        session = pm.login_account(self.database, "alice", "alice master password")
        self.assertEqual(session.owner_id, self.session.owner_id)
        self.assertIsNotNone(session.cipher)
        session.lock()

    def test_failed_login_does_not_reveal_whether_account_exists(self):
        for username in ["alice", "unknown"]:
            with self.subTest(username=username):
                with self.assertRaisesRegex(ValueError, "Invalid username or master password"):
                    pm.login_account(self.database, username, "wrong password")

    def test_duplicate_registration_preserves_existing_account(self):
        with self.assertRaisesRegex(ValueError, "already taken"):
            pm.register_account(self.database, "alice", "different master password")
        self.assertEqual(self.database.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_credentials_are_encrypted_and_readable_after_reopening(self):
        entry_id = self.add_entry()
        raw = (self.folder / "data" / "vault.db").read_bytes()
        self.assertNotIn(b"entry secret", raw)
        self.assertNotIn(b"alice@example.test", raw)
        reopened = pm.open_database(self.folder / "data" / "vault.db")
        try:
            pm.copy_entry_password(reopened, self.session, entry_id)
        finally:
            reopened.close()
        self.session.clipboard.copy.assert_called_once_with("entry secret")

    def test_update_and_delete_change_only_selected_entry(self):
        entry_id = self.add_entry()
        other_id = self.add_entry()
        pm.update_entry(self.database, self.session, entry_id, "Changed", "new user", "new secret")
        entry = pm.load_entry(self.database, self.session, entry_id)
        self.assertEqual((entry["service"], entry["username"], entry["password"]),
                         ("Changed", "new user", "new secret"))
        pm.delete_entry(self.database, self.session, entry_id)
        self.assertEqual([row["id"] for row in pm.list_entries(self.database, self.session)], [other_id])

    def test_another_account_cannot_read_update_or_delete_entry(self):
        entry_id = self.add_entry()
        pm.register_account(self.database, "bob", "bob master password")
        bob = pm.login_account(self.database, "bob", "bob master password")
        bob.clipboard = Mock()
        self.addCleanup(bob.lock)
        self.assertEqual(pm.list_entries(self.database, bob), [])
        with self.assertRaises(ValueError):
            pm.copy_entry_password(self.database, bob, entry_id)
        with self.assertRaises(ValueError):
            pm.update_entry(self.database, bob, entry_id, "Changed", "user")
        with self.assertRaises(ValueError):
            pm.delete_entry(self.database, bob, entry_id)
        bob.clipboard.copy.assert_not_called()
        self.assertEqual(len(pm.list_entries(self.database, self.session)), 1)

    def test_damaged_ciphertext_is_rejected(self):
        entry_id = self.add_entry()
        with self.database:
            self.database.execute("UPDATE entries SET payload = ? WHERE id = ?", (b"damaged", entry_id))
        with self.assertRaisesRegex(ValueError, "integrity check failed"):
            pm.copy_entry_password(self.database, self.session, entry_id)
        self.session.clipboard.copy.assert_not_called()

    def test_swapped_encrypted_records_are_rejected(self):
        first, second = self.add_entry(), self.add_entry()
        payload = self.database.execute("SELECT payload FROM entries WHERE id = ?", (first,)).fetchone()[0]
        with self.database:
            self.database.execute("UPDATE entries SET payload = ? WHERE id = ?", (payload, second))
        with self.assertRaisesRegex(ValueError, "integrity check failed"):
            pm.load_entry(self.database, self.session, second)

    def test_invalid_entry_fields_do_not_save_data(self):
        for value in ["", "   ", "x" * 257, "line\nbreak", "\x1b[2J", None]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    pm.add_entry(self.database, self.session, value, "user", "secret")
                with self.assertRaises(ValueError):
                    pm.add_entry(self.database, self.session, "site", value, "secret")
        self.assertEqual(pm.list_entries(self.database, self.session), [])

    def test_valid_unicode_and_sql_like_text_are_stored_as_data(self):
        service = "Ülikool ' OR 1=1 --"
        entry_id = pm.add_entry(self.database, self.session, service, "õpilane", "🔐secret")
        self.assertEqual(pm.load_entry(self.database, self.session, entry_id)["service"], service)
        self.assertEqual(self.database.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_listing_and_display_do_not_expose_passwords(self):
        self.add_entry()
        summaries = pm.list_entries(self.database, self.session)
        self.assertNotIn("password", summaries[0])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pm.print_entries(summaries)
        self.assertNotIn("entry secret", output.getvalue())

    def test_failed_transaction_rolls_back_instead_of_logging_success(self):
        entry_id = self.add_entry()
        original = pm.load_entry(self.database, self.session, entry_id)
        # This real SQLite error occurs after the update has begun.
        self.database.execute("""
            CREATE TRIGGER fail_update AFTER UPDATE ON entries BEGIN
                SELECT RAISE(FAIL, 'test write failure');
            END
        """)
        with patch.object(audit, "log_event") as log:
            with self.assertRaises(sqlite3.IntegrityError):
                pm.update_entry(self.database, self.session, entry_id, "Changed", "user")
        self.assertEqual(pm.load_entry(self.database, self.session, entry_id), original)
        self.assertFalse(self.database.in_transaction)
        log.assert_not_called()

    def test_generated_password_is_saved_without_being_displayed(self):
        output = io.StringIO()
        with patch.object(self.session, "read_input", side_effect=["site", "user", "y"]):
            with contextlib.redirect_stdout(output):
                pm.prompt_add_entry(self.database, self.session)
        entry_id = pm.list_entries(self.database, self.session)[0]["id"]
        password = pm.load_entry(self.database, self.session, entry_id)["password"]
        self.assertEqual(len(password), 20)
        self.assertNotIn(password, output.getvalue())

    def test_logging_records_events_without_credential_contents(self):
        path = self.folder / "logs" / "events.jsonl"
        handler = audit.configure_logging(path)
        try:
            with self.assertRaises(ValueError):
                pm.login_account(self.database, "unknown account", "wrong password")
            entry_id = self.add_entry()
            pm.update_entry(self.database, self.session, entry_id, "Changed", "user")
            pm.delete_entry(self.database, self.session, entry_id)
        finally:
            audit.LOGGER.removeHandler(handler)
            handler.stream.close()
            handler.close()
        text = path.read_text()
        events = [json.loads(line) for line in text.splitlines()]
        self.assertEqual([event["event"] for event in events],
                         ["login_failed", "entry_created", "entry_updated", "entry_deleted"])
        self.assertNotIn("user_id", events[0])
        self.assertTrue(all(event["user_id"] == self.session.owner_id for event in events[1:]))
        self.assertNotIn("entry secret", text)
        self.assertNotIn("alice@example.test", text)
        self.assertNotIn("unknown account", text)
        self.assertNotIn("wrong password", text)

    def test_lock_releases_key_and_blocks_record_operations(self):
        entry_id = self.add_entry()
        self.session.lock()
        self.assertIsNone(self.session.cipher)
        self.session.clipboard.clear.assert_called_once_with()
        with self.assertRaisesRegex(ValueError, "locked"):
            pm.list_entries(self.database, self.session)
        with self.assertRaisesRegex(ValueError, "locked"):
            pm.update_entry(self.database, self.session, entry_id, "site", "user")
        with self.assertRaisesRegex(ValueError, "locked"):
            pm.delete_entry(self.database, self.session, entry_id)

    def test_timeout_during_delete_confirmation_does_not_delete(self):
        self.add_entry()
        # Navigate to the first entry, choose delete, then expire at confirmation.
        answers = ["2", "1", "3", pm.SessionExpired(pm.INACTIVITY_MESSAGE)]
        with patch.object(self.session, "read_input", side_effect=answers):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(pm.run_vault(self.database, self.session))
        self.assertIsNone(self.session.cipher)
        self.assertEqual(self.database.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 1)

    def test_interrupted_vault_locks_before_exiting(self):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    pm.run_vault(self.database, self.session)
        self.assertIsNone(self.session.cipher)
        self.session.clipboard.clear.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
