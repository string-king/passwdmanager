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
import session as sessions
import vault


class VaultTests(unittest.TestCase):
    def setUp(self):
        # Each test starts with one account and an empty temporary database.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name)
        self.database = vault.open_database(self.folder / "data" / "vault.db")
        self.addCleanup(self.database.close)
        vault.register_account(self.database, "alice", "alice master password")
        self.session = vault.login_account(self.database, "alice", "alice master password")
        # Tests never read or change the real macOS clipboard.
        self.session.clipboard = Mock(warning="")
        self.addCleanup(self.session.lock)

    def add_entry(self, service="Example"):
        return vault.add_entry(self.database, self.session, service, "alice@example.test", "entry secret")

    def test_duplicate_service_and_username_are_rejected_only_for_same_account(self):
        self.add_entry()
        with self.assertRaisesRegex(ValueError, "already exists"):
            vault.add_entry(self.database, self.session, "Example", "alice@example.test", "different password")
        self.assertEqual(len(vault.list_entries(self.database, self.session)), 1)
        vault.add_entry(self.database, self.session, "Example", "another user", "secret")
        self.add_entry("example")  # Matching is exact and case-sensitive.
        vault.register_account(self.database, "bob", "bob master password")
        bob = vault.login_account(self.database, "bob", "bob master password")
        bob.clipboard = Mock()
        self.addCleanup(bob.lock)
        vault.add_entry(self.database, bob, "Example", "alice@example.test", "secret")
        self.assertEqual(len(vault.list_entries(self.database, bob)), 1)

    def test_edit_rejects_duplicate_but_allows_keeping_own_service_and_username(self):
        first = self.add_entry()
        second = self.add_entry("Other service")
        with self.assertRaisesRegex(ValueError, "already exists"):
            vault.update_entry(self.database, self.session, second, "Example", "alice@example.test", "replacement")
        entry = vault.load_entry(self.database, self.session, second)
        self.assertEqual((entry["service"], entry["password"]), ("Other service", "entry secret"))
        vault.update_entry(self.database, self.session, first, "Example", "alice@example.test", "replacement")
        self.assertEqual(vault.load_entry(self.database, self.session, first)["password"], "replacement")

    def test_correct_login_opens_the_account_vault(self):
        session = vault.login_account(self.database, "alice", "alice master password")
        self.assertEqual(session.owner_id, self.session.owner_id)
        self.assertEqual(session.username, "alice")
        self.assertIsNotNone(session.cipher)
        session.lock()

    def test_failed_login_does_not_reveal_whether_account_exists(self):
        for username in ["alice", "unknown"]:
            with self.subTest(username=username):
                with self.assertRaisesRegex(ValueError, "Invalid username or master password"):
                    vault.login_account(self.database, username, "wrong password")

    def test_duplicate_registration_preserves_existing_account(self):
        with self.assertRaisesRegex(ValueError, "already taken"):
            vault.register_account(self.database, "alice", "different master password")
        self.assertEqual(self.database.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_registration_retries_invalid_fields_and_confirmation(self):
        output = io.StringIO()
        with patch("builtins.input", side_effect=["", "new account"]):
            with patch.object(sessions, "read_password", side_effect=[
                "short", "new master password", "mismatch", "new master password",
            ]):
                with contextlib.redirect_stdout(output):
                    pm.prompt_registration(self.database)
        session = vault.login_account(self.database, "new account", "new master password")
        self.addCleanup(session.lock)
        self.assertEqual(session.username, "new account")
        self.assertNotIn("new master password", output.getvalue())
        self.assertNotIn("mismatch", output.getvalue())

    def test_failed_login_can_retry_or_return_without_exposing_secrets(self):
        output = io.StringIO()
        with patch("builtins.input", side_effect=["unknown", "invalid choice", "1", "alice"]):
            with patch.object(sessions, "read_password", side_effect=["wrong password", "alice master password"]):
                with contextlib.redirect_stdout(output):
                    session = pm.prompt_login(self.database)
        self.addCleanup(session.lock)
        self.assertEqual(session.owner_id, self.session.owner_id)
        with patch("builtins.input", side_effect=["unknown", "2"]):
            with patch.object(sessions, "read_password", return_value="wrong password"):
                with contextlib.redirect_stdout(output):
                    self.assertIsNone(pm.prompt_login(self.database))
        self.assertNotIn("wrong password", output.getvalue())
        self.assertNotIn("alice master password", output.getvalue())

    def test_credentials_are_encrypted_and_readable_after_reopening(self):
        entry_id = self.add_entry()
        raw = (self.folder / "data" / "vault.db").read_bytes()
        self.assertNotIn(b"entry secret", raw)
        self.assertNotIn(b"alice@example.test", raw)
        reopened = vault.open_database(self.folder / "data" / "vault.db")
        try:
            vault.copy_entry_password(reopened, self.session, entry_id)
        finally:
            reopened.close()
        self.session.clipboard.copy.assert_called_once_with("entry secret")

    def test_update_and_delete_change_only_selected_entry(self):
        entry_id = self.add_entry()
        other_id = self.add_entry("Other service")
        vault.update_entry(self.database, self.session, entry_id, "Changed", "new user", "new secret")
        entry = vault.load_entry(self.database, self.session, entry_id)
        self.assertEqual((entry["service"], entry["username"], entry["password"]),
                         ("Changed", "new user", "new secret"))
        vault.delete_entry(self.database, self.session, entry_id)
        self.assertEqual([row["id"] for row in vault.list_entries(self.database, self.session)], [other_id])

    def test_editing_display_fields_preserves_existing_password(self):
        entry_id = self.add_entry()
        vault.update_entry(self.database, self.session, entry_id, "Changed", "new user")
        entry = vault.load_entry(self.database, self.session, entry_id)
        self.assertEqual((entry["service"], entry["username"], entry["password"]),
                         ("Changed", "new user", "entry secret"))

    def test_another_account_cannot_read_update_or_delete_entry(self):
        entry_id = self.add_entry()
        vault.register_account(self.database, "bob", "bob master password")
        bob = vault.login_account(self.database, "bob", "bob master password")
        bob.clipboard = Mock()
        self.addCleanup(bob.lock)
        self.assertEqual(vault.list_entries(self.database, bob), [])
        with self.assertRaises(ValueError):
            vault.copy_entry_password(self.database, bob, entry_id)
        with self.assertRaises(ValueError):
            vault.update_entry(self.database, bob, entry_id, "Changed", "user")
        with self.assertRaises(ValueError):
            vault.delete_entry(self.database, bob, entry_id)
        bob.clipboard.copy.assert_not_called()
        self.assertEqual(len(vault.list_entries(self.database, self.session)), 1)

    def test_damaged_ciphertext_is_rejected(self):
        entry_id = self.add_entry()
        with self.database:
            self.database.execute("UPDATE entries SET payload = ? WHERE id = ?", (b"damaged", entry_id))
        with self.assertRaisesRegex(ValueError, "integrity check failed"):
            vault.copy_entry_password(self.database, self.session, entry_id)
        self.session.clipboard.copy.assert_not_called()

    def test_swapped_encrypted_records_are_rejected(self):
        first, second = self.add_entry(), self.add_entry("Other service")
        payload = self.database.execute("SELECT payload FROM entries WHERE id = ?", (first,)).fetchone()[0]
        with self.database:
            self.database.execute("UPDATE entries SET payload = ? WHERE id = ?", (payload, second))
        with self.assertRaisesRegex(ValueError, "integrity check failed"):
            vault.load_entry(self.database, self.session, second)

    def test_invalid_entry_fields_do_not_save_data(self):
        for value in ["", "   ", "x" * 257, "line\nbreak", "\x1b[2J", None]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    vault.add_entry(self.database, self.session, value, "user", "secret")
                with self.assertRaises(ValueError):
                    vault.add_entry(self.database, self.session, "site", value, "secret")
        self.assertEqual(vault.list_entries(self.database, self.session), [])

    def test_valid_unicode_and_sql_like_text_are_stored_as_data(self):
        service = "Ülikool ' OR 1=1 --"
        entry_id = vault.add_entry(self.database, self.session, service, "õpilane", "🔐secret")
        self.assertEqual(vault.load_entry(self.database, self.session, entry_id)["service"], service)
        self.assertEqual(self.database.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_listing_and_display_do_not_expose_passwords(self):
        self.add_entry()
        summaries = vault.list_entries(self.database, self.session)
        self.assertNotIn("password", summaries[0])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pm.print_entries(summaries)
        self.assertNotIn("entry secret", output.getvalue())

    def test_unrepresentable_local_timestamp_does_not_break_display(self):
        # Simulate date conversion failing, independently of the machine's timezone.
        timestamp = Mock()
        timestamp.astimezone.side_effect = OverflowError("date value out of range")
        entry = dict(service="Example", username="alice", updated_at=timestamp)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pm.print_entries([entry])
        self.assertIn("Invalid date", output.getvalue())
        self.assertIn("Example", output.getvalue())

    def test_failed_transaction_rolls_back_instead_of_logging_success(self):
        entry_id = self.add_entry()
        original = vault.load_entry(self.database, self.session, entry_id)
        # This real SQLite error occurs after the update has begun.
        self.database.execute("""
            CREATE TRIGGER fail_update AFTER UPDATE ON entries BEGIN
                SELECT RAISE(FAIL, 'test write failure');
            END
        """)
        with patch.object(audit, "log_event") as log:
            with self.assertRaises(sqlite3.IntegrityError):
                vault.update_entry(self.database, self.session, entry_id, "Changed", "user")
        self.assertEqual(vault.load_entry(self.database, self.session, entry_id), original)
        self.assertFalse(self.database.in_transaction)
        log.assert_not_called()

    def test_generated_password_is_saved_without_being_displayed(self):
        output = io.StringIO()
        with patch.object(self.session, "read_input", side_effect=["site", "user", "y"]):
            with contextlib.redirect_stdout(output):
                pm.prompt_add_entry(self.database, self.session)
        entry_id = vault.list_entries(self.database, self.session)[0]["id"]
        password = vault.load_entry(self.database, self.session, entry_id)["password"]
        self.assertEqual(len(password), 20)
        self.assertNotIn(password, output.getvalue())

    def test_add_retries_only_the_invalid_field(self):
        answers = ["", "x" * 257, "GitHub", "\x1b[2J", "alice", "y"]
        with patch.object(self.session, "read_input", side_effect=answers):
            with contextlib.redirect_stdout(io.StringIO()):
                pm.prompt_add_entry(self.database, self.session)
        entry = vault.list_entries(self.database, self.session)[0]
        self.assertEqual((entry["service"], entry["username"]), ("GitHub", "alice"))

    def test_edit_retries_fields_and_preserves_password_when_declined(self):
        entry_id = self.add_entry()
        summary = vault.list_entries(self.database, self.session)[0]
        answers = ["   ", "", "\n", "new user", "maybe", "n"]
        with patch.object(self.session, "read_input", side_effect=answers):
            with contextlib.redirect_stdout(io.StringIO()):
                pm.prompt_edit_entry(self.database, self.session, summary)
        entry = vault.load_entry(self.database, self.session, entry_id)
        self.assertEqual((entry["service"], entry["username"], entry["password"]),
                         ("Example", "new user", "entry secret"))

    def test_retrying_invalid_input_still_allows_timeout_or_interruption(self):
        for error in [sessions.SessionExpired("Timed out"), KeyboardInterrupt()]:
            with self.subTest(error=type(error).__name__):
                with patch.object(self.session, "read_input", side_effect=["", error]):
                    with contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaises(type(error)):
                            pm.prompt_add_entry(self.database, self.session)
        self.assertEqual(vault.list_entries(self.database, self.session), [])

    def test_browse_filter_matches_service_or_username_and_clear_resets_page(self):
        entries = [dict(id=str(i), service=f"Site {i}", username="alice", updated_at=None)
                   for i in range(12)]
        answers = ["n", "f", "SITE 11", "f", "ALICE", "n", "c", "b"]
        with patch.object(self.session, "read_input", side_effect=answers):
            with patch.object(pm, "print_entry_page") as render:
                pm.browse_entries(self.database, self.session, entries)
        pages = render.call_args_list
        self.assertEqual(pages[1].args[1], 1)
        self.assertEqual(pages[2].args[0], [entries[11]])
        self.assertEqual(pages[2].args[1], 0)
        self.assertEqual(pages[3].args[0], entries)
        self.assertEqual(pages[-1].args[1], 0)
        self.assertEqual(pages[-1].args[-1], "")

    def test_browse_keeps_filter_after_edit_and_handles_no_matches(self):
        entry_id = self.add_entry("Target service")
        self.add_entry("Other service")
        def edit_selected(database, session, entry):
            self.assertEqual(entry["id"], entry_id)
            vault.update_entry(database, session, entry["id"], "Renamed", "new user")
            return "Entry updated."
        answers = ["f", "target", "1", "c", "b"]
        output = io.StringIO()
        with patch.object(self.session, "read_input", side_effect=answers):
            with patch.object(pm, "entry_actions", side_effect=edit_selected):
                with patch.object(pm, "print_entry_page", wraps=pm.print_entry_page) as render:
                    with contextlib.redirect_stdout(output):
                        pm.browse_entries(self.database, self.session, vault.list_entries(self.database, self.session))
        empty_page = render.call_args_list[2].args
        self.assertEqual(empty_page[0], [])
        self.assertEqual(empty_page[-1], "target")
        self.assertEqual(len(render.call_args_list[3].args[0]), 2)
        self.assertIn("No matching entries", output.getvalue())

    def test_logging_records_events_without_credential_contents(self):
        path = self.folder / "logs" / "events.jsonl"
        handler = audit.configure_logging(path)
        try:
            with self.assertRaises(ValueError):
                vault.login_account(self.database, "unknown account", "wrong password")
            entry_id = self.add_entry()
            vault.update_entry(self.database, self.session, entry_id, "Changed", "user")
            vault.delete_entry(self.database, self.session, entry_id)
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
            vault.list_entries(self.database, self.session)
        with self.assertRaisesRegex(ValueError, "locked"):
            vault.update_entry(self.database, self.session, entry_id, "site", "user")
        with self.assertRaisesRegex(ValueError, "locked"):
            vault.delete_entry(self.database, self.session, entry_id)

    def test_timeout_during_delete_confirmation_does_not_delete(self):
        self.add_entry()
        # Navigate to the first entry, choose delete, then expire at confirmation.
        answers = ["2", "1", "3", sessions.SessionExpired(sessions.INACTIVITY_MESSAGE)]
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
