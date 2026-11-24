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
                contents = bytes(kwargs["input"])
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

    def test_update_preserves_password_and_record_identity(self):
        entry_id = self.add_entry()
        before = pm.list_entries(self.database, self.alice)[0]["updated_at"]
        pm.update_entry(self.database, self.alice, entry_id, "Changed", "new user")
        entry = pm.load_entry(self.database, self.alice, entry_id)
        self.assertEqual(entry["service"], "Changed")
        self.assertEqual(entry["username"], "new user")
        self.assertEqual(entry["password"], "stored secret")
        self.assertEqual(entry["id"], entry_id)
        self.assertEqual(entry["owner_id"], self.alice.owner_id)
        self.assertGreaterEqual(entry["updated_at"], before)

    def test_update_replaces_password_with_encrypted_storage(self):
        entry_id = self.add_entry()
        pm.update_entry(self.database, self.alice, entry_id, "Changed", "new user", "replacement secret")
        pm.copy_entry_password(self.database, self.alice, entry_id)
        self.alice.clipboard.copy.assert_called_once_with("replacement secret")
        payload = self.database.execute("SELECT payload FROM entries WHERE id = ?", (entry_id,)).fetchone()[0]
        self.assertNotIn(b"replacement secret", payload)

    def test_update_validation_leaves_record_unchanged(self):
        entry_id = self.add_entry()
        before = pm.load_entry(self.database, self.alice, entry_id)
        invalid_changes = [("", "user", None), ("site", "\x1b[2J", None), ("site", "user", "")]
        for service, username, password in invalid_changes:
            with self.subTest(service=service, username=username, password=password):
                with self.assertRaises(ValueError):
                    pm.update_entry(self.database, self.alice, entry_id, service, username, password)
                self.assertEqual(pm.load_entry(self.database, self.alice, entry_id), before)

    def test_update_and_delete_reject_other_users_and_missing_records(self):
        entry_id = self.add_entry()
        for identifier in [entry_id, "missing", "' OR 1=1 --"]:
            with self.subTest(identifier=identifier):
                with self.assertRaisesRegex(ValueError, "not found"):
                    pm.update_entry(self.database, self.bob, identifier, "changed", "user")
                with self.assertRaisesRegex(ValueError, "not found"):
                    pm.delete_entry(self.database, self.bob, identifier)
        self.assertEqual(pm.load_entry(self.database, self.alice, entry_id)["service"], "Example")

    def test_delete_removes_only_selected_record(self):
        first = self.add_entry()
        second = self.add_entry(service="Other")
        pm.delete_entry(self.database, self.alice, first)
        self.assertEqual([entry["id"] for entry in pm.list_entries(self.database, self.alice)], [second])
        with self.assertRaisesRegex(ValueError, "not found"):
            pm.delete_entry(self.database, self.alice, first)

    def test_update_and_delete_reject_locked_and_expired_sessions(self):
        entry_id = self.add_entry()
        self.alice.deadline = pm.time.monotonic() - 1
        with self.assertRaises(pm.SessionExpired):
            pm.update_entry(self.database, self.alice, entry_id, "changed", "user")
        with self.assertRaisesRegex(ValueError, "locked"):
            pm.delete_entry(self.database, self.alice, entry_id)
        self.assertEqual(self.database.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 1)

    def test_update_rejects_tampered_record(self):
        entry_id = self.add_entry()
        self.database.execute("UPDATE entries SET payload = ? WHERE id = ?", (b"damaged", entry_id))
        with self.assertRaisesRegex(ValueError, "integrity check failed"):
            pm.update_entry(self.database, self.alice, entry_id, "changed", "user")

    def test_edit_prompt_keeps_fields_and_password_by_default(self):
        entry_id = self.add_entry()
        summary = pm.list_entries(self.database, self.alice)[0]
        with patch.object(self.alice, "read_input", side_effect=["", "", ""]):
            pm.prompt_edit_entry(self.database, self.alice, summary)
        entry = pm.load_entry(self.database, self.alice, entry_id)
        self.assertEqual(entry["service"], "Example")
        self.assertEqual(entry["username"], "alice@example.test")
        self.assertEqual(entry["password"], "stored secret")

    def test_edit_password_is_hidden_and_never_printed(self):
        self.add_entry()
        summary = pm.list_entries(self.database, self.alice)[0]
        output = io.StringIO()
        with patch.object(self.alice, "read_input", side_effect=["2", "Changed", "user", "y", "n", "replacement secret"]) as reader, \
                patch.object(pm, "clear_console"), contextlib.redirect_stdout(output):
            self.assertEqual(pm.entry_actions(self.database, self.alice, summary), "Entry updated.")
        reader.assert_any_call("New entry password: ", hidden=True)
        self.assertNotIn("replacement secret", output.getvalue())
        self.assertNotIn("stored secret", output.getvalue())

    def test_generated_password_is_encrypted_and_not_displayed_when_adding(self):
        generated = "Generated-Only-For-Tests-9!"
        output = io.StringIO()
        with patch.object(self.alice, "read_input", side_effect=["site", "user", "y", "", ""]), \
                patch.object(pm, "generate_password", return_value=generated) as generator, \
                contextlib.redirect_stdout(output):
            pm.prompt_add_entry(self.database, self.alice)
        generator.assert_called_once_with(20, include_symbols=True)
        entry_id = pm.list_entries(self.database, self.alice)[0]["id"]
        self.assertEqual(pm.load_entry(self.database, self.alice, entry_id)["password"], generated)
        payload = self.database.execute("SELECT payload FROM entries WHERE id = ?", (entry_id,)).fetchone()[0]
        self.assertNotIn(generated.encode(), payload)
        self.assertNotIn(generated, output.getvalue())

    def test_edit_can_replace_password_with_generated_value(self):
        entry_id = self.add_entry()
        summary = pm.list_entries(self.database, self.alice)[0]
        with patch.object(self.alice, "read_input", side_effect=["", "", "y", "y", "32", "n"]), \
                patch.object(pm, "generate_password", return_value="GeneratedTest9") as generator:
            pm.prompt_edit_entry(self.database, self.alice, summary)
        generator.assert_called_once_with(32, include_symbols=False)
        self.assertEqual(pm.load_entry(self.database, self.alice, entry_id)["password"], "GeneratedTest9")

    def test_invalid_generation_options_do_not_save_entry(self):
        with patch.object(self.alice, "read_input", side_effect=["site", "user", "y", "abc"]):
            with self.assertRaises(ValueError):
                pm.prompt_add_entry(self.database, self.alice)
        self.assertEqual(pm.list_entries(self.database, self.alice), [])

    def test_delete_requires_exact_confirmation(self):
        self.add_entry()
        summary = pm.list_entries(self.database, self.alice)[0]
        for response in ["", "y", "delete"]:
            with self.subTest(response=response), patch.object(self.alice, "read_input", side_effect=["3", response]), \
                    patch.object(pm, "clear_console"), patch("builtins.print"):
                self.assertEqual(pm.entry_actions(self.database, self.alice, summary), "Deletion cancelled.")
            self.assertEqual(len(pm.list_entries(self.database, self.alice)), 1)
        with patch.object(self.alice, "read_input", side_effect=["3", "DELETE"]), \
                patch.object(pm, "clear_console"), patch("builtins.print"):
            self.assertEqual(pm.entry_actions(self.database, self.alice, summary), "Entry deleted.")
        self.assertEqual(pm.list_entries(self.database, self.alice), [])

    def assert_entry_write_rolls_back(self, operation, action, *arguments):
        before = [tuple(row) for row in self.database.execute("SELECT * FROM entries ORDER BY id")]
        # FAIL leaves a statement's earlier writes pending: the app must roll them back.
        self.database.execute(f"""
            CREATE TRIGGER injected_failure AFTER {operation} ON entries BEGIN
                UPDATE users SET username = 'changed by failing trigger' WHERE id = 2;
                SELECT RAISE(FAIL, 'injected write failure');
            END
        """)
        with patch.object(pm, "log_event") as log:
            with self.assertRaises(sqlite3.IntegrityError):
                action(self.database, self.alice, *arguments)
        self.assertEqual([tuple(row) for row in self.database.execute("SELECT * FROM entries ORDER BY id")], before)
        self.assertEqual(self.database.execute("SELECT username FROM users WHERE id = 2").fetchone()[0], "bob")
        self.assertFalse(self.database.in_transaction)
        log.assert_not_called()

    def test_failed_insert_rolls_back_all_transaction_changes(self):
        self.assert_entry_write_rolls_back("INSERT", pm.add_entry, "site", "user", "secret")

    def test_failed_update_rolls_back_all_transaction_changes(self):
        entry_id = self.add_entry()
        self.assert_entry_write_rolls_back("UPDATE", pm.update_entry, entry_id, "changed", "user")

    def test_failed_delete_rolls_back_all_transaction_changes(self):
        entry_id = self.add_entry()
        self.assert_entry_write_rolls_back("DELETE", pm.delete_entry, entry_id)

    def test_commit_failure_rolls_back_update_and_does_not_log_success(self):
        entry_id = self.add_entry()
        before = pm.load_entry(self.database, self.alice, entry_id)
        self.database.execute("PRAGMA defer_foreign_keys = ON")
        self.database.execute("""
            CREATE TRIGGER fail_commit AFTER UPDATE ON entries BEGIN
                INSERT INTO entries (id, owner_id, payload) VALUES ('orphan', 999, X'00');
            END
        """)
        with patch.object(pm, "log_event") as log:
            with self.assertRaises(sqlite3.IntegrityError):
                pm.update_entry(self.database, self.alice, entry_id, "changed", "user")
        log.assert_not_called()
        self.assertEqual(pm.load_entry(self.database, self.alice, entry_id), before)
        self.assertEqual(self.database.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 1)
        self.assertFalse(self.database.in_transaction)

    def test_timeout_during_each_edit_prompt_preserves_record(self):
        entry_id = self.add_entry()
        before = pm.load_entry(self.database, self.alice, entry_id)
        prompts = ["Service (Enter to keep): ", "Username/email (Enter to keep): ",
                   "Replace password? [y/N]: ", "Generate password? [y/N]: ", "New entry password: "]
        for target in prompts:
            with self.subTest(prompt=target):
                session = pm.Session(1, self.alice_cipher)
                session.clipboard = Mock(warning="")
                now = session.deadline - pm.IDLE_SECONDS
                choices = iter(["2", "1", "2"])
                def respond(prompt):
                    nonlocal now
                    if prompt == target:
                        now = session.deadline
                    if prompt == "Choice: ":
                        return next(choices)
                    if prompt == "Generate password? [y/N]: ":
                        return "n"
                    return "y" if prompt == "Replace password? [y/N]: " else "changed value"
                with patch("builtins.input", side_effect=respond), patch.object(pm, "read_password", side_effect=respond), \
                        patch.object(pm.time, "monotonic", side_effect=lambda: now), \
                        patch.object(pm, "clear_console"), patch("builtins.print"):
                    self.assertFalse(pm.run_vault(self.database, session))
                self.assertIsNone(session.cipher)
                session.clipboard.clear.assert_called()
                self.assertEqual(pm.load_entry(self.database, self.alice, entry_id), before)

    def test_timeout_during_delete_confirmation_preserves_record(self):
        entry_id = self.add_entry()
        self.alice.clipboard.warning = ""
        now = self.alice.deadline - pm.IDLE_SECONDS
        choices = iter(["2", "1", "3"])
        def respond(prompt):
            nonlocal now
            if prompt.startswith("Delete this entry?"):
                now = self.alice.deadline
                return "DELETE"
            return next(choices)
        with patch("builtins.input", side_effect=respond), \
                patch.object(pm.time, "monotonic", side_effect=lambda: now), \
                patch.object(pm, "clear_console"), patch("builtins.print"):
            self.assertFalse(pm.run_vault(self.database, self.alice))
        self.assertIsNone(self.alice.cipher)
        self.alice.clipboard.clear.assert_called()
        self.assertEqual(self.database.execute("SELECT id FROM entries").fetchone()[0], entry_id)

    def test_browser_preserves_page_boundaries_and_back_action(self):
        self.add_entry()
        entries = pm.list_entries(self.database, self.alice)
        self.alice.clipboard.warning = ""
        with patch.object(self.alice, "read_input", side_effect=["p", "n", "1", "4", "b"]), \
                patch.object(pm, "clear_console"), patch("builtins.print") as printer:
            pm.browse_entries(self.database, self.alice, entries)
        printer.assert_any_call("\nAlready on the first page.")
        printer.assert_any_call("\nAlready on the last page.")
        self.alice.clipboard.copy.assert_not_called()

    def test_vault_recovers_from_add_and_list_validation_errors(self):
        self.alice.clipboard.warning = ""
        with patch.object(self.alice, "read_input", side_effect=["1", "2", "3"]), \
                patch.object(pm, "prompt_add_entry", side_effect=ValueError("Invalid service")), \
                patch.object(pm, "list_entries", side_effect=ValueError("Damaged entry")), \
                patch.object(pm, "clear_console"), patch("builtins.print") as printer:
            self.assertFalse(pm.run_vault(self.database, self.alice))
        self.assertTrue(any(str(call.args[0]) == "Invalid service" for call in printer.call_args_list if call.args))
        self.assertTrue(any(str(call.args[0]) == "Damaged entry" for call in printer.call_args_list if call.args))
        self.assertIsNone(self.alice.cipher)
        self.alice.clipboard.clear.assert_called_once_with()

    def test_browser_refreshes_after_deleting_last_entry_on_page(self):
        for number in range(pm.PAGE_SIZE + 1):
            self.add_entry(service=f"Site {number}")
        with patch.object(self.alice, "read_input", side_effect=["n", "1", "3", "DELETE", "b"]), \
                patch.object(pm, "clear_console"), patch("builtins.print") as printer:
            pm.browse_entries(self.database, self.alice, pm.list_entries(self.database, self.alice))
        self.assertEqual(len(pm.list_entries(self.database, self.alice)), pm.PAGE_SIZE)
        printer.assert_any_call(f"Page 1 of 1 | {pm.PAGE_SIZE} entries")

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
            self.contents = bytes(kwargs["input"])
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
        self.timer_factory.return_value.cancel.assert_called_once_with()
        self.assertIsNotNone(self.clipboard.digest)
        self.assertIn("Clear it manually", self.clipboard.warning)

    def test_copy_failure_before_writing_preserves_unrelated_clipboard(self):
        self.contents = b"unrelated user content"
        def fail_copy(command, **kwargs):
            if command[0] == "/usr/bin/pbcopy" and kwargs.get("input"):
                self.assertIsNotNone(self.clipboard.digest)
                raise OSError("copy failed before writing")
            return self.run_clipboard(command, **kwargs)
        self.process.side_effect = fail_copy
        with self.assertRaises(ValueError):
            self.clipboard.copy("secret")
        self.assertEqual(self.contents, b"unrelated user content")
        self.assertIsNone(self.clipboard.digest)
        self.assertIsNone(self.clipboard.timer)
        self.assertEqual(self.clipboard.warning, "")

    def test_copy_failure_after_writing_clears_password(self):
        errors = [OSError("copy failed"), subprocess.TimeoutExpired("pbcopy", 3),
                  subprocess.CalledProcessError(1, "pbcopy")]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                def fail_after_write(command, **kwargs):
                    result = self.run_clipboard(command, **kwargs)
                    if command[0] == "/usr/bin/pbcopy" and kwargs.get("input"):
                        raise error
                    return result
                self.process.side_effect = fail_after_write
                with self.assertRaises(ValueError):
                    self.clipboard.copy("secret")
                self.assertEqual(self.contents, b"")
                self.assertIsNone(self.clipboard.digest)
                self.assertIsNone(self.clipboard.timer)
                self.assertEqual(self.clipboard.warning, "")

    def test_failed_copy_and_cleanup_retain_tracking_for_retry(self):
        def fail_copy_and_clear(command, **kwargs):
            if command[0] == "/usr/bin/pbcopy":
                if kwargs.get("input"):
                    self.contents = bytes(kwargs["input"])
                raise OSError("clipboard unavailable")
            return self.run_clipboard(command, **kwargs)
        self.process.side_effect = fail_copy_and_clear
        with self.assertRaises(ValueError):
            self.clipboard.copy("secret")
        self.assertEqual(self.contents, b"secret")
        self.assertIsNotNone(self.clipboard.digest)
        self.assertIn("Clear it manually", self.clipboard.warning)
        self.process.side_effect = self.run_clipboard
        self.clipboard.clear()
        self.assertEqual(self.contents, b"")
        self.assertIsNone(self.clipboard.digest)
        self.assertEqual(self.clipboard.warning, "")

    def test_failed_replacement_does_not_leave_previous_password_untracked(self):
        self.clipboard.copy("first")
        def fail_new_copy(command, **kwargs):
            if command[0] == "/usr/bin/pbcopy" and kwargs.get("input"):
                raise OSError("new copy failed")
            return self.run_clipboard(command, **kwargs)
        self.process.side_effect = fail_new_copy
        with self.assertRaises(ValueError):
            self.clipboard.copy("second")
        self.assertEqual(self.contents, b"")
        self.assertIsNone(self.clipboard.digest)

    def test_unclearable_previous_copy_blocks_replacement(self):
        self.clipboard.copy("first")
        digest = self.clipboard.digest
        self.process.side_effect = OSError("clipboard unavailable")
        with self.assertRaisesRegex(ValueError, "previous password"):
            self.clipboard.copy("second")
        self.assertEqual(self.contents, b"first")
        self.assertEqual(self.clipboard.digest, digest)
        self.process.side_effect = self.run_clipboard
        self.clipboard.clear()
        self.assertEqual(self.contents, b"")

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
