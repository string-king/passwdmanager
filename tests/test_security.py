"""Small checks for validation, memory cleanup, and clipboard safety."""

import json
from pathlib import Path
import sqlite3
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import clipboard
import passwdmanager as pm
import session as sessions
import security


class SecurityTests(unittest.TestCase):
    def test_password_length_boundaries(self):
        for password in ["", "x" * 11, "x" * 1025, None]:
            with self.subTest(length=len(password) if password is not None else None):
                with self.assertRaises(ValueError):
                    security.validate_master_password(password)
        security.validate_master_password("x" * 12)
        security.validate_master_password("õ" * 1024)
        with self.assertRaises(ValueError):
            security.validate_password("", "Entry password")
        security.validate_password("x", "Entry password")

    def test_invalid_names_and_record_ids_are_rejected(self):
        for username in ["", "   ", "x" * 65, "line\nbreak", None]:
            with self.subTest(username=username):
                with self.assertRaises(ValueError):
                    security.validate_account_username(username)
        for entry_id in ["", "A" * 32, "a" * 31, None]:
            with self.subTest(entry_id=entry_id):
                with self.assertRaises(ValueError):
                    security.validate_entry_id(entry_id)

    def test_invalid_encrypted_record_contents_have_safe_errors(self):
        session = sessions.Session(1, pm.Fernet(pm.Fernet.generate_key()))
        entry_id = "a" * 32
        entry = dict(id=entry_id, owner_id=True, service="site", username="user", password="secret")
        invalid_json = ["{broken", '{"id":"first","id":"second"}',
                        "[" * 1500 + "0" + "]" * 1500, json.dumps(entry)]
        payloads = [None, "not bytes", b"", b"x" * (pm.MAX_PAYLOAD_BYTES + 1)]
        payloads += [session.cipher.encrypt(text.encode()) for text in invalid_json]
        for payload in payloads:
            row = {"id": entry_id, "payload": payload}
            with self.subTest(payload_type=type(payload).__name__):
                with self.assertRaisesRegex(ValueError, "integrity check failed"):
                    pm.decrypt_entry(session, row)
        session.lock()

    def test_untrusted_kdf_settings_are_rejected_before_derivation(self):
        with tempfile.TemporaryDirectory() as directory:
            database = pm.open_database(Path(directory) / "vault.db")
            try:
                pm.register_account(database, "alice", "alice master password")
                with database:
                    database.execute("UPDATE users SET memory_cost = 1")
                with patch.object(security, "password_kdf") as kdf:
                    with self.assertRaises(ValueError):
                        pm.login_account(database, "alice", "alice master password")
                kdf.assert_not_called()
            finally:
                database.close()

    def test_database_is_private_and_symlink_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data" / "vault.db"
            database = pm.open_database(path)
            database.close()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            link = path.parent / "link.db"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                pm.open_database(link)

    def test_wiping_overwrites_the_existing_buffer(self):
        secret = bytearray(b"secret")
        same_memory = memoryview(secret)
        security.wipe_buffer(secret)
        self.assertEqual(bytes(same_memory), b"\x00" * 6)

    def test_password_buffer_is_wiped_when_key_derivation_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            database = pm.open_database(Path(directory) / "vault.db")
            try:
                with patch.object(security, "password_kdf") as factory:
                    factory.return_value.derive.side_effect = RuntimeError("test KDF failure")
                    with self.assertRaises(RuntimeError):
                        pm.register_account(database, "alice", "alice master password")
                    buffer = factory.return_value.derive.call_args.args[0]
                self.assertEqual(buffer, bytearray(len(buffer)))
            finally:
                database.close()

    def test_expired_session_releases_key_and_clears_clipboard(self):
        session = sessions.Session(1, pm.Fernet(pm.Fernet.generate_key()))
        session.clipboard = Mock()
        with patch.object(sessions.time, "monotonic", return_value=session.deadline):
            with self.assertRaises(sessions.SessionExpired):
                session.require_unlocked()
        self.assertIsNone(session.cipher)
        session.clipboard.clear.assert_called_once_with()


class ClipboardTests(unittest.TestCase):
    def setUp(self):
        # Suppress real timers; mock subprocess.run separately in each test.
        timer_patch = patch.object(clipboard.threading, "Timer")
        timer_patch.start()
        self.addCleanup(timer_patch.stop)
        self.clipboard = clipboard.Clipboard()

    def test_unchanged_clipboard_is_cleared_and_input_buffer_is_wiped(self):
        with patch.object(clipboard.subprocess, "run") as command:
            self.clipboard.copy("secret")
            buffer = command.call_args.kwargs["input"]
            self.assertEqual(buffer, bytearray(6))
            command.return_value.stdout = b"secret"
            self.clipboard.clear()
            self.assertEqual(command.call_args.kwargs["input"], b"")
        self.assertIsNone(self.clipboard.digest)

    def test_unrelated_clipboard_contents_are_preserved(self):
        with patch.object(clipboard.subprocess, "run") as command:
            self.clipboard.copy("secret")
            command.reset_mock()
            command.return_value.stdout = b"user copied something else"
            self.clipboard.clear()
            # Only pbpaste was called; no command overwrote the clipboard.
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args[0][0], "/usr/bin/pbpaste")

    def test_failed_copy_still_clears_password_if_it_was_written(self):
        responses = [subprocess.TimeoutExpired("pbcopy", 3),
                     subprocess.CompletedProcess([], 0, stdout=b"secret"),
                     subprocess.CompletedProcess([], 0)]
        with patch.object(clipboard.subprocess, "run", side_effect=responses) as command:
            with self.assertRaises(ValueError):
                self.clipboard.copy("secret")
            self.assertEqual(command.call_args.kwargs["input"], b"")
        self.assertIsNone(self.clipboard.digest)

    def test_failed_cleanup_warns_and_keeps_tracking_for_retry(self):
        with patch.object(clipboard.subprocess, "run", side_effect=OSError("test failure")):
            with self.assertRaises(ValueError):
                self.clipboard.copy("secret")
        self.assertIsNotNone(self.clipboard.digest)
        self.assertIn("Clear it manually", self.clipboard.warning)
        with patch.object(clipboard.subprocess, "run") as command:
            command.return_value.stdout = b"secret"
            self.clipboard.clear()
        self.assertIsNone(self.clipboard.digest)
        self.assertEqual(self.clipboard.warning, "")


if __name__ == "__main__":
    unittest.main()
