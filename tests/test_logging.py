"""Audit format, privacy, permissions, and real event integration."""

import contextlib
import io
import json
import sqlite3
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

import passwdmanager as pm


class EventLoggingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "logs" / "events.jsonl"
        self.handler = pm.configure_logging(self.path)
        self.addCleanup(self.close_log)

    def close_log(self):
        pm.LOGGER.removeHandler(self.handler)
        self.handler.stream.close()
        self.handler.close()

    def events(self):
        return [json.loads(line) for line in self.path.read_text().splitlines()]

    def test_json_lines_append_and_private_permissions(self):
        pm.log_event("login_failed")
        pm.log_event("vault_locked", user_id=7, reason="inactivity")
        events = self.events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["severity"], "WARNING")
        self.assertNotIn("user_id", events[0])
        self.assertEqual(events[1]["user_id"], 7)
        self.assertEqual(events[1]["reason"], "inactivity")
        self.assertEqual(pm.datetime.fromisoformat(events[1]["timestamp"]).utcoffset().total_seconds(), 0)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)

    def test_log_file_symlink_is_rejected(self):
        target = Path(self.directory.name) / "target"
        target.write_text("untouched")
        link = self.path.parent / "link.jsonl"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            pm.configure_logging(link)
        self.assertEqual(target.read_text(), "untouched")

    def test_write_failure_has_safe_warning(self):
        original_stream = self.handler.stream
        broken_stream = Mock()
        broken_stream.write.side_effect = OSError("private diagnostic")
        self.handler.setStream(broken_stream)
        output = io.StringIO()
        try:
            with contextlib.redirect_stderr(output):
                pm.log_event("entry_created", user_id=1)
        finally:
            self.handler.setStream(original_stream)
        self.assertIn("Could not write the security log", output.getvalue())
        self.assertNotIn("private diagnostic", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

    def test_real_workflow_events_exclude_secrets(self):
        database = pm.open_database(Path(self.directory.name) / "data" / "vault.db")
        self.addCleanup(database.close)
        username = "private account"
        master = "private master password"
        pm.register_account(database, username, master)
        with self.assertRaises(ValueError):
            pm.login_account(database, "private missing account", "private wrong password")
        with self.assertRaises(ValueError):
            pm.login_account(database, username, "private wrong password")
        session = pm.login_account(database, username, master)
        session.clipboard = Mock()
        entry_id = pm.add_entry(database, session, "private service", "private email", "private entry password")
        pm.copy_entry_password(database, session, entry_id)
        pm.update_entry(database, session, entry_id, "private changed service", "private email")
        pm.delete_entry(database, session, entry_id)
        damaged = pm.add_entry(database, session, "private service", "private email", "private entry password")
        with database:
            database.execute("UPDATE entries SET payload = ? WHERE id = ?", (b"private damaged token", damaged))
        with self.assertRaises(ValueError):
            pm.copy_entry_password(database, session, damaged)
        session.lock(reason="inactivity")
        session.lock()  # Repeated cleanup must not duplicate a lock event.
        names = [event["event"] for event in self.events()]
        self.assertEqual(names, ["account_created", "login_failed", "login_failed", "login_succeeded",
                                 "entry_created", "password_copied", "entry_updated", "entry_deleted",
                                 "entry_created", "integrity_check_failed", "vault_locked"])
        for event in self.events():
            if event["event"] == "login_failed":
                self.assertNotIn("user_id", event)
            else:
                self.assertEqual(event["user_id"], session.owner_id)
        self.assertNotIn("private", self.path.read_text())

    def test_database_failure_logs_user_and_locks_with_safe_error(self):
        database = Mock()
        database.execute.side_effect = sqlite3.OperationalError("private diagnostic")
        session = pm.Session(5, pm.Fernet(pm.Fernet.generate_key()))
        session.clipboard = Mock(warning="")
        output = io.StringIO()
        with patch("builtins.input", return_value="2"), patch.object(pm, "clear_console"), \
                contextlib.redirect_stdout(output):
            self.assertFalse(pm.run_vault(database, session))
        self.assertIsNone(session.cipher)
        events = self.events()
        self.assertEqual(events[0]["event"], "operation_failed")
        self.assertEqual(events[0]["user_id"], 5)
        self.assertEqual(events[1]["event"], "vault_locked")
        self.assertEqual(events[1]["reason"], "error")
        self.assertNotIn("private diagnostic", self.path.read_text() + output.getvalue())

    def test_failed_copy_is_logged_without_success(self):
        clipboard = pm.Clipboard(owner_id=9)
        with patch.object(pm.subprocess, "run", side_effect=OSError("private diagnostic")):
            with self.assertRaises(ValueError):
                clipboard.copy("private password")
        self.assertEqual(self.events()[0]["event"], "operation_failed")
        self.assertEqual(self.events()[0]["operation"], "clipboard_copy")
        self.assertEqual(self.events()[0]["user_id"], 9)
        self.assertNotIn("private", self.path.read_text())


if __name__ == "__main__":
    unittest.main()
